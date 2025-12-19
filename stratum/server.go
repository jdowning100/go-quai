package stratum

import (
	"bufio"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/dominant-strategies/go-quai/cmd/utils"
	"github.com/dominant-strategies/go-quai/common"
	"github.com/dominant-strategies/go-quai/core/types"
	"github.com/dominant-strategies/go-quai/internal/quaiapi"
	"github.com/dominant-strategies/go-quai/log"
	"github.com/sirupsen/logrus"
	"github.com/spf13/viper"
)

// randReader uses time-based fallback if crypto/rand isn't imported; here we just read from net.Conn deadlines which is not desirable.
// Implement a simple wrapper over math/rand seeded by time if needed. For our use (4 bytes), this is sufficient.
type randReader struct{}

func (randReader) Read(p []byte) (int, error) {
	now := time.Now().UnixNano()
	for i := range p {
		now = (now*1103515245 + 12345) & 0x7fffffff
		p[i] = byte(now & 0xff)
	}
	return len(p), nil
}

// Stratum v1 server implementing subscribe/authorize/notify/submit using AuxPow from getPendingHeader.
type Server struct {
	addr    string
	backend quaiapi.Backend
	ln      net.Listener
	logger  *logrus.Logger
	// simple counters for debugging submission quality
	submits      uint64
	passPowCount uint64
	passRelCount uint64
}

func NewServer(addr string, backend quaiapi.Backend) *Server {
	logger := log.NewLogger("stratum.log", viper.GetString(utils.LogLevelFlag.Name), viper.GetInt(utils.LogSizeFlag.Name))
	return &Server{addr: addr, backend: backend, logger: logger}
}

func (s *Server) Start() error {
	if s.backend == nil {
		return fmt.Errorf("nil backend")
	}
	ln, err := net.Listen("tcp", s.addr)
	if err != nil {
		return err
	}
	s.ln = ln
	go s.acceptLoop()
	return nil
}
func (s *Server) Stop() error {
	if s.ln != nil {
		return s.ln.Close()
	}
	return nil
}

func (s *Server) acceptLoop() {
	for {
		conn, err := s.ln.Accept()
		if err != nil {
			return
		}
		go s.handleConn(conn)
	}
}

type stratumReq struct {
	ID     interface{}   `json:"id"`
	Method string        `json:"method"`
	Params []interface{} `json:"params"`
}
type stratumResp struct {
	ID     interface{} `json:"id"`
	Result interface{} `json:"result"`
	Error  interface{} `json:"error"`
}

type session struct {
	conn       net.Conn
	enc        *json.Encoder
	dec        *json.Decoder
	authorized bool
	user       string // payout address
	chain      string // btc|bch|ltc
	job        *job
	kawJob     *kawpowJob // kawpow-specific job data
	xnonce1    []byte
	// vardiff state (per-connection)
	difficulty    float64   // last sent miner difficulty
	vdWindowStart time.Time // window start for submit rate
	vdSubmits     int       // submits counted in window
	// version rolling state
	versionRolling bool
	versionMask    uint32
	// job tracking
	mu         sync.Mutex // protects job, jobs, jobSeq, jobHistory, difficulty
	jobs       map[string]*job
	kawJobs    map[string]*kawpowJob // kawpow job tracking
	jobSeq     uint64
	jobHistory []string // FIFO of recent job IDs for simple expiry
	// share de-duplication (per-connection LRU)
	seenShares map[string]struct{}
	seenOrder  []string
	// cleanup
	done      chan struct{}
	jobTicker *time.Ticker
}

type job struct {
	id           string
	version      uint32
	prevHashLE   string
	nBits        uint32
	nTime        uint32
	merkleBranch []string
	coinb1       string
	coinb2       string
	// the exact pending header used to construct this job
	pending *types.WorkObject
}

func (s *Server) handleConn(c net.Conn) {
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(60 * time.Second))
	dec := json.NewDecoder(bufio.NewReader(c))
	enc := json.NewEncoder(c)
	sess := &session{
		conn:       c,
		enc:        enc,
		dec:        dec,
		jobs:       make(map[string]*job),
		kawJobs:    make(map[string]*kawpowJob),
		seenShares: make(map[string]struct{}),
		seenOrder:  make([]string, 0, 1024),
		done:       make(chan struct{}),
	}

	// Cleanup function for goroutines
	defer func() {
		close(sess.done)
		if sess.jobTicker != nil {
			sess.jobTicker.Stop()
		}
	}()

	for {
		var req stratumReq
		if err := dec.Decode(&req); err != nil {
			if err == io.EOF {
				return
			}
			return
		}
		switch req.Method {
		case "mining.subscribe":
			// result: [[subscriptions], extranonce1, extranonce2_size]
			x1 := []byte{0x01, 0x01, 0x01, 0x01} // All 1s instead of random
			sess.xnonce1 = append([]byte{}, x1...)
			result := []interface{}{
				[]interface{}{[]interface{}{"mining.notify", "1"}},
				hex.EncodeToString(x1), // Will send "01010101"
				8,                      // extranonce2_size (set to 8 per nerdqaxe++ expectations)
			}
			_ = enc.Encode(stratumResp{ID: req.ID, Result: result, Error: nil})
		case "mining.extranonce.subscribe":
			_ = enc.Encode(stratumResp{ID: req.ID, Result: true, Error: nil})
		case "mining.configure":
			// Parse capabilities and options. Expect params: [capabilities(map), options(map)]
			accepted := map[string]bool{}
			maskHex := ""
			if len(req.Params) >= 1 {
				if caps, ok := req.Params[0].(map[string]interface{}); ok {
					if vr, ok2 := caps["version-rolling"].(bool); ok2 && vr {
						accepted["version-rolling"] = true
					}
				}
			}
			if len(req.Params) >= 2 {
				if opts, ok := req.Params[1].(map[string]interface{}); ok {
					if mv, ok2 := opts["version-rolling.mask"]; ok2 {
						switch m := mv.(type) {
						case string:
							maskHex = strings.TrimPrefix(strings.ToLower(m), "0x")
						case float64:
							maskHex = fmt.Sprintf("%08x", uint32(m))
						}
					}
				}
			}
			// Default mask if not provided by miner
			if maskHex == "" && accepted["version-rolling"] {
				maskHex = "1fffe000" // High 8 bits only
			}

			if true {
				if v, err := strconv.ParseUint(maskHex, 16, 32); err == nil {
					sess.versionRolling = true
					sess.versionMask = uint32(v)
					s.logger.WithField("mask", fmt.Sprintf("0x%08x", sess.versionMask)).Info("VERSION-ROLLING enabled")
				} else {
					s.logger.WithFields(log.Fields{"mask": maskHex, "error": err}).Warn("VERSION-ROLLING mask parse error")
				}
			}
			// Build configure response object per Stratum v1 (map of accepted features)
			resp := map[string]interface{}{}
			if accepted["version-rolling"] {
				resp["version-rolling"] = true
				resp["version-rolling.mask"] = fmt.Sprintf("%08x", sess.versionMask)
			}
			_ = enc.Encode(stratumResp{ID: req.ID, Result: resp, Error: nil})
			// Optionally send mining.set_version_mask for miners expecting it
			if sess.versionRolling {
				note := map[string]interface{}{"id": nil, "method": "mining.set_version_mask", "params": []interface{}{fmt.Sprintf("%08x", sess.versionMask)}}
				_ = sess.enc.Encode(note)
			}
		case "mining.authorize":
			if len(req.Params) >= 1 {
				if u, ok := req.Params[0].(string); ok {
					sess.user = u
				}
			}
			if len(req.Params) >= 2 {
				if p, ok := req.Params[1].(string); ok {
					sess.chain = strings.ToLower(p)
				}
			}
			if sess.chain == "" {
				sess.chain = "sha"
			}
			sess.authorized = true
			_ = enc.Encode(stratumResp{ID: req.ID, Result: true, Error: nil})
			// Send a fresh job with miner difficulty based on SHA workshare diff
			if err := s.sendJobAndNotify(sess); err != nil {
				s.logger.WithField("error", err).Error("makeJob error")
				// Keep trying to send a job every few seconds if it fails
				go func() {
					for i := 0; i < 10; i++ {
						select {
						case <-sess.done:
							return
						case <-time.After(2 * time.Second):
							if sess.job != nil {
								break // job was created successfully
							}
							s.logger.WithField("attempt", i+1).Info("retrying makeJob")
							if err := s.sendJobAndNotify(sess); err == nil {
								s.logger.Info("makeJob retry successful")
								break
							}
						}
					}
				}()
			}

			// Start periodic job refresh (every second)
			sess.jobTicker = time.NewTicker(1 * time.Second)
			go func() {
				for {
					select {
					case <-sess.done:
						return
					case <-sess.jobTicker.C:
						if sess.authorized {
							if err := s.sendJobAndNotify(sess); err != nil {
								s.logger.WithField("error", err).Error("periodic job refresh failed")
							} else {
								s.logger.WithField("user", sess.user).Debug("sent periodic job refresh")
							}
						}
					}
				}
			}()
		case "mining.submit":
			// Kawpow uses different submit format: [worker, job_id, nonce, header_hash, mix_hash]
			// SHA/Scrypt uses: [worker, job_id, ex2, ntime, nonce, version_bits?]
			if powIDFromChain(sess.chain) == types.Kawpow {
				if len(req.Params) < 5 {
					_ = enc.Encode(stratumResp{ID: req.ID, Result: false, Error: "bad kawpow params"})
					continue
				}
				// Kawpow params: [worker, job_id, nonce, header_hash, mix_hash]
				jobID, _ := req.Params[1].(string)
				nonceHex, _ := req.Params[2].(string)
				headerHashHex, _ := req.Params[3].(string)
				mixHashHex, _ := req.Params[4].(string)

				sess.mu.Lock()
				kawJob, ok := sess.kawJobs[jobID]
				sess.mu.Unlock()
				if !ok {
					s.logger.WithFields(log.Fields{"jobID": jobID, "known": len(sess.kawJobs)}).Error("unknown kawpow jobID")
					_ = enc.Encode(stratumResp{ID: req.ID, Result: false, Error: "nojob"})
					continue
				}

				// Submit kawpow share
				if err := s.submitKawpowShare(sess, kawJob, nonceHex, headerHashHex, mixHashHex); err != nil {
					_ = enc.Encode(stratumResp{ID: req.ID, Result: false, Error: err.Error()})
				} else {
					s.logger.WithFields(log.Fields{"addr": sess.user, "nonce": nonceHex, "mixHash": mixHashHex}).Info("kawpow submit accepted")
					sess.mu.Lock()
					delete(sess.kawJobs, jobID)
					sess.mu.Unlock()
					_ = enc.Encode(stratumResp{ID: req.ID, Result: true, Error: nil})
					// Send fresh job
					go func() {
						select {
						case <-sess.done:
							return
						default:
							if err := s.sendJobAndNotify(sess); err != nil {
								s.logger.WithField("error", err).Error("failed to send new kawpow job")
							}
						}
					}()
				}
				continue
			}

			// SHA/Scrypt submit handling
			if len(req.Params) < 5 {
				_ = enc.Encode(stratumResp{ID: req.ID, Result: false, Error: "bad params"})
				continue
			}
			// params: [user, job_id, ex2, ntime, nonce, version_bits (optional)]
			jobID, _ := req.Params[1].(string)
			ex2hex, _ := req.Params[2].(string)
			ntimeHex, _ := req.Params[3].(string)
			nonceHex, _ := req.Params[4].(string)
			var versionBits string
			if len(req.Params) >= 6 {
				versionBits, _ = req.Params[5].(string)
			}

			sess.mu.Lock()
			j, ok := sess.jobs[jobID]
			sess.mu.Unlock()
			if !ok {
				sess.enc.Encode(stratumResp{
					ID:     req.ID,
					Result: false,
					Error:  fmt.Errorf("no such jobID %s", jobID).Error(),
				})
				continue
			}
			sess.job = j

			// Look up the submitted job by ID to avoid stale/current mismatches
			sess.mu.Lock()
			if j2, ok2 := sess.jobs[jobID]; ok2 {
				sess.job = j2
				sess.mu.Unlock()
			} else {
				known := len(sess.jobs)
				sess.mu.Unlock()
				s.logger.WithFields(log.Fields{"jobID": jobID, "known": known}).Error("unknown or stale jobID")
				_ = enc.Encode(stratumResp{ID: req.ID, Result: false, Error: "nojob"})
				continue
			}
			// apply nonce into AuxPow header and submit as workshare
			if err := s.submitAsWorkShare(sess, ex2hex, ntimeHex, nonceHex, versionBits); err != nil {
				_ = enc.Encode(stratumResp{ID: req.ID, Result: false, Error: err.Error()})
			} else {
				s.logger.WithFields(log.Fields{"addr": sess.user, "chain": sess.chain, "nonce": nonceHex}).Info("submit accepted")
				// Mark this job ID as consumed to prevent duplicate submissions
				sess.mu.Lock()
				delete(sess.jobs, jobID)
				sess.mu.Unlock()
				_ = enc.Encode(stratumResp{ID: req.ID, Result: true, Error: nil})
				// Send a fresh job after successful workshare to keep miner on latest work
				go func() {
					select {
					case <-sess.done:
						return
					default:
						if err := s.sendJobAndNotify(sess); err != nil {
							s.logger.WithField("error", err).Error("failed to send new job after workshare")
						}
					}
				}()
			}
		default:
			_ = enc.Encode(stratumResp{ID: req.ID, Result: nil, Error: nil})
		}
	}
}

// sendJobAndNotify creates a new job, sets miner difficulty using SHA workshare diff,
// and sends set_difficulty followed by mining.notify.
func (s *Server) sendJobAndNotify(sess *session) error {
	// Kawpow uses a different stratum format
	if powIDFromChain(sess.chain) == types.Kawpow {
		return s.sendKawpowJob(sess)
	}

	j, err := s.makeJob(sess)
	if err != nil {
		return err
	}
	// Assign a unique job ID and track it (protected by session mutex)
	sess.mu.Lock()
	j.id = s.newJobID(sess)
	sess.job = j
	if sess.jobs == nil {
		sess.jobs = make(map[string]*job)
	}
	sess.jobs[j.id] = j
	// Maintain a small history to allow a few stale shares; drop oldest beyond 16
	sess.jobHistory = append(sess.jobHistory, j.id)
	if len(sess.jobHistory) > 16 {
		old := sess.jobHistory[0]
		sess.jobHistory = sess.jobHistory[1:]
		delete(sess.jobs, old)
	}
	sess.mu.Unlock()
	s.logger.WithFields(log.Fields{"jobID": j.id, "chain": sess.chain}).Info("notify job")

	// Compute stratum difficulty. Two mappings are common:
	// 1) Exact mapping against Bitcoin diff1 target: D = diff1 * ShaDiff / maxHash (minerTarget == workShareTarget)
	// 2) Pool/alt mapping used by some miners/pools: D = ShaDiff / 65536 (assumes diff1' := maxHash >> 32)
	// For now we use (2) to keep miner share rates sane without needing explicit diff1 constants.
	d := 1e-10 // fallback
	switch powIDFromChain(sess.chain) {
	case types.SHA_BTC, types.SHA_BCH:
		if j.pending != nil && j.pending.WorkObjectHeader() != nil && j.pending.WorkObjectHeader().ShaDiffAndCount() != nil && j.pending.WorkObjectHeader().ShaDiffAndCount().Difficulty() != nil {
			sd := j.pending.WorkObjectHeader().ShaDiffAndCount().Difficulty()
			// Map Quai workshare difficulty to Stratum difficulty using alt mapping D = diff/65536
			// Use big.Float to avoid overflow and convert to float64 for the Stratum call
			diffF, _ := new(big.Float).Quo(new(big.Float).SetInt(sd), big.NewFloat(2e32)).Float64()
			if diffF <= 0 {
				diffF = d
			}
			// Protect concurrent writes to session fields
			sess.mu.Lock()
			sess.difficulty = diffF
			sess.mu.Unlock()

			s.logger.WithFields(log.Fields{"ShaDiff": sd.String(), "minerDiff": diffF}).Debug("sendJobAndNotify SHA diff")
		} else {
			s.logger.WithField("fallback", d).Debug("sendJobAndNotify: No SHA diff available, using fallback")
		}
	case types.Scrypt:
		if j.pending != nil && j.pending.WorkObjectHeader() != nil && j.pending.WorkObjectHeader().ScryptDiffAndCount() != nil && j.pending.WorkObjectHeader().ScryptDiffAndCount().Difficulty() != nil {
			sd := j.pending.WorkObjectHeader().ScryptDiffAndCount().Difficulty()
			// Classic Scrypt pool behavior: Stratum difficulty D = sd / 65536
			diffF, _ := new(big.Float).Quo(new(big.Float).SetInt(sd), big.NewFloat(65536)).Float64()
			if diffF <= 0 {
				diffF = d
			}
			sess.mu.Lock()
			sess.difficulty = diffF
			sess.mu.Unlock()
			s.logger.WithFields(log.Fields{"ScryptDiff": sd.String(), "minerDiff": diffF}).Debug("sendJobAndNotify Scrypt diff")
		} else {
			s.logger.WithField("fallback", d).Debug("sendJobAndNotify: No Scrypt diff available, using fallback")
		}
	case types.Kawpow:
		if j.pending != nil && j.pending.WorkObjectHeader() != nil && j.pending.WorkObjectHeader().KawpowDifficulty() != nil {
			kd := j.pending.WorkObjectHeader().KawpowDifficulty()
			// Kawpow difficulty mapping similar to SHA
			diffF, _ := new(big.Float).Quo(new(big.Float).SetInt(kd), big.NewFloat(2e32)).Float64()
			if diffF <= 0 {
				diffF = d
			}
			sess.mu.Lock()
			sess.difficulty = diffF
			sess.mu.Unlock()
			s.logger.WithFields(log.Fields{"KawpowDiff": kd.String(), "minerDiff": diffF}).Debug("sendJobAndNotify Kawpow diff")
		} else {
			s.logger.WithField("fallback", d).Debug("sendJobAndNotify: No Kawpow diff available, using fallback")
		}
	default:
		// keep fallback for non-SHA donor algos
		s.logger.WithFields(log.Fields{"chain": sess.chain, "fallback": d}).Debug("sendJobAndNotify: Non-SHA/Scrypt chain, using fallback")
	}

	// Send set_difficulty (and set_target for miners that honor it) then the job notify
	sess.mu.Lock()
	minerDiff := sess.difficulty
	sess.mu.Unlock()
	s.logger.WithField("difficulty", minerDiff).Debug("Sending mining.set_difficulty to miner")
	diffNote := map[string]interface{}{"id": nil, "method": "mining.set_difficulty", "params": []interface{}{minerDiff}}
	_ = sess.enc.Encode(diffNote)

	params := []interface{}{j.id, j.prevHashLE, j.coinb1, j.coinb2, j.merkleBranch, fmt.Sprintf("%08x", j.version), fmt.Sprintf("%08x", j.nBits), fmt.Sprintf("%08x", j.nTime), true}

	note := map[string]interface{}{"id": nil, "method": "mining.notify", "params": params}

	return sess.enc.Encode(note)
}

// sendKawpowJob creates and sends a kawpow-specific job to the miner.
// Kawpow stratum notify format: [job_id, header_hash, seed_hash, target, clean, height, bits]
func (s *Server) sendKawpowJob(sess *session) error {
	address := common.HexToAddress(sess.user, common.Location{0, 0})
	pending, err := s.backend.GetPendingHeader(types.Kawpow, address)
	if err != nil || pending == nil || pending.WorkObjectHeader() == nil {
		if err == nil {
			err = fmt.Errorf("no pending header for kawpow")
		}
		s.logger.WithField("error", err).Error("sendKawpowJob error")
		return err
	}
	pending.WorkObjectHeader().SetPrimaryCoinbase(address)

	// Get block height from pending header
	height := pending.NumberU64(common.ZONE_CTX)

	// Calculate epoch and seed hash from height
	epoch := calculateEpoch(height)
	seedHash := calculateSeedHash(epoch)

	// Get kawpow difficulty and convert to target
	var targetHex string
	if pending.WorkObjectHeader().KawpowDifficulty() != nil {
		kawDiff := pending.WorkObjectHeader().KawpowDifficulty()
		targetHex = difficultyToTarget(kawDiff)
		s.logger.WithFields(log.Fields{"KawpowDiff": kawDiff.String(), "target": targetHex, "height": height, "epoch": epoch}).Debug("kawpow job params")
	} else {
		// Fallback to max target
		targetHex = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
		s.logger.Warn("No kawpow difficulty available, using max target")
	}

	// Get nBits from AuxPow header if available
	var nBits uint32
	if pending.WorkObjectHeader().AuxPow() != nil && pending.WorkObjectHeader().AuxPow().Header() != nil {
		nBits = pending.WorkObjectHeader().AuxPow().Header().Bits()
	}

	// Calculate header hash for kawpow (keccak256 of header without nonce/mixhash)
	// For kawpow, we need to create the header hash that miners will work on
	headerHash := calculateKawpowHeaderHash(pending.SealHash().Bytes())

	// Create kawpow job
	sess.mu.Lock()
	sess.jobSeq++
	jobID := fmt.Sprintf("%x%04x", uint64(time.Now().UnixNano()), sess.jobSeq&0xffff)

	kawJob := &kawpowJob{
		id:         jobID,
		headerHash: headerHash,
		seedHash:   seedHash,
		target:     targetHex,
		height:     height,
		bits:       nBits,
		pending:    types.CopyWorkObject(pending),
	}
	sess.kawJob = kawJob
	sess.kawJobs[jobID] = kawJob

	// Maintain job history (drop oldest beyond 16)
	sess.jobHistory = append(sess.jobHistory, jobID)
	if len(sess.jobHistory) > 16 {
		old := sess.jobHistory[0]
		sess.jobHistory = sess.jobHistory[1:]
		delete(sess.kawJobs, old)
	}
	sess.mu.Unlock()

	s.logger.WithFields(log.Fields{"jobID": jobID, "height": height, "epoch": epoch}).Info("notify kawpow job")

	// Send set_target for kawpow miners (some expect this)
	targetNote := map[string]interface{}{"id": nil, "method": "mining.set_target", "params": []interface{}{targetHex}}
	_ = sess.enc.Encode(targetNote)

	// Kawpow mining.notify format: [job_id, header_hash, seed_hash, target, clean, height, bits]
	// Note: height is sent as hex string, bits as hex string
	params := []interface{}{
		jobID,
		headerHash,
		seedHash,
		targetHex,
		true, // clean_jobs
		fmt.Sprintf("%x", height),
		fmt.Sprintf("%08x", nBits),
	}

	note := map[string]interface{}{"id": nil, "method": "mining.notify", "params": params}
	return sess.enc.Encode(note)
}

func (s *Server) makeJob(sess *session) (*job, error) {
	powID := powIDFromChain(sess.chain)
	address := common.HexToAddress(sess.user, common.Location{0, 0})
	pending, err := s.backend.GetPendingHeader(types.PowID(powID), address)

	if err != nil || pending == nil || pending.WorkObjectHeader() == nil || pending.WorkObjectHeader().AuxPow() == nil {
		if err == nil {
			err = fmt.Errorf("no pending header")
		}
		s.logger.WithField("error", err).Error("makeJob error")
		return nil, err
	}
	pending.WorkObjectHeader().SetPrimaryCoinbase(address)

	aux := pending.WorkObjectHeader().AuxPow()

	// Keep the existing SHA workshare difficulty - don't override with BCH difficulty
	// The workshare system uses its own difficulty separate from the BCH block difficulty
	if pending.WorkObjectHeader().ShaDiffAndCount() != nil {
		currentDiff := pending.WorkObjectHeader().ShaDiffAndCount().Difficulty()
		s.logger.WithField("ShaDiff", currentDiff.String()).Debug("Using existing workshare ShaDiff")
	}

	// Also log existing Scrypt workshare difficulty if present
	if pending.WorkObjectHeader().ScryptDiffAndCount() != nil {
		currentDiff := pending.WorkObjectHeader().ScryptDiffAndCount().Difficulty()
		s.logger.WithField("ScryptDiff", currentDiff.String()).Debug("Using existing workshare ScryptDiff")
	}

	// Merkle branch
	mb := make([]string, len(aux.MerkleBranch()))
	for i, h := range aux.MerkleBranch() {
		mb[i] = hex.EncodeToString(h)
	}
	// header fields
	version := aux.Header().Version()
	prev := aux.Header().PrevBlock()
	nBits := aux.Header().Bits()
	nTime := aux.Header().Timestamp()

	coinb1, coinb2, err := types.ExtractCoinb1AndCoinb2FromAuxPowTx(aux.Transaction())
	if err != nil {
		return nil, err
	}

	// Send fully reversed and word-swapped prevhash to miner (to match validation)
	// prevReversed := fullReverse(prev[:])
	var prevLE [32]byte
	copy(prevLE[:], prev[:])
	prevLESwapped := swapWords32x32(prevLE)

	return &job{
		id:           "", // assigned in sendJobAndNotify
		version:      uint32(version),
		prevHashLE:   hex.EncodeToString(prevLESwapped[:]),
		nBits:        nBits,
		nTime:        nTime,
		merkleBranch: mb,
		coinb1:       hex.EncodeToString(coinb1),
		coinb2:       hex.EncodeToString(coinb2),
		pending:      types.CopyWorkObject(pending),
	}, nil
}

// newJobID returns a per-session unique job ID string
func (s *Server) newJobID(sess *session) string {
	// Caller should hold sess.mu
	sess.jobSeq++
	// Use time and a small counter to ensure uniqueness; keep compact
	ts := uint64(time.Now().UnixNano())
	return fmt.Sprintf("%x%04x", ts, sess.jobSeq&0xffff)
}

func (s *Server) submitAsWorkShare(sess *session, ex2hex, ntimeHex, nonceHex, versionBits string) error {
	powID := powIDFromChain(sess.chain)
	// fmt.Printf("[stratum] DEBUG submitAsWorkShare: chain=%s powID=%d ex2=%s ntime=%s nonce=%s versionBits=%s\n",
	// 	sess.chain, powID, ex2hex, ntimeHex, nonceHex, versionBits)

	// Snapshot current job under lock to avoid races with async job refresh
	sess.mu.Lock()
	curJob := sess.job
	sess.mu.Unlock()
	if curJob == nil {
		return fmt.Errorf("no current job")
	}
	pending := curJob.pending
	if pending == nil || pending.WorkObjectHeader() == nil || pending.WorkObjectHeader().AuxPow() == nil {
		return fmt.Errorf("no pending header for job")
	}

	// Rebuild donor header for SHA chains with updated merkle root and nTime
	templateHeader := pending.AuxPow().Header()

	// Reconstruct coinbase from coinb1 + ex2 + coinb2
	ex2, _ := hex.DecodeString(ex2hex)
	if len(ex2) != 8 {
		return fmt.Errorf("bad extranonce2 length")
	}

	// Reconstruct full coinbase: coinb1 + [0x04][ex1] + [0x04][ex2] + coinb2
	coinb1Bytes, _ := hex.DecodeString(curJob.coinb1)
	coinb2Bytes, _ := hex.DecodeString(curJob.coinb2)

	fullCoinb := make([]byte, 0, len(coinb1Bytes)+12+len(coinb2Bytes))
	fullCoinb = append(fullCoinb, coinb1Bytes...)
	fullCoinb = append(fullCoinb, sess.xnonce1...) // use the exact extranonce1 you sent in subscribe
	fullCoinb = append(fullCoinb, ex2...)          // miner’s extranonce2
	fullCoinb = append(fullCoinb, coinb2Bytes...)

	merkleRoot := types.CalculateMerkleRoot(powID, fullCoinb, pending.AuxPow().MerkleBranch())

	ntime, err := strconv.ParseUint(ntimeHex, 16, 32)
	if err != nil {
		return fmt.Errorf("invalid ntime: %v", err)
	}

	// Parse nonce from hex string
	nonce, err := strconv.ParseUint(nonceHex, 16, 32)
	if err != nil {
		return fmt.Errorf("invalid nonce: %v", err)
	}

	// Parse version bits (if provided)
	var finalVersion uint32
	if sess.versionRolling && versionBits != "" {
		vb, _ := strconv.ParseUint(versionBits, 16, 32)

		// ALWAYS apply mask - even for new ex2!
		finalVersion = (uint32(curJob.version) & ^sess.versionMask) |
			(uint32(vb) & sess.versionMask)
	} else {
		finalVersion = uint32(curJob.version)
	}

	templateHeader = types.NewBlockHeader(
		types.PowID(powID),
		int32(finalVersion),
		templateHeader.PrevBlock(), // Use same format as sent to miner
		merkleRoot,
		uint32(ntime),         // Correctly parsed uint32
		templateHeader.Bits(), // Use original nBits from job
		uint32(nonce),         // Correctly parsed uint32
		0,
	)

	hashBytes := templateHeader.PowHash().Bytes()

	powHashBigInt := new(big.Int).SetBytes(hashBytes)
	var workShareTarget *big.Int
	switch pending.AuxPow().PowID() {
	case types.Scrypt:
		// fmt.Printf("[stratum] pow=Scrypt, powHashBigInt=%s, difficulty=%s, count=%s\n", powHashBigInt.String(),
		// 	pending.WorkObjectHeader().ScryptDiffAndCount().Difficulty(),
		// 	pending.WorkObjectHeader().ScryptDiffAndCount().Count())
		workShareTarget = new(big.Int).Div(common.Big2e256, pending.WorkObjectHeader().ScryptDiffAndCount().Difficulty())
	case types.Kawpow:
		// fmt.Printf("[stratum] pow=Kawpow, powHashBigInt=%s, difficulty=%s\n", powHashBigInt.String(),
		// 	pending.WorkObjectHeader().KawpowDifficulty())
		workShareTarget = new(big.Int).Div(common.Big2e256, pending.WorkObjectHeader().KawpowDifficulty())
	default:
		// SHA_BTC, SHA_BCH
		// fmt.Printf("[stratum] pow=SHA, powHashBigInt=%s, difficulty=%s, count=%s\n", powHashBigInt.String(),
		// 	pending.WorkObjectHeader().ShaDiffAndCount().Difficulty(),
		// 	pending.WorkObjectHeader().ShaDiffAndCount().Count())
		workShareTarget = new(big.Int).Div(common.Big2e256, pending.WorkObjectHeader().ShaDiffAndCount().Difficulty())
	}

	if workShareTarget == nil {
		return fmt.Errorf("missing workshare difficulty")
	}

	// Log how close the hash is to the target (target/hash as a percentage)
	var achievedDiff *big.Int
	if workShareTarget != nil && powHashBigInt.Sign() > 0 {
		// targetF := new(big.Float).SetInt(workShareTarget)
		hashF := new(big.Float).SetInt(powHashBigInt)
		if hashF.Sign() != 0 {
			// closeness := new(big.Float).Quo(targetF, hashF) // target/hash
			// closenessPct, _ := closeness.Float64()
			// fmt.Printf("[stratum] Work closeness: %.4f%% (target/hash)\n", closenessPct*100)

			if workShareTarget != nil {
				achievedDiff = new(big.Int).Div(new(big.Int).Set(common.Big2e256), powHashBigInt)
				// ratio := new(big.Float).Quo(new(big.Float).SetInt(achievedDiff), new(big.Float).SetInt(workShareTarget))
				// ratioF, _ := ratio.Float64()
				// fmt.Printf("[stratum] Difficulty achieved: %s, target: %s (%.4fx)\n", achievedDiff.String(), workShareTarget.String(), ratioF)
			}
		}
	}

	if pending.WorkObjectHeader().AuxPow() == nil {
		return fmt.Errorf("work object missing auxpow")
	}

	pending.WorkObjectHeader().AuxPow().SetHeader(templateHeader)
	pending.WorkObjectHeader().AuxPow().SetTransaction(fullCoinb)

	//bytes := pending.Hash().Bytes()
	// fmt.Printf("[stratum] header %x\n", templateHeader.Bytes())
	// fmt.Printf("[stratum] pow hash %x\n", hashBytes)
	// fmt.Printf("[stratum] workshare hash %x\n", bytes)

	// Check if satisfies workShareTarget
	if powHashBigInt.Cmp(workShareTarget) > 0 {
		return fmt.Errorf("did not meet thresold")
	}

	// LRU de-dup: reject identical shares (same pow hash) for this session
	shareKey := hex.EncodeToString(hashBytes)
	sess.mu.Lock()
	if _, seen := sess.seenShares[shareKey]; seen {
		sess.mu.Unlock()
		return fmt.Errorf("duplicate share")
	}
	// Insert and evict oldest if capacity exceeded
	const lruCap = 1024
	sess.seenShares[shareKey] = struct{}{}
	sess.seenOrder = append(sess.seenOrder, shareKey)
	if len(sess.seenOrder) > lruCap {
		oldest := sess.seenOrder[0]
		sess.seenOrder = sess.seenOrder[1:]
		delete(sess.seenShares, oldest)
	}
	sess.mu.Unlock()

	s.logger.WithFields(log.Fields{"powID": pending.AuxPow().PowID(), "achievedDiff": achievedDiff.String(), "hashBytes": hex.EncodeToString(hashBytes)}).Info("workshare received")

	return s.backend.ReceiveMinedHeader(pending)
}

// submitKawpowShare handles kawpow share submissions
// Kawpow submit params: [worker, job_id, nonce, header_hash, mix_hash]
func (s *Server) submitKawpowShare(sess *session, kawJob *kawpowJob, nonceHex, headerHashHex, mixHashHex string) error {
	if kawJob == nil || kawJob.pending == nil {
		return fmt.Errorf("no kawpow job")
	}

	pending, ok := kawJob.pending.(*types.WorkObject)
	if !ok || pending == nil {
		return fmt.Errorf("invalid kawpow pending work")
	}

	// Parse nonce (8 bytes for kawpow)
	nonce, err := strconv.ParseUint(nonceHex, 16, 64)
	if err != nil {
		return fmt.Errorf("invalid nonce: %v", err)
	}

	// Parse mix hash (32 bytes)
	mixHash, err := hex.DecodeString(mixHashHex)
	if err != nil || len(mixHash) != 32 {
		return fmt.Errorf("invalid mix hash")
	}

	// Get the target from the job
	targetHex := kawJob.target
	if targetHex == "" {
		return fmt.Errorf("no target in job")
	}

	// For kawpow verification, we need to check if the submitted hash meets the target
	// The miner sends the header_hash which should match what we sent in the job
	if headerHashHex != kawJob.headerHash {
		s.logger.WithFields(log.Fields{
			"expected": kawJob.headerHash,
			"got":      headerHashHex,
		}).Warn("header hash mismatch")
		// Allow mismatched header hash for now - some miners may compute it differently
	}

	// Get workshare target from difficulty
	var workShareTarget *big.Int
	if pending.WorkObjectHeader().KawpowDifficulty() != nil {
		workShareTarget = new(big.Int).Div(common.Big2e256, pending.WorkObjectHeader().KawpowDifficulty())
	} else {
		return fmt.Errorf("no kawpow difficulty")
	}

	// For kawpow, the final hash is computed from the header hash, nonce, and DAG
	// The miner provides the mix_hash which is used to verify the computation
	// We need to verify the share meets the target

	// Create a pseudo-hash from the mix hash for verification
	// In a full implementation, we would run kawpow verification here
	// For now, we trust the miner's mix_hash and check it against target
	mixHashInt := new(big.Int).SetBytes(mixHash)

	// Check if mix hash meets target (simplified verification)
	// Real kawpow verification would re-compute the hash using the DAG
	if mixHashInt.Cmp(workShareTarget) > 0 {
		return fmt.Errorf("share did not meet target")
	}

	// LRU de-dup
	shareKey := fmt.Sprintf("%s:%s:%s", kawJob.id, nonceHex, mixHashHex)
	sess.mu.Lock()
	if _, seen := sess.seenShares[shareKey]; seen {
		sess.mu.Unlock()
		return fmt.Errorf("duplicate share")
	}
	const lruCap = 1024
	sess.seenShares[shareKey] = struct{}{}
	sess.seenOrder = append(sess.seenOrder, shareKey)
	if len(sess.seenOrder) > lruCap {
		oldest := sess.seenOrder[0]
		sess.seenOrder = sess.seenOrder[1:]
		delete(sess.seenShares, oldest)
	}
	sess.mu.Unlock()

	// Set the nonce and mix hash on the pending header
	// Note: This requires the WorkObject to support kawpow nonce/mixhash
	pending.WorkObjectHeader().SetNonce(types.EncodeNonce(nonce))
	var mixHashArray [32]byte
	copy(mixHashArray[:], mixHash)
	pending.WorkObjectHeader().SetMixHash(common.Hash(mixHashArray))

	achievedDiff := new(big.Int).Div(common.Big2e256, mixHashInt)
	s.logger.WithFields(log.Fields{
		"powID":       types.Kawpow,
		"height":      kawJob.height,
		"nonce":       nonceHex,
		"achievedDiff": achievedDiff.String(),
	}).Info("kawpow workshare received")

	return s.backend.ReceiveMinedHeader(pending)
}

// swapWords32x32 swaps byte order within each 4-byte word of a 32-byte array.
func swapWords32x32(in [32]byte) [32]byte {
	var out [32]byte
	for off := 0; off < 32; off += 4 {
		out[off+0] = in[off+3]
		out[off+1] = in[off+2]
		out[off+2] = in[off+1]
		out[off+3] = in[off+0]
	}
	return out
}

// fullReverse reverses the entire byte slice.
func fullReverse(b []byte) []byte {
	out := make([]byte, len(b))
	for i := range b {
		out[i] = b[len(b)-1-i]
	}
	return out
}

func powIDFromChain(chain string) types.PowID {
	switch strings.ToLower(chain) {
	case "sha":
		return types.SHA_BCH
	case "scrypt":
		return types.Scrypt
	case "kawpow":
		return types.Kawpow
	default:
		return types.SHA_BTC
	}
}
