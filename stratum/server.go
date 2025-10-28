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

	"github.com/dominant-strategies/go-quai/common"
	"github.com/dominant-strategies/go-quai/core/types"
	"github.com/dominant-strategies/go-quai/internal/quaiapi"
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
	// simple counters for debugging submission quality
	submits      uint64
	passPowCount uint64
	passRelCount uint64
}

func NewServer(addr string, backend quaiapi.Backend) *Server {
	return &Server{addr: addr, backend: backend}
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
					fmt.Printf("[stratum] VERSION-ROLLING enabled mask=0x%08x\n", sess.versionMask)
				} else {
					fmt.Printf("[stratum] VERSION-ROLLING mask parse error for %q: %v\n", maskHex, err)
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
				sess.chain = "btc"
			}
			sess.authorized = true
			_ = enc.Encode(stratumResp{ID: req.ID, Result: true, Error: nil})
			// Send a fresh job with miner difficulty based on SHA workshare diff
			if err := s.sendJobAndNotify(sess); err != nil {
				fmt.Printf("[stratum] makeJob error: %v\n", err)
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
							fmt.Printf("[stratum] retrying makeJob (attempt %d)...\n", i+1)
							if err := s.sendJobAndNotify(sess); err == nil {
								fmt.Printf("[stratum] makeJob retry successful\n")
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
								fmt.Printf("[stratum] periodic job refresh failed: %v\n", err)
							} else {
								fmt.Printf("[stratum] sent periodic job refresh to %s\n", sess.user)
							}
						}
					}
				}
			}()
		case "mining.submit":
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
				// fmt.Printf("[stratum] DEBUG: miner submitted version bits: %s\n", versionBits)
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
				continue // Ignore this submission gracefully
			}
			sess.job = j

			// Debug job tracking
			// sess.mu.Lock()
			// curJobID := "nil"
			// if sess.job != nil {
			// 	curJobID = sess.job.id
			// }
			// sess.mu.Unlock()
			//fmt.Printf("[stratum] DEBUG mining.submit: jobID=%s sess.job.id=%s\n", jobID, curJobID)

			// Look up the submitted job by ID to avoid stale/current mismatches
			sess.mu.Lock()
			if j2, ok2 := sess.jobs[jobID]; ok2 {
				sess.job = j2
				sess.mu.Unlock()
			} else {
				known := len(sess.jobs)
				sess.mu.Unlock()
				fmt.Printf("[stratum] ERROR: unknown or stale jobID=%s (known=%d)\n", jobID, known)
				_ = enc.Encode(stratumResp{ID: req.ID, Result: false, Error: "nojob"})
				continue
			}
			// apply nonce into AuxPow header and submit as workshare
			if err := s.submitAsWorkShare(sess, ex2hex, ntimeHex, nonceHex, versionBits); err != nil {
				_ = enc.Encode(stratumResp{ID: req.ID, Result: false, Error: err.Error()})
			} else {
				fmt.Printf("[stratum] submit accepted addr=%s chain=%s nonce=%s\n", sess.user, sess.chain, nonceHex)
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
							fmt.Printf("[stratum] failed to send new job after workshare: %v\n", err)
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
	fmt.Printf("[stratum] notify job id=%s chain=%s\n", j.id, sess.chain)

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

			fmt.Printf("[stratum] DEBUG sendJobAndNotify: ShaDiff=%s minerDiff(mapped)=%.6f \n", sd.String(), diffF)
		} else {
			fmt.Printf("[stratum] DEBUG sendJobAndNotify: No SHA diff available, using fallback %f\n", d)
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
			fmt.Printf("[stratum] DEBUG sendJobAndNotify: ScryptDiff=%s minerDiff(mapped)=%.6f \n", sd.String(), diffF)
		} else {
			fmt.Printf("[stratum] DEBUG sendJobAndNotify: No Scrypt diff available, using fallback %f\n", d)
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
			fmt.Printf("[stratum] DEBUG sendJobAndNotify: KawpowDiff=%s minerDiff(mapped)=%.6f \n", kd.String(), diffF)
		} else {
			fmt.Printf("[stratum] DEBUG sendJobAndNotify: No Kawpow diff available, using fallback %f\n", d)
		}
	default:
		// keep fallback for non-SHA donor algos
		fmt.Printf("[stratum] DEBUG sendJobAndNotify: Non-SHA/Scrypt chain %s, using fallback %f\n", sess.chain, d)
	}

	// Send set_difficulty (and set_target for miners that honor it) then the job notify
	sess.mu.Lock()
	minerDiff := sess.difficulty
	sess.mu.Unlock()
	fmt.Printf("[stratum] DEBUG: Sending mining.set_difficulty with value %.6f to miner\n", minerDiff)
	diffNote := map[string]interface{}{"id": nil, "method": "mining.set_difficulty", "params": []interface{}{minerDiff}}
	_ = sess.enc.Encode(diffNote)

	params := []interface{}{j.id, j.prevHashLE, j.coinb1, j.coinb2, j.merkleBranch, fmt.Sprintf("%08x", j.version), fmt.Sprintf("%08x", j.nBits), fmt.Sprintf("%08x", j.nTime), true}

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
		fmt.Printf("[stratum] makeJob error: %v\n", err)
		return nil, err
	}
	pending.WorkObjectHeader().SetPrimaryCoinbase(address)

	aux := pending.WorkObjectHeader().AuxPow()

	// Keep the existing SHA workshare difficulty - don't override with BCH difficulty
	// The workshare system uses its own difficulty separate from the BCH block difficulty
	if pending.WorkObjectHeader().ShaDiffAndCount() != nil {
		currentDiff := pending.WorkObjectHeader().ShaDiffAndCount().Difficulty()
		fmt.Printf("[stratum] DEBUG: Using existing workshare ShaDiff: %s\n", currentDiff.String())
	}

	// Also log existing Scrypt workshare difficulty if present
	if pending.WorkObjectHeader().ScryptDiffAndCount() != nil {
		currentDiff := pending.WorkObjectHeader().ScryptDiffAndCount().Difficulty()
		fmt.Printf("[stratum] DEBUG: Using existing workshare ScryptDiff: %s\n", currentDiff.String())
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

	fmt.Printf("[stratum] workshare received powID=%d achievedDiff=%s hashBytes=%x\n", pending.AuxPow().PowID(), achievedDiff.String(), hashBytes)

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
	case "btc":
		return types.SHA_BTC
	case "bch":
		return types.SHA_BCH
	case "ltc", "scrypt":
		return types.Scrypt
	case "rvn", "kawpow":
		return types.Kawpow
	default:
		return types.SHA_BTC
	}
}
