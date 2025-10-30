package telemetry

import (
	"encoding/json"
	"sync"
	"sync/atomic"
	"time"

	lru "github.com/hashicorp/golang-lru/v2"

	"github.com/dominant-strategies/go-quai/common"
	"github.com/dominant-strategies/go-quai/core/types"
	"github.com/dominant-strategies/go-quai/log"
)

type algoKey string

const (
	algoProgpow algoKey = "progpow"
	algoKawpow  algoKey = "kawpow"
	algoSHA     algoKey = "sha"
	algoScrypt  algoKey = "scrypt"

	wsLRUSize = 4096
)

// WorkshareRecord keeps the header, optional full WO and firstSeen time.
type WorkshareRecord struct {
	Header     *types.WorkObjectHeader
	WorkObject *types.WorkObject
	FirstSeen  time.Time
}

// counters holds aggregate and per-algorithm counters.
type counters struct {
	// Received from miner (local)
	recTotal   atomic.Uint64
	recProgpow atomic.Uint64
	recKawpow  atomic.Uint64
	recSHA     atomic.Uint64
	recScrypt  atomic.Uint64
	// Sent into libp2p
	sentTotal   atomic.Uint64
	sentProgpow atomic.Uint64
	sentKawpow  atomic.Uint64
	sentSHA     atomic.Uint64
	sentScrypt  atomic.Uint64
	// Included in blocks (totals across all blocks processed)
	inclTotal   atomic.Uint64
	inclProgpow atomic.Uint64
	inclKawpow  atomic.Uint64
	inclSHA     atomic.Uint64
	inclScrypt  atomic.Uint64
	// Included in blocks that were produced locally
	inclMineTotal   atomic.Uint64
	inclMineProgpow atomic.Uint64
	inclMineKawpow  atomic.Uint64
	inclMineSHA     atomic.Uint64
	inclMineScrypt  atomic.Uint64
}

var (
	wsCtr counters

	// localShares holds hashes of workshares produced locally (received from miner API).
	localSharesMu sync.RWMutex
	localShares   = make(map[common.Hash]algoKey, 1024)

	// Stage LRUs
	initOnce sync.Once
	recLRU   *lru.Cache[common.Hash, *WorkshareRecord]
	sentLRU  *lru.Cache[common.Hash, *WorkshareRecord]
	inclLRU  *lru.Cache[common.Hash, *WorkshareRecord]
)

// limitEntries returns at most n entries from es (generic helper).
func limitEntries[T any](es []T, n int) []T {
	if n <= 0 {
		return nil
	}
	if len(es) > n {
		return es[:n]
	}
	return es
}

func ensureLRUs() {
	initOnce.Do(func() {
		recLRU, _ = lru.New[common.Hash, *WorkshareRecord](wsLRUSize)
		sentLRU, _ = lru.New[common.Hash, *WorkshareRecord](wsLRUSize)
		inclLRU, _ = lru.New[common.Hash, *WorkshareRecord](wsLRUSize)
	})
}

func algoFromHeader(h *types.WorkObjectHeader) algoKey {
	if h == nil || h.AuxPow() == nil {
		return algoProgpow
	}
	switch h.AuxPow().PowID() {
	case types.Kawpow:
		return algoKawpow
	case types.SHA_BTC, types.SHA_BCH:
		return algoSHA
	case types.Scrypt:
		return algoScrypt
	default:
		return algoProgpow
	}
}

func bumpByAlgo(which algoKey, total, progpow, kawpow, sha, scrypt *atomic.Uint64) {
	total.Add(1)
	switch which {
	case algoProgpow:
		progpow.Add(1)
	case algoKawpow:
		kawpow.Add(1)
	case algoSHA:
		sha.Add(1)
	case algoScrypt:
		scrypt.Add(1)
	}
}

func upsertRecordIn(l *lru.Cache[common.Hash, *WorkshareRecord], h *types.WorkObjectHeader, wo *types.WorkObject) *WorkshareRecord {
	if h == nil {
		return nil
	}
	hash := h.Hash()
	if rec, ok := l.Get(hash); ok && rec != nil {
		// Update WO if provided
		if wo != nil {
			rec.WorkObject = wo
		}
		l.Add(hash, rec)
		return rec
	}
	rec := &WorkshareRecord{Header: h, WorkObject: wo, FirstSeen: time.Now()}
	l.Add(hash, rec)
	return rec
}

func deleteFrom(l *lru.Cache[common.Hash, *WorkshareRecord], hash common.Hash) {
	if l == nil {
		return
	}
	l.Remove(hash)
}

// RecordReceived increments counters and adds to "received" LRU (header-only available here).
func RecordReceived(h *types.WorkObjectHeader) {
	RecordReceivedHeader(h)
}

// RecordReceivedHeader increments counters and adds to "received" LRU.
func RecordReceivedHeader(h *types.WorkObjectHeader) {
	if h == nil {
		return
	}
	ensureLRUs()

	algo := algoFromHeader(h)
	bumpByAlgo(algo, &wsCtr.recTotal, &wsCtr.recProgpow, &wsCtr.recKawpow, &wsCtr.recSHA, &wsCtr.recScrypt)

	// Mark local share and add to received LRU
	localSharesMu.Lock()
	localShares[h.Hash()] = algo
	localSharesMu.Unlock()

	upsertRecordIn(recLRU, h, nil)
	// Ensure not present in later stages yet
	deleteFrom(sentLRU, h.Hash())
	deleteFrom(inclLRU, h.Hash())

	log.Global.WithFields(log.Fields{
		"type":   "workshare.received",
		"algo":   string(algo),
		"hash":   h.Hash(),
		"totals": snapshot(),
	}).Info("Workshare received from miner")
}

// RecordSent keeps header-only support.
func RecordSent(h *types.WorkObjectHeader) {
	RecordSentHeader(h)
}

// RecordSentHeader moves header to "sent" LRU.
func RecordSentHeader(h *types.WorkObjectHeader) {
	if h == nil {
		return
	}
	ensureLRUs()

	algo := algoFromHeader(h)
	bumpByAlgo(algo, &wsCtr.sentTotal, &wsCtr.sentProgpow, &wsCtr.sentKawpow, &wsCtr.sentSHA, &wsCtr.sentScrypt)

	// Move to sent LRU
	deleteFrom(recLRU, h.Hash())
	upsertRecordIn(sentLRU, h, nil)

	log.Global.WithFields(log.Fields{
		"type":   "workshare.sent",
		"algo":   string(algo),
		"hash":   h.Hash(),
		"totals": snapshot(),
	}).Info("Workshare sent to libp2p")
}

// RecordSentWO moves to "sent" and attaches the full WorkObject when available.
func RecordSentWO(wo *types.WorkObject) {
	if wo == nil || wo.WorkObjectHeader() == nil {
		return
	}
	ensureLRUs()
	h := wo.WorkObjectHeader()

	algo := algoFromHeader(h)
	bumpByAlgo(algo, &wsCtr.sentTotal, &wsCtr.sentProgpow, &wsCtr.sentKawpow, &wsCtr.sentSHA, &wsCtr.sentScrypt)

	deleteFrom(recLRU, h.Hash())
	upsertRecordIn(sentLRU, h, wo)

	log.Global.WithFields(log.Fields{
		"type":   "workshare.sent",
		"algo":   string(algo),
		"hash":   h.Hash(),
		"totals": snapshot(),
	}).Info("Workshare sent to libp2p")
}

// IsLocalShare returns true if the given hash is a locally produced workshare.
func IsLocalShare(hash common.Hash) bool {
	localSharesMu.RLock()
	_, ok := localShares[hash]
	localSharesMu.RUnlock()
	return ok
}

// RecordIncludedHeader moves the header/WO to the "included" LRU.
func RecordIncludedHeader(h *types.WorkObjectHeader) {
	if h == nil {
		return
	}
	ensureLRUs()
	// Prefer existing record with WO if present in earlier stages
	if rec, ok := sentLRU.Get(h.Hash()); ok && rec != nil {
		deleteFrom(sentLRU, h.Hash())
		upsertRecordIn(inclLRU, rec.Header, rec.WorkObject)
	} else if rec, ok := recLRU.Get(h.Hash()); ok && rec != nil {
		deleteFrom(recLRU, h.Hash())
		upsertRecordIn(inclLRU, rec.Header, rec.WorkObject)
	} else {
		upsertRecordIn(inclLRU, h, nil)
	}
}

// RecordBlockInclusions updates inclusion counters and logs per-block summary.
func RecordBlockInclusions(blockHash common.Hash, perAlgoTotal map[string]int, perAlgoMine map[string]int) {
	inc := func(algo algoKey, n int, total, progpow, kawpow, sha, scrypt *atomic.Uint64) {
		if n <= 0 {
			return
		}
		total.Add(uint64(n))
		switch algo {
		case algoProgpow:
			progpow.Add(uint64(n))
		case algoKawpow:
			kawpow.Add(uint64(n))
		case algoSHA:
			sha.Add(uint64(n))
		case algoScrypt:
			scrypt.Add(uint64(n))
		}
	}

	// Update global totals for included (all)
	inc(algoProgpow, perAlgoTotal[string(algoProgpow)], &wsCtr.inclTotal, &wsCtr.inclProgpow, &wsCtr.inclKawpow, &wsCtr.inclSHA, &wsCtr.inclScrypt)
	inc(algoKawpow, perAlgoTotal[string(algoKawpow)], &wsCtr.inclTotal, &wsCtr.inclProgpow, &wsCtr.inclKawpow, &wsCtr.inclSHA, &wsCtr.inclScrypt)
	inc(algoSHA, perAlgoTotal[string(algoSHA)], &wsCtr.inclTotal, &wsCtr.inclProgpow, &wsCtr.inclKawpow, &wsCtr.inclSHA, &wsCtr.inclScrypt)
	inc(algoScrypt, perAlgoTotal[string(algoScrypt)], &wsCtr.inclTotal, &wsCtr.inclProgpow, &wsCtr.inclKawpow, &wsCtr.inclSHA, &wsCtr.inclScrypt)

	// Update global totals for included (mine)
	inc(algoProgpow, perAlgoMine[string(algoProgpow)], &wsCtr.inclMineTotal, &wsCtr.inclMineProgpow, &wsCtr.inclMineKawpow, &wsCtr.inclMineSHA, &wsCtr.inclMineScrypt)
	inc(algoKawpow, perAlgoMine[string(algoKawpow)], &wsCtr.inclMineTotal, &wsCtr.inclMineProgpow, &wsCtr.inclMineKawpow, &wsCtr.inclMineSHA, &wsCtr.inclMineScrypt)
	inc(algoSHA, perAlgoMine[string(algoSHA)], &wsCtr.inclMineTotal, &wsCtr.inclMineProgpow, &wsCtr.inclMineKawpow, &wsCtr.inclMineSHA, &wsCtr.inclMineScrypt)
	inc(algoScrypt, perAlgoMine[string(algoScrypt)], &wsCtr.inclMineTotal, &wsCtr.inclMineProgpow, &wsCtr.inclMineKawpow, &wsCtr.inclMineSHA, &wsCtr.inclMineScrypt)

	log.Global.WithFields(log.Fields{
		"type":         "workshare.block_inclusion",
		"block":        blockHash,
		"perAlgoTotal": perAlgoTotal,
		"perAlgoMine":  perAlgoMine,
		"totals":       snapshot(),
	}).Info("Workshare inclusion summary for block")
}

// snapshot returns a map snapshot of the current aggregate counters for structured logs.
func snapshot() map[string]any {
	ensureLRUs()
	return map[string]any{
		"received": map[string]uint64{
			"total":   wsCtr.recTotal.Load(),
			"progpow": wsCtr.recProgpow.Load(),
			"kawpow":  wsCtr.recKawpow.Load(),
			"sha":     wsCtr.recSHA.Load(),
			"scrypt":  wsCtr.recScrypt.Load(),
		},
		"sent": map[string]uint64{
			"total":   wsCtr.sentTotal.Load(),
			"progpow": wsCtr.sentProgpow.Load(),
			"kawpow":  wsCtr.sentKawpow.Load(),
			"sha":     wsCtr.sentSHA.Load(),
			"scrypt":  wsCtr.sentScrypt.Load(),
		},
		"included": map[string]uint64{
			"total":   wsCtr.inclTotal.Load(),
			"progpow": wsCtr.inclProgpow.Load(),
			"kawpow":  wsCtr.inclKawpow.Load(),
			"sha":     wsCtr.inclSHA.Load(),
			"scrypt":  wsCtr.inclScrypt.Load(),
		},
		"includedMine": map[string]uint64{
			"total":   wsCtr.inclMineTotal.Load(),
			"progpow": wsCtr.inclMineProgpow.Load(),
			"kawpow":  wsCtr.inclMineKawpow.Load(),
			"sha":     wsCtr.inclMineSHA.Load(),
			"scrypt":  wsCtr.inclMineScrypt.Load(),
		},
		"lru": map[string]int{
			"received": recLRU.Len(),
			"sent":     sentLRU.Len(),
			"included": inclLRU.Len(),
		},
	}
}

// BuildWorkshareLRUDump builds a structured dump of the current WS LRUs.
// limit caps the number of entries per list returned.
func BuildWorkshareLRUDump(limit int) map[string]interface{} {
	ensureLRUs()

	type entry struct {
		Hash   string
		Algo   string
		AgeSec int64
		Stage  string
		HasWO  bool
	}
	now := time.Now()

	makeEntry := func(h common.Hash, rec *WorkshareRecord, stage string) entry {
		algo := string(algoFromHeader(rec.Header))
		age := int64(0)
		if !rec.FirstSeen.IsZero() {
			age = int64(now.Sub(rec.FirstSeen).Seconds())
		}
		return entry{
			Hash:   h.Hex(),
			Algo:   algo,
			AgeSec: age,
			Stage:  stage,
			HasWO:  rec.WorkObject != nil,
		}
	}
	marshalHeaderJSON := func(hdr *types.WorkObjectHeader) string {
		if hdr == nil {
			return ""
		}
		js, err := json.Marshal(hdr.RPCMarshalWorkObjectHeader())
		if err != nil {
			return ""
		}
		return string(js)
	}

	recNotSent := make([]entry, 0)
	recNotSentJSON := make([]string, 0)
	for _, h := range recLRU.Keys() {
		if _, ok := sentLRU.Get(h); ok {
			continue
		}
		if rec, ok := recLRU.Get(h); ok && rec != nil {
			recNotSent = append(recNotSent, makeEntry(h, rec, "received"))
			recNotSentJSON = append(recNotSentJSON, marshalHeaderJSON(rec.Header))
		}
	}

	sentNotIncl := make([]entry, 0)
	sentNotInclJSON := make([]string, 0)
	for _, h := range sentLRU.Keys() {
		if _, ok := inclLRU.Get(h); ok {
			continue
		}
		if rec, ok := sentLRU.Get(h); ok && rec != nil {
			sentNotIncl = append(sentNotIncl, makeEntry(h, rec, "sent"))
			sentNotInclJSON = append(sentNotInclJSON, marshalHeaderJSON(rec.Header))
		}
	}

	return map[string]interface{}{
		"sizes":                  map[string]int{"received": recLRU.Len(), "sent": sentLRU.Len(), "included": inclLRU.Len()},
		"received_not_sent_cnt":  len(recNotSent),
		"sent_not_included_cnt":  len(sentNotIncl),
		"received_not_sent":      limitEntries(recNotSent, limit),
		"sent_not_included":      limitEntries(sentNotIncl, limit),
		"received_not_sent_json": limitEntries(recNotSentJSON, limit),
		"sent_not_included_json": limitEntries(sentNotInclJSON, limit),
	}
}

// DumpWorkshareLRUs logs a snapshot of the workshare LRUs (kept for convenience).
func DumpWorkshareLRUs() {
	d := BuildWorkshareLRUDump(100)
	log.Global.WithFields(log.Fields{
		"type": "workshare.lru_dump",
		// Flatten d map into fields
		"sizes":                  d["sizes"],
		"received_not_sent_cnt":  d["received_not_sent_cnt"],
		"sent_not_included_cnt":  d["sent_not_included_cnt"],
		"received_not_sent":      d["received_not_sent"],
		"sent_not_included":      d["sent_not_included"],
		"received_not_sent_json": d["received_not_sent_json"],
		"sent_not_included_json": d["sent_not_included_json"],
	}).Info("Workshare LRU dump")
}
