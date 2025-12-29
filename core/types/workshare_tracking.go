// Workshare tracking experiment types for analyzing workshare inclusion patterns

package types

import (
	"math/big"

	"github.com/dominant-strategies/go-quai/common"
)

// MissedReason indicates why a workshare was not included
type MissedReason uint32

const (
	MissedExpired         MissedReason = 0 // Exceeded WorkSharesInclusionDepth
	MissedNotSeenByWorker MissedReason = 1 // Worker never saw it
	MissedRejected        MissedReason = 2 // Rejected by validation
)

// WorkerRejectionReason indicates why the worker rejected a workshare
type WorkerRejectionReason uint32

const (
	RejectionNone              WorkerRejectionReason = 0  // Not rejected (included successfully)
	RejectionExpiredInCache    WorkerRejectionReason = 1  // Workshare too old, removed from cache
	RejectionMaxCountReached   WorkerRejectionReason = 2  // Block already has MaxWorkShareCount
	RejectionMaxShaReached     WorkerRejectionReason = 3  // Max SHA workshares per block reached
	RejectionMaxScryptReached  WorkerRejectionReason = 4  // Max Scrypt workshares per block reached
	RejectionCommitUncleFailed WorkerRejectionReason = 5  // commitUncle validation failed
	RejectionDuplicate         WorkerRejectionReason = 6  // Workshare already in block
	RejectionParentUnknown     WorkerRejectionReason = 7  // Parent hash not found
	RejectionTooOld            WorkerRejectionReason = 8  // Workshare number too old for current block
	RejectionBadDifficulty     WorkerRejectionReason = 9  // Difficulty validation failed
	RejectionOther             WorkerRejectionReason = 99 // Other/unknown reason
)

// WorkerRejectionReasonString returns a human-readable string for the rejection reason
func (r WorkerRejectionReason) String() string {
	switch r {
	case RejectionNone:
		return "none"
	case RejectionExpiredInCache:
		return "expired_in_cache"
	case RejectionMaxCountReached:
		return "max_workshare_count_reached"
	case RejectionMaxShaReached:
		return "max_sha_count_reached"
	case RejectionMaxScryptReached:
		return "max_scrypt_count_reached"
	case RejectionCommitUncleFailed:
		return "commit_uncle_failed"
	case RejectionDuplicate:
		return "duplicate"
	case RejectionParentUnknown:
		return "parent_unknown"
	case RejectionTooOld:
		return "too_old"
	case RejectionBadDifficulty:
		return "bad_difficulty"
	case RejectionOther:
		return "other"
	default:
		return "unknown"
	}
}

// WorkerRejection records when and why a worker rejected a workshare
type WorkerRejection struct {
	WorkshareHash     common.Hash
	RejectionReason   WorkerRejectionReason
	RejectionTime     uint64
	BlockNumber       uint64 // Block number being built when rejection occurred
	AdditionalInfo    string // Optional: error message or additional context
}

// ProtoEncode converts WorkerRejection to protobuf format
func (wr *WorkerRejection) ProtoEncode() *ProtoWorkerRejection {
	if wr == nil {
		return nil
	}
	return &ProtoWorkerRejection{
		WorkshareHash:   wr.WorkshareHash.ProtoEncode(),
		RejectionReason: uint32(wr.RejectionReason),
		RejectionTime:   wr.RejectionTime,
		BlockNumber:     wr.BlockNumber,
		AdditionalInfo:  wr.AdditionalInfo,
	}
}

// ProtoDecode converts protobuf format to WorkerRejection
func (wr *WorkerRejection) ProtoDecode(proto *ProtoWorkerRejection) error {
	if proto == nil {
		return nil
	}
	wr.WorkshareHash.ProtoDecode(proto.WorkshareHash)
	wr.RejectionReason = WorkerRejectionReason(proto.RejectionReason)
	wr.RejectionTime = proto.RejectionTime
	wr.BlockNumber = proto.BlockNumber
	wr.AdditionalInfo = proto.AdditionalInfo
	return nil
}

// WorkshareReception records when a valid workshare is first received from p2p
type WorkshareReception struct {
	WorkshareHash          common.Hash
	ReceivedTimestamp      uint64
	BlockHeightAtReception uint64
	Coinbase               common.Address
	PowType                PowID
	ParentHash             common.Hash
	WorkshareNumber        uint64
}

// ProtoEncode converts WorkshareReception to protobuf format
func (wr *WorkshareReception) ProtoEncode() *ProtoWorkshareReception {
	if wr == nil {
		return nil
	}
	powType := uint32(wr.PowType)
	return &ProtoWorkshareReception{
		WorkshareHash:          wr.WorkshareHash.ProtoEncode(),
		ReceivedTimestamp:      wr.ReceivedTimestamp,
		BlockHeightAtReception: wr.BlockHeightAtReception,
		Coinbase:               wr.Coinbase.ProtoEncode(),
		PowType:                powType,
		ParentHash:             wr.ParentHash.ProtoEncode(),
		WorkshareNumber:        wr.WorkshareNumber,
	}
}

// ProtoDecode converts protobuf format to WorkshareReception
func (wr *WorkshareReception) ProtoDecode(proto *ProtoWorkshareReception, location common.Location) error {
	if proto == nil {
		return nil
	}
	wr.WorkshareHash.ProtoDecode(proto.WorkshareHash)
	wr.ReceivedTimestamp = proto.ReceivedTimestamp
	wr.BlockHeightAtReception = proto.BlockHeightAtReception
	wr.Coinbase.ProtoDecode(proto.Coinbase, location)
	wr.PowType = PowID(proto.PowType)
	wr.ParentHash.ProtoDecode(proto.ParentHash)
	wr.WorkshareNumber = proto.WorkshareNumber
	return nil
}

// WorkerInclusionRecord tracks when worker adds workshare to pending block
type WorkerInclusionRecord struct {
	WorkshareHash        common.Hash
	PendingBlockHash     common.Hash
	PendingBlockNumber   uint64
	InclusionTimestamp   uint64
	ConfirmedBlockHash   common.Hash // Block hash when confirmed in canonical chain
	ConfirmedBlockNumber uint64      // Block number when confirmed
	ConfirmedTimestamp   uint64      // Timestamp when confirmed
}

// IsConfirmed returns true if the workshare was confirmed in a canonical block
func (wir *WorkerInclusionRecord) IsConfirmed() bool {
	return wir.ConfirmedBlockHash != common.Hash{}
}

// ProtoEncode converts WorkerInclusionRecord to protobuf format
func (wir *WorkerInclusionRecord) ProtoEncode() *ProtoWorkerInclusionRecord {
	if wir == nil {
		return nil
	}
	return &ProtoWorkerInclusionRecord{
		WorkshareHash:        wir.WorkshareHash.ProtoEncode(),
		PendingBlockHash:     wir.PendingBlockHash.ProtoEncode(),
		PendingBlockNumber:   wir.PendingBlockNumber,
		InclusionTimestamp:   wir.InclusionTimestamp,
		ConfirmedBlockHash:   wir.ConfirmedBlockHash.ProtoEncode(),
		ConfirmedBlockNumber: wir.ConfirmedBlockNumber,
		ConfirmedTimestamp:   wir.ConfirmedTimestamp,
	}
}

// ProtoDecode converts protobuf format to WorkerInclusionRecord
func (wir *WorkerInclusionRecord) ProtoDecode(proto *ProtoWorkerInclusionRecord) error {
	if proto == nil {
		return nil
	}
	wir.WorkshareHash.ProtoDecode(proto.WorkshareHash)
	wir.PendingBlockHash.ProtoDecode(proto.PendingBlockHash)
	wir.PendingBlockNumber = proto.PendingBlockNumber
	wir.InclusionTimestamp = proto.InclusionTimestamp
	wir.ConfirmedBlockHash.ProtoDecode(proto.ConfirmedBlockHash)
	wir.ConfirmedBlockNumber = proto.ConfirmedBlockNumber
	wir.ConfirmedTimestamp = proto.ConfirmedTimestamp
	return nil
}

// MissedWorkshare records workshares not included within the inclusion window
type MissedWorkshare struct {
	WorkshareHash     common.Hash
	ReceivedTimestamp uint64
	ExpiredAtBlock    uint64
	Reason            MissedReason
	Coinbase          common.Address
	PowType           PowID
}

// ProtoEncode converts MissedWorkshare to protobuf format
func (mw *MissedWorkshare) ProtoEncode() *ProtoMissedWorkshare {
	if mw == nil {
		return nil
	}
	reason := uint32(mw.Reason)
	powType := uint32(mw.PowType)
	return &ProtoMissedWorkshare{
		WorkshareHash:     mw.WorkshareHash.ProtoEncode(),
		ReceivedTimestamp: mw.ReceivedTimestamp,
		ExpiredAtBlock:    mw.ExpiredAtBlock,
		Reason:            reason,
		Coinbase:          mw.Coinbase.ProtoEncode(),
		PowType:           powType,
	}
}

// ProtoDecode converts protobuf format to MissedWorkshare
func (mw *MissedWorkshare) ProtoDecode(proto *ProtoMissedWorkshare, location common.Location) error {
	if proto == nil {
		return nil
	}
	mw.WorkshareHash.ProtoDecode(proto.WorkshareHash)
	mw.ReceivedTimestamp = proto.ReceivedTimestamp
	mw.ExpiredAtBlock = proto.ExpiredAtBlock
	mw.Reason = MissedReason(proto.Reason)
	mw.Coinbase.ProtoDecode(proto.Coinbase, location)
	mw.PowType = PowID(proto.PowType)
	return nil
}

// ReorgEvent records chain reorganization with workshare analysis
type ReorgEvent struct {
	OldHead                common.Hash
	NewHead                common.Hash
	CommonAncestor         common.Hash
	ReorgDepth             uint64
	Timestamp              uint64
	OldChainWorkshareCount uint32
	OldChainEntropy        *big.Int
	NewChainWorkshareCount uint32
	NewChainEntropy        *big.Int
	WorksharesLost         []common.Hash
	WorksharesGained       []common.Hash
}

// ProtoEncode converts ReorgEvent to protobuf format
func (re *ReorgEvent) ProtoEncode() *ProtoReorgEvent {
	if re == nil {
		return nil
	}

	worksharesLost := make([]*common.ProtoHash, len(re.WorksharesLost))
	for i, h := range re.WorksharesLost {
		worksharesLost[i] = h.ProtoEncode()
	}

	worksharesGained := make([]*common.ProtoHash, len(re.WorksharesGained))
	for i, h := range re.WorksharesGained {
		worksharesGained[i] = h.ProtoEncode()
	}

	var oldEntropy, newEntropy []byte
	if re.OldChainEntropy != nil {
		oldEntropy = re.OldChainEntropy.Bytes()
	}
	if re.NewChainEntropy != nil {
		newEntropy = re.NewChainEntropy.Bytes()
	}

	return &ProtoReorgEvent{
		OldHead:                re.OldHead.ProtoEncode(),
		NewHead:                re.NewHead.ProtoEncode(),
		CommonAncestor:         re.CommonAncestor.ProtoEncode(),
		ReorgDepth:             re.ReorgDepth,
		Timestamp:              re.Timestamp,
		OldChainWorkshareCount: re.OldChainWorkshareCount,
		OldChainEntropy:        oldEntropy,
		NewChainWorkshareCount: re.NewChainWorkshareCount,
		NewChainEntropy:        newEntropy,
		WorksharesLost:         worksharesLost,
		WorksharesGained:       worksharesGained,
	}
}

// ProtoDecode converts protobuf format to ReorgEvent
func (re *ReorgEvent) ProtoDecode(proto *ProtoReorgEvent) error {
	if proto == nil {
		return nil
	}
	re.OldHead.ProtoDecode(proto.OldHead)
	re.NewHead.ProtoDecode(proto.NewHead)
	re.CommonAncestor.ProtoDecode(proto.CommonAncestor)
	re.ReorgDepth = proto.ReorgDepth
	re.Timestamp = proto.Timestamp
	re.OldChainWorkshareCount = proto.OldChainWorkshareCount
	re.OldChainEntropy = new(big.Int).SetBytes(proto.OldChainEntropy)
	re.NewChainWorkshareCount = proto.NewChainWorkshareCount
	re.NewChainEntropy = new(big.Int).SetBytes(proto.NewChainEntropy)

	re.WorksharesLost = make([]common.Hash, len(proto.WorksharesLost))
	for i, ph := range proto.WorksharesLost {
		re.WorksharesLost[i].ProtoDecode(ph)
	}

	re.WorksharesGained = make([]common.Hash, len(proto.WorksharesGained))
	for i, ph := range proto.WorksharesGained {
		re.WorksharesGained[i].ProtoDecode(ph)
	}

	return nil
}

// BlockRecord tracks a block and the workshares it contains
type BlockRecord struct {
	BlockHash             common.Hash
	BlockNumber           uint64
	ReceivedTimestamp     uint64
	WorkshareHashes       []common.Hash
	WorkshareCount        uint32
	TotalWorkshareEntropy *big.Int
	Coinbase              common.Address
	IsCanonical           bool
}

// ProtoEncode converts BlockRecord to protobuf format
func (br *BlockRecord) ProtoEncode() *ProtoBlockRecord {
	if br == nil {
		return nil
	}

	workshareHashes := make([]*common.ProtoHash, len(br.WorkshareHashes))
	for i, h := range br.WorkshareHashes {
		workshareHashes[i] = h.ProtoEncode()
	}

	var entropy []byte
	if br.TotalWorkshareEntropy != nil {
		entropy = br.TotalWorkshareEntropy.Bytes()
	}

	return &ProtoBlockRecord{
		BlockHash:             br.BlockHash.ProtoEncode(),
		BlockNumber:           br.BlockNumber,
		ReceivedTimestamp:     br.ReceivedTimestamp,
		WorkshareHashes:       workshareHashes,
		WorkshareCount:        br.WorkshareCount,
		TotalWorkshareEntropy: entropy,
		Coinbase:              br.Coinbase.ProtoEncode(),
		IsCanonical:           br.IsCanonical,
	}
}

// ProtoDecode converts protobuf format to BlockRecord
func (br *BlockRecord) ProtoDecode(proto *ProtoBlockRecord, location common.Location) error {
	if proto == nil {
		return nil
	}
	br.BlockHash.ProtoDecode(proto.BlockHash)
	br.BlockNumber = proto.BlockNumber
	br.ReceivedTimestamp = proto.ReceivedTimestamp
	br.WorkshareCount = proto.WorkshareCount
	br.TotalWorkshareEntropy = new(big.Int).SetBytes(proto.TotalWorkshareEntropy)
	br.Coinbase.ProtoDecode(proto.Coinbase, location)
	br.IsCanonical = proto.IsCanonical

	br.WorkshareHashes = make([]common.Hash, len(proto.WorkshareHashes))
	for i, ph := range proto.WorkshareHashes {
		br.WorkshareHashes[i].ProtoDecode(ph)
	}

	return nil
}

// OrphanedBlock tracks a block that became non-canonical after a reorg
type OrphanedBlock struct {
	BlockHash             common.Hash
	BlockNumber           uint64
	OrphanedAtTimestamp   uint64
	OrphanedAtBlock       uint64
	WorkshareHashes       []common.Hash
	WorkshareCount        uint32
	TotalWorkshareEntropy *big.Int
	Coinbase              common.Address
	ReplacedBy            common.Hash
}

// ProtoEncode converts OrphanedBlock to protobuf format
func (ob *OrphanedBlock) ProtoEncode() *ProtoOrphanedBlock {
	if ob == nil {
		return nil
	}

	workshareHashes := make([]*common.ProtoHash, len(ob.WorkshareHashes))
	for i, h := range ob.WorkshareHashes {
		workshareHashes[i] = h.ProtoEncode()
	}

	var entropy []byte
	if ob.TotalWorkshareEntropy != nil {
		entropy = ob.TotalWorkshareEntropy.Bytes()
	}

	return &ProtoOrphanedBlock{
		BlockHash:             ob.BlockHash.ProtoEncode(),
		BlockNumber:           ob.BlockNumber,
		OrphanedAtTimestamp:   ob.OrphanedAtTimestamp,
		OrphanedAtBlock:       ob.OrphanedAtBlock,
		WorkshareHashes:       workshareHashes,
		WorkshareCount:        ob.WorkshareCount,
		TotalWorkshareEntropy: entropy,
		Coinbase:              ob.Coinbase.ProtoEncode(),
		ReplacedBy:            ob.ReplacedBy.ProtoEncode(),
	}
}

// ProtoDecode converts protobuf format to OrphanedBlock
func (ob *OrphanedBlock) ProtoDecode(proto *ProtoOrphanedBlock, location common.Location) error {
	if proto == nil {
		return nil
	}
	ob.BlockHash.ProtoDecode(proto.BlockHash)
	ob.BlockNumber = proto.BlockNumber
	ob.OrphanedAtTimestamp = proto.OrphanedAtTimestamp
	ob.OrphanedAtBlock = proto.OrphanedAtBlock
	ob.WorkshareCount = proto.WorkshareCount
	ob.TotalWorkshareEntropy = new(big.Int).SetBytes(proto.TotalWorkshareEntropy)
	ob.Coinbase.ProtoDecode(proto.Coinbase, location)
	ob.ReplacedBy.ProtoDecode(proto.ReplacedBy)

	ob.WorkshareHashes = make([]common.Hash, len(proto.WorkshareHashes))
	for i, ph := range proto.WorkshareHashes {
		ob.WorkshareHashes[i].ProtoDecode(ph)
	}

	return nil
}

// ForkOutcome indicates whether a block won or lost a fork competition
type ForkOutcome uint32

const (
	ForkOutcomeWon  ForkOutcome = 0 // This block became/stayed canonical
	ForkOutcomeLost ForkOutcome = 1 // This block lost to a competitor
)

// ForkCompetition records when blocks compete for the same height
type ForkCompetition struct {
	BlockHash         common.Hash // Hash of the block being tracked
	BlockNumber       uint64      // Zone block number
	Timestamp         uint64      // When this competition was recorded
	WorkshareCount    uint32      // Number of workshares in this block
	IntrinsicEntropy  uint64      // Intrinsic PoW entropy (bits)
	Outcome           ForkOutcome // Whether this block won or lost
	CompetitorHash    common.Hash // Hash of the competing block
	CompetitorWsCount uint32      // Workshares in competitor
	CompetitorEntropy uint64      // Competitor's intrinsic entropy
}

// ProtoEncode converts ForkCompetition to protobuf format
func (fc *ForkCompetition) ProtoEncode() *ProtoForkCompetition {
	if fc == nil {
		return nil
	}
	return &ProtoForkCompetition{
		BlockHash:         fc.BlockHash.ProtoEncode(),
		BlockNumber:       fc.BlockNumber,
		Timestamp:         fc.Timestamp,
		WorkshareCount:    fc.WorkshareCount,
		IntrinsicEntropy:  fc.IntrinsicEntropy,
		Outcome:           uint32(fc.Outcome),
		CompetitorHash:    fc.CompetitorHash.ProtoEncode(),
		CompetitorWsCount: fc.CompetitorWsCount,
		CompetitorEntropy: fc.CompetitorEntropy,
	}
}

// ProtoDecode converts protobuf format to ForkCompetition
func (fc *ForkCompetition) ProtoDecode(proto *ProtoForkCompetition) error {
	if proto == nil {
		return nil
	}
	fc.BlockHash.ProtoDecode(proto.BlockHash)
	fc.BlockNumber = proto.BlockNumber
	fc.Timestamp = proto.Timestamp
	fc.WorkshareCount = proto.WorkshareCount
	fc.IntrinsicEntropy = proto.IntrinsicEntropy
	fc.Outcome = ForkOutcome(proto.Outcome)
	fc.CompetitorHash.ProtoDecode(proto.CompetitorHash)
	fc.CompetitorWsCount = proto.CompetitorWsCount
	fc.CompetitorEntropy = proto.CompetitorEntropy
	return nil
}
