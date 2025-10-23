// Copyright 2017-2025 The go-quai Authors
// This file is part of the go-quai library.

package sha256d

import (
	"math/big"
	"time"

	"github.com/dominant-strategies/go-quai/common"
	"github.com/dominant-strategies/go-quai/consensus"
	"github.com/dominant-strategies/go-quai/core/state"
	"github.com/dominant-strategies/go-quai/core/types"
	"github.com/dominant-strategies/go-quai/crypto/multiset"
	"github.com/dominant-strategies/go-quai/ethdb"
	"github.com/dominant-strategies/go-quai/log"
	"github.com/dominant-strategies/go-quai/params"
)

// SHA256d proof-of-work protocol constants.
var (
	allowedFutureBlockTime = 15 * time.Second // Max time from current time allowed for blocks, before they're considered future blocks
)

// Various error messages to mark blocks invalid.
var (
	errInvalidDifficulty = consensus.ErrInvalidDifficulty
	errInvalidPoW        = consensus.ErrInvalidPoW
)

// Mode defines the type and amount of PoW verification a sha256d engine makes.
type Mode uint

const (
	ModeNormal Mode = iota
	ModeFake
	ModeFullFake
)

// Config are the configuration parameters of the sha256d.
type Config struct {
	PowMode Mode

	Log *log.Logger `toml:"-"`
}

// SHA256d is a consensus engine based on SHA256d proof-of-work implementing the consensus.Engine interface.
type SHA256d struct {
	config Config

	// Mining related fields
	shared    *SHA256d // Shared PoW verifier to avoid cache regeneration
	fakeFail  uint64   // Block number which fails PoW check even in fake mode
	fakeDelay time.Duration

	logger *log.Logger
}

// New creates a SHA256d consensus engine with the given config.
func New(config Config, nodeLocation common.Location, logger *log.Logger) *SHA256d {
	if config.Log == nil {
		config.Log = logger
	}

	sha := &SHA256d{
		config: config,
		logger: logger,
	}

	logger.Info("SHA256d consensus engine initialized")
	return sha
}

// NewFaker creates a SHA256d consensus engine with a fake PoW scheme that accepts
// all blocks as valid apart from the single one specified.
func NewFaker() *SHA256d {
	return &SHA256d{
		config: Config{
			PowMode: ModeFake,
		},
	}
}

// NewFakeFailer creates a SHA256d consensus engine with a fake PoW scheme that
// accepts all blocks as valid apart from the single one specified, though they all still have to conform to the Quai consensus rules.
func NewFakeFailer(fail uint64) *SHA256d {
	return &SHA256d{
		config: Config{
			PowMode: ModeFake,
		},
		fakeFail: fail,
	}
}

// NewFakeDelayer creates a SHA256d consensus engine with a fake PoW scheme that
// accepts all blocks as valid, but delays verifications by some time, though they all still have to conform to the Quai consensus rules.
func NewFakeDelayer(delay time.Duration) *SHA256d {
	return &SHA256d{
		config: Config{
			PowMode: ModeFake,
		},
		fakeDelay: delay,
	}
}

// NewFullFaker creates a SHA256d consensus engine with a full fake scheme that
// accepts all blocks as valid, without checking any consensus rules whatsoever.
func NewFullFaker() *SHA256d {
	return &SHA256d{
		config: Config{
			PowMode: ModeFullFake,
		},
	}
}

// NewShared creates a SHA256d consensus engine shared among list of nodes
func NewShared() *SHA256d {
	return &SHA256d{shared: &SHA256d{}}
}

// Close closes the exit channel to exit the thread of c_asyncWorkShareUpdateLoop.
func (sha *SHA256d) Close() error {
	return nil
}

// Author implements consensus.Engine, returning the header's coinbase as the
// proof-of-work verified author of the block.
func (sha *SHA256d) Author(header *types.WorkObject) (common.Address, error) {
	return header.PrimaryCoinbase(), nil
}

// VerifyHeader checks whether a header conforms to the consensus rules of the
// stock Quai sha256d engine.
func (sha *SHA256d) VerifyHeader(chain consensus.ChainHeaderReader, header *types.WorkObject) error {
	// Short circuit if the header is known
	if chain.GetHeaderByHash(header.Hash()) != nil {
		return nil
	}
	// Verify the seal
	_, err := sha.VerifySeal(header.WorkObjectHeader())
	return err
}

// VerifyHeaders is similar to VerifyHeader, but verifies a batch of headers
// concurrently. The method returns a quit channel to abort the operations and
// a results channel to retrieve the async verifications.
func (sha *SHA256d) VerifyHeaders(chain consensus.ChainHeaderReader, headers []*types.WorkObject) (chan<- struct{}, <-chan error) {
	abort := make(chan struct{})
	results := make(chan error, len(headers))

	go func() {
		for _, header := range headers {
			err := sha.VerifyHeader(chain, header)

			select {
			case <-abort:
				return
			case results <- err:
			}
		}
	}()
	return abort, results
}

// VerifyUncles verifies that the given block's uncles conform to the consensus
// rules of the stock Quai sha256d engine.
func (sha *SHA256d) VerifyUncles(chain consensus.ChainReader, block *types.WorkObject) error {
	// Verify that there are at most params.MaxWorkShareCount uncles included in this block
	if len(block.Uncles()) > params.MaxWorkShareCount {
		return consensus.ErrTooManyUncles
	}
	return nil
}

// VerifySeal checks whether the crypto seal on a header is valid according to
// the consensus rules of the given engine.
func (sha *SHA256d) VerifySeal(header *types.WorkObjectHeader) (common.Hash, error) {
	return sha.verifySeal(header)
}

// verifySeal checks whether a block satisfies the PoW difficulty requirements,
// using the SHA256d double-hash algorithm.
func (sha *SHA256d) verifySeal(header *types.WorkObjectHeader) (common.Hash, error) {
	// If we're running a fake PoW, accept any seal as valid
	if sha.config.PowMode == ModeFake || sha.config.PowMode == ModeFullFake {
		time.Sleep(sha.fakeDelay)
		if sha.fakeFail == header.NumberU64() {
			return common.Hash{}, consensus.ErrInvalidPoW
		}
		return common.Hash{}, nil
	}
	// If we're running a shared PoW, delegate verification to it
	if sha.shared != nil {
		return sha.shared.verifySeal(header)
	}
	// Verify this is a SHA256d block
	if header.AuxPow() == nil {
		return common.Hash{}, consensus.ErrInvalidPoW
	}

	powID := header.AuxPow().PowID()
	if powID != types.SHA_BTC && powID != types.SHA_BCH {
		return common.Hash{}, consensus.ErrInvalidPoW
	}

	// For SHA256d, compute pow hash and compare against Quai's block difficulty
	// (NOT the AuxPow header nBits, which is just a template value)
	powHash := header.AuxPow().Header().PowHash()

	// Get the target from Quai's difficulty: target = 2^256 / difficulty
	quaiDifficulty := header.Difficulty()
	if quaiDifficulty == nil || quaiDifficulty.Sign() <= 0 {
		sha.logger.Error("Invalid Quai difficulty")
		return common.Hash{}, consensus.ErrInvalidPoW
	}

	two256 := new(big.Int).Lsh(big.NewInt(1), 256)
	target := new(big.Int).Div(two256, quaiDifficulty)

	if target.Sign() <= 0 {
		sha.logger.Error("Invalid target calculated from Quai difficulty")
		return common.Hash{}, consensus.ErrInvalidPoW
	}

	powHashInt := new(big.Int).SetBytes(powHash[:])

	if powHashInt.Cmp(target) > 0 {
		// Calculate the actual difficulty achieved by this hash
		// actualDifficulty = 2^256 / powHash
		actualDifficulty := new(big.Int).Div(two256, powHashInt)

		sha.logger.WithFields(log.Fields{
			"powHash":          powHash.Hex(),
			"powHashInt":       powHashInt.String(),
			"target":           target.String(),
			"quaiDifficulty":   quaiDifficulty.String(),
			"actualDifficulty": actualDifficulty.String(),
		}).Error("SHA256d PoW verification failed - hash exceeds Quai difficulty target")
		return powHash, consensus.ErrInvalidPoW
	}
	return powHash, nil
}

// bitsToTarget converts compact Bitcoin-style nBits to a full target big.Int
func bitsToTarget(nBits uint32) *big.Int {
	exponent := nBits >> 24
	coefficient := nBits & 0x007fffff
	if exponent == 0 {
		return big.NewInt(0)
	}
	target := new(big.Int).SetInt64(int64(coefficient))
	if exponent <= 3 {
		target.Rsh(target, uint(8*(3-exponent)))
	} else {
		target.Lsh(target, uint(8*(exponent-3)))
	}
	return target
}

// Prepare initializes the consensus fields of a block header according to the
// rules of a particular engine. The changes are executed inline.
func (sha *SHA256d) Prepare(chain consensus.ChainHeaderReader, header *types.WorkObject, parent *types.WorkObject) error {
	header.WorkObjectHeader().SetDifficulty(sha.CalcDifficulty(chain, parent.WorkObjectHeader(), parent.ExpansionNumber()))
	return nil
}

// Finalize runs any post-transaction state modifications (e.g. block rewards)
// but does not assemble the block.
func (sha *SHA256d) Finalize(chain consensus.ChainHeaderReader, batch ethdb.Batch, header *types.WorkObject, state *state.StateDB, setRoots bool, utxoSetSize uint64, utxosCreate, utxosDelete []common.Hash, supplyRemovedQi *big.Int) (*multiset.MultiSet, uint64, []*types.SpentUtxoEntry, error) {
	// Delegate to the progpow engine for finalization since the rewards/state modifications are the same
	// This is just a PoW verification engine
	return nil, utxoSetSize, nil, nil
}

// FinalizeAndAssemble runs any post-transaction state modifications (e.g. block
// rewards) and assembles the final block.
func (sha *SHA256d) FinalizeAndAssemble(chain consensus.ChainHeaderReader, woHeader *types.WorkObject, state *state.StateDB, txs []*types.Transaction, uncles []*types.WorkObjectHeader, etxs []*types.Transaction, subManifest types.BlockManifest, receipts []*types.Receipt, parentUtxoSetSize uint64, utxosCreate, utxosDelete []common.Hash) (*types.WorkObject, error) {
	// Delegate to the progpow engine for finalization
	return nil, consensus.ErrUnknownAncestor
}

// CalcDifficulty is the difficulty adjustment algorithm. It returns
// the difficulty that a new block should have when created at time
// given the parent block's time and difficulty.
func (sha *SHA256d) CalcDifficulty(chain consensus.ChainHeaderReader, parent *types.WorkObjectHeader, expansionNum uint8) *big.Int {
	// SHA256d uses the same difficulty as the parent for now
	// This should be updated with proper difficulty adjustment logic
	return parent.Difficulty()
}

// IntrinsicLogEntropy returns the logarithm of the intrinsic entropy reduction of a PoW hash
func (sha *SHA256d) IntrinsicLogEntropy(powHash common.Hash) *big.Int {
	return common.IntrinsicLogEntropy(powHash)
}

// TotalLogEntropy returns the total entropy reduction if the chain since genesis to the given header
func (sha *SHA256d) TotalLogEntropy(chain consensus.ChainHeaderReader, header *types.WorkObject) *big.Int {
	// Delegate to chain reader for total entropy calculation
	return big.NewInt(0)
}

// WorkShareLogEntropy returns the log entropy of a workshare
func (sha *SHA256d) WorkShareLogEntropy(chain consensus.ChainHeaderReader, header *types.WorkObject) *big.Int {
	powHash := header.AuxPow().Header().PowHash()
	return common.IntrinsicLogEntropy(powHash)
}

// TotalLogWorkShareEntropy returns the total entropy of workshares in the slice
func (sha *SHA256d) TotalLogWorkShareEntropy(chain consensus.ChainHeaderReader, header *types.WorkObject) *big.Int {
	return big.NewInt(0)
}

// CalcOrder returns the order of the block within the hierarchy of chains
func (sha *SHA256d) CalcOrder(chain consensus.BlockReader, header *types.WorkObject) (*big.Int, int, error) {
	return big.NewInt(0), 0, nil
}

// CheckIfValidWorkShare checks if the given header is a valid work share
func (sha *SHA256d) CheckIfValidWorkShare(workShare *types.WorkObjectHeader) types.WorkShareValidity {
	if workShare.AuxPow() == nil {
		return types.Invalid
	}

	powID := workShare.AuxPow().PowID()
	if powID != types.SHA_BTC && powID != types.SHA_BCH {
		return types.Invalid
	}

	// Verify the PoW hash meets the workshare target
	powHash := workShare.AuxPow().Header().PowHash()
	target := new(big.Int).Div(common.Big2e256, workShare.ShaDiffAndCount().Difficulty())

	if new(big.Int).SetBytes(powHash.Bytes()).Cmp(target) > 0 {
		return types.Invalid
	}

	return types.Valid
}

// IntrinsicLogS returns the logarithm of the intrinsic entropy reduction of a PoW hash
func (sha *SHA256d) IntrinsicLogS(powHash common.Hash) *big.Int {
	return common.IntrinsicLogEntropy(powHash)
}

// IsDomCoincident returns true if the header is dom coincident with the given location
func (sha *SHA256d) IsDomCoincident(chain consensus.ChainHeaderReader, header *types.WorkObject) bool {
	return false
}

// ComputePowLight computes the PoW hash for the given header
func (sha *SHA256d) ComputePowLight(header *types.WorkObjectHeader) (common.Hash, common.Hash) {
	if header.AuxPow() == nil {
		return common.Hash{}, common.Hash{}
	}
	powHash := header.AuxPow().Header().PowHash()
	return common.Hash{}, powHash
}

// VerifyWorkThreshold verifies the work threshold for a work share
func (sha *SHA256d) VerifyWorkThreshold(chain consensus.ChainHeaderReader, header *types.WorkObject, workShareThreshold int) error {
	return nil
}

// CheckWorkShareThreshold checks if the given work share meets the threshold
func (sha *SHA256d) CheckWorkShareThreshold(chain consensus.ChainHeaderReader, wo *types.WorkObject, workShareThreshold int) bool {
	return true
}

// DeltaLogEntropy returns the log of the entropy delta for a chain since its prior coincidence
func (sha *SHA256d) DeltaLogEntropy(chain consensus.ChainHeaderReader, header *types.WorkObject) *big.Int {
	return big.NewInt(0)
}

// UncledDeltaLogEntropy returns the log of the uncled entropy reduction since the past coincident
func (sha *SHA256d) UncledDeltaLogEntropy(chain consensus.ChainHeaderReader, header *types.WorkObject) *big.Int {
	return big.NewInt(0)
}

// CalcRank calculates the rank of the prime block
func (sha *SHA256d) CalcRank(chain consensus.ChainHeaderReader, header *types.WorkObject) (int, error) {
	return 0, nil
}

// ComputePowHash returns the pow hash of the work object header
func (sha *SHA256d) ComputePowHash(header *types.WorkObjectHeader) (common.Hash, error) {
	if header.AuxPow() == nil {
		return common.Hash{}, consensus.ErrInvalidPoW
	}
	return header.AuxPow().Header().PowHash(), nil
}

// CheckWorkThreshold checks if the work meets the difficulty requirement
func (sha *SHA256d) CheckWorkThreshold(workObjectHeader *types.WorkObjectHeader, workShareThreshold int) bool {
	return true
}

// SetThreads updates the number of mining threads
func (sha *SHA256d) SetThreads(threads int) {
	// SHA256d doesn't support local mining, this is a no-op
}

// Seal generates a new sealing request for the given input block
func (sha *SHA256d) Seal(header *types.WorkObject, results chan<- *types.WorkObject, stop <-chan struct{}) error {
	// SHA256d doesn't support local mining
	return consensus.ErrUnknownAncestor
}

// Mine is the actual proof-of-work miner
func (sha *SHA256d) Mine(workObject *types.WorkObject, abort <-chan struct{}, found chan *types.WorkObject) {
	// SHA256d doesn't support local mining
}

// MineToThreshold allows for customization of the difficulty threshold
func (sha *SHA256d) MineToThreshold(workObject *types.WorkObject, threshold int, abort <-chan struct{}, found chan *types.WorkObject) {
	// SHA256d doesn't support local mining
}
