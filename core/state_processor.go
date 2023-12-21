// Copyright 2015 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-ethereum library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>.

package core

import (
	"errors"
	"fmt"
	"math/big"
	"sync"
	"time"

	"github.com/dominant-strategies/go-quai/common"
	"github.com/dominant-strategies/go-quai/common/prque"
	"github.com/dominant-strategies/go-quai/consensus"
	"github.com/dominant-strategies/go-quai/core/rawdb"
	"github.com/dominant-strategies/go-quai/core/state"
	"github.com/dominant-strategies/go-quai/core/state/snapshot"
	"github.com/dominant-strategies/go-quai/core/types"
	"github.com/dominant-strategies/go-quai/core/vm"
	"github.com/dominant-strategies/go-quai/crypto"
	"github.com/dominant-strategies/go-quai/ethdb"
	"github.com/dominant-strategies/go-quai/event"
	"github.com/dominant-strategies/go-quai/log"
	"github.com/dominant-strategies/go-quai/metrics"
	"github.com/dominant-strategies/go-quai/params"
	"github.com/dominant-strategies/go-quai/trie"
	lru "github.com/hashicorp/golang-lru"
)

var (
	accountReadTimer   = metrics.NewRegisteredTimer("chain/account/reads", nil)
	accountHashTimer   = metrics.NewRegisteredTimer("chain/account/hashes", nil)
	accountUpdateTimer = metrics.NewRegisteredTimer("chain/account/updates", nil)
	accountCommitTimer = metrics.NewRegisteredTimer("chain/account/commits", nil)

	storageReadTimer   = metrics.NewRegisteredTimer("chain/storage/reads", nil)
	storageHashTimer   = metrics.NewRegisteredTimer("chain/storage/hashes", nil)
	storageUpdateTimer = metrics.NewRegisteredTimer("chain/storage/updates", nil)
	storageCommitTimer = metrics.NewRegisteredTimer("chain/storage/commits", nil)

	snapshotAccountReadTimer = metrics.NewRegisteredTimer("chain/snapshot/account/reads", nil)
	snapshotStorageReadTimer = metrics.NewRegisteredTimer("chain/snapshot/storage/reads", nil)
	snapshotCommitTimer      = metrics.NewRegisteredTimer("chain/snapshot/commits", nil)
)

const (
	receiptsCacheLimit = 32
	txLookupCacheLimit = 1024
	TriesInMemory      = 128

	// BlockChainVersion ensures that an incompatible database forces a resync from scratch.
	//
	// Changelog:
	//
	// - Version 4
	//   The following incompatible database changes were added:
	//   * the `BlockNumber`, `TxHash`, `TxIndex`, `BlockHash` and `Index` fields of log are deleted
	//   * the `Bloom` field of receipt is deleted
	//   * the `BlockIndex` and `TxIndex` fields of txlookup are deleted
	// - Version 5
	//  The following incompatible database changes were added:
	//    * the `TxHash`, `GasCost`, and `ContractAddress` fields are no longer stored for a receipt
	//    * the `TxHash`, `GasCost`, and `ContractAddress` fields are computed by looking up the
	//      receipts' corresponding block
	// - Version 6
	//  The following incompatible database changes were added:
	//    * Transaction lookup information stores the corresponding block number instead of block hash
	// - Version 7
	//  The following incompatible database changes were added:
	//    * Use freezer as the ancient database to maintain all ancient data
	// - Version 8
	//  The following incompatible database changes were added:
	//    * New scheme for contract code in order to separate the codes and trie nodes
	BlockChainVersion uint64 = 8
)

// CacheConfig contains the configuration values for the trie caching/pruning
// that's resident in a blockchain.
type CacheConfig struct {
	TrieCleanLimit      int           // Memory allowance (MB) to use for caching trie nodes in memory
	TrieCleanJournal    string        // Disk journal for saving clean cache entries.
	TrieCleanRejournal  time.Duration // Time interval to dump clean cache to disk periodically
	TrieCleanNoPrefetch bool          // Whether to disable heuristic state prefetching for followup blocks
	TrieDirtyLimit      int           // Memory limit (MB) at which to start flushing dirty trie nodes to disk
	TrieTimeLimit       time.Duration // Time limit after which to flush the current in-memory trie to disk
	SnapshotLimit       int           // Memory allowance (MB) to use for caching snapshot entries in memory
	Preimages           bool          // Whether to store preimage of trie key to the disk
}

// defaultCacheConfig are the default caching values if none are specified by the
// user (also used during testing).
var defaultCacheConfig = &CacheConfig{
	TrieCleanLimit: 256,
	TrieDirtyLimit: 256,
	TrieTimeLimit:  5 * time.Minute,
	SnapshotLimit:  256,
}

// StateProcessor is a basic Processor, which takes care of transitioning
// state from one point to another.
//
// StateProcessor implements Processor.
type StateProcessor struct {
	config        *params.ChainConfig // Chain configuration options
	hc            *HeaderChain        // Canonical block chain
	engine        consensus.Engine    // Consensus engine used for block rewards
	logsFeed      event.Feed
	rmLogsFeed    event.Feed
	cacheConfig   *CacheConfig   // CacheConfig for StateProcessor
	stateCache    state.Database // State database to reuse between imports (contains state cache)
	receiptsCache *lru.Cache     // Cache for the most recent receipts per block
	txLookupCache *lru.Cache
	validator     Validator // Block and state validator interface
	prefetcher    Prefetcher
	vmConfig      vm.Config

	scope         event.SubscriptionScope
	wg            sync.WaitGroup // chain processing wait group for shutting down
	quit          chan struct{}  // state processor quit channel
	txLookupLimit uint64

	snaps  *snapshot.Tree
	triegc *prque.Prque  // Priority queue mapping block numbers to tries to gc
	gcproc time.Duration // Accumulates canonical block processing for trie dumping
}

// NewStateProcessor initialises a new StateProcessor.
func NewStateProcessor(config *params.ChainConfig, hc *HeaderChain, engine consensus.Engine, vmConfig vm.Config, cacheConfig *CacheConfig, txLookupLimit *uint64) *StateProcessor {
	receiptsCache, _ := lru.New(receiptsCacheLimit)
	txLookupCache, _ := lru.New(txLookupCacheLimit)

	if cacheConfig == nil {
		cacheConfig = defaultCacheConfig
	}

	sp := &StateProcessor{
		config:        config,
		hc:            hc,
		receiptsCache: receiptsCache,
		txLookupCache: txLookupCache,
		vmConfig:      vmConfig,
		cacheConfig:   cacheConfig,
		stateCache: state.NewDatabaseWithConfig(hc.headerDb, &trie.Config{
			Cache:     cacheConfig.TrieCleanLimit,
			Journal:   cacheConfig.TrieCleanJournal,
			Preimages: cacheConfig.Preimages,
		}),
		engine: engine,
		triegc: prque.New(nil),
		quit:   make(chan struct{}),
	}
	sp.validator = NewBlockValidator(config, hc, engine)

	// Load any existing snapshot, regenerating it if loading failed
	if sp.cacheConfig.SnapshotLimit > 0 {
		// TODO: If the state is not available, enable snapshot recovery
		head := hc.CurrentHeader()
		sp.snaps, _ = snapshot.New(hc.headerDb, sp.stateCache.TrieDB(), sp.cacheConfig.SnapshotLimit, head.Root(), true, false)
	}
	if txLookupLimit != nil {
		sp.txLookupLimit = *txLookupLimit
	}
	// If periodic cache journal is required, spin it up.
	if sp.cacheConfig.TrieCleanRejournal > 0 {
		if sp.cacheConfig.TrieCleanRejournal < time.Minute {
			log.Warn("Sanitizing invalid trie cache journal time", "provided", sp.cacheConfig.TrieCleanRejournal, "updated", time.Minute)
			sp.cacheConfig.TrieCleanRejournal = time.Minute
		}
		triedb := sp.stateCache.TrieDB()
		sp.wg.Add(1)
		go func() {
			defer sp.wg.Done()
			triedb.SaveCachePeriodically(sp.cacheConfig.TrieCleanJournal, sp.cacheConfig.TrieCleanRejournal, sp.quit)
		}()
	}
	return sp
}

// Process processes the state changes according to the Quai rules by running
// the transaction messages using the statedb and applying any rewards to both
// the processor (coinbase) and any included uncles.
//
// Process returns the receipts and logs accumulated during the process and
// returns the amount of gas that was used in the process. If any of the
// transactions failed to execute due to insufficient gas it will return an error.
func (p *StateProcessor) Process(block *types.Block, etxSet types.EtxSet) (types.Receipts, []*types.Log, *state.StateDB, *types.UtxoViewpoint, uint64, error) {
	var (
		receipts    types.Receipts
		usedGas     = new(uint64)
		header      = types.CopyHeader(block.Header())
		blockHash   = block.Hash()
		blockNumber = block.Number()
		allLogs     []*types.Log
		gp          = new(GasPool).AddGas(block.GasLimit())
	)

	start := time.Now()
	parent := p.hc.GetBlock(block.Header().ParentHash(), block.NumberU64()-1)
	if parent == nil {
		return types.Receipts{}, []*types.Log{}, nil, nil, 0, errors.New("parent block is nil for the block given to process")
	}
	time1 := common.PrettyDuration(time.Since(start))

	// Initialize a statedb
	statedb, err := state.New(parent.Header().Root(), p.stateCache, p.snaps)
	if err != nil {
		return types.Receipts{}, []*types.Log{}, nil, nil, 0, err
	}
	time2 := common.PrettyDuration(time.Since(start))

	// Set up UTXO processing
	utxoView := types.NewUtxoViewpoint()
	utxoView.SetBestHash(parent.Hash())
	stxos := make([]types.SpentTxOut, 0, types.CountSpentOutputs(block))
	err = p.hc.fetchInputUtxos(utxoView, block)
	if err != nil {
		return types.Receipts{}, []*types.Log{}, nil, nil, 0, err
	}

	if err != nil {
		return types.Receipts{}, []*types.Log{}, nil, nil, 0, err
	}

	var timeSenders, timeSign, timePrepare, timeEtx, timeTx time.Duration
	startTimeSenders := time.Now()
	senders := make(map[common.Hash]*common.InternalAddress) // temporary cache for senders of internal txs
	numInternalTxs := 0
	p.hc.pool.SendersMutex.RLock()
	for _, tx := range block.Transactions() { // get all senders of internal txs from cache - easier on the SendersMutex to do it all at once here
		if tx.Type() == types.InternalTxType || tx.Type() == types.InternalToExternalTxType {
			numInternalTxs++
			if sender, ok := p.hc.pool.GetSenderThreadUnsafe(tx.Hash()); ok {
				senders[tx.Hash()] = &sender // This pointer must never be modified
			} else {
				// TODO: calcuate the sender and add it to the pool senders cache in case of reorg (not necessary for now)
			}
		}
	}
	p.hc.pool.SendersMutex.RUnlock()
	timeSenders = time.Since(startTimeSenders)
	blockContext := NewEVMBlockContext(header, p.hc, nil)
	vmenv := vm.NewEVM(blockContext, vm.TxContext{}, statedb, p.config, p.vmConfig)
	time3 := common.PrettyDuration(time.Since(start))

	// Iterate over and process the individual transactions.
	etxRLimit := len(parent.Transactions()) / params.ETXRegionMaxFraction
	if etxRLimit < params.ETXRLimitMin {
		etxRLimit = params.ETXRLimitMin
	}
	etxPLimit := len(parent.Transactions()) / params.ETXPrimeMaxFraction
	if etxPLimit < params.ETXPLimitMin {
		etxPLimit = params.ETXPLimitMin
	}

	for i, tx := range block.Transactions() {
		startProcess := time.Now()
		msg, err := tx.AsMessageWithSender(types.MakeSigner(p.config, header.Number()), header.BaseFee(), senders[tx.Hash()])
		if err != nil {
			return nil, nil, nil, nil, 0, fmt.Errorf("could not apply tx %d [%v]: %w", i, tx.Hash().Hex(), err)
		}
		timeSignDelta := time.Since(startProcess)
		timeSign += timeSignDelta

		startTimePrepare := time.Now()
		statedb.Prepare(tx.Hash(), i)
		timePrepareDelta := time.Since(startTimePrepare)
		timePrepare += timePrepareDelta

		var receipt *types.Receipt
		if tx.Type() == types.ExternalTxType {
			startTimeEtx := time.Now()
			etxEntry, exists := etxSet[tx.Hash()]
			if !exists { // Verify that the ETX exists in the set
				return nil, nil, nil, nil, 0, fmt.Errorf("invalid external transaction: etx %x not found in unspent etx set", tx.Hash())
			}
			prevZeroBal := prepareApplyETX(statedb, &etxEntry.ETX)
			receipt, err = applyTransaction(msg, p.config, p.hc, nil, gp, statedb, blockNumber, blockHash, &etxEntry.ETX, usedGas, vmenv, &etxRLimit, &etxPLimit)
			statedb.SetBalance(common.ZeroInternal, prevZeroBal) // Reset the balance to what it previously was. Residual balance will be lost

			if err != nil {
				return nil, nil, nil, nil, 0, fmt.Errorf("could not apply tx %d [%v]: %w", i, etxEntry.ETX.Hash().Hex(), err)
			}

			delete(etxSet, etxEntry.ETX.Hash()) // This ETX has been spent so remove it from the unspent set
			timeEtxDelta := time.Since(startTimeEtx)
			timeEtx += timeEtxDelta

		} else if tx.Type() == types.InternalTxType || tx.Type() == types.InternalToExternalTxType {
			startTimeTx := time.Now()

			receipt, err = applyTransaction(msg, p.config, p.hc, nil, gp, statedb, blockNumber, blockHash, tx, usedGas, vmenv, &etxRLimit, &etxPLimit)
			if err != nil {
				return nil, nil, nil, nil, 0, fmt.Errorf("could not apply tx %d [%v]: %w", i, tx.Hash().Hex(), err)
			}
			timeTxDelta := time.Since(startTimeTx)
			timeTx += timeTxDelta
		} else if tx.Type() == types.UtxoTxType {
			_, err := types.CheckTransactionInputs(tx, block.Header().NumberU64(), utxoView)
			if err != nil {
				return nil, nil, nil, nil, 0, fmt.Errorf("could not apply tx %d [%v]: %w", i, tx.Hash().Hex(), err)
			}

			// Add all of the outputs for this transaction which are not
			// provably unspendable as available utxos.  Also, the passed
			// spent txos slice is updated to contain an entry for each
			// spent txout in the order each transaction spends them.
			err = utxoView.ConnectTransaction(tx, block.Header().NumberU64(), &stxos)
			if err != nil {
				return nil, nil, nil, nil, 0, fmt.Errorf("could not apply tx %d [%v]: %w", i, tx.Hash().Hex(), err)
			}
		} else {
			return nil, nil, nil, nil, 0, ErrTxTypeNotSupported
		}
		receipts = append(receipts, receipt)
		allLogs = append(allLogs, receipt.Logs...)
		i++
	}

	time4 := common.PrettyDuration(time.Since(start))
	// Finalize the block, applying any consensus engine specific extras (e.g. block rewards)
	p.engine.Finalize(p.hc, header, statedb, block.Transactions(), block.Uncles())
	time5 := common.PrettyDuration(time.Since(start))

	log.Debug("Total Tx Processing Time", "signing time", common.PrettyDuration(timeSign), "prepare state time", common.PrettyDuration(timePrepare), "etx time", common.PrettyDuration(timeEtx), "tx time", common.PrettyDuration(timeTx))
	log.Debug("Time taken in Process", "time1", time1, "time2", time2, "time3", time3, "time4", time4, "time5", time5)

	log.Debug("Total Tx Processing Time", "signing time", common.PrettyDuration(timeSign), "senders cache time", common.PrettyDuration(timeSenders), "percent cached internal txs", fmt.Sprintf("%.2f", float64(len(senders))/float64(numInternalTxs)*100), "prepare state time", common.PrettyDuration(timePrepare), "etx time", common.PrettyDuration(timeEtx), "tx time", common.PrettyDuration(timeTx))

	return receipts, allLogs, statedb, utxoView, *usedGas, nil
}

func applyTransaction(msg types.Message, config *params.ChainConfig, bc ChainContext, author *common.Address, gp *GasPool, statedb *state.StateDB, blockNumber *big.Int, blockHash common.Hash, tx *types.Transaction, usedGas *uint64, evm *vm.EVM, etxRLimit, etxPLimit *int) (*types.Receipt, error) {
	// Create a new context to be used in the EVM environment.
	txContext := NewEVMTxContext(msg)
	evm.Reset(txContext, statedb)

	// Apply the transaction to the current state (included in the env).
	result, err := ApplyMessage(evm, msg, gp)
	if err != nil {
		return nil, err
	}
	var ETXRCount int
	var ETXPCount int
	for _, tx := range result.Etxs {
		// Count which ETXs are cross-region
		if tx.To().Location().CommonDom(common.NodeLocation).Context() == common.REGION_CTX {
			ETXRCount++
		}
		// Count which ETXs are cross-prime
		if tx.To().Location().CommonDom(common.NodeLocation).Context() == common.PRIME_CTX {
			ETXPCount++
		}
	}
	if ETXRCount > *etxRLimit {
		return nil, fmt.Errorf("tx %032x emits too many cross-region ETXs for block. emitted: %d, limit: %d", tx.Hash(), ETXRCount, *etxRLimit)
	}
	if ETXPCount > *etxPLimit {
		return nil, fmt.Errorf("tx %032x emits too many cross-prime ETXs for block. emitted: %d, limit: %d", tx.Hash(), ETXPCount, *etxPLimit)
	}
	*etxRLimit -= ETXRCount
	*etxPLimit -= ETXPCount

	// Update the state with pending changes.
	var root []byte
	statedb.Finalise(true)

	*usedGas += result.UsedGas

	// Create a new receipt for the transaction, storing the intermediate root and gas used
	// by the tx.
	receipt := &types.Receipt{Type: tx.Type(), PostState: root, CumulativeGasUsed: *usedGas, Etxs: result.Etxs}
	if result.Failed() {
		receipt.Status = types.ReceiptStatusFailed
		log.Debug(result.Err.Error())
	} else {
		receipt.Status = types.ReceiptStatusSuccessful
	}
	receipt.TxHash = tx.Hash()
	receipt.GasUsed = result.UsedGas

	// If the transaction created a contract, store the creation address in the receipt.
	if msg.To() == nil {
		receipt.ContractAddress = crypto.CreateAddress(evm.TxContext.Origin, tx.Nonce(), tx.Data())
	}

	// Set the receipt logs and create the bloom filter.
	receipt.Logs = statedb.GetLogs(tx.Hash(), blockHash)
	receipt.Bloom = types.CreateBloom(types.Receipts{receipt})
	receipt.BlockHash = blockHash
	receipt.BlockNumber = blockNumber
	receipt.TransactionIndex = uint(statedb.TxIndex())
	return receipt, err
}

var lastWrite uint64

// Apply State
func (p *StateProcessor) Apply(batch ethdb.Batch, block *types.Block, newInboundEtxs types.Transactions) (*types.UtxoViewpoint, []*types.Log, error) {
	// Update the set of inbound ETXs which may be mined. This adds new inbound
	// ETXs to the set and removes expired ETXs so they are no longer available
	start := time.Now()
	blockHash := block.Hash()
	header := types.CopyHeader(block.Header())
	etxSet := rawdb.ReadEtxSet(p.hc.bc.db, block.ParentHash(), block.NumberU64()-1)
	time1 := common.PrettyDuration(time.Since(start))
	if etxSet == nil {
		return nil, nil, errors.New("failed to load etx set")
	}
	etxSet.Update(newInboundEtxs, block.NumberU64())
	time2 := common.PrettyDuration(time.Since(start))
	// Process our block
	receipts, logs, statedb, utxoView, usedGas, err := p.Process(block, etxSet)
	if err != nil {
		return nil, nil, err
	}
	if block.Hash() != blockHash {
		log.Warn("Block hash changed after Processing the block", "old hash", blockHash, "new hash", block.Hash())
	}
	time3 := common.PrettyDuration(time.Since(start))
	err = p.validator.ValidateState(block, statedb, receipts, usedGas)
	if err != nil {
		return nil, nil, err
	}
	time4 := common.PrettyDuration(time.Since(start))
	rawdb.WriteReceipts(batch, block.Hash(), block.NumberU64(), receipts)
	time4_5 := common.PrettyDuration(time.Since(start))
	// Create bloom filter and write it to cache/db
	bloom := types.CreateBloom(receipts)
	p.hc.AddBloom(bloom, block.Hash())
	time5 := common.PrettyDuration(time.Since(start))
	rawdb.WritePreimages(batch, statedb.Preimages())
	time6 := common.PrettyDuration(time.Since(start))
	// Commit all cached state changes into underlying memory database.
	root, err := statedb.Commit(true)
	if err != nil {
		return nil, nil, err
	}
	triedb := p.stateCache.TrieDB()
	time7 := common.PrettyDuration(time.Since(start))
	var time8 common.PrettyDuration
	var time9 common.PrettyDuration
	var time10 common.PrettyDuration
	var time11 common.PrettyDuration
	if err := triedb.Commit(root, false, nil); err != nil {
		return nil, nil, err
	}
	time8 = common.PrettyDuration(time.Since(start))
	rawdb.WriteEtxSet(batch, header.Hash(), header.NumberU64(), etxSet)
	time12 := common.PrettyDuration(time.Since(start))

	log.Debug("times during state processor apply:", "t1:", time1, "t2:", time2, "t3:", time3, "t4:", time4, "t4.5:", time4_5, "t5:", time5, "t6:", time6, "t7:", time7, "t8:", time8, "t9:", time9, "t10:", time10, "t11:", time11, "t12:", time12)
	return utxoView, logs, nil
}

// ApplyTransaction attempts to apply a transaction to the given state database
// and uses the input parameters for its environment. It returns the receipt
// for the transaction, gas used and an error if the transaction failed,
// indicating the block was invalid.
func ApplyTransaction(config *params.ChainConfig, bc ChainContext, author *common.Address, gp *GasPool, statedb *state.StateDB, header *types.Header, tx *types.Transaction, usedGas *uint64, cfg vm.Config, etxRLimit, etxPLimit *int) (*types.Receipt, error) {
	msg, err := tx.AsMessage(types.MakeSigner(config, header.Number()), header.BaseFee())
	if err != nil {
		return nil, err
	}
	// Create a new context to be used in the EVM environment
	blockContext := NewEVMBlockContext(header, bc, author)
	vmenv := vm.NewEVM(blockContext, vm.TxContext{}, statedb, config, cfg)
	if tx.Type() == types.ExternalTxType {
		prevZeroBal := prepareApplyETX(statedb, tx)
		receipt, err := applyTransaction(msg, config, bc, author, gp, statedb, header.Number(), header.Hash(), tx, usedGas, vmenv, etxRLimit, etxPLimit)
		statedb.SetBalance(common.ZeroInternal, prevZeroBal) // Reset the balance to what it previously was (currently a failed external transaction removes all the sent coins from the supply and any residual balance is gone as well)
		return receipt, err
	}
	return applyTransaction(msg, config, bc, author, gp, statedb, header.Number(), header.Hash(), tx, usedGas, vmenv, etxRLimit, etxPLimit)
}

// GetVMConfig returns the block chain VM config.
func (p *StateProcessor) GetVMConfig() *vm.Config {
	return &p.vmConfig
}

// State returns a new mutable state based on the current HEAD block.
func (p *StateProcessor) State() (*state.StateDB, error) {
	return p.StateAt(p.hc.GetBlockByHash(p.hc.CurrentHeader().Hash()).Root())
}

// StateAt returns a new mutable state based on a particular point in time.
func (p *StateProcessor) StateAt(root common.Hash) (*state.StateDB, error) {
	return state.New(root, p.stateCache, p.snaps)
}

// StateCache returns the caching database underpinning the blockchain instance.
func (p *StateProcessor) StateCache() state.Database {
	return p.stateCache
}

// HasState checks if state trie is fully present in the database or not.
func (p *StateProcessor) HasState(hash common.Hash) bool {
	_, err := p.stateCache.OpenTrie(hash)
	return err == nil
}

// HasBlockAndState checks if a block and associated state trie is fully present
// in the database or not, caching it if present.
func (p *StateProcessor) HasBlockAndState(hash common.Hash, number uint64) bool {
	// Check first that the block itself is known
	block := p.hc.GetBlock(hash, number)
	if block == nil {
		return false
	}
	return p.HasState(block.Root())
}

// GetReceiptsByHash retrieves the receipts for all transactions in a given block.
func (p *StateProcessor) GetReceiptsByHash(hash common.Hash) types.Receipts {
	if receipts, ok := p.receiptsCache.Get(hash); ok {
		return receipts.(types.Receipts)
	}
	number := rawdb.ReadHeaderNumber(p.hc.headerDb, hash)
	if number == nil {
		return nil
	}
	receipts := rawdb.ReadReceipts(p.hc.headerDb, hash, *number, p.hc.config)
	if receipts == nil {
		return nil
	}
	p.receiptsCache.Add(hash, receipts)
	return receipts
}

// GetTransactionLookup retrieves the lookup associate with the given transaction
// hash from the cache or database.
func (p *StateProcessor) GetTransactionLookup(hash common.Hash) *rawdb.LegacyTxLookupEntry {
	// Short circuit if the txlookup already in the cache, retrieve otherwise
	if lookup, exist := p.txLookupCache.Get(hash); exist {
		return lookup.(*rawdb.LegacyTxLookupEntry)
	}
	tx, blockHash, blockNumber, txIndex := rawdb.ReadTransaction(p.hc.headerDb, hash)
	if tx == nil {
		return nil
	}
	lookup := &rawdb.LegacyTxLookupEntry{BlockHash: blockHash, BlockIndex: blockNumber, Index: txIndex}
	p.txLookupCache.Add(hash, lookup)
	return lookup
}

// ContractCode retrieves a blob of data associated with a contract hash
// either from ephemeral in-memory cache, or from persistent storage.
func (p *StateProcessor) ContractCode(hash common.Hash) ([]byte, error) {
	return p.stateCache.ContractCode(common.Hash{}, hash)
}

// either from ephemeral in-memory cache, or from persistent storage.
func (p *StateProcessor) TrieNode(hash common.Hash) ([]byte, error) {
	return p.stateCache.TrieDB().Node(hash)
}

// ContractCodeWithPrefix retrieves a blob of data associated with a contract
// hash either from ephemeral in-memory cache, or from persistent storage.
//
// If the code doesn't exist in the in-memory cache, check the storage with
// new code scheme.
func (p *StateProcessor) ContractCodeWithPrefix(hash common.Hash) ([]byte, error) {
	type codeReader interface {
		ContractCodeWithPrefix(addrHash, codeHash common.Hash) ([]byte, error)
	}
	return p.stateCache.(codeReader).ContractCodeWithPrefix(common.Hash{}, hash)
}

// StateAtBlock retrieves the state database associated with a certain block.
// If no state is locally available for the given block, a number of blocks
// are attempted to be reexecuted to generate the desired state. The optional
// base layer statedb can be passed then it's regarded as the statedb of the
// parent block.
// Parameters:
//   - block: The block for which we want the state (== state at the stateRoot of the parent)
//   - reexec: The maximum number of blocks to reprocess trying to obtain the desired state
//   - base: If the caller is tracing multiple blocks, the caller can provide the parent state
//     continuously from the callsite.
//   - checklive: if true, then the live 'blockchain' state database is used. If the caller want to
//     perform Commit or other 'save-to-disk' changes, this should be set to false to avoid
//     storing trash persistently
func (p *StateProcessor) StateAtBlock(block *types.Block, reexec uint64, base *state.StateDB, checkLive bool) (statedb *state.StateDB, err error) {
	var (
		current  *types.Header
		database state.Database
		report   = true
		origin   = block.NumberU64()
	)
	// Check the live database first if we have the state fully available, use that.
	if checkLive {
		statedb, err = p.StateAt(block.Root())
		if err == nil {
			return statedb, nil
		}
	}

	var newHeads []*types.Header
	if base != nil {
		// The optional base statedb is given, mark the start point as parent block
		statedb, database, report = base, base.Database(), false
		current = p.hc.GetHeaderOrCandidate(block.ParentHash(), block.NumberU64()-1)
	} else {
		// Otherwise try to reexec blocks until we find a state or reach our limit
		current = types.CopyHeader(block.Header())

		// Create an ephemeral trie.Database for isolating the live one. Otherwise
		// the internal junks created by tracing will be persisted into the disk.
		database = state.NewDatabaseWithConfig(p.hc.headerDb, &trie.Config{Cache: 16})

		// If we didn't check the dirty database, do check the clean one, otherwise
		// we would rewind past a persisted block (specific corner case is chain
		// tracing from the genesis).
		if !checkLive {
			statedb, err = state.New(current.Root(), database, nil)
			if err == nil {
				return statedb, nil
			}
		}
		newHeads = append(newHeads, current)
		// Database does not have the state for the given block, try to regenerate
		for i := uint64(0); i < reexec; i++ {
			if current.NumberU64() == 0 {
				return nil, errors.New("genesis state is missing")
			}
			parent := p.hc.GetHeaderOrCandidate(current.ParentHash(), current.NumberU64()-1)
			if parent == nil {
				return nil, fmt.Errorf("missing block %v %d", current.ParentHash(), current.NumberU64()-1)
			}
			current = types.CopyHeader(parent)

			statedb, err = state.New(current.Root(), database, nil)
			if err == nil {
				break
			}
			newHeads = append(newHeads, current)
		}
		if err != nil {
			switch err.(type) {
			case *trie.MissingNodeError:
				return nil, fmt.Errorf("required historical state unavailable (reexec=%d)", reexec)
			default:
				return nil, err
			}
		}
	}
	// State was available at historical point, regenerate
	var (
		start  = time.Now()
		logged time.Time
		parent common.Hash
	)
	for i := len(newHeads) - 1; i >= 0; i-- {
		current := newHeads[i]
		// Print progress logs if long enough time elapsed
		if time.Since(logged) > 8*time.Second && report {
			log.Info("Regenerating historical state", "block", current.NumberU64()+1, "target", origin, "remaining", origin-current.NumberU64()-1, "elapsed", time.Since(start))
			logged = time.Now()
		}

		etxSet := rawdb.ReadEtxSet(p.hc.bc.db, current.ParentHash(), current.NumberU64()-1)
		if etxSet == nil {
			return nil, errors.New("etxSet set is nil in StateProcessor")
		}
		inboundEtxs := rawdb.ReadInboundEtxs(p.hc.bc.db, current.Hash())
		etxSet.Update(inboundEtxs, current.NumberU64())

		currentBlock := rawdb.ReadBlock(p.hc.bc.db, current.Hash(), current.NumberU64())
		if currentBlock == nil {
			return nil, errors.New("detached block found trying to regenerate state")
		}
		_, _, _, _, _, err := p.Process(currentBlock, etxSet)
		if err != nil {
			return nil, fmt.Errorf("processing block %d failed: %v", current.NumberU64(), err)
		}
		// Finalize the state so any modifications are written to the trie
		root, err := statedb.Commit(true)
		if err != nil {
			return nil, fmt.Errorf("stateAtBlock commit failed, number %d root %v: %w",
				current.NumberU64(), current.Root().Hex(), err)
		}
		statedb, err = state.New(root, database, nil)
		if err != nil {
			return nil, fmt.Errorf("state reset after block %d failed: %v", current.NumberU64(), err)
		}
		database.TrieDB().Reference(root, common.Hash{})
		if parent != (common.Hash{}) {
			database.TrieDB().Dereference(parent)
		}
		parent = root
	}
	if report {
		nodes, imgs := database.TrieDB().Size()
		log.Info("Historical state regenerated", "block", current.NumberU64(), "elapsed", time.Since(start), "nodes", nodes, "preimages", imgs)
	}
	return statedb, nil
}

// stateAtTransaction returns the execution environment of a certain transaction.
func (p *StateProcessor) StateAtTransaction(block *types.Block, txIndex int, reexec uint64) (Message, vm.BlockContext, *state.StateDB, error) {
	// Short circuit if it's genesis block.
	if block.NumberU64() == 0 {
		return nil, vm.BlockContext{}, nil, errors.New("no transaction in genesis")
	}
	// Create the parent state database
	parent := p.hc.GetBlock(block.ParentHash(), block.NumberU64()-1)
	if parent == nil {
		return nil, vm.BlockContext{}, nil, fmt.Errorf("parent %#x not found", block.ParentHash())
	}
	// Lookup the statedb of parent block from the live database,
	// otherwise regenerate it on the flight.
	statedb, err := p.StateAtBlock(parent, reexec, nil, true)
	if err != nil {
		return nil, vm.BlockContext{}, nil, err
	}
	if txIndex == 0 && len(block.Transactions()) == 0 {
		return nil, vm.BlockContext{}, statedb, nil
	}
	// Recompute transactions up to the target index.
	signer := types.MakeSigner(p.hc.Config(), block.Number())
	for idx, tx := range block.Transactions() {
		// Assemble the transaction call message and return if the requested offset
		msg, _ := tx.AsMessage(signer, block.BaseFee())
		txContext := NewEVMTxContext(msg)
		context := NewEVMBlockContext(block.Header(), p.hc, nil)
		if idx == txIndex {
			return msg, context, statedb, nil
		}
		// Not yet the searched for transaction, execute on top of the current state
		vmenv := vm.NewEVM(context, txContext, statedb, p.hc.Config(), vm.Config{})
		statedb.Prepare(tx.Hash(), idx)
		if _, err := ApplyMessage(vmenv, msg, new(GasPool).AddGas(tx.Gas())); err != nil {
			return nil, vm.BlockContext{}, nil, fmt.Errorf("transaction %#x failed: %v", tx.Hash(), err)
		}
		// Ensure any modifications are committed to the state
		statedb.Finalise(true)
	}
	return nil, vm.BlockContext{}, nil, fmt.Errorf("transaction index %d out of range for block %#x", txIndex, block.Hash())
}

func (p *StateProcessor) Stop() {
	// Ensure all live cached entries be saved into disk, so that we can skip
	// cache warmup when node restarts.
	if p.cacheConfig.TrieCleanJournal != "" {
		triedb := p.stateCache.TrieDB()
		triedb.SaveCache(p.cacheConfig.TrieCleanJournal)
	}
	close(p.quit)
	log.Info("State Processor stopped")
}

func prepareApplyETX(statedb *state.StateDB, tx *types.Transaction) *big.Int {
	prevZeroBal := statedb.GetBalance(common.ZeroInternal)   // Get current zero address balance
	fee := big.NewInt(0).Add(tx.GasFeeCap(), tx.GasTipCap()) // Add gas price cap to miner tip cap
	fee.Mul(fee, big.NewInt(int64(tx.Gas())))                // Multiply gas price by gas limit (may need to check for int64 overflow)
	total := big.NewInt(0).Add(fee, tx.Value())              // Add gas fee to value
	statedb.SetBalance(common.ZeroInternal, total)           // Use zero address at temp placeholder and set it to gas fee plus value
	return prevZeroBal
}
