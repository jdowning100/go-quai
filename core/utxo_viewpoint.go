package core

import (
	"fmt"

	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcutil"
	"github.com/dominant-strategies/go-quai/common"
	"github.com/dominant-strategies/go-quai/core/state"
	"github.com/dominant-strategies/go-quai/core/types"
)

// txoFlags is a bitmask defining additional information and state for a
// transaction output in a utxo view.
type txoFlags uint8

const (
	// tfCoinBase indicates that a txout was contained in a coinbase tx.
	tfCoinBase txoFlags = 1 << iota

	// tfSpent indicates that a txout is spent.
	tfSpent

	// tfModified indicates that a txout has been modified since it was
	// loaded.
	tfModified
)

// UtxoEntry houses details about an individual transaction output in a utxo
// view such as whether or not it was contained in a coinbase tx, the height of
// the block that contains the tx, whether or not it is spent, its public key
// script, and how much it pays.
type UtxoEntry struct {
	// NOTE: Additions, deletions, or modifications to the order of the
	// definitions in this struct should not be changed without considering
	// how it affects alignment on 64-bit platforms.  The current order is
	// specifically crafted to result in minimal padding.  There will be a
	// lot of these in memory, so a few extra bytes of padding adds up.

	amount      int64
	pkScript    []byte // The public key script for the output.
	blockHeight int32  // Height of block containing tx.

	// packedFlags contains additional info about output such as whether it
	// is a coinbase, whether it is spent, and whether it has been modified
	// since it was loaded.  This approach is used in order to reduce memory
	// usage since there will be a lot of these in memory.
	packedFlags txoFlags
}

// isModified returns whether or not the output has been modified since it was
// loaded.
func (entry *UtxoEntry) isModified() bool {
	return entry.packedFlags&tfModified == tfModified
}

// IsCoinBase returns whether or not the output was contained in a coinbase
// transaction.
func (entry *UtxoEntry) IsCoinBase() bool {
	return entry.packedFlags&tfCoinBase == tfCoinBase
}

// BlockHeight returns the height of the block containing the output.
func (entry *UtxoEntry) BlockHeight() int32 {
	return entry.blockHeight
}

// IsSpent returns whether or not the output has been spent based upon the
// current state of the unspent transaction output view it was obtained from.
func (entry *UtxoEntry) IsSpent() bool {
	return entry.packedFlags&tfSpent == tfSpent
}

// Spend marks the output as spent.  Spending an output that is already spent
// has no effect.
func (entry *UtxoEntry) Spend() {
	// Nothing to do if the output is already spent.
	if entry.IsSpent() {
		return
	}

	// Mark the output as spent and modified.
	entry.packedFlags |= tfSpent | tfModified
}

// Amount returns the amount of the output.
func (entry *UtxoEntry) Amount() int64 {
	return entry.amount
}

// PkScript returns the public key script for the output.
func (entry *UtxoEntry) PkScript() []byte {
	return entry.pkScript
}

// Clone returns a shallow copy of the utxo entry.
func (entry *UtxoEntry) Clone() *UtxoEntry {
	if entry == nil {
		return nil
	}

	return &UtxoEntry{
		amount:      entry.amount,
		pkScript:    entry.pkScript,
		blockHeight: entry.blockHeight,
		packedFlags: entry.packedFlags,
	}
}

// NewUtxoEntry returns a new UtxoEntry built from the arguments.
func NewUtxoEntry(
	txOut *types.TxOut, blockHeight int32, isCoinbase bool) *UtxoEntry {
	var cbFlag txoFlags
	if isCoinbase {
		cbFlag |= tfCoinBase
	}

	return &UtxoEntry{
		amount:      txOut.Value,
		pkScript:    txOut.PkScript,
		blockHeight: blockHeight,
		packedFlags: cbFlag,
	}
}

// UtxoViewpoint represents a view into the set of unspent transaction outputs
// from a specific point of view in the chain.  For example, it could be for
// the end of the main chain, some point in the history of the main chain, or
// down a side chain.
//
// The unspent outputs are needed by other transactions for things such as
// script validation and double spend prevention.
type UtxoViewpoint struct {
	entries  map[types.OutPoint]*UtxoEntry
	bestHash common.Hash
}

// BestHash returns the hash of the best block in the chain the view currently
// respresents.
func (view *UtxoViewpoint) BestHash() common.Hash {
	return view.bestHash
}

// SetBestHash sets the hash of the best block in the chain the view currently
// respresents.
func (view *UtxoViewpoint) SetBestHash(hash common.Hash) {
	view.bestHash = hash
}

// LookupEntry returns information about a given transaction output according to
// the current state of the view.  It will return nil if the passed output does
// not exist in the view or is otherwise not available such as when it has been
// disconnected during a reorg.
func (view *UtxoViewpoint) LookupEntry(outpoint types.OutPoint) *UtxoEntry {
	return view.entries[outpoint]
}

// FetchPrevOutput fetches the previous output referenced by the passed
// outpoint. This is identical to the LookupEntry method, but it returns a
// types.TxOut instead.
//
// NOTE: This is an implementation of the txscript.PrevOutputFetcher interface.
func (view *UtxoViewpoint) FetchPrevOutput(op types.OutPoint) *types.TxOut {
	prevOut := view.entries[op]
	if prevOut == nil {
		return nil
	}

	return &types.TxOut{
		Value:    prevOut.amount,
		PkScript: prevOut.PkScript(),
	}
}

// addTxOut adds the specified output to the view if it is not provably
// unspendable.  When the view already has an entry for the output, it will be
// marked unspent.  All fields will be updated for existing entries since it's
// possible it has changed during a reorg.
func (view *UtxoViewpoint) addTxOut(outpoint types.OutPoint, txOut *types.TxOut, isCoinBase bool, blockHeight int32) {
	// Don't add provably unspendable outputs.
	if txscript.IsUnspendable(txOut.PkScript) {
		return
	}

	// Update existing entries.  All fields are updated because it's
	// possible (although extremely unlikely) that the existing entry is
	// being replaced by a different transaction with the same hash.  This
	// is allowed so long as the previous transaction is fully spent.
	entry := view.LookupEntry(outpoint)
	if entry == nil {
		entry = new(UtxoEntry)
		view.entries[outpoint] = entry
	}

	entry.amount = txOut.Value
	entry.pkScript = txOut.PkScript
	entry.blockHeight = blockHeight
	entry.packedFlags = tfModified
	if isCoinBase {
		entry.packedFlags |= tfCoinBase
	}
}

// AddTxOut adds the specified output of the passed transaction to the view if
// it exists and is not provably unspendable.  When the view already has an
// entry for the output, it will be marked unspent.  All fields will be updated
// for existing entries since it's possible it has changed during a reorg.
func (view *UtxoViewpoint) AddTxOut(tx *btcutil.Tx, txOutIdx uint32, blockHeight int32) {
	// Can't add an output for an out of bounds index.
	if txOutIdx >= uint32(len(tx.MsgTx().TxOut)) {
		return
	}

	// Update existing entries.  All fields are updated because it's
	// possible (although extremely unlikely) that the existing entry is
	// being replaced by a different transaction with the same hash.  This
	// is allowed so long as the previous transaction is fully spent.
	prevOut := types.OutPoint{Hash: *tx.Hash(), Index: txOutIdx}
	txOut := tx.MsgTx().TxOut[txOutIdx]
	view.addTxOut(prevOut, txOut, IsCoinBaseTx(tx.msgTx()), blockHeight)
}

// AddTxOuts adds all outputs in the passed transaction which are not provably
// unspendable to the view.  When the view already has entries for any of the
// outputs, they are simply marked unspent.  All fields will be updated for
// existing entries since it's possible it has changed during a reorg.
func (view *UtxoViewpoint) AddTxOuts(tx *btcutil.Tx, blockHeight int32) {
	// Loop all of the transaction outputs and add those which are not
	// provably unspendable.
	isCoinBase := IsCoinBaseTx(tx.msgTx())
	prevOut := types.OutPoint{Hash: *tx.Hash()}
	for txOutIdx, txOut := range tx.MsgTx().TxOut {
		// Update existing entries.  All fields are updated because it's
		// possible (although extremely unlikely) that the existing
		// entry is being replaced by a different transaction with the
		// same hash.  This is allowed so long as the previous
		// transaction is fully spent.
		prevOut.Index = uint32(txOutIdx)
		view.addTxOut(prevOut, txOut, isCoinBase, blockHeight)
	}
}

// NewUtxoViewpoint returns a new empty unspent transaction output view.
func NewUtxoViewpoint() *UtxoViewpoint {
	return &UtxoViewpoint{
		entries: make(map[types.OutPoint]*UtxoEntry),
	}
}

// fetchInputUtxos loads the unspent transaction outputs for the inputs
// referenced by the transactions in the given block into the view from the
// database as needed.  In particular, referenced entries that are earlier in
// the block are added to the view and entries that are already in the view are
// not modified.
func (view *UtxoViewpoint) fetchInputUtxos(db *state.StateDB, block *types.Block) error {
	// Build a map of in-flight transactions because some of the inputs in
	// this block could be referencing other transactions earlier in this
	// block which are not yet in the chain.
	txInFlight := map[common.Hash]int{}
	transactions := block.UTXOs()
	for i, tx := range transactions {
		txInFlight[*tx.Hash()] = i
	}

	// Loop through all of the transaction inputs (except for the coinbase
	// which has no inputs) collecting them into sets of what is needed and
	// what is already known (in-flight).
	needed := make([]types.OutPoint, 0, len(transactions))
	for i, tx := range transactions[1:] {
		for _, txIn := range tx.MsgTx().TxIn {
			// It is acceptable for a transaction input to reference
			// the output of another transaction in this block only
			// if the referenced transaction comes before the
			// current one in this block.  Add the outputs of the
			// referenced transaction as available utxos when this
			// is the case.  Otherwise, the utxo details are still
			// needed.
			//
			// NOTE: The >= is correct here because i is one less
			// than the actual position of the transaction within
			// the block due to skipping the coinbase.
			originHash := &txIn.PreviousOutPoint.Hash
			if inFlightIndex, ok := txInFlight[*originHash]; ok &&
				i >= inFlightIndex {

				originTx := transactions[inFlightIndex]
				view.AddTxOuts(originTx, block.Height())
				continue
			}

			// Don't request entries that are already in the view
			// from the database.
			if _, ok := view.entries[txIn.PreviousOutPoint]; ok {
				continue
			}

			needed = append(needed, txIn.PreviousOutPoint)
		}
	}

	// Request the input utxos from the database.
	return view.fetchUtxosMain(db, needed)
}

// connectTransaction updates the view by adding all new utxos created by the
// passed transaction and marking all utxos that the transactions spend as
// spent.  In addition, when the 'stxos' argument is not nil, it will be updated
// to append an entry for each spent txout.  An error will be returned if the
// view does not contain the required utxos.
func (view *UtxoViewpoint) connectTransaction(tx *btcutil.Tx, blockHeight int32, stxos *[]SpentTxOut) error {
	// Coinbase transactions don't have any inputs to spend.
	if IsCoinBaseTx(tx.MsgUTXO()) {
		// Add the transaction's outputs as available utxos.
		view.AddTxOuts(tx, blockHeight)
		return nil
	}

	// Spend the referenced utxos by marking them spent in the view and,
	// if a slice was provided for the spent txout details, append an entry
	// to it.
	for _, txIn := range tx.MsgTx().TxIn {
		// Ensure the referenced utxo exists in the view.  This should
		// never happen unless there is a bug is introduced in the code.
		entry := view.entries[txIn.PreviousOutPoint]
		if entry == nil {
			return AssertError(fmt.Sprintf("view missing input %v",
				txIn.PreviousOutPoint))
		}

		// Only create the stxo details if requested.
		if stxos != nil {
			// Populate the stxo details using the utxo entry.
			var stxo = SpentTxOut{
				Amount:     entry.Amount(),
				PkScript:   entry.PkScript(),
				Height:     entry.BlockHeight(),
				IsCoinBase: entry.IsCoinBase(),
			}
			*stxos = append(*stxos, stxo)
		}

		// Mark the entry as spent.  This is not done until after the
		// relevant details have been accessed since spending it might
		// clear the fields from memory in the future.
		entry.Spend()
	}

	// Add the transaction's outputs as available utxos.
	view.AddTxOuts(tx, blockHeight)
	return nil
}
