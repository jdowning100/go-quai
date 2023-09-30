package core

import "github.com/dominant-strategies/go-quai/core/types"

// SpentTxOut contains a spent transaction output and potentially additional
// contextual information such as whether or not it was contained in a coinbase
// transaction, the version of the transaction it was contained in, and which
// block height the containing transaction was included in.  As described in
// the comments above, the additional contextual information will only be valid
// when this spent txout is spending the last unspent output of the containing
// transaction.
type SpentTxOut struct {
	// Amount is the amount of the output.
	Amount int64

	// PkScipt is the public key script for the output.
	PkScript []byte

	// Height is the height of the block containing the creating tx.
	Height int32

	// Denotes if the creating tx is a coinbase.
	IsCoinBase bool
}

// countSpentOutputs returns the number of utxos the passed block spends.
func countSpentOutputs(block *types.Block) int {
	// Exclude the coinbase transaction since it can't spend anything.
	var numSpent int
	for _, tx := range block.UTXOs()[1:] {
		numSpent += len(tx.MsgTx().TxIn)
	}
	return numSpent
}
