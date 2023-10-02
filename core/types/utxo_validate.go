package types

import (
	"github.com/dominant-strategies/go-quai/common"
	"github.com/dominant-strategies/go-quai/common/math"
)

// IsCoinBaseTx determines whether or not a transaction is a coinbase.  A coinbase
// is a special transaction created by miners that has no inputs.  This is
// represented in the block chain by a transaction with a single input that has
// a previous output transaction index set to the maximum value along with a
// zero hash.
//
// This function only differs from IsCoinBase in that it works with a raw wire
// transaction as opposed to a higher level util transaction.
func IsCoinBaseTx(msgTx *MsgUTXO) bool {
	// A coin base must only have one transaction input.
	if len(msgTx.TxIn) != 1 {
		return false
	}

	// The previous output of a coin base must have a max value index and
	// a zero hash.
	prevOut := &msgTx.TxIn[0].PreviousOutPoint
	if (prevOut.Index != math.MaxUint32 || prevOut.Hash != common.Hash{}) {
		return false
	}

	return true
}

// CheckTransactionSanity performs some preliminary checks on a transaction to
// ensure it is sane.  These checks are context free.
func CheckTransactionSanity(tx *UTXO) error {
	// A transaction must have at least one input.
	msgTx := tx.MsgTx()
	if len(msgTx.TxIn) == 0 {
		return nil
	}

	// A transaction must have at least one output.
	if len(msgTx.TxOut) == 0 {
		return nil
	}

	// A transaction must not exceed the maximum allowed block payload when
	// serialized.
	// serializedTxSize := tx.MsgTx().SerializeSizeStripped()
	// if serializedTxSize > MaxBlockBaseSize {
	// 	str := fmt.Sprintf("serialized transaction is too big - got "+
	// 		"%d, max %d", serializedTxSize, MaxBlockBaseSize)
	// 	return nil
	// }

	// Ensure the transaction amounts are in range.  Each transaction
	// output must not be negative or more than the max allowed per
	// transaction.  Also, the total of all outputs must abide by the same
	// restrictions.  All amounts in a transaction are in a unit value known
	// as a satoshi.  One bitcoin is a quantity of satoshi as defined by the
	// SatoshiPerBitcoin constant.
	// var totalSatoshi uint64
	// for _, txOut := range msgTx.TxOut {
	// 	satoshi := txOut.Value
	// if satoshi < 0 {
	// 	str := fmt.Sprintf("transaction output has negative "+
	// 		"value of %v", satoshi)
	// 	return ruleError(ErrBadTxOutValue, str)
	// }
	// if satoshi > btcutil.MaxSatoshi {
	// 	str := fmt.Sprintf("transaction output value of %v is "+
	// 		"higher than max allowed value of %v", satoshi,
	// 		btcutil.MaxSatoshi)
	// 	return ruleError(ErrBadTxOutValue, str)
	// }

	// Two's complement uint64 overflow guarantees that any overflow
	// is detected and reported.  This is impossible for Bitcoin, but
	// perhaps possible if an alt increases the total money supply.
	// totalSatoshi += satoshi
	// if totalSatoshi < 0 {
	// 	str := fmt.Sprintf("total value of all transaction "+
	// 		"outputs exceeds max allowed value of %v",
	// 		btcutil.MaxSatoshi)
	// 	return ruleError(ErrBadTxOutValue, str)
	// }
	// if totalSatoshi > btcutil.MaxSatoshi {
	// 	str := fmt.Sprintf("total value of all transaction "+
	// 		"outputs is %v which is higher than max "+
	// 		"allowed value of %v", totalSatoshi,
	// 		btcutil.MaxSatoshi)
	// 	return ruleError(ErrBadTxOutValue, str)
	// }
	// }

	// Check for duplicate transaction inputs.
	// existingTxOut := make(map[wire.OutPoint]struct{})
	// for _, txIn := range msgTx.TxIn {
	// 	if _, exists := existingTxOut[txIn.PreviousOutPoint]; exists {
	// 		return ruleError(ErrDuplicateTxInputs, "transaction "+
	// 			"contains duplicate inputs")
	// 	}
	// 	existingTxOut[txIn.PreviousOutPoint] = struct{}{}
	// }

	// Coinbase script length must be between min and max length.
	// if IsCoinBaseTx(tx.MsgTx()) {
	// 	slen := len(msgTx.TxIn[0].SignatureScript)
	// 	if slen < MinCoinbaseScriptLen || slen > MaxCoinbaseScriptLen {
	// 		str := fmt.Sprintf("coinbase transaction script length "+
	// 			"of %d is out of range (min: %d, max: %d)",
	// 			slen, MinCoinbaseScriptLen, MaxCoinbaseScriptLen)
	// 		return ruleError(ErrBadCoinbaseScriptLen, str)
	// 	}
	// } else {
	// 	// Previous transaction outputs referenced by the inputs to this
	// 	// transaction must not be null.
	// 	for _, txIn := range msgTx.TxIn {
	// 		if isNullOutpoint(&txIn.PreviousOutPoint) {
	// 			return ruleError(ErrBadTxInput, "transaction "+
	// 				"input refers to previous output that "+
	// 				"is null")
	// 		}
	// 	}
	//}

	return nil
}

// CheckTransactionInputs performs a series of checks on the inputs to a
// transaction to ensure they are valid.  An example of some of the checks
// include verifying all inputs exist, ensuring the coinbase seasoning
// requirements are met, detecting double spends, validating all values and fees
// are in the legal range and the total output amount doesn't exceed the input
// amount, and verifying the signatures to prove the spender was the owner of
// the bitcoins and therefore allowed to spend them.  As it checks the inputs,
// it also calculates the total fees for the transaction and returns that value.
//
// NOTE: The transaction MUST have already been sanity checked with the
// CheckTransactionSanity function prior to calling this function.
func CheckTransactionInputs(tx *MsgUTXO, txHeight uint64, utxoView *UtxoViewpoint) (uint64, error) {
	// Coinbase transactions have no inputs.
	if IsCoinBaseTx(tx) {
		return 0, nil
	}

	var totalSatoshiIn uint64
	for _, txIn := range tx.TxIn {
		// Ensure the referenced input transaction is available.
		utxo := utxoView.LookupEntry(txIn.PreviousOutPoint)
		if utxo == nil || utxo.IsSpent() {
			// str := fmt.Sprintf("output %v referenced from "+
			// 	"transaction %s:%d either does not exist or "+
			// 	"has already been spent", txIn.PreviousOutPoint,
			// 	tx.Hash(), txInIndex)
			// return 0, ruleError(ErrMissingTxOut, str)
		}

		// Ensure the transaction is not spending coins which have not
		// yet reached the required coinbase maturity.
		// if utxo.IsCoinBase() {
		// 	originHeight := utxo.BlockHeight()
		// 	blocksSincePrev := txHeight - originHeight
		// 	coinbaseMaturity := int32(chainParams.CoinbaseMaturity)
		// 	if blocksSincePrev < coinbaseMaturity {
		// 		str := fmt.Sprintf("tried to spend coinbase "+
		// 			"transaction output %v from height %v "+
		// 			"at height %v before required maturity "+
		// 			"of %v blocks", txIn.PreviousOutPoint,
		// 			originHeight, txHeight,
		// 			coinbaseMaturity)
		// 		return 0, ruleError(ErrImmatureSpend, str)
		// 	}
		// }

		// Ensure the transaction amounts are in range.  Each of the
		// output values of the input transactions must not be negative
		// or more than the max allowed per transaction.  All amounts in
		// a transaction are in a unit value known as a satoshi.  One
		// bitcoin is a quantity of satoshi as defined by the
		// SatoshiPerBitcoin constant.
		originTxSatoshi := utxo.Amount()
		if originTxSatoshi < 0 {
			// str := fmt.Sprintf("transaction output has negative "+
			// 	"value of %v", btcutil.Amount(originTxSatoshi))
			// return 0, ruleError(ErrBadTxOutValue, str)
		}
		// if originTxSatoshi > btcutil.MaxSatoshi {
		// str := fmt.Sprintf("transaction output value of %v is "+
		// 	"higher than max allowed value of %v",
		// 	btcutil.Amount(originTxSatoshi),
		// 	btcutil.MaxSatoshi)
		// return 0, ruleError(ErrBadTxOutValue, str)
		// }

		// The total of all outputs must not be more than the max
		// allowed per transaction.  Also, we could potentially overflow
		// the accumulator so check for overflow.
		// lastSatoshiIn := totalSatoshiIn
		// totalSatoshiIn += originTxSatoshi
		// if totalSatoshiIn < lastSatoshiIn ||
		// totalSatoshiIn > btcutil.MaxSatoshi {
		// str := fmt.Sprintf("total value of all transaction "+
		// 	"inputs is %v which is higher than max "+
		// 	"allowed value of %v", totalSatoshiIn,
		// 	btcutil.MaxSatoshi)
		// return 0, ruleError(ErrBadTxOutValue, str)
		// }
	}

	// Calculate the total output amount for this transaction.  It is safe
	// to ignore overflow and out of range errors here because those error
	// conditions would have already been caught by checkTransactionSanity.
	var totalSatoshiOut uint64
	for _, txOut := range tx.TxOut {
		totalSatoshiOut += txOut.Value
	}

	// Ensure the transaction does not spend more than its inputs.
	if totalSatoshiIn < totalSatoshiOut {
		// str := fmt.Sprintf("total value of all transaction inputs for "+
		// 	"transaction %v is %v which is less than the amount "+
		// 	"spent of %v", tx.Hash(), totalSatoshiIn, totalSatoshiOut)
		// return 0, ruleError(ErrSpendTooHigh, str)
	}

	// NOTE: bitcoind checks if the transaction fees are < 0 here, but that
	// is an impossible condition because of the check above that ensures
	// the inputs are >= the outputs.
	txFeeInSatoshi := totalSatoshiIn - totalSatoshiOut
	return txFeeInSatoshi, nil
}
