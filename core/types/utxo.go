package types

import (
	"errors"
	"fmt"
	"math"

	"github.com/dominant-strategies/go-quai/common"
)

const (

	// UTXOVersion is the current latest supported transaction version.
	UTXOVersion = 1

	// MaxTxInSequenceNum is the maximum sequence number the sequence field
	// of a transaction input can be.
	MaxTxInSequenceNum uint32 = 0xffffffff

	// MaxPrevOutIndex is the maximum index the index field of a previous
	// outpoint can be.
	MaxPrevOutIndex uint32 = 0xffffffff

	// SatoshiPerBitcent is the number of satoshi in one bitcoin cent.
	SatoshiPerBitcent = 1e6

	// SatoshiPerBitcoin is the number of satoshi in one bitcoin (1 BTC).
	SatoshiPerBitcoin = 1e8

	// MaxSatoshi is the maximum transaction amount allowed in satoshi.
	MaxSatoshi = 21e6 * SatoshiPerBitcoin
)

// TxIn defines a bitcoin transaction input.
type TxIn struct {
	PreviousOutPoint OutPoint
	PubKey           []byte
}

// OutPoint defines a bitcoin data type that is used to track previous
// transaction outputs.
type OutPoint struct {
	Hash  common.Hash
	Index uint32
}

// NewOutPoint returns a new bitcoin transaction outpoint point with the
// provided hash and index.
func NewOutPoint(hash *common.Hash, index uint32) *OutPoint {
	return &OutPoint{
		Hash:  *hash,
		Index: index,
	}
}

// NewTxIn returns a new bitcoin transaction input with the provided
// previous outpoint point and signature script with a default sequence of
// MaxTxInSequenceNum.
func NewTxIn(prevOut *OutPoint, pubkey []byte, witness [][]byte) *TxIn {
	return &TxIn{
		PreviousOutPoint: *prevOut,
		PubKey:           pubkey,
	}
}

// TxOut defines a bitcoin transaction output.
type TxOut struct {
	Value   uint64
	Address []byte
}

// SerializeSize returns the number of bytes it would take to serialize the
// the transaction output.
// func (t *TxOut) SerializeSize() int {
// 	// Value 8 bytes + serialized varint size for the length of PkScript +
// 	// PkScript bytes.
// 	return 8 + VarIntSerializeSize(uuint64(len(t.PkScript))) + len(t.PkScript)
// }

// NewTxOut returns a new bitcoin transaction output with the provided
// transaction value and public key script.
func NewTxOut(value uint64, address []byte) *TxOut {
	return &TxOut{
		Value:   value,
		Address: address,
	}
}

// CheckTransactionSanity performs some preliminary checks on a transaction to
// ensure it is sane.  These checks are context free.
func CheckUTXOTransactionSanity(tx *Transaction, location common.Location) error {
	// A transaction must have at least one input.
	if len(tx.TxIn()) == 0 {
		return errors.New("transaction has no inputs")
	}

	// A transaction must have at least one output.
	if len(tx.TxOut()) == 0 {
		return errors.New("transaction has no outputs")
	}

	// TODO: A transaction must not exceed the maximum allowed block payload when
	// serialized.

	// Ensure the transaction amounts are in range.  Each transaction
	// output must not be negative or more than the max allowed per
	// transaction.  Also, the total of all outputs must abide by the same
	// restrictions.  All amounts in a transaction are in a unit value known
	// as a satoshi.  One bitcoin is a quantity of satoshi as defined by the
	// SatoshiPerBitcoin constant.
	var totalSatoshi uint64
	for _, txOut := range tx.TxOut() {
		satoshi := txOut.Value
		if satoshi > MaxSatoshi {
			str := fmt.Sprintf("transaction output value of %v is "+
				"higher than max allowed value of %v", satoshi,
				MaxSatoshi)
			return errors.New(str)
		}

		// Two's complement int64 overflow guarantees that any overflow
		// is detected and reported.  This is impossible for Bitcoin, but
		// perhaps possible if an alt increases the total money supply.
		totalSatoshi += satoshi
		if totalSatoshi > MaxSatoshi {
			str := fmt.Sprintf("total value of all transaction "+
				"outputs is %v which is higher than max "+
				"allowed value of %v", totalSatoshi,
				MaxSatoshi)
			return errors.New(str)
		}

		if _, err := common.BytesToAddress(txOut.Address, location).InternalAddress(); err != nil {
			return errors.New("invalid output address: " + err.Error())
		}
	}

	// Check for duplicate transaction inputs.
	existingTxOut := make(map[OutPoint]struct{})
	for _, txIn := range tx.TxIn() {
		if _, exists := existingTxOut[txIn.PreviousOutPoint]; exists {
			return errors.New("transaction contains duplicate inputs")
		}
		existingTxOut[txIn.PreviousOutPoint] = struct{}{}
	}

	// Previous transaction outputs referenced by the inputs to this
	// transaction must not be null.
	for _, txIn := range tx.TxIn() {
		if txIn.PreviousOutPoint.Index == math.MaxUint32 && txIn.PreviousOutPoint.Hash == common.ZeroHash {
			return errors.New("transaction " +
				"input refers to previous output that " +
				"is null")
		}
	}

	return nil
}
