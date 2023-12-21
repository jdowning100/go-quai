package types

import (
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
