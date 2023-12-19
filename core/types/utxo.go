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

	// defaultTxInOutAlloc is the default size used for the backing array for
	// transaction inputs and outputs.  The array will dynamically grow as needed,
	// but this figure is intended to provide enough space for the number of
	// inputs and outputs in a typical transaction without needing to grow the
	// backing array multiple times.
	defaultTxInOutAlloc = 15
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

// NewOutPointFromString returns a new bitcoin transaction outpoint parsed from
// the provided string, which should be in the format "hash:index".
// func NewOutPointFromString(outpoint string) (*OutPoint, error) {
// 	parts := strings.Split(outpoint, ":")
// 	if len(parts) != 2 {
// 		return nil, errors.New("outpoint should be of the form txid:index")
// 	}
// 	hash, err := chainhash.NewHashFromStr(parts[0])
// 	if err != nil {
// 		return nil, err
// 	}

// 	outputIndex, err := strconv.ParseUint(parts[1], 10, 32)
// 	if err != nil {
// 		return nil, fmt.Errorf("invalid output index: %v", err)
// 	}

// 	return &OutPoint{
// 		Hash:  *hash,
// 		Index: uint32(outputIndex),
// 	}, nil
// }

// String returns the OutPoint in the human-readable form "hash:index".
// func (o OutPoint) String() string {
// 	// Allocate enough for hash string, colon, and 10 digits.  Although
// 	// at the time of writing, the number of digits can be no greater than
// 	// the length of the decimal representation of maxTxOutPerMessage, the
// 	// maximum message payload may increase in the future and this
// 	// optimization may go unnoticed, so allocate space for 10 decimal
// 	// digits, which will fit any uint32.
// 	buf := make([]byte, 2*common.HashSize+1, 2*common.HashSize+1+10)
// 	copy(buf, o.Hash.String())
// 	buf[2*common.HashSize] = ':'
// 	buf = strconv.AppendUint(buf, uuint64(o.Index), 10)
// 	return string(buf)
// }

// SerializeSize returns the number of bytes it would take to serialize the
// the transaction input.
// func (t *TxIn) SerializeSize() int {
// 	// Outpoint Hash 32 bytes + Outpoint Index 4 bytes + Sequence 4 bytes +
// 	// serialized varint size for the length of SignatureScript +
// 	// SignatureScript bytes.
// 	return 40 + VarIntSerializeSize(uuint64(len(t.SignatureScript))) +
// 		len(t.SignatureScript)
// }

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
