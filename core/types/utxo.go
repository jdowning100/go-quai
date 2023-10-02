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

// Tx defines a bitcoin transaction that provides easier and more efficient
// manipulation of raw transactions.  It also memoizes the hash for the
// transaction on its first access so subsequent accesses don't have to repeat
// the relatively expensive hashing operations.
type UTXO struct {
	msgUTXO       *MsgUTXO    // Underlying MsgUTXO
	txHash        common.Hash // Cached transaction hash
	txHashWitness common.Hash // Cached transaction witness hash
	txHasWitness  *bool       // If the transaction has witness data
	txIndex       int         // Position within a block or TxIndexUnknown
}

// MsgTx returns the underlying wire.MsgTx for the transaction.
func (t *UTXO) MsgTx() *MsgUTXO {
	// Return the cached transaction.
	return t.msgUTXO
}

// NewMsgTx returns a new bitcoin tx message that conforms to the Message
// interface.  The return instance has a default version of TxVersion and there
// are no transaction inputs or outputs.  Also, the lock time is set to zero
// to indicate the transaction is valid immediately as opposed to some time in
// future.
func NewMsgTx(version int32) *MsgUTXO {
	return &MsgUTXO{
		Version: version,
		TxIn:    make([]*TxIn, 0, defaultTxInOutAlloc),
		TxOut:   make([]*TxOut, 0, defaultTxInOutAlloc),
	}
}

// Hash returns the hash of the transaction.  This is equivalent to
// calling TxHash on the underlying wire.MsgTx, however it caches the
// result so subsequent calls are more efficient.
func (t *UTXO) Hash() common.Hash {
	// Return the cached hash if it has already been generated.
	if (t.txHash != common.Hash{}) {
		return t.txHash
	}

	// Cache the hash and return it.
	hash := t.msgUTXO.TxHash()
	t.txHash = hash
	return hash
}

// MsgUTXO implements the Message interface and represents a bitcoin tx message.
// It is used to deliver transaction information in response to a getdata
// message (MsgGetData) for a given transaction.
//
// Use the AddTxIn and AddTxOut functions to build up the list of transaction
// inputs and outputs.
type MsgUTXO struct {
	Version  int32
	TxIn     []*TxIn
	TxOut    []*TxOut
	LockTime uint32
}

// AddTxIn adds a transaction input to the message.
func (msg *MsgUTXO) AddTxIn(ti *TxIn) {
	msg.TxIn = append(msg.TxIn, ti)
}

// AddTxOut adds a transaction output to the message.
func (msg *MsgUTXO) AddTxOut(to *TxOut) {
	msg.TxOut = append(msg.TxOut, to)
}

// TxHash generates the Hash for the transaction.
func (msg *MsgUTXO) TxHash() common.Hash {
	return prefixedRlpHash(3, msg)
}

// GetBlockTemplateResultTx models the transactions field of the
// getblocktemplate command.
type GetBlockTemplateResultTx struct {
	Data    string  `json:"data"`
	Hash    string  `json:"hash"`
	TxID    string  `json:"txid"`
	Depends []int64 `json:"depends"`
	Fee     int64   `json:"fee"`
	SigOps  int64   `json:"sigops"`
	Weight  int64   `json:"weight"`
}

// TxIn defines a bitcoin transaction input.
type TxIn struct {
	PreviousOutPoint OutPoint
	SignatureScript  []byte
	Witness          TxWitness
	Sequence         uint32
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
// 	buf = strconv.AppendUint(buf, uint64(o.Index), 10)
// 	return string(buf)
// }

// SerializeSize returns the number of bytes it would take to serialize the
// the transaction input.
// func (t *TxIn) SerializeSize() int {
// 	// Outpoint Hash 32 bytes + Outpoint Index 4 bytes + Sequence 4 bytes +
// 	// serialized varint size for the length of SignatureScript +
// 	// SignatureScript bytes.
// 	return 40 + VarIntSerializeSize(uint64(len(t.SignatureScript))) +
// 		len(t.SignatureScript)
// }

// NewTxIn returns a new bitcoin transaction input with the provided
// previous outpoint point and signature script with a default sequence of
// MaxTxInSequenceNum.
func NewTxIn(prevOut *OutPoint, signatureScript []byte, witness [][]byte) *TxIn {
	return &TxIn{
		PreviousOutPoint: *prevOut,
		SignatureScript:  signatureScript,
		Witness:          witness,
		// Sequence:         MaxTxInSequenceNum,
	}
}

// TxWitness defines the witness for a TxIn. A witness is to be interpreted as
// a slice of byte slices, or a stack with one or many elements.
type TxWitness [][]byte

// SerializeSize returns the number of bytes it would take to serialize the
// transaction input's witness.
// func (t TxWitness) SerializeSize() int {
// 	// A varint to signal the number of elements the witness has.
// 	n := VarIntSerializeSize(uint64(len(t)))

// 	// For each element in the witness, we'll need a varint to signal the
// 	// size of the element, then finally the number of bytes the element
// 	// itself comprises.
// 	for _, witItem := range t {
// 		n += VarIntSerializeSize(uint64(len(witItem)))
// 		n += len(witItem)
// 	}

// 	return n
// }

// TxOut defines a bitcoin transaction output.
type TxOut struct {
	Value    int64
	PkScript []byte
}

// SerializeSize returns the number of bytes it would take to serialize the
// the transaction output.
// func (t *TxOut) SerializeSize() int {
// 	// Value 8 bytes + serialized varint size for the length of PkScript +
// 	// PkScript bytes.
// 	return 8 + VarIntSerializeSize(uint64(len(t.PkScript))) + len(t.PkScript)
// }

// NewTxOut returns a new bitcoin transaction output with the provided
// transaction value and public key script.
func NewTxOut(value int64, pkScript []byte) *TxOut {
	return &TxOut{
		Value:    value,
		PkScript: pkScript,
	}
}
