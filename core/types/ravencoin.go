// Copyright 2017-2025 The go-quai Authors
// This file is part of the go-quai library.

package types

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"

	btcdutil "github.com/btcsuite/btcd/btcutil"
	btchash "github.com/btcsuite/btcd/chaincfg/chainhash"
	btcdwire "github.com/btcsuite/btcd/wire"
	"github.com/dominant-strategies/go-quai/common"
	ltcdwire "github.com/dominant-strategies/ltcd/wire"
)

type RavencoinBlockWrapper struct {
	BlockHeader  *RavencoinBlockHeader
	Transactions []*btcdwire.MsgTx
}

// RavencoinBlockHeader represents the Ravencoin KAWPOW block header structure
type RavencoinBlockHeader struct {
	// Standard Bitcoin-derived fields
	Version        int32       `json:"version"        gencodec:"required"`
	HashPrevBlock  common.Hash `json:"hashPrevBlock"  gencodec:"required"`
	HashMerkleRoot common.Hash `json:"hashMerkleRoot" gencodec:"required"`
	Time           uint32      `json:"time"           gencodec:"required"`
	Bits           uint32      `json:"bits"           gencodec:"required"`

	// KAWPOW-specific fields
	Height  uint32      `json:"height"   gencodec:"required"`
	Nonce64 uint64      `json:"nonce64"  gencodec:"required"`
	MixHash common.Hash `json:"mixHash"  gencodec:"required"`
}

// RavencoinKAWPOWInput represents the input structure for KAWPOW hashing
// This excludes nNonce64 and mixHash for header hash calculation
type RavencoinKAWPOWInput struct {
	Version        int32       `json:"version"        gencodec:"required"`
	HashPrevBlock  common.Hash `json:"hashPrevBlock"  gencodec:"required"`
	HashMerkleRoot common.Hash `json:"hashMerkleRoot" gencodec:"required"`
	Time           uint32      `json:"time"           gencodec:"required"`
	Bits           uint32      `json:"bits"           gencodec:"required"`
	Height         uint32      `json:"height"         gencodec:"required"`
}

type RavencoinAddress struct {
	Address btcdutil.Address
}

func NewRavencoinBlock(header *RavencoinBlockHeader) *RavencoinBlockWrapper {
	return &RavencoinBlockWrapper{BlockHeader: header}
}

func (rb *RavencoinBlockWrapper) Header() AuxHeaderData {
	return rb.BlockHeader
}

func (rb *RavencoinBlockWrapper) AddTransaction(tx *AuxPowTx) error {
	if tx == nil || tx.inner == nil {
		return fmt.Errorf("cannot add transaction: tx is nil")
	}

	switch inner := tx.inner.(type) {
	case *RavencoinTx:
		if inner.MsgTx == nil {
			return fmt.Errorf("cannot add transaction: underlying MsgTx is nil")
		}
		rb.Transactions = append(rb.Transactions, inner.MsgTx.Copy())
		return nil
	default:
		return fmt.Errorf("unsupported transaction type %T for Ravencoin block", inner)
	}
}

func (rb *RavencoinBlockWrapper) Copy() AuxPowBlockData {
	block := &RavencoinBlockWrapper{
		BlockHeader:  rb.BlockHeader,
		Transactions: make([]*btcdwire.MsgTx, len(rb.Transactions)),
	}

	for i, tx := range rb.Transactions {
		block.Transactions[i] = tx.Copy()
	}
	return block
}

func (rb *RavencoinBlockWrapper) Serialize(w io.Writer) error {
	if rb.BlockHeader == nil {
		return fmt.Errorf("cannot serialize Ravencoin block: header is nil")
	}
	if err := rb.BlockHeader.Serialize(w); err != nil {
		return err
	}

	// Write the number of transactions as a VarInt
	txCount := uint64(len(rb.Transactions))
	if err := btcdwire.WriteVarInt(w, 0, txCount); err != nil {
		return err
	}

	// Write each transaction
	for _, tx := range rb.Transactions {
		if err := tx.SerializeNoWitness(w); err != nil {
			return err
		}
	}

	return nil
}

// NewBlockHeader creates a new Ravencoin block header
func NewRavencoinBlockHeader(version int32, prevBlockHash [32]byte, merkleRootHash [32]byte, time uint32, bits uint32, height uint32) *RavencoinBlockHeader {
	return &RavencoinBlockHeader{
		Version:        version,
		HashPrevBlock:  common.BytesToHash(prevBlockHash[:]),
		HashMerkleRoot: common.BytesToHash(merkleRootHash[:]),
		Time:           time,
		Bits:           bits,
		Height:         height,
	}
}

// GetKAWPOWHeaderHash returns the header hash for KAWPOW input
// This excludes nNonce64 and mixHash, following Ravencoin's CKAWPOWInput
func (h *RavencoinBlockHeader) GetKAWPOWHeaderHash() common.Hash {
	input := RavencoinKAWPOWInput{
		Version:        h.Version,
		HashPrevBlock:  h.HashPrevBlock,
		HashMerkleRoot: h.HashMerkleRoot,
		Time:           h.Time,
		Bits:           h.Bits,
		Height:         h.Height,
	}

	// Serialize the input and calculate SHA256D (double SHA256)
	data := input.EncodeBinaryRavencoinKAWPOW()

	first := sha256.Sum256(data)
	second := sha256.Sum256(first[:])

	return common.BytesToHash(second[:])
}

// EncodeBinary encodes the header to Ravencoin's binary format
func (h *RavencoinBlockHeader) EncodeBinaryRavencoinHeader() []byte {
	var buf bytes.Buffer

	// KAWPOW block header format (120 bytes total)
	// Version (4 bytes, little endian)
	binary.Write(&buf, binary.LittleEndian, h.Version)

	// HashPrevBlock (32 bytes)
	buf.Write(h.HashPrevBlock.Bytes())

	// HashMerkleRoot (32 bytes)
	buf.Write(h.HashMerkleRoot.Bytes())

	// Time (4 bytes, little endian)
	binary.Write(&buf, binary.LittleEndian, h.Time)

	// Bits (4 bytes, little endian)
	binary.Write(&buf, binary.LittleEndian, h.Bits)

	// KAWPOW-specific fields
	// Height (4 bytes, little endian)
	binary.Write(&buf, binary.LittleEndian, h.Height)

	// Nonce64 (8 bytes, little endian)
	binary.Write(&buf, binary.LittleEndian, h.Nonce64)

	// MixHash (32 bytes)
	buf.Write(h.MixHash.Bytes())

	return buf.Bytes()
}

// DecodeRavencoinHeader decodes bytes into a RavencoinBlockHeader
func DecodeRavencoinHeader(data []byte) (*RavencoinBlockHeader, error) {
	if len(data) < 120 {
		return nil, fmt.Errorf("header data too short: %d bytes (minimum 120 for KAWPOW)", len(data))
	}

	h := &RavencoinBlockHeader{}
	buf := bytes.NewReader(data[:120]) // Read 120 bytes for KAWPOW header

	// Read version (4 bytes)
	if err := binary.Read(buf, binary.LittleEndian, &h.Version); err != nil {
		return nil, err
	}

	// Read hashPrevBlock (32 bytes)
	if _, err := io.ReadFull(buf, h.HashPrevBlock[:]); err != nil {
		return nil, err
	}

	// Read hashMerkleRoot (32 bytes)
	if _, err := io.ReadFull(buf, h.HashMerkleRoot[:]); err != nil {
		return nil, err
	}

	// Read time (4 bytes)
	if err := binary.Read(buf, binary.LittleEndian, &h.Time); err != nil {
		return nil, err
	}

	// Read bits (4 bytes)
	if err := binary.Read(buf, binary.LittleEndian, &h.Bits); err != nil {
		return nil, err
	}

	// Read KAWPOW-specific fields
	// Read height (4 bytes)
	if err := binary.Read(buf, binary.LittleEndian, &h.Height); err != nil {
		return nil, err
	}

	// Read nonce64 (8 bytes)
	if err := binary.Read(buf, binary.LittleEndian, &h.Nonce64); err != nil {
		return nil, err
	}

	// Read mixHash (32 bytes)
	if _, err := io.ReadFull(buf, h.MixHash[:]); err != nil {
		return nil, err
	}

	return h, nil
}

// EncodeBinary encodes the KAWPOW input structure (without nonce64 and mixHash)
func (input *RavencoinKAWPOWInput) EncodeBinaryRavencoinKAWPOW() []byte {
	var buf bytes.Buffer

	// Write version (4 bytes, little endian)
	binary.Write(&buf, binary.LittleEndian, input.Version)

	// Write hashPrevBlock (32 bytes)
	buf.Write(input.HashPrevBlock.Bytes())

	// Write hashMerkleRoot (32 bytes)
	buf.Write(input.HashMerkleRoot.Bytes())

	// Write time (4 bytes, little endian)
	binary.Write(&buf, binary.LittleEndian, input.Time)

	// Write bits (4 bytes, little endian)
	binary.Write(&buf, binary.LittleEndian, input.Bits)

	// Write height (4 bytes, little endian)
	binary.Write(&buf, binary.LittleEndian, input.Height)

	return buf.Bytes()
}

// String returns a string representation of the header
func (h *RavencoinBlockHeader) String() string {
	return fmt.Sprintf("RavencoinBlockHeader{Version: 0x%08x, HashPrevBlock: %s, HashMerkleRoot: %s, Time: %d, Bits: 0x%08x, Height: %d, Nonce64: 0x%016x, MixHash: %s}",
		h.Version,
		h.HashPrevBlock.Hex(),
		h.HashMerkleRoot.Hex(),
		h.Time,
		h.Bits,
		h.Height,
		h.Nonce64,
		h.MixHash.Hex(),
	)
}

// Size returns the size of the header in bytes
func (h *RavencoinBlockHeader) Size() int {
	// Base size: version(4) + hashPrevBlock(32) + hashMerkleRoot(32) + time(4) + bits(4)
	baseSize := 4 + 32 + 32 + 4 + 4

	// KAWPOW: height(4) + nonce64(8) + mixHash(32) = 44 bytes
	return baseSize + 44 // 76 + 44 = 120 bytes
}

func (h *RavencoinBlockHeader) PowHash() common.Hash {
	// PowHash for the kawpow cannot be calculated from the standard header alone
	return common.Hash{}
}

// Implement AuxHeaderData interface for RavencoinBlockHeader
func (h *RavencoinBlockHeader) Serialize(w io.Writer) error {
	data := h.EncodeBinaryRavencoinHeader()
	_, err := w.Write(data)
	return err
}

func (h *RavencoinBlockHeader) Deserialize(r io.Reader) error {
	data := make([]byte, 120)
	if _, err := io.ReadFull(r, data); err != nil {
		return err
	}
	decoded, err := DecodeRavencoinHeader(data)
	if err != nil {
		return err
	}
	*h = *decoded
	return nil
}

func (h *RavencoinBlockHeader) GetVersion() int32 {
	return h.Version
}

func (h *RavencoinBlockHeader) GetPrevBlock() [32]byte {
	var result [32]byte
	copy(result[:], h.HashPrevBlock[:])
	return result
}

func (h *RavencoinBlockHeader) GetMerkleRoot() [32]byte {
	var result [32]byte
	copy(result[:], h.HashMerkleRoot[:])
	return result
}

func (h *RavencoinBlockHeader) GetTimestamp() uint32 {
	return h.Time
}

func (h *RavencoinBlockHeader) GetBits() uint32 {
	return h.Bits
}

func (h *RavencoinBlockHeader) GetNonce() uint32 {
	// Standard 32-bit nonce is not used in KAWPOW
	return 0
}

func (h *RavencoinBlockHeader) GetNonce64() uint64 {
	return h.Nonce64
}

func (h *RavencoinBlockHeader) GetMixHash() common.Hash {
	return h.MixHash
}

func (h *RavencoinBlockHeader) GetHeight() uint32 {
	return h.Height
}

func (h *RavencoinBlockHeader) GetSealHash() common.Hash {
	// The seal hash is the KAWPOW header hash used for PoW
	return h.GetKAWPOWHeaderHash()
}

func (h *RavencoinBlockHeader) SetNonce(nonce uint32) {
	// Standard 32-bit nonce is not used in KAWPOW, so this is a no-op
}

func (h *RavencoinBlockHeader) SetNonce64(nonce uint64) {
	h.Nonce64 = nonce
}

func (h *RavencoinBlockHeader) SetMixHash(mixHash common.Hash) {
	h.MixHash = mixHash
}

func (h *RavencoinBlockHeader) SetHeight(height uint32) {
	h.Height = height
}

func (h *RavencoinBlockHeader) Copy() AuxHeaderData {
	copiedHeader := *h
	copiedHeader.Version = h.Version
	copiedHeader.HashPrevBlock = h.HashPrevBlock
	copiedHeader.HashMerkleRoot = h.HashMerkleRoot
	copiedHeader.Time = h.Time
	copiedHeader.Bits = h.Bits
	copiedHeader.Nonce64 = h.Nonce64
	copiedHeader.MixHash = h.MixHash
	copiedHeader.Height = h.Height
	return &copiedHeader
}

type RavencoinTx struct {
	*btcdwire.MsgTx
}

func NewRavencoinCoinbaseTx(height uint32, coinbaseOut []byte, sealHash common.Hash, signatureTime uint32, witness bool) []byte {
	coinbaseTx := &RavencoinTx{MsgTx: btcdwire.NewMsgTx(2)} // Version 2 for Ravencoin

	// Create the coinbase input with seal hash
	scriptSig := BuildCoinbaseScriptSigWithNonce(height, 0, 0, sealHash, 1, signatureTime)
	coinbaseIn := &btcdwire.TxIn{
		PreviousOutPoint: btcdwire.OutPoint{
			Hash:  btchash.Hash{}, // Coinbase has no previous output
			Index: 0xffffffff,     // Coinbase has no previous output
		},
		SignatureScript: scriptSig,
		Sequence:        0xffffffff,
	}
	coinbaseTx.AddTxIn(coinbaseIn)

	var buffer bytes.Buffer
	if witness {
		coinbaseTx.Serialize(&buffer)
	} else {
		coinbaseTx.SerializeNoWitness(&buffer)
	}

	// Since the emtpty serialization of the coinbase transaction adds 5 bytes at the end,
	// we need to trim these before appending the coinbaseOut
	raw := buffer.Bytes()
	if len(raw) < 5 {
		return append([]byte{}, coinbaseOut...)
	}
	trimmed := append([]byte{}, raw[:len(raw)-5]...)
	return append(trimmed, coinbaseOut...)
}

func (rct *RavencoinTx) Copy() AuxPowTxData {
	return &RavencoinTx{MsgTx: rct.MsgTx.Copy()}
}

func (rct *RavencoinTx) scriptSig() []byte {
	if rct.MsgTx == nil || len(rct.MsgTx.TxIn) == 0 {
		return nil
	}
	return rct.MsgTx.TxIn[0].SignatureScript
}

func (rct *RavencoinTx) value() int64 {
	var totalValue int64
	for _, txOut := range rct.MsgTx.TxOut {
		totalValue += txOut.Value
	}
	return totalValue
}

func (rct *RavencoinTx) version() int32 {
	if rct.MsgTx == nil {
		return 0
	}
	return rct.MsgTx.Version
}

// txHash returns the little endian hash of the transaction
func (rct *RavencoinTx) txHash() [32]byte {
	if rct.MsgTx == nil {
		return [32]byte{}
	}
	return rct.MsgTx.TxHash()
}

func (rct *RavencoinTx) pkScript() []byte {
	if rct.MsgTx == nil || len(rct.MsgTx.TxOut) == 0 {
		return nil
	}
	return rct.MsgTx.TxOut[0].PkScript
}

func (rct *RavencoinTx) txOut() []*AuxPowCoinbaseOut {
	if rct.MsgTx == nil {
		return nil
	}
	txOuts := make([]*AuxPowCoinbaseOut, 0, len(rct.MsgTx.TxOut))
	for _, txOut := range rct.MsgTx.TxOut {
		txOuts = append(txOuts, &AuxPowCoinbaseOut{NewRavencoinCoinbaseTxOut(txOut.Value, txOut.PkScript)})
	}
	return txOuts
}

func (rct *RavencoinTx) Serialize(w io.Writer) error {
	if rct.MsgTx == nil {
		return fmt.Errorf("cannot serialize: MsgTx is nil")
	}
	return rct.MsgTx.Serialize(w)
}

func (rct *RavencoinTx) Deserialize(r io.Reader) error {
	if rct.MsgTx == nil {
		return fmt.Errorf("cannot deserialize: MsgTx is nil")
	}
	return rct.MsgTx.Deserialize(r)
}

func (rct *RavencoinTx) DeserializeNoWitness(r io.Reader) error {
	if rct.MsgTx == nil {
		return fmt.Errorf("cannot deserialize: MsgTx is nil")
	}
	return rct.MsgTx.DeserializeNoWitness(r)
}

type RavencoinCoinbaseTxOut struct {
	*btcdwire.TxOut
}

func NewRavencoinCoinbaseTxOut(value int64, pkScript []byte) *RavencoinCoinbaseTxOut {
	return &RavencoinCoinbaseTxOut{TxOut: &btcdwire.TxOut{Value: value, PkScript: pkScript}}
}

// Value implements AuxPowCoinbaseOutData interface
func (rco *RavencoinCoinbaseTxOut) Value() int64 {
	return rco.TxOut.Value
}

// PkScript implements AuxPowCoinbaseOutData interface
func (rco *RavencoinCoinbaseTxOut) PkScript() []byte {
	return rco.TxOut.PkScript
}

// MWEB methods - Ravencoin does not support MWEB, so these return errors
func (rb *RavencoinBlockWrapper) SetMwebBlock(header *ltcdwire.MwebHeader, txBody *ltcdwire.MwebTxBody) error {
	return fmt.Errorf("mweb is not supported by ravencoin blocks")
}
