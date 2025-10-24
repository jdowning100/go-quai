package types

import (
	"errors"
	"io"

	"github.com/dominant-strategies/go-quai/common"
	bchhash "github.com/gcash/bchd/chaincfg/chainhash"
	bchdwire "github.com/gcash/bchd/wire"
)

type BitcoinCashBlockWrapper struct {
	Block *bchdwire.MsgBlock
}

// BitcoinCashHeaderWrapper wraps bchdwire.BlockHeader to implement AuxHeaderData
type BitcoinCashHeaderWrapper struct {
	*bchdwire.BlockHeader
}

type BitcoinCashTxWrapper struct {
	*bchdwire.MsgTx
}

type BitcoinCashCoinbaseTxOutWrapper struct {
	*bchdwire.TxOut
}

func NewBitcoinCashBlockWrapper(header *bchdwire.BlockHeader) *BitcoinCashBlockWrapper {
	return &BitcoinCashBlockWrapper{&bchdwire.MsgBlock{Header: *header}}
}

func NewBitcoinCashHeaderWrapper(header *bchdwire.BlockHeader) *BitcoinCashHeaderWrapper {
	return &BitcoinCashHeaderWrapper{BlockHeader: header}
}

func NewBitcoinCashCoinbaseTxOut(value int64, pkScript []byte) *BitcoinCashCoinbaseTxOutWrapper {
	return &BitcoinCashCoinbaseTxOutWrapper{TxOut: &bchdwire.TxOut{Value: value, PkScript: pkScript}}
}

func (bcb *BitcoinCashBlockWrapper) Header() AuxHeaderData {
	if bcb.Block == nil {
		return &BitcoinCashHeaderWrapper{}
	}
	return &BitcoinCashHeaderWrapper{BlockHeader: &bcb.Block.Header}
}

func (bcb *BitcoinCashBlockWrapper) Serialize(w io.Writer) error {
	return bcb.Block.Serialize(w)
}

func (bcb *BitcoinCashBlockWrapper) Copy() AuxPowBlockData {

	copyBlock := &bchdwire.MsgBlock{
		Header:       bcb.Block.Header,
		Transactions: make([]*bchdwire.MsgTx, len(bcb.Block.Transactions)),
	}

	for i, tx := range bcb.Block.Transactions {
		if tx == nil {
			continue
		}
		copyBlock.Transactions[i] = tx.Copy()
	}

	return &BitcoinCashBlockWrapper{copyBlock}
}

func (bcb *BitcoinCashBlockWrapper) AddTransaction(tx *AuxPowTx) error {
	if tx == nil || tx.inner == nil {
		return errors.New("cannot add transaction: tx is nil")
	}

	switch inner := tx.inner.(type) {
	case *BitcoinCashTxWrapper:
		if inner.MsgTx == nil {
			return errors.New("cannot add transaction: underlying MsgTx is nil")
		}
		if bcb.Block == nil {
			return errors.New("cannot add transaction: block is nil")
		}
		return bcb.Block.AddTransaction(inner.MsgTx.Copy())
	default:
		return errors.New("unsupported transaction type for Bitcoin Cash block")
	}
}

func NewBitcoinCashBlockHeader(version int32, prevBlockHash [32]byte, merkleRootHash [32]byte, time uint32, bits uint32, nonce uint32) *BitcoinCashHeaderWrapper {
	prevHash := bchhash.Hash{}
	copy(prevHash[:], prevBlockHash[:])
	merkleRoot := bchhash.Hash{}
	copy(merkleRoot[:], merkleRootHash[:])
	header := bchdwire.NewBlockHeader(version, &prevHash, &merkleRoot, bits, nonce)
	return &BitcoinCashHeaderWrapper{BlockHeader: header}
}

func (bch *BitcoinCashHeaderWrapper) PowHash() common.Hash {
	blockHash := bch.BlockHeader.BlockHash()
	return common.BytesToHash(reverseBytesCopy(blockHash[:]))
}

func (bch *BitcoinCashHeaderWrapper) Serialize(wr io.Writer) error {
	return bch.BlockHeader.Serialize(wr)
}

func (bch *BitcoinCashHeaderWrapper) Deserialize(r io.Reader) error {
	bch.BlockHeader = &bchdwire.BlockHeader{}
	return bch.BlockHeader.Deserialize(r)
}

func (bch *BitcoinCashHeaderWrapper) GetVersion() int32 {
	return bch.BlockHeader.Version
}

func (bch *BitcoinCashHeaderWrapper) GetPrevBlock() [32]byte {
	return [32]byte(bch.BlockHeader.PrevBlock)
}

func (bch *BitcoinCashHeaderWrapper) GetMerkleRoot() [32]byte {
	return [32]byte(bch.BlockHeader.MerkleRoot)
}

func (bch *BitcoinCashHeaderWrapper) GetTimestamp() uint32 {
	return uint32(bch.BlockHeader.Timestamp.Unix())
}

func (bch *BitcoinCashHeaderWrapper) GetBits() uint32 {
	return bch.BlockHeader.Bits
}

func (bch *BitcoinCashHeaderWrapper) GetNonce() uint32 {
	return bch.BlockHeader.Nonce
}

func (bch *BitcoinCashHeaderWrapper) GetNonce64() uint64 {
	// Standard Bitcoin Cash headers don't have a 64-bit nonce
	return 0
}

func (bch *BitcoinCashHeaderWrapper) GetMixHash() common.Hash {
	// Standard Bitcoin Cash headers don't have a mix hash
	return common.Hash{}
}

func (bch *BitcoinCashHeaderWrapper) GetHeight() uint32 {
	// Standard Bitcoin Cash headers don't include height
	return 0
}

func (bch *BitcoinCashHeaderWrapper) GetSealHash() common.Hash {
	// Standard Bitcoin Cash headers don't have a seal hash
	return common.Hash{}
}

func (bch *BitcoinCashHeaderWrapper) SetNonce(nonce uint32) {
	bch.BlockHeader.Nonce = nonce
}

func (bch *BitcoinCashHeaderWrapper) SetNonce64(nonce uint64) {
	// Standard Bitcoin Cash headers don't have a 64-bit nonce, so this is a no-op
}

func (bch *BitcoinCashHeaderWrapper) SetMixHash(mixHash common.Hash) {
	// Standard Bitcoin Cash headers don't have a mix hash, so this is a no-op
}

func (bch *BitcoinCashHeaderWrapper) SetHeight(height uint32) {
	// Standard Bitcoin Cash headers don't have a height, so this is a no-op
}

func (bch *BitcoinCashHeaderWrapper) Copy() AuxHeaderData {
	copiedHeader := *bch.BlockHeader
	copiedHeader.Version = bch.BlockHeader.Version
	copiedHeader.PrevBlock = bch.BlockHeader.PrevBlock
	copiedHeader.MerkleRoot = bch.BlockHeader.MerkleRoot
	copiedHeader.Timestamp = bch.BlockHeader.Timestamp
	copiedHeader.Bits = bch.BlockHeader.Bits
	copiedHeader.Nonce = bch.BlockHeader.Nonce
	return &BitcoinCashHeaderWrapper{BlockHeader: &copiedHeader}
}

func NewBitcoinCashCoinbaseTxWrapper(height uint32, coinbaseOut *AuxPowCoinbaseOut, sealHash common.Hash) *BitcoinCashTxWrapper {
	coinbaseTx := &BitcoinCashTxWrapper{MsgTx: bchdwire.NewMsgTx(2)}

	// Create the coinbase input with seal hash in scriptSig
	scriptSig := BuildCoinbaseScriptSigWithNonce(height, 0, 0, sealHash)
	coinbaseTx.AddTxIn(&bchdwire.TxIn{
		PreviousOutPoint: bchdwire.OutPoint{
			Hash:  bchhash.Hash{}, // Coinbase has no previous output
			Index: 0xffffffff,     // Coinbase has no previous output
		},
		SignatureScript: scriptSig,
		Sequence:        0xffffffff,
	})

	// Add the coinbase output
	if coinbaseOut != nil {
		value := coinbaseOut.Value()
		pkScript := coinbaseOut.PkScript()
		txOut := NewBitcoinCashCoinbaseTxOut(value, pkScript)
		coinbaseTx.AddTxOut(txOut.TxOut)
	}

	return coinbaseTx
}

func (bct *BitcoinCashTxWrapper) Copy() AuxPowTxData {
	return &BitcoinCashTxWrapper{MsgTx: bct.MsgTx.Copy()}
}

func (bct *BitcoinCashTxWrapper) scriptSig() []byte {
	if bct.MsgTx == nil || len(bct.MsgTx.TxIn) == 0 {
		return nil
	}
	return bct.MsgTx.TxIn[0].SignatureScript
}

func (bct *BitcoinCashTxWrapper) value() int64 {
	var totalValue int64
	for _, txOut := range bct.MsgTx.TxOut {
		totalValue += txOut.Value
	}
	return totalValue
}

func (bct *BitcoinCashTxWrapper) version() int32 {
	if bct.MsgTx == nil {
		return 0
	}
	return bct.MsgTx.Version
}

// txHash returns the little endian hash of the transaction
func (bct *BitcoinCashTxWrapper) txHash() [32]byte {
	if bct.MsgTx == nil {
		return [32]byte{}
	}
	return bct.MsgTx.TxHash()
}

func (bct *BitcoinCashTxWrapper) pkScript() []byte {
	if bct.MsgTx == nil || len(bct.MsgTx.TxOut) == 0 {
		return nil
	}
	return bct.MsgTx.TxOut[0].PkScript
}

func (bct *BitcoinCashTxWrapper) Serialize(w io.Writer) error {
	if bct.MsgTx == nil {
		return errors.New("cannot serialize: MsgTx is nil")
	}
	return bct.MsgTx.Serialize(w)
}

func (bct *BitcoinCashTxWrapper) Deserialize(r io.Reader) error {
	if bct.MsgTx == nil {
		return errors.New("cannot deserialize: MsgTx is nil")
	}
	return bct.MsgTx.Deserialize(r)
}

func (bct *BitcoinCashTxWrapper) DeserializeNoWitness(r io.Reader) error {
	if bct.MsgTx == nil {
		return errors.New("cannot deserialize: MsgTx is nil")
	}
	// Bitcoin Cash doesn't use SegWit, so Deserialize is the same as DeserializeNoWitness
	return bct.MsgTx.Deserialize(r)
}

func (bco *BitcoinCashCoinbaseTxOutWrapper) Value() int64 {
	return bco.TxOut.Value
}

func (bco *BitcoinCashCoinbaseTxOutWrapper) PkScript() []byte {
	return bco.TxOut.PkScript
}
