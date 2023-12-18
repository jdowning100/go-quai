package types

import (
	"math/big"

	"github.com/dominant-strategies/go-quai/common"
)

type UtxoTx struct {
	ChainID *big.Int // replay protection
	TxIn    []*TxIn
	TxOut   []*TxOut
	// Signature values
	V *big.Int `json:"v" gencodec:"required"`
	R *big.Int `json:"r" gencodec:"required"`
	S *big.Int `json:"s" gencodec:"required"`
}

// copy creates a deep copy of the transaction data and initializes all fields.
func (tx *UtxoTx) copy() TxData {
	cpy := &UtxoTx{
		ChainID: new(big.Int),
		V:       new(big.Int),
		R:       new(big.Int),
		S:       new(big.Int),
	}
	if tx.ChainID != nil {
		cpy.ChainID.Set(tx.ChainID)
	}
	if tx.V != nil {
		cpy.V.Set(tx.V)
	}
	if tx.R != nil {
		cpy.R.Set(tx.R)
	}
	if tx.S != nil {
		cpy.S.Set(tx.S)
	}
	cpy.TxIn = make([]*TxIn, len(tx.TxIn))
	cpy.TxOut = make([]*TxOut, len(tx.TxOut))
	copy(cpy.TxIn, tx.TxIn)
	copy(cpy.TxOut, tx.TxOut)
	return cpy
}

// accessors for innerTx.
func (tx *UtxoTx) txType() byte              { return UtxoTxType }
func (tx *UtxoTx) chainID() *big.Int         { return tx.ChainID }
func (tx *UtxoTx) protected() bool           { return true }
func (tx *UtxoTx) accessList() AccessList    { panic("UTXO TX does not have accessList") }
func (tx *UtxoTx) data() []byte              { panic("UTXO TX does not have data") }
func (tx *UtxoTx) gas() uint64               { panic("UTXO TX does not have gas") }
func (tx *UtxoTx) gasFeeCap() *big.Int       { panic("UTXO TX does not have gasFeeCap") }
func (tx *UtxoTx) gasTipCap() *big.Int       { panic("UTXO TX does not have gasTipCap") }
func (tx *UtxoTx) gasPrice() *big.Int        { panic("UTXO TX does not have gasPrice") }
func (tx *UtxoTx) value() *big.Int           { panic("UTXO TX does not have value") }
func (tx *UtxoTx) nonce() uint64             { panic("UTXO TX does not have nonce") }
func (tx *UtxoTx) to() *common.Address       { panic("UTXO TX does not have to") }
func (tx *UtxoTx) etxGasLimit() uint64       { panic("internal TX does not have etxGasLimit") }
func (tx *UtxoTx) etxGasPrice() *big.Int     { panic("internal TX does not have etxGasPrice") }
func (tx *UtxoTx) etxGasTip() *big.Int       { panic("internal TX does not have etxGasTip") }
func (tx *UtxoTx) etxData() []byte           { panic("internal TX does not have etxData") }
func (tx *UtxoTx) etxAccessList() AccessList { panic("internal TX does not have etxAccessList") }
func (tx *UtxoTx) txIn() []*TxIn             { return tx.TxIn }
func (tx *UtxoTx) txOut() []*TxOut           { return tx.TxOut }

func (tx *UtxoTx) rawSignatureValues() (v, r, s *big.Int) {
	return tx.V, tx.R, tx.S
}

func (tx *UtxoTx) setSignatureValues(chainID, v, r, s *big.Int) {
	tx.ChainID, tx.V, tx.R, tx.S = chainID, v, r, s
}
