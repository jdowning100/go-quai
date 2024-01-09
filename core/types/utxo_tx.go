package types

import (
	"math/big"

	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/dominant-strategies/go-quai/common"
)

type UtxoTx struct {
	ChainID *big.Int // replay protection
	TxIn    []TxIn
	TxOut   []TxOut

	Signature *schnorr.Signature
}

type WireUtxoTx struct {
	ChainID   *big.Int // replay protection
	TxIn      []TxIn
	TxOut     []TxOut
	Signature []byte
}

type UtxoTxWithMinerFee struct {
	Tx       *Transaction
	Fee      uint64
	FeePerKB uint64
}

// copy creates a deep copy of the transaction data and initializes all fields.
func (tx *UtxoTx) copy() TxData {
	cpy := &UtxoTx{
		ChainID: new(big.Int),
	}
	if tx.ChainID != nil {
		cpy.ChainID.Set(tx.ChainID)
	}

	cpy.TxIn = make([]TxIn, len(tx.TxIn))
	cpy.TxOut = make([]TxOut, len(tx.TxOut))
	if tx.Signature != nil {
		cpy.Signature, _ = schnorr.ParseSignature(tx.Signature.Serialize()) // optional: fatal if error is not nil
	} else {
		cpy.Signature = new(schnorr.Signature)
	}
	copy(cpy.TxIn, tx.TxIn)
	copy(cpy.TxOut, tx.TxOut)
	return cpy
}

func (tx *UtxoTx) copyToWire() *WireUtxoTx {
	cpy := &WireUtxoTx{
		ChainID:   new(big.Int),
		Signature: make([]byte, 64),
	}
	if tx.ChainID != nil {
		cpy.ChainID.Set(tx.ChainID)
	}

	cpy.TxIn = make([]TxIn, len(tx.TxIn))
	cpy.TxOut = make([]TxOut, len(tx.TxOut))
	if tx.Signature != nil {
		copy(cpy.Signature, tx.Signature.Serialize())
	} else {
		copy(cpy.Signature, make([]byte, 64))
	}
	copy(cpy.TxIn, tx.TxIn)
	copy(cpy.TxOut, tx.TxOut)
	return cpy
}

func (tx *WireUtxoTx) copyFromWire() *UtxoTx {
	cpy := &UtxoTx{
		ChainID: new(big.Int),
	}
	if tx.ChainID != nil {
		cpy.ChainID.Set(tx.ChainID)
	}

	cpy.TxIn = make([]TxIn, len(tx.TxIn))
	cpy.TxOut = make([]TxOut, len(tx.TxOut))
	if tx.Signature != nil {
		cpy.Signature, _ = schnorr.ParseSignature(tx.Signature) // optional: fatal if error is not nil
	} else {
		cpy.Signature = new(schnorr.Signature)
	}
	copy(cpy.TxIn, tx.TxIn)
	copy(cpy.TxOut, tx.TxOut)
	return cpy
}

// accessors for innerTx.
func (tx *UtxoTx) txType() byte                      { return UtxoTxType }
func (tx *UtxoTx) chainID() *big.Int                 { return tx.ChainID }
func (tx *UtxoTx) protected() bool                   { return true }
func (tx *UtxoTx) accessList() AccessList            { panic("UTXO TX does not have accessList") }
func (tx *UtxoTx) data() []byte                      { panic("UTXO TX does not have data") }
func (tx *UtxoTx) gas() uint64                       { panic("UTXO TX does not have gas") }
func (tx *UtxoTx) gasFeeCap() *big.Int               { panic("UTXO TX does not have gasFeeCap") }
func (tx *UtxoTx) gasTipCap() *big.Int               { panic("UTXO TX does not have gasTipCap") }
func (tx *UtxoTx) gasPrice() *big.Int                { panic("UTXO TX does not have gasPrice") }
func (tx *UtxoTx) value() *big.Int                   { panic("UTXO TX does not have value") }
func (tx *UtxoTx) nonce() uint64                     { panic("UTXO TX does not have nonce") }
func (tx *UtxoTx) to() *common.Address               { panic("UTXO TX does not have to") }
func (tx *UtxoTx) etxGasLimit() uint64               { panic("internal TX does not have etxGasLimit") }
func (tx *UtxoTx) etxGasPrice() *big.Int             { panic("internal TX does not have etxGasPrice") }
func (tx *UtxoTx) etxGasTip() *big.Int               { panic("internal TX does not have etxGasTip") }
func (tx *UtxoTx) etxData() []byte                   { panic("internal TX does not have etxData") }
func (tx *UtxoTx) etxAccessList() AccessList         { panic("internal TX does not have etxAccessList") }
func (tx *UtxoTx) txIn() []TxIn                      { return tx.TxIn }
func (tx *UtxoTx) txOut() []TxOut                    { return tx.TxOut }
func (tx *UtxoTx) utxoSignature() *schnorr.Signature { return tx.Signature }

func (tx *UtxoTx) rawSignatureValues() (v, r, s *big.Int) {
	panic("UTXO TX does not have raw signature values")
}

func (tx *UtxoTx) setSignatureValues(chainID, v, r, s *big.Int) {
	panic("UTXO TX does not have set signature values")
}
