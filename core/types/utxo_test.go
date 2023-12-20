package types

import (
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/dominant-strategies/go-quai/common"
	"github.com/dominant-strategies/go-quai/crypto"
)

func TestMakeAddress(t *testing.T) {

	// ECDSA key
	key, err := crypto.HexToECDSA("345debf66bc68724062b236d3b0a6eb30f051e725ebb770f1dc367f2c569f003")
	if err != nil {
		fmt.Println(err)
	}
	addr := crypto.PubkeyToAddress(key.PublicKey)
	fmt.Println(addr.Hex())

	b, err := hex.DecodeString("345debf66bc68724062b236d3b0a6eb30f051e725ebb770f1dc367f2c569f003")
	if err != nil {
		fmt.Println(err)
	}

	// btcec key for schnorr use
	btcecKey, _ := btcec.PrivKeyFromBytes(b)

	// Spendable out, could come from anywhere
	coinbaseOutput := &TxOut{
		Value:   10000000,
		Address: addr.Bytes(),
	}

	fmt.Println(coinbaseOutput)

	coinbaseBlockHash := common.HexToHash("00000000000000000000000000000000000000000000000000000")
	coinbaseIndex := uint32(0)

	// key = hash(blockHash, index)
	// Find hash / index for originUtxo / imagine this is block hash
	prevOut := *NewOutPoint(&coinbaseBlockHash, coinbaseIndex)

	in := &TxIn{
		PreviousOutPoint: prevOut,
		PubKey:           crypto.FromECDSAPub(&key.PublicKey),
	}

	newOut := &TxOut{
		Value: 10000000,
		// Value:    blockchain.CalcBlockSubsidy(nextBlockHeight, params),
		Address: addr.Bytes(),
	}

	utxo := &UtxoTx{
		TxIn:  []*TxIn{in},
		TxOut: []*TxOut{newOut},
	}

	tx := NewTx(utxo)

	// Need agg signature for all of the inputs
	sig, err := schnorr.Sign(btcecKey, tx.Hash().Bytes())
	if err != nil {
		fmt.Println(err)
	}

	txHash := tx.Hash()

	tx.UtxoSignatures()[0] = sig

	fmt.Println(txHash)
}
