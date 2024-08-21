package core

import (
	"context"
	"fmt"
	"math/big"
	"testing"

	interfaces "github.com/dominant-strategies/go-quai"
	"github.com/dominant-strategies/go-quai/common"
	"github.com/dominant-strategies/go-quai/core/types"
	"github.com/dominant-strategies/go-quai/crypto"
	"github.com/dominant-strategies/go-quai/params"
	"github.com/dominant-strategies/go-quai/quaiclient/ethclient"
)

func TestSuicideTx(t *testing.T) {
	signer := types.LatestSigner(params.Blake3PowLocalChainConfig)
	client, err := ethclient.Dial(rpcUrl)
	if err != nil {
		t.Fatalf("Failed to connect to the Ethereum WebSocket client: %v", err)
	}
	from := common.HexToAddress("0x002a8cf994379232561556Da89C148eeec9539cd", nodeLocation)
	fromPrivKey, err := crypto.ToECDSA(common.FromHex("0xefdc32bef4218d3e5bae3858e45d4f18ed257c617bd8b7bae0939fae6f6bd6d6"))
	if err != nil {
		t.Log(err)
		return
	}
	block, err := client.BlockByNumber(context.Background(), nil)
	if err != nil {
		fmt.Println(err.Error())
		return
	}
	fmt.Println("State size1: ", block.Body().Header().QuaiStateSize())
	nonce, err := client.PendingNonceAt(context.Background(), common.NewMixedcaseAddress(from))
	if err != nil {
		t.Error(err.Error())
		t.Fail()
		return
	}
	balance, err := client.BalanceAt(context.Background(), from.MixedcaseAddress(), nil)
	if err != nil {
		fmt.Println(err.Error())
		return
	}
	beneficiary := common.HexToAddress("0x0000442019A336Ef82C5E56f4c9Bd7BD86F603a0", nodeLocation)
	data := append([]byte("Suicide"), beneficiary.Bytes()...)
	gas, err := client.EstimateGas(context.Background(), interfaces.CallMsg{From: from, To: &from, Gas: 0, Value: common.Big0, Data: data})
	if err != nil {
		fmt.Println(err.Error())
		return
	}
	fmt.Println("gas: ", gas)
	fmt.Println("Balance: ", balance)
	fmt.Println("Nonce: ", nonce)
	inner_tx := types.QuaiTx{ChainID: params.Blake3PowLocalChainConfig.ChainID, Nonce: nonce, GasTipCap: big.NewInt(1 * params.GWei), GasFeeCap: big.NewInt(1 * params.GWei), Gas: gas, To: &from, Value: common.Big0, Data: data, AccessList: types.AccessList{}}
	tx, err := types.SignTx(types.NewTx(&inner_tx), signer, fromPrivKey)
	if err != nil {
		t.Error(err.Error())
		t.Fail()
		return
	}
	if err := client.SendTransaction(context.Background(), tx); err != nil {
		t.Log(err)
		return
	}
	balance, err = client.BalanceAt(context.Background(), from.MixedcaseAddress(), nil)
	if err != nil {
		fmt.Println(err.Error())
		return
	}
	fmt.Println("Balance2: ", balance)
	balance, err = client.BalanceAt(context.Background(), beneficiary.MixedcaseAddress(), nil)
	if err != nil {
		fmt.Println(err.Error())
		return
	}
	fmt.Println("Beneficiary balance: ", balance)
	block, err = client.BlockByNumber(context.Background(), nil)
	if err != nil {
		fmt.Println(err.Error())
		return
	}
	fmt.Println("State size2: ", block.Body().Header().QuaiStateSize())
}
