package quaiclient

import (
	"context"
	"encoding/hex"
	"fmt"
	"math/big"
	"testing"

	"github.com/dominant-strategies/go-quai/common"
	"github.com/dominant-strategies/go-quai/core/types"
	"github.com/dominant-strategies/go-quai/crypto"
	"github.com/dominant-strategies/go-quai/params"
	"github.com/dominant-strategies/go-quai/quaiclient/ethclient"
	"github.com/holiman/uint256"
)

const (
	wsUrl_ = "ws://127.0.0.1:8200"
)

var (
	quaiGenAllocAddr1    = "0x0003590fc75D4136Fd78CCf325764E51df61b282"
	quaiGenAllocPrivKey1 = "0x65170b303462e72db2923146ebe933faa77a7f1d53a199c2ab30815aad708f1c"
	quaiGenAllocAddr2    = "0x003B3DBe0275aF66aB64D6b1905BCf876445bd7b"
	quaiGenAllocPrivKey2 = "0x72547e1254df3971eb1be4c3da7b1c63bf493cdd077eda0c60e7fad10b328fe1"
	location             = common.Location{0, 0}
	binary               = "608060405234801561001057600080fd5b5033600160006101000a81548173ffffffffffffffffffffffffffffffffffffffff021916908373ffffffffffffffffffffffffffffffffffffffff1602179055506103cb806100616000396000f3fe608060405234801561001057600080fd5b506004361061007d5760003560e01c806357e871e71161005b57806357e871e7146100c65780638da5cb5b146100e4578063ba7b37d414610102578063c96cd46f1461011e5761007d565b80631b6a24811461008257806327e235e31461008c5780634243911d146100bc575b600080fd5b61008a610128565b005b6100a660048036038101906100a1919061029f565b610131565b6040516100b391906102e5565b60405180910390f35b6100c4610149565b005b6100ce61018e565b6040516100db91906102e5565b60405180910390f35b6100ec610194565b6040516100f99190610321565b60405180910390f35b61011c60048036038101906101179190610368565b6101ba565b005b610126610201565b005b43600081905550565b60026020528060005260406000206000915090505481565b600260003373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060009055565b60005481565b600160009054906101000a900473ffffffffffffffffffffffffffffffffffffffff1681565b80600260003373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020019081526020016000208190555050565b600160009054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16ff5b600080fd5b600073ffffffffffffffffffffffffffffffffffffffff82169050919050565b600061026c82610241565b9050919050565b61027c81610261565b811461028757600080fd5b50565b60008135905061029981610273565b92915050565b6000602082840312156102b5576102b461023c565b5b60006102c38482850161028a565b91505092915050565b6000819050919050565b6102df816102cc565b82525050565b60006020820190506102fa60008301846102d6565b92915050565b600061030b82610241565b9050919050565b61031b81610300565b82525050565b60006020820190506103366000830184610312565b92915050565b610345816102cc565b811461035057600080fd5b50565b6000813590506103628161033c565b92915050565b60006020828403121561037e5761037d61023c565b5b600061038c84828501610353565b9150509291505056fea26469706673582212207782c1e83da0d053b8e41e7f8e0667f7d91adbd62d8fc48835895c48c3c057e464736f6c63430008130033"
	MAXFEE               = big.NewInt(1 * params.GWei)
	BASEFEE              = MAXFEE
	MINERTIP             = big.NewInt(1 * params.GWei)
	// Change the params to the proper chain config
	PARAMS = params.Blake3PowLocalChainConfig
)

func TestSmartContract(t *testing.T) {

	client, err := ethclient.Dial(wsUrl_)
	if err != nil {
		t.Fatalf("Failed to connect to the Ethereum WebSocket client: %v", err)
	}
	defer client.Close()
	fromAddress1 := common.HexToAddress(quaiGenAllocAddr1, location)
	privKey1, err := crypto.ToECDSA(common.FromHex(quaiGenAllocPrivKey1))
	if err != nil {
		t.Fatalf("Failed to convert private key to ECDSA: %v", err)
	}
	from := crypto.PubkeyToAddress(privKey1.PublicKey, location)
	if !from.Equal(fromAddress1) {
		t.Fatalf("Failed to convert public key to address: %v", err)
	}
	fromAddress2 := common.HexToAddress(quaiGenAllocAddr2, location)
	privKey2, err := crypto.ToECDSA(common.FromHex(quaiGenAllocPrivKey2))
	if err != nil {
		t.Fatalf("Failed to convert private key to ECDSA: %v", err)
	}
	from = crypto.PubkeyToAddress(privKey2.PublicKey, location)
	if !from.Equal(fromAddress2) {
		t.Fatalf("Failed to convert public key to address: %v", err)
	}
	// Check balance
	balance, err := client.BalanceAt(context.Background(), fromAddress1.MixedcaseAddress(), nil)
	if err != nil {
		fmt.Println(err.Error())
		return
	}
	nonce, err := client.PendingNonceAt(context.Background(), fromAddress1.MixedcaseAddress())
	if err != nil {
		fmt.Println(err.Error())
		return
	}
	fmt.Printf("Balance of %s: %s nonce: %d\n", fromAddress1.String(), balance.String(), nonce)

	// Deploy QXC contract with the proper address that gives me tokens in zone 0-0
	contract, err := hex.DecodeString(binary)
	if err != nil {
		fmt.Println(err.Error())
		return
	}
	i := uint8(0)
	j := uint8(0)
	contract = append(contract, i)
	contract = append(contract, j)
	var contractAddr common.Address
	// Grind contract address
grind:
	for {
		contract[len(contract)-2] = i
		for j = 0; j < 255; j++ {
			contract[len(contract)-1] = j
			contractAddr = crypto.CreateAddress(fromAddress1, nonce, contract, location)
			if common.IsInChainScope(contractAddr.Bytes(), location) && contractAddr.IsInQuaiLedgerScope() {
				break grind
			}
		}
		i++
	}
	fmt.Println("Contract address: ", contractAddr.String())
	fmt.Println("Took ", (i+1)*(j+1), " iterations to find contract address")
	signer := types.LatestSigner(PARAMS)
	// Construct deployment tx
	inner_tx := types.QuaiTx{ChainID: params.Blake3PowLocalChainConfig.ChainID, Nonce: nonce, GasTipCap: big.NewInt(1 * params.GWei), GasFeeCap: big.NewInt(1 * params.GWei), Gas: 30000000, To: nil, Value: common.Big0, Data: contract, AccessList: types.AccessList{}}
	tx, err := types.SignTx(types.NewTx(&inner_tx), signer, privKey1)
	if err != nil {
		t.Error(err.Error())
		t.Fail()
		return
	}

	err = client.SendTransaction(context.Background(), tx)
	if err != nil {
		fmt.Println(err.Error())
		return
	}
	fmt.Println("tx: ", tx.Hash().String())
	//time.Sleep(5 * time.Second) // Wait for it to be mined
	tx, isPending, err := client.TransactionByHash(context.Background(), tx.Hash())
	fmt.Printf("tx: %+v isPending: %v err: %v\n", tx, isPending, err)
	receipt, err := client.TransactionReceipt(context.Background(), tx.Hash())
	if err != nil {
		fmt.Println(err.Error())
		return
	}
	fmt.Printf("Receipt: %+v\n", receipt)
	contractAddr = receipt.ContractAddress

	currentBlockNumber, err := client.BlockNumber(context.Background())
	if err != nil {
		fmt.Println(err.Error())
		return
	}
	// Check contract size
	contractSize, err := client.ContractSizeAt(context.Background(), contractAddr.MixedcaseAddress(), big.NewInt(int64(currentBlockNumber)))
	if err != nil {
		fmt.Println(err.Error())
	}

	fmt.Printf("ContractSize: %+v\n", contractSize)

	// update balance
	sig := crypto.Keccak256([]byte("updateBalance(uint256)"))[:4]
	data := make([]byte, 0, 0)
	data = append(data, sig...)
	newBalance_, err := uint256.FromHex("0x1")
	if err != nil {
		fmt.Println(err.Error())
		return
	}
	temp := newBalance_.Bytes32()
	data = append(data, temp[:]...)

	inner_tx = types.QuaiTx{ChainID: params.Blake3PowLocalChainConfig.ChainID, Nonce: nonce + 1, GasTipCap: big.NewInt(1 * params.GWei), GasFeeCap: big.NewInt(1 * params.GWei), Gas: 30000000, To: &contractAddr, Value: common.Big0, Data: data, AccessList: types.AccessList{}}
	tx, err = types.SignTx(types.NewTx(&inner_tx), signer, privKey1)
	if err != nil {
		t.Error(err.Error())
		t.Fail()
		return
	}
	err = client.SendTransaction(context.Background(), tx)
	if err != nil {
		fmt.Println(err.Error())
		return
	}
	fmt.Printf("Balance of %s: %s\n", fromAddress1.String(), new(big.Int).SetBytes(data).String())
	// Check contract size
	contractSize, err = client.ContractSizeAt(context.Background(), contractAddr.MixedcaseAddress(), nil)
	if err != nil {
		fmt.Println(err.Error())
	}
	fmt.Printf("ContractSize: %+v\n", contractSize)

	// update balance for the second address
	sig = crypto.Keccak256([]byte("updateBalance(uint256)"))[:4]
	data = make([]byte, 0, 0)
	data = append(data, sig...)
	newBalance_, err = uint256.FromHex("0x1")
	if err != nil {
		fmt.Println(err.Error())
		return
	}
	temp = newBalance_.Bytes32()
	data = append(data, temp[:]...)

	inner_tx = types.QuaiTx{ChainID: params.Blake3PowLocalChainConfig.ChainID, Nonce: nonce, GasTipCap: big.NewInt(1 * params.GWei), GasFeeCap: big.NewInt(1 * params.GWei), Gas: 30000000, To: &contractAddr, Value: common.Big0, Data: data, AccessList: types.AccessList{}}
	tx, err = types.SignTx(types.NewTx(&inner_tx), signer, privKey2)
	if err != nil {
		t.Error(err.Error())
		t.Fail()
		return
	}
	err = client.SendTransaction(context.Background(), tx)
	if err != nil {
		fmt.Println(err.Error())
		return
	}
	fmt.Printf("Balance of %s: %s\n", fromAddress2.String(), new(big.Int).SetBytes(data).String())

	// Check contract size
	contractSize, err = client.ContractSizeAt(context.Background(), contractAddr.MixedcaseAddress(), nil)
	if err != nil {
		fmt.Println(err.Error())
	}

	fmt.Printf("ContractSize: %+v\n", contractSize)

	// delete the second address from the address
	sig = crypto.Keccak256([]byte("deleteBalance()"))[:4]
	data = make([]byte, 0, 0)
	data = append(data, sig...)

	inner_tx = types.QuaiTx{ChainID: params.Blake3PowLocalChainConfig.ChainID, Nonce: nonce + 1, GasTipCap: big.NewInt(1 * params.GWei), GasFeeCap: big.NewInt(1 * params.GWei), Gas: 30000000, To: &contractAddr, Value: common.Big0, Data: data, AccessList: types.AccessList{}}
	tx, err = types.SignTx(types.NewTx(&inner_tx), signer, privKey2)
	if err != nil {
		t.Error(err.Error())
		t.Fail()
		return
	}
	err = client.SendTransaction(context.Background(), tx)
	if err != nil {
		fmt.Println(err.Error())
		return
	}
	fmt.Printf("Balance of %s: %s\n", fromAddress2.String(), new(big.Int).SetBytes(data).String())
	// Check contract size
	contractSize, err = client.ContractSizeAt(context.Background(), contractAddr.MixedcaseAddress(), nil)
	if err != nil {
		fmt.Println(err.Error())
	}

	fmt.Printf("ContractSize: %+v\n", contractSize)

	// delete the contract
	sig = crypto.Keccak256([]byte("suicide()"))[:4]
	data = make([]byte, 0, 0)
	data = append(data, sig...)

	inner_tx = types.QuaiTx{ChainID: params.Blake3PowLocalChainConfig.ChainID, Nonce: nonce + 2, GasTipCap: big.NewInt(1 * params.GWei), GasFeeCap: big.NewInt(1 * params.GWei), Gas: 30000000, To: &contractAddr, Value: common.Big0, Data: data, AccessList: types.AccessList{}}
	tx, err = types.SignTx(types.NewTx(&inner_tx), signer, privKey1)
	if err != nil {
		t.Error(err.Error())
		t.Fail()
		return
	}
	err = client.SendTransaction(context.Background(), tx)
	if err != nil {
		fmt.Println(err.Error())
		return
	}

	// Check contract size
	contractSize, err = client.ContractSizeAt(context.Background(), contractAddr.MixedcaseAddress(), nil)
	if err != nil {
		fmt.Println(err.Error())
	}

	fmt.Printf("ContractSize: %+v\n", contractSize)
}
