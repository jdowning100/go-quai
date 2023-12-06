package vm

import (
	"encoding/hex"
	"log"
	"math/big"
	"testing"

	"github.com/bytecodealliance/wasmtime-go"
	"github.com/dominant-strategies/go-quai/common"
	"github.com/dominant-strategies/go-quai/crypto"
	"github.com/dominant-strategies/go-quai/params"
)

func BenchmarkWASMBlockNumberOperation(b *testing.B) {
	context := BlockContext{
		BlockNumber: big.NewInt(100),
	}

	wasmCode := `
	(module
		(import "quai" "getBlockNumber" (func $getBlockNumber (result i64)))
		(func (export "main")
			call $getBlockNumber  ;; Directly call getBlockNumber
			drop  ;; Drop the result as it's not stored or used
		)
	)
	`

	wasmBytes, err := wasmtime.Wat2Wasm(wasmCode)
	if err != nil {
		b.Fatalf("failed to convert WAT to WASM: %v", err)
	}

	for i := 0; i < b.N; i++ {
		var (
			env             = NewEVM(context, TxContext{}, nil, params.TestChainConfig, Config{})
			wasmInterpreter = NewWASMInterpreter(env, env.Config)
		)

		contract := NewContract(&dummyContractRef{}, &dummyContractRef{}, new(big.Int), 2000)
		contract.SetCodeOptionalHash(&common.ZeroAddr, &codeAndHash{
			code: wasmBytes,
			hash: crypto.Keccak256Hash(wasmBytes),
		})

		_, err2 := wasmInterpreter.Run(contract, nil, false)
		if err2 != nil {
			log.Fatal(err)
		}
	}
}

func BenchmarkEVMBlockNumberOperation(b *testing.B) {
	context := BlockContext{
		BlockNumber: big.NewInt(100),
	}

	// block.number
	evmString := "0x43"

	// Remove the "0x" prefix
	evmString = evmString[2:]

	// Convert the hexadecimal string to bytes
	evmBytes, err := hex.DecodeString(evmString)
	if err != nil {
		log.Fatal(err)
	}

	for i := 0; i < b.N; i++ {
		var (
			env            = NewEVM(context, TxContext{}, nil, params.TestChainConfig, Config{})
			evmInterpreter = NewEVMInterpreter(env, env.Config)
		)

		contract := NewContract(&dummyContractRef{}, &dummyContractRef{}, new(big.Int), 2000)
		contract.SetCodeOptionalHash(&common.ZeroAddr, &codeAndHash{
			code: evmBytes,
			hash: crypto.Keccak256Hash(evmBytes),
		})

		_, err2 := evmInterpreter.Run(contract, nil, false)
		if err2 != nil {
			log.Fatal(err)
		}
	}
}
