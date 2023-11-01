package vm

import (
	"bytes"
	"math/big"
	"strings"
	"testing"

	"github.com/bytecodealliance/wasmtime-go"
	"github.com/dominant-strategies/go-quai/common"
	"github.com/dominant-strategies/go-quai/core/rawdb"
	"github.com/dominant-strategies/go-quai/core/state"
	"github.com/dominant-strategies/go-quai/crypto"
	"github.com/dominant-strategies/go-quai/params"
)

func TestHelloContract(t *testing.T) {
	var (
		env             = NewEVM(BlockContext{}, TxContext{}, nil, params.TestChainConfig, Config{})
		wasmInterpreter = NewWASMInterpreter(env, env.Config)
	)

	wasmBytes, err := wasmtime.Wat2Wasm(`
		(module
		  (func $logHelloWorld (import "" "logHelloWorld"))
		  (func (export "run") (call $logHelloWorld))
		)
		`)

	if err != nil {
		t.Errorf("error: %v", err)
	}

	// Track time taken and memory usage
	// defer trackTime(time.Now(), "wasm")

	// Initialise a new contract and set the code that is to be used by the EVM.
	// The contract is a scoped environment for this execution context only.
	contract := NewContract(&dummyContractRef{}, &dummyContractRef{}, new(big.Int), 2000)
	contract.SetCodeOptionalHash(nil, &codeAndHash{
		code: wasmBytes,
	})

	_, err = wasmInterpreter.Run(contract, nil, false)
	if err != nil {
		t.Errorf("error: %v", err)
	}
}

func TestUseGasContract(t *testing.T) {
	var (
		env             = NewEVM(BlockContext{}, TxContext{}, nil, params.TestChainConfig, Config{})
		wasmInterpreter = NewWASMInterpreter(env, env.Config)
	)

	wasmBytes, err := wasmtime.Wat2Wasm(`
	(module
		(func $useGas (import "" "useGas") (param i64))
		(func (export "run") (call $useGas (i64.const 1)))
	  )
		`)

	if err != nil {
		t.Errorf("error: %v", err)
	}
	// Track time taken and memory usage
	// defer trackTime(time.Now(), "wasm")

	// Initialise a new contract and set the code that is to be used by the EVM.
	// The contract is a scoped environment for this execution context only.
	contract := NewContract(&dummyContractRef{}, &dummyContractRef{}, new(big.Int), 2000)
	contract.SetCodeOptionalHash(nil, &codeAndHash{
		code: wasmBytes,
	})

	_, err = wasmInterpreter.Run(contract, nil, false)
	if err != nil {
		t.Errorf("error: %v", err)
	}
}
func TestGetAddressContract(t *testing.T) {
	var (
		env             = NewEVM(BlockContext{}, TxContext{}, nil, params.TestChainConfig, Config{})
		wasmInterpreter = NewWASMInterpreter(env, env.Config)
	)

	wasmBytes, err := wasmtime.Wat2Wasm(`
    (module
        (func $getAddress (import "" "getAddress") (param i32))
        (func (export "run") 
            (local i32)
            (local.set 0 (i32.const 0))  ;; Set memory offset to 0
            (call $getAddress (local.get 0))  ;; Call getAddress with memory offset
        )
    )
`)
	if err != nil {
		t.Errorf("error: %v", err)
	}

	contractOutOfGas := NewContract(&dummyContractRef{}, &dummyContractRef{}, new(big.Int), 50)
	contractOutOfGas.SetCodeOptionalHash(&common.ZeroAddr, &codeAndHash{
		code: wasmBytes,
		hash: crypto.Keccak256Hash(wasmBytes),
	})

	_, err = wasmInterpreter.Run(contractOutOfGas, nil, false)
	if !strings.Contains(err.Error(), "out of gas") {
		t.Errorf("error: %v", err)
	}

	contract := NewContract(&dummyContractRef{}, &dummyContractRef{}, new(big.Int), 10000)
	contract.SetCodeOptionalHash(&common.ZeroAddr, &codeAndHash{
		code: wasmBytes,
		hash: crypto.Keccak256Hash(wasmBytes),
	})

	_, err = wasmInterpreter.Run(contract, nil, false)
	if err != nil {
		t.Errorf("error: %v", err)
	}
}

func TestFuelConsumption(t *testing.T) {
	var (
		env             = NewEVM(BlockContext{}, TxContext{}, nil, params.TestChainConfig, Config{})
		wasmInterpreter = NewWASMInterpreter(env, env.Config)
	)

	wasmBytes, _ := wasmtime.Wat2Wasm(`
		(module
			(func (export "run") (loop (br 0))) ;; Infinite loop
		)
	`)

	contract := NewContract(&dummyContractRef{}, &dummyContractRef{}, new(big.Int), 2000)
	contract.SetCodeOptionalHash(&common.ZeroAddr, &codeAndHash{
		code: wasmBytes,
		hash: crypto.Keccak256Hash(wasmBytes),
	})

	_, err := wasmInterpreter.Run(contract, nil, false)
	if !strings.Contains(err.Error(), "all fuel consumed by WebAssembly") {
		t.Errorf("error: %v", err)
	}
}

func TestGetBlockNumber(t *testing.T) {
	context := BlockContext{
		BlockNumber: big.NewInt(100),
	}

	var (
		env             = NewEVM(context, TxContext{}, nil, params.TestChainConfig, Config{})
		wasmInterpreter = NewWASMInterpreter(env, env.Config)
	)

	wasmCode := `
	(module
		(import "" "getBlockNumber" (func $getBlockNumber (result i64)))
		(func (export "run")
			(local i64)  ;; Local variable to hold the block number
			(local.set 0 (call $getBlockNumber))  ;; Call getBlockNumber and store the result in the local variable
		)
	)
	`
	wasmBytes, err := wasmtime.Wat2Wasm(wasmCode)
	if err != nil {
		t.Fatalf("failed to convert WAT to WASM: %v", err)
	}

	// Track time taken and memory usage
	// defer trackTime(time.Now(), "wasm")

	// Initialise a new contract and set the code that is to be used by the EVM.
	// The contract is a scoped environment for this execution context only.
	contract := NewContract(&dummyContractRef{}, &dummyContractRef{}, new(big.Int), 2000)
	contract.SetCodeOptionalHash(&common.ZeroAddr, &codeAndHash{
		code: wasmBytes,
		hash: crypto.Keccak256Hash(wasmBytes),
	})

	_, err2 := wasmInterpreter.Run(contract, nil, false)
	if err2 != nil {
		t.Errorf("error: %v", err2)
	}
}

func CanTransfer(db StateDB, addr common.Address, amount *big.Int) bool {
	internalAddr, err := addr.InternalAddress()
	if err != nil {
		return false
	}
	return db.GetBalance(internalAddr).Cmp(amount) >= 0
}

func Transfer(db StateDB, sender, recipient common.Address, amount *big.Int) error {
	internalSender, err := sender.InternalAddress()
	if err != nil {
		return err
	}
	internalRecipient, err := recipient.InternalAddress()
	if err != nil {
		return err
	}
	db.SubBalance(internalSender, amount)
	db.AddBalance(internalRecipient, amount)
	return nil
}

func TestCreate(t *testing.T) {

	// Set node location to zone-0-0 so that ZeroAddr returns properly in dummyContractRef
	common.NodeLocation = append(common.NodeLocation, byte(0))
	common.NodeLocation = append(common.NodeLocation, byte(0))

	statedb, _ := state.New(common.Hash{}, state.NewDatabase(rawdb.NewMemoryDatabase()), nil)

	blockContext := BlockContext{
		CanTransfer: CanTransfer,
		Transfer:    Transfer,
	}

	var (
		env = NewEVM(blockContext, TxContext{},
			statedb, params.TestChainConfig, Config{})
		wasmInterpreter = NewWASMInterpreter(env, env.Config)
	)

	testCases := []struct {
		wasmCode    string
		expected    int32
		description string
	}{
		// Result offset of 100 right now is arbitrary, should be standardized
		{
			wasmCode: `
			(module
				(import "" "create" (func $create (param i32 i32 i32 i32) (result i32)))
				(func (export "run")
					(local i32)  ;; Local variable to hold the result of the create call
					(local.set 0 (call $create (i32.const 0) (i32.const 0) (i32.const 0) (i32.const 100)))  ;; Call create with 0 value and no code, and store the result in the local variable
				)
			)
			`,
			expected:    QEICallSuccess,
			description: "Create an account with 0 wei and no code",
		},
		{
			wasmCode: `
			(module
				(import "" "create" (func $create (param i32 i32 i32 i32) (result i32)))
				(memory 1)  ;; This line defines a memory with an initial size of 1 page (64KiB)
				(func (export "run")
					(local i32)  ;; Local variable to hold the return value
					;; Setup memory for value
					(i32.store (i32.const 0) (i32.const 9))
					(local.set 0 (call $create (i32.const 0) (i32.const 0) (i32.const 0) (i32.const 100)))  ;; Call create with the specified arguments
				)
			)
		`,
			expected:    QEICallSuccess,
			description: "Create an account with 9 wei and no code",
		},
		{
			wasmCode: `
			(module
				(import "" "create" (func $create (param i32 i32 i32 i32) (result i32)))
				(import "" "memory" (memory 1))
				(data (i32.const 0) "\6F\FF\FF\FF\FF\60\00\52\60\04\60\1C\F3")
				(func (export "run")
					(local i32)  ;; Local variable to hold the return value
					;; Setup memory for value
					(i32.store (i32.const 13) (i32.const 0))
					(local.set 0 (call $create (i32.const 13) (i32.const 0) (i32.const 13) (i32.const 100)))  ;; Call create with the specified arguments
				)
			)
		`,
			expected:    QEICallSuccess,
			description: "Create an account with 0 wei and 4 FF as code",
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.description, func(t *testing.T) {
			wasmBytes, err := wasmtime.Wat2Wasm(testCase.wasmCode)
			if err != nil {
				t.Fatalf("failed to convert WAT to WASM: %v", err)
			}

			// Create a new contract and set the code that is to be used by the EVM.
			contract := NewContract(&dummyContractRef{}, &dummyContractRef{}, new(big.Int), 2000)
			contract.SetCodeOptionalHash(&common.ZeroAddr, &codeAndHash{
				code: wasmBytes,
				hash: crypto.Keccak256Hash(wasmBytes),
			})

			_, err2 := wasmInterpreter.Run(contract, wasmBytes, false)
			if err2 != nil {
				t.Errorf("error: %v", err2)
			}

			// Check the return value and any other relevant state.
			// if ret != testCase.expected {
			// 	t.Errorf("expected %v, got %v", testCase.expected, ret)
			// }
		})
	}
}

func TestCall(t *testing.T) {
	// Set node location to zone-0-0 so that ZeroAddr returns properly in dummyContractRef
	common.NodeLocation = append(common.NodeLocation, byte(0))
	common.NodeLocation = append(common.NodeLocation, byte(0))

	statedb, _ := state.New(common.Hash{}, state.NewDatabase(rawdb.NewMemoryDatabase()), nil)

	blockContext := BlockContext{
		CanTransfer: CanTransfer,
		Transfer:    Transfer,
	}

	var (
		env = NewEVM(blockContext, TxContext{},
			statedb, params.TestChainConfig, Config{})
		wasmInterpreter = NewWASMInterpreter(env, env.Config)
	)

	// Create a basic contract to call
	wasmCode := `
	(module
		(import "" "create" (func $create (param i32 i32 i32 i32) (result i32)))
		(import "" "memory" (memory 1))
		(data (i32.const 0) "\6F\FF\FF\FF\FF\60\00\52\60\04\60\1C\F3")
		(func (export "run")
			(local i32)  ;; Local variable to hold the result of the create call
			(local.set 0 (call $create (i32.const 0) (i32.const 0) (i32.const 0) (i32.const 100)))  ;; Call create with 0 value and no code, and store the result in the local variable
		)
	)
	`

	wasmBytes, err := wasmtime.Wat2Wasm(wasmCode)
	if err != nil {
		t.Fatalf("failed to convert WAT to WASM: %v", err)
	}

	byteSlice := [20]byte{}
	byteSlice[0] = 1
	addr := common.Bytes20ToAddress(byteSlice)

	createContractRef := &dummyContractRef{}
	createContractRef.SetAddress(addr)
	createContract := NewContract(createContractRef, createContractRef, new(big.Int), 2000)

	createContract.SetCodeOptionalHash(&common.ZeroAddr, &codeAndHash{
		code: wasmBytes,
		hash: crypto.Keccak256Hash(wasmBytes),
	})

	_, err2 := wasmInterpreter.Run(createContract, nil, false)
	if err2 != nil {
		t.Errorf("error: %v", err2)
	}

	// Create a basic contract to call
	callWasmCode := `
		(module
			(import "" "call" (func $call (param i64 i32 i32 i32 i32) (result i32)))
			(import "" "memory" (memory 1))
			(data (i32.const 0) "\01\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00")  ;; Zero address at offset 0
			(func (export "run")
				(local i32)  ;; Local variable to hold the result of the call
				(local.set 0 (call $call (i64.const 0) (i32.const 0) (i32.const 21) (i32.const 0) (i32.const 0)))  ;; Call call with zero address and other necessary parameters, and store the result in the local variable
			)
		)
		`

	callWasmBytes, err := wasmtime.Wat2Wasm(callWasmCode)
	if err != nil {
		t.Fatalf("failed to convert WAT to WASM: %v", err)
	}

	byteSlice = [20]byte{}
	byteSlice[0] = 2
	addr = common.Bytes20ToAddress(byteSlice)

	callContractRef := &dummyContractRef{}
	callContractRef.SetAddress(addr)
	callContract := NewContract(callContractRef, callContractRef, new(big.Int), 2000)

	callContract.SetCodeOptionalHash(&addr, &codeAndHash{
		code: callWasmBytes,
		hash: crypto.Keccak256Hash(callWasmBytes),
	})

	_, err3 := wasmInterpreter.Run(callContract, nil, false)
	if err3 != nil {
		t.Errorf("error: %v", err3)
	}

}

func TestGetCallDataSize(t *testing.T) {
	context := BlockContext{
		BlockNumber: big.NewInt(100),
	}

	var (
		env             = NewEVM(context, TxContext{}, nil, params.TestChainConfig, Config{})
		wasmInterpreter = NewWASMInterpreter(env, env.Config)
	)

	wasmCode := `
	(module
		(import "" "getCallDataSize" (func $getCallDataSize (result i32)))
		(func (export "run")
			(local i32)  ;; Local variable to hold the block number
			(local.set 0 (call $getCallDataSize))  ;; Call getCallDataSize and store the result in the local variable
		)
	)
	`
	wasmBytes, err := wasmtime.Wat2Wasm(wasmCode)
	if err != nil {
		t.Fatalf("failed to convert WAT to WASM: %v", err)
	}

	contract := NewContract(&dummyContractRef{}, &dummyContractRef{}, new(big.Int), 2000)
	contract.SetCodeOptionalHash(&common.ZeroAddr, &codeAndHash{
		code: wasmBytes,
		hash: crypto.Keccak256Hash(wasmBytes),
	})

	callData := make([]byte, 5) // Create a byte slice of length 5 filled with zeros
	_, err2 := wasmInterpreter.Run(contract, callData, false)

	if err2 != nil {
		t.Errorf("error: %v", err2)
	}
}

func TestCallDataCopy(t *testing.T) {
	context := BlockContext{
		BlockNumber: big.NewInt(100),
	}

	var (
		env             = NewEVM(context, TxContext{}, nil, params.TestChainConfig, Config{})
		wasmInterpreter = NewWASMInterpreter(env, env.Config)
	)

	wasmCode := `
    (module
        (import "" "callDataCopy" (func $callDataCopy (param i32 i32 i32)))
		(import "" "memory" (memory 1))
		(func (export "run")
            (call $callDataCopy (i32.const 0) (i32.const 0) (i32.const 5))
        )
    )
    `
	wasmBytes, err := wasmtime.Wat2Wasm(wasmCode)
	if err != nil {
		t.Fatalf("failed to convert WAT to WASM: %v", err)
	}

	// Initialise a new contract and set the code that is to be used by the EVM.
	contract := NewContract(&dummyContractRef{}, &dummyContractRef{}, new(big.Int), 2000)
	contract.SetCodeOptionalHash(&common.ZeroAddr, &codeAndHash{
		code: wasmBytes,
		hash: crypto.Keccak256Hash(wasmBytes),
	})

	callData := []byte{1, 2, 3, 4, 5} // Create a byte slice of length 5 with specified values
	_, err2 := wasmInterpreter.Run(contract, callData, false)

	if err2 != nil {
		t.Errorf("error: %v", err2)
	}

	memoryData := wasmInterpreter.vm.memory.UnsafeData(wasmInterpreter.vm.store)
	if !bytes.Equal(memoryData[:5], callData) {
		t.Errorf("Expected memory to contain %v, but got %v", callData, memoryData[:5])
	}
}
