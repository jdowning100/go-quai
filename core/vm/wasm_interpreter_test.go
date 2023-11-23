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

func TestCoinflipContract(t *testing.T) {
	var (
		env             = NewEVM(BlockContext{}, TxContext{}, &dummyStatedb{}, params.TestChainConfig, Config{})
		wasmInterpreter = NewWASMInterpreter(env, env.Config)
	)

	wasmBytes, err := wasmtime.Wat2Wasm(coinflip)

	if err != nil {
		t.Errorf("wast error: %v", err)
	}

	// Track time taken and memory usage
	// defer trackTime(time.Now(), "wasm")

	// Initialise a new contract and set the code that is to be used by the EVM.
	// The contract is a scoped environment for this execution context only.
	contract := NewContract(&dummyContractRef{address: common.Address{}}, &dummyContractRef{address: common.Address{}}, new(big.Int), 200000)
	contract.SetCodeOptionalHash(&common.Address{}, &codeAndHash{
		code: wasmBytes,
	})

	_, err = wasmInterpreter.Run(contract, nil, false)
	if err != nil {
		t.Errorf("wasm error: %v", err)
	}
}

func TestHelloContract(t *testing.T) {
	var (
		env             = NewEVM(BlockContext{}, TxContext{}, nil, params.TestChainConfig, Config{})
		wasmInterpreter = NewWASMInterpreter(env, env.Config)
	)

	wasmBytes, err := wasmtime.Wat2Wasm(`
	(module
		(import "quai" "useGas" (func $useGas (param i64)))
		(global $cb_dest (mut i32) (i32.const 0))
		(global $sp (mut i32) (i32.const -32))
		(global $init (mut i32) (i32.const 0))
	  
		;; memory related global
		(global $memstart i32  (i32.const 33832))
		;; the number of 256 words stored in memory
		(global $wordCount (mut i64) (i64.const 0))
		;; what was charged for the last memory allocation
		(global $prevMemCost (mut i64) (i64.const 0))
	  
		;; TODO: memory should only be 1, but can't resize right now
		(memory 500)
		(export "memory" (memory 0))
	  
		
	  
		
		(func $main
		  (export "main")
		  (local $jump_dest i32) (local $jump_map_switch i32)
		  (set_local $jump_dest (i32.const -1))
	  
		  (block $done
			(loop $loop
			  
		(block $0 
		  (if
			(i32.eqz (get_global $init))
			(then
			  (set_global $init (i32.const 1))
			  (br $0))
			(else
			  ;; the callback dest can never be in the first block
			  (if (i32.eq (get_global $cb_dest) (i32.const 0)) 
				(then
				  (unreachable)
				)
				(else 
				  ;; return callback destination and zero out $cb_dest 
				  (set_local $jump_map_switch (get_global $cb_dest))
				  (set_global $cb_dest (i32.const 0))
				  (br_table $0  (get_local $jump_map_switch))
				))))))))
	  )
	`)

	if err != nil {
		t.Errorf("wasm error: %v", err)
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

var coinflip = `

(module
  






	(import "quai" "storageStore" (func $storageStore (param i32 i32) ))
	(import "quai" "getCallValue" (func $getCallValue (param i32) ))
	
	(import "quai" "revert" (func $revert (param i32 i32) ))
	
	
	
	
	
	
	
	
	(import "quai" "storageLoad" (func $storageLoad (param i32 i32) ))
	
	
	(import "quai" "codeCopy" (func $codeCopy (param i32 i32 i32) ))
	(import "quai" "finish" (func $finish (param i32 i32) ))
	(import "quai" "getCallDataSize" (func $getCallDataSize  (result i32)))
	(import "quai" "getCaller" (func $getCaller (param i32) ))
	(import "quai" "log" (func $log (param i32 i32 i32 i32 i32 i32 i32) ))
	(import "quai" "callDataCopy" (func $callDataCopy (param i32 i32 i32) ))
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	(import "quai" "useGas" (func $useGas (param i64)))
	  (global $cb_dest (mut i32) (i32.const 0))
	  (global $sp (mut i32) (i32.const -32))
	  (global $init (mut i32) (i32.const 0))
	
	  ;; memory related global
	  (global $memstart i32  (i32.const 33832))
	  ;; the number of 256 words stored in memory
	  (global $wordCount (mut i64) (i64.const 0))
	  ;; what was charged for the last memory allocation
	  (global $prevMemCost (mut i64) (i64.const 0))
	
	  ;; TODO: memory should only be 1, but can't resize right now
	  (memory 500)
	  (export "memory" (memory 0))
	
	  
	
	  (func $PUSH
	  (param $a0 i64)
	  (param $a1 i64)
	  (param $a2 i64)
	  (param $a3 i64)
	  (local $sp i32)
	
	  ;; increament stack pointer
	  (set_local $sp (i32.add (get_global $sp) (i32.const 32)))
	
	  (i64.store (get_local $sp) (get_local $a3))
	  (i64.store (i32.add (get_local $sp) (i32.const 8)) (get_local $a2))
	  (i64.store (i32.add (get_local $sp) (i32.const 16)) (get_local $a1))
	  (i64.store (i32.add (get_local $sp) (i32.const 24)) (get_local $a0))
	)
	;; stack:
	;;  0: word
	;; -1: offset
	(func $MSTORE
	  (local $sp i32)
	
	  (local $offset   i32)
	  
	  (local $offset0 i64)
	  (local $offset1 i64)
	  (local $offset2 i64)
	  (local $offset3 i64)
	
	  ;; load args from the stack
	  (set_local $offset0 (i64.load          (get_global $sp)))
	  (set_local $offset1 (i64.load (i32.add (get_global $sp) (i32.const 8))))
	  (set_local $offset2 (i64.load (i32.add (get_global $sp) (i32.const 16))))
	  (set_local $offset3 (i64.load (i32.add (get_global $sp) (i32.const 24))))
	
	  (set_local $offset 
				 (call $check_overflow (get_local $offset0)
									   (get_local $offset1)
									   (get_local $offset2)
									   (get_local $offset3)))
	  ;; subtrace gas useage
	  (call $memusegas (get_local $offset) (i32.const 32))
	
	  ;; pop item from the stack
	  (set_local $sp (i32.sub (get_global $sp) (i32.const 32)))
	
	  ;; swap top stack item
	  (drop (call $bswap_m256 (get_local $sp)))
	
	  (set_local $offset (i32.add (get_local $offset) (get_global $memstart)))
	  ;; store word to memory
	  (i64.store          (get_local $offset)                 (i64.load          (get_local $sp)))
	  (i64.store (i32.add (get_local $offset) (i32.const 8))  (i64.load (i32.add (get_local $sp) (i32.const  8))))
	  (i64.store (i32.add (get_local $offset) (i32.const 16)) (i64.load (i32.add (get_local $sp) (i32.const 16))))
	  (i64.store (i32.add (get_local $offset) (i32.const 24)) (i64.load (i32.add (get_local $sp) (i32.const 24))))
	)
	;; stack:
	;;  0: offset
	(func $MLOAD
	  (local $offset i32)
	  (local $offset0 i64)
	  (local $offset1 i64)
	  (local $offset2 i64)
	  (local $offset3 i64)
	
	  ;; load args from the stack
	  (set_local $offset0 (i64.load          (get_global $sp)))
	  (set_local $offset1 (i64.load (i32.add (get_global $sp) (i32.const 8))))
	  (set_local $offset2 (i64.load (i32.add (get_global $sp) (i32.const 16))))
	  (set_local $offset3 (i64.load (i32.add (get_global $sp) (i32.const 24))))
	
	  (set_local $offset 
				 (call $check_overflow (get_local $offset0)
									   (get_local $offset1)
									   (get_local $offset2)
									   (get_local $offset3)))
	  ;; subttract gas useage
	  (call $memusegas (get_local $offset) (i32.const  32))
	
	  ;; FIXME: how to deal with overflow?
	  (set_local $offset (i32.add (get_local $offset) (get_global $memstart)))
	
	  (i64.store (i32.add (get_global $sp) (i32.const 24)) (i64.load (i32.add (get_local $offset) (i32.const 24))))
	  (i64.store (i32.add (get_global $sp) (i32.const 16)) (i64.load (i32.add (get_local $offset) (i32.const 16))))
	  (i64.store (i32.add (get_global $sp) (i32.const  8)) (i64.load (i32.add (get_local $offset) (i32.const  8))))
	  (i64.store          (get_global $sp)                 (i64.load          (get_local $offset)))
	
	  ;; swap
	  (drop (call $bswap_m256 (get_global $sp)))
	)
	(func $DUP
	  (param $a0 i32)
	  (local $sp i32)
	
	  (local $sp_ref i32)
	  
	  (set_local $sp (i32.add (get_global $sp) (i32.const 32)))
	  (set_local $sp_ref (i32.sub (i32.sub (get_local $sp) (i32.const 8)) (i32.mul (get_local $a0) (i32.const 32))))
	  
	  (i64.store (i32.add (get_local $sp) (i32.const 24)) (i64.load (get_local $sp_ref)))
	  (i64.store (i32.add (get_local $sp) (i32.const 16)) (i64.load (i32.sub (get_local $sp_ref) (i32.const 8))))
	  (i64.store (i32.add (get_local $sp) (i32.const  8)) (i64.load (i32.sub (get_local $sp_ref) (i32.const 16))))
	  (i64.store          (get_local $sp)                 (i64.load (i32.sub (get_local $sp_ref) (i32.const 24))))
	)
	(func $ADD
	  (local $sp i32)
	
	  (local $a i64)
	  (local $c i64)
	  (local $d i64)
	  (local $carry i64)
	
	  (set_local $sp (get_global $sp))
	  
	  ;; d c b a
	  ;; pop the stack 
	  (set_local $a (i64.load (i32.add (get_local $sp) (i32.const 24))))
	  (set_local $c (i64.load (i32.add (get_local $sp) (i32.const 8))))
	  (set_local $d (i64.load (get_local $sp)))
	  ;; decement the stack pointer
	  (set_local $sp (i32.sub (get_local $sp) (i32.const 8)))
	
	  ;; d 
	  (set_local $carry (i64.add (get_local $d) (i64.load (i32.sub (get_local $sp) (i32.const 24)))))
	  ;; save d  to mem
	  (i64.store (i32.sub (get_local $sp) (i32.const 24)) (get_local $carry))
	  ;; check  for overflow
	  (set_local $carry (i64.extend_u/i32 (i64.lt_u (get_local $carry) (get_local $d))))
	
	  ;; c use $d as reg
	  (set_local $d     (i64.add (i64.load (i32.sub (get_local $sp) (i32.const 16))) (get_local $carry)))
	  (set_local $carry (i64.extend_u/i32 (i64.lt_u (get_local $d) (get_local $carry))))
	  (set_local $d     (i64.add (get_local $c) (get_local $d)))
	  ;; store the result
	  (i64.store (i32.sub (get_local $sp) (i32.const 16)) (get_local $d))
	  ;; check overflow
	  (set_local $carry (i64.or (i64.extend_u/i32  (i64.lt_u (get_local $d) (get_local $c))) (get_local $carry)))
	
	  ;; b
	  ;; add carry
	  (set_local $d     (i64.add (i64.load (i32.sub (get_local $sp) (i32.const 8))) (get_local $carry)))
	  (set_local $carry (i64.extend_u/i32 (i64.lt_u (get_local $d) (get_local $carry))))
	
	  ;; use reg c
	  (set_local $c (i64.load (i32.add (get_local $sp) (i32.const 24))))
	  (set_local $d (i64.add (get_local $c) (get_local $d)))
	  (i64.store (i32.sub (get_local $sp) (i32.const 8)) (get_local $d))
	  ;; a
	  (i64.store (get_local $sp) 
				 (i64.add        ;; add a 
				   (get_local $a)
				   (i64.add
					 (i64.load (get_local $sp))  ;; load the operand
					 (i64.or  ;; carry 
					   (i64.extend_u/i32 (i64.lt_u (get_local $d) (get_local $c))) 
					   (get_local $carry)))))
	)
	(func $SWAP
	  (param $a0 i32)
	  (local $sp_ref i32)
	
	  (local $topa i64)
	  (local $topb i64)
	  (local $topc i64)
	  (local $topd i64)
	  
	  (set_local $sp_ref (i32.sub (i32.add  (get_global $sp) (i32.const 24)) (i32.mul (i32.add (get_local $a0) (i32.const 1)) (i32.const 32))))
	
	  (set_local $topa (i64.load (i32.add (get_global $sp) (i32.const 24))))
	  (set_local $topb (i64.load (i32.add (get_global $sp) (i32.const 16))))
	  (set_local $topc (i64.load (i32.add (get_global $sp) (i32.const  8))))
	  (set_local $topd (i64.load          (get_global $sp)))
	  
	  ;; replace the top element
	  (i64.store (i32.add (get_global $sp) (i32.const 24)) (i64.load (get_local $sp_ref)))
	  (i64.store (i32.add (get_global $sp) (i32.const 16)) (i64.load (i32.sub (get_local $sp_ref) (i32.const 8))))
	  (i64.store (i32.add (get_global $sp) (i32.const  8)) (i64.load (i32.sub (get_local $sp_ref) (i32.const 16))))
	  (i64.store          (get_global $sp)                 (i64.load (i32.sub (get_local $sp_ref) (i32.const 24))))
	
	  ;; store the old top element
	  (i64.store (get_local $sp_ref)                          (get_local $topa))
	  (i64.store (i32.sub (get_local $sp_ref) (i32.const 8))  (get_local $topb))
	  (i64.store (i32.sub (get_local $sp_ref) (i32.const 16)) (get_local $topc))
	  (i64.store (i32.sub (get_local $sp_ref) (i32.const 24)) (get_local $topd))
	)
	(func $check_overflow
	  (param $a i64)
	  (param $b i64)
	  (param $c i64)
	  (param $d i64)
	  (result i32)
	
	  (local $MAX_INT i32)
	  (set_local $MAX_INT (i32.const -1))
	
	  (if
		(i32.and 
		  (i32.and 
			(i64.eqz  (get_local $d))
			(i64.eqz  (get_local $c)))
		  (i32.and 
			(i64.eqz  (get_local $b))
			(i64.lt_u (get_local $a) (i64.extend_u/i32 (get_local $MAX_INT)))))
		 (return (i32.wrap/i64 (get_local $a))))
	
		 (return (get_local $MAX_INT))
	)
	;; generated by ./wasm/generateInterface.js
	(func $SSTORE   (call $storageStore(call $bswap_m256 (get_global $sp))(call $bswap_m256 (i32.add (get_global $sp) (i32.const -32)))));; generated by ./wasm/generateInterface.js
	(func $CALLVALUE   (call $getCallValue(i32.add (get_global $sp) (i32.const 32)))
		;; zero out mem
		(i64.store (i32.add (get_global $sp) (i32.const 56)) (i64.const 0))
		(i64.store (i32.add (get_global $sp) (i32.const 48)) (i64.const 0)))(func $ISZERO
	  (local $a0 i64)
	  (local $a1 i64)
	  (local $a2 i64)
	  (local $a3 i64)
	
	  ;; load args from the stack
	  (set_local $a0 (i64.load (i32.add (get_global $sp) (i32.const 24))))
	  (set_local $a1 (i64.load (i32.add (get_global $sp) (i32.const 16))))
	  (set_local $a2 (i64.load (i32.add (get_global $sp) (i32.const 8))))
	  (set_local $a3 (i64.load (get_global $sp)))
	
	  (i64.store (get_global $sp)
		(i64.extend_u/i32
		  (call $iszero_256 (get_local $a0) (get_local $a1) (get_local $a2) (get_local $a3))
		)
	  )
	
	  ;; zero out the rest of memory
	  (i64.store (i32.add (get_global $sp) (i32.const 8)) (i64.const 0))
	  (i64.store (i32.add (get_global $sp) (i32.const 16)) (i64.const 0))
	  (i64.store (i32.add (get_global $sp) (i32.const 24)) (i64.const 0))
	)
	;; generated by ./wasm/generateInterface.js
	(func $REVERT (local $offset0 i32)(local $length0 i32) (set_local $offset0 (call $check_overflow
			  (i64.load (get_global $sp))
			  (i64.load (i32.add (get_global $sp) (i32.const 8)))
			  (i64.load (i32.add (get_global $sp) (i32.const 16)))
			  (i64.load (i32.add (get_global $sp) (i32.const 24)))))(set_local $length0 (call $check_overflow
			  (i64.load (i32.add (get_global $sp) (i32.const -32)))
			  (i64.load (i32.add (get_global $sp) (i32.const -24)))
			  (i64.load (i32.add (get_global $sp) (i32.const -16)))
			  (i64.load (i32.add (get_global $sp) (i32.const -8)))))
		(call $memusegas (get_local $offset0) (get_local $length0))
		(set_local $offset0 (i32.add (get_global $memstart) (get_local $offset0))) (call $revert(get_local $offset0)(get_local $length0)))(func $DIV
	  (local $sp i32)
	  ;; dividend
	  (local $a i64)
	  (local $b i64)
	  (local $c i64)
	  (local $d i64)
	
	  ;; divisor
	  (local $a1 i64)
	  (local $b1 i64)
	  (local $c1 i64)
	  (local $d1 i64)
	
	  ;; quotient
	  (local $aq i64)
	  (local $bq i64)
	  (local $cq i64)
	  (local $dq i64)
	
	  ;; mask
	  (local $maska i64)
	  (local $maskb i64)
	  (local $maskc i64)
	  (local $maskd i64)
	  (local $carry i32)
	  (local $temp  i64)
	  (local $temp2  i64)
	
	  (set_local $sp (get_global $sp))
	  (set_local $maskd (i64.const 1))
	
	  ;; load args from the stack
	  (set_local $a (i64.load (i32.add (get_local $sp) (i32.const 24))))
	  (set_local $b (i64.load (i32.add (get_local $sp) (i32.const 16))))
	  (set_local $c (i64.load (i32.add (get_local $sp) (i32.const 8))))
	  (set_local $d (i64.load (get_local $sp)))
	
	  (set_local $sp (i32.sub (get_local $sp) (i32.const 32)))
	
	  (set_local $a1 (i64.load (i32.add (get_local $sp) (i32.const 24))))
	  (set_local $b1 (i64.load (i32.add (get_local $sp) (i32.const 16))))
	  (set_local $c1 (i64.load (i32.add (get_local $sp) (i32.const 8))))
	  (set_local $d1 (i64.load (get_local $sp)))
	
	  (block $main
		;; check div by 0
		(if (call $iszero_256 (get_local $a1) (get_local $b1) (get_local $c1) (get_local $d1))
		  (br $main)
		)
	
		;; align bits
		(block $done
		  (loop $loop
			;; align bits;
			(if 
			  ;; check to make sure we are not overflowing
			  (i32.or (i64.eqz (i64.clz (get_local $a1)))
			  ;;  divisor < dividend
			  (call $gte_256 (get_local $a1) (get_local $b1) (get_local $c1) (get_local $d1) (get_local $a) (get_local $b) (get_local $c) (get_local $d)))
			  (br $done)
			)
	
			;; divisor = divisor << 1
			(set_local $a1 (i64.add (i64.shl (get_local $a1) (i64.const 1)) (i64.shr_u (get_local $b1) (i64.const 63))))
			(set_local $b1 (i64.add (i64.shl (get_local $b1) (i64.const 1)) (i64.shr_u (get_local $c1) (i64.const 63))))
			(set_local $c1 (i64.add (i64.shl (get_local $c1) (i64.const 1)) (i64.shr_u (get_local $d1) (i64.const 63))))
			(set_local $d1 (i64.shl (get_local $d1) (i64.const 1)))
	
			;; mask = mask << 1
			(set_local $maska (i64.add (i64.shl (get_local $maska) (i64.const 1)) (i64.shr_u (get_local $maskb) (i64.const 63))))
			(set_local $maskb (i64.add (i64.shl (get_local $maskb) (i64.const 1)) (i64.shr_u (get_local $maskc) (i64.const 63))))
			(set_local $maskc (i64.add (i64.shl (get_local $maskc) (i64.const 1)) (i64.shr_u (get_local $maskd) (i64.const 63))))
			(set_local $maskd (i64.shl (get_local $maskd) (i64.const 1)))
	
			(br $loop)
		  )
		)
	
	
		(block $done
		  (loop $loop
			;; loop while mask != 0
			(if (call $iszero_256 (get_local $maska) (get_local $maskb) (get_local $maskc) (get_local $maskd))
			  (br $done)
			)
			;; if dividend >= divisor
			(if (call $gte_256 (get_local $a) (get_local $b) (get_local $c) (get_local $d) (get_local $a1) (get_local $b1) (get_local $c1) (get_local $d1))
			  (then
				;; dividend = dividend - divisor
				(set_local $carry (i64.lt_u (get_local $d) (get_local $d1)))
				(set_local $d     (i64.sub  (get_local $d) (get_local $d1)))
				(set_local $temp  (i64.sub  (get_local $c) (i64.extend_u/i32 (get_local $carry))))
				(set_local $carry (i64.gt_u (get_local $temp) (get_local $c)))
				(set_local $c     (i64.sub  (get_local $temp) (get_local $c1)))
				(set_local $carry (i32.or   (i64.gt_u (get_local $c) (get_local $temp)) (get_local $carry)))
				(set_local $temp  (i64.sub  (get_local $b) (i64.extend_u/i32 (get_local $carry))))
				(set_local $carry (i64.gt_u (get_local $temp) (get_local $b)))
				(set_local $b     (i64.sub  (get_local $temp) (get_local $b1)))
				(set_local $carry (i32.or   (i64.gt_u (get_local $b) (get_local $temp)) (get_local $carry)))
				(set_local $a     (i64.sub  (i64.sub (get_local $a) (i64.extend_u/i32 (get_local $carry))) (get_local $a1)))
	
				;; result = result + mask
				(set_local $dq   (i64.add (get_local $maskd) (get_local $dq)))
				(set_local $temp (i64.extend_u/i32 (i64.lt_u (get_local $dq) (get_local $maskd))))
				(set_local $cq   (i64.add (get_local $cq) (get_local $temp)))
				(set_local $temp (i64.extend_u/i32 (i64.lt_u (get_local $cq) (get_local $temp))))
				(set_local $cq   (i64.add (get_local $maskc) (get_local $cq)))
				(set_local $temp (i64.or (i64.extend_u/i32  (i64.lt_u (get_local $cq) (get_local $maskc))) (get_local $temp)))
				(set_local $bq   (i64.add (get_local $bq) (get_local $temp)))
				(set_local $temp (i64.extend_u/i32 (i64.lt_u (get_local $bq) (get_local $temp))))
				(set_local $bq   (i64.add (get_local $maskb) (get_local $bq)))
				(set_local $aq   (i64.add (get_local $maska) (i64.add (get_local $aq) (i64.or (i64.extend_u/i32 (i64.lt_u (get_local $bq) (get_local $maskb))) (get_local $temp)))))
			  )
			)
			;; divisor = divisor >> 1
			(set_local $d1 (i64.add (i64.shr_u (get_local $d1) (i64.const 1)) (i64.shl (get_local $c1) (i64.const 63))))
			(set_local $c1 (i64.add (i64.shr_u (get_local $c1) (i64.const 1)) (i64.shl (get_local $b1) (i64.const 63))))
			(set_local $b1 (i64.add (i64.shr_u (get_local $b1) (i64.const 1)) (i64.shl (get_local $a1) (i64.const 63))))
			(set_local $a1 (i64.shr_u (get_local $a1) (i64.const 1)))
	
			;; mask = mask >> 1
			(set_local $maskd (i64.add (i64.shr_u (get_local $maskd) (i64.const 1)) (i64.shl (get_local $maskc) (i64.const 63))))
			(set_local $maskc (i64.add (i64.shr_u (get_local $maskc) (i64.const 1)) (i64.shl (get_local $maskb) (i64.const 63))))
			(set_local $maskb (i64.add (i64.shr_u (get_local $maskb) (i64.const 1)) (i64.shl (get_local $maska) (i64.const 63))))
			(set_local $maska (i64.shr_u (get_local $maska) (i64.const 1)))
			(br $loop)
		  )
		)
	  );; end of main
	
	  (i64.store (i32.add (get_local $sp) (i32.const 24)) (get_local $aq))
	  (i64.store (i32.add (get_local $sp) (i32.const 16)) (get_local $bq))
	  (i64.store (i32.add (get_local $sp) (i32.const 8))  (get_local $cq))
	  (i64.store (get_local $sp) (get_local $dq))
	)
	(func $AND
	  (i64.store (i32.sub (get_global $sp) (i32.const 8))  (i64.and (i64.load (i32.sub (get_global $sp) (i32.const 8)))  (i64.load (i32.add (get_global $sp) (i32.const 24)))))
	  (i64.store (i32.sub (get_global $sp) (i32.const 16)) (i64.and (i64.load (i32.sub (get_global $sp) (i32.const 16))) (i64.load (i32.add (get_global $sp) (i32.const 16)))))
	  (i64.store (i32.sub (get_global $sp) (i32.const 24)) (i64.and (i64.load (i32.sub (get_global $sp) (i32.const 24))) (i64.load (i32.add (get_global $sp) (i32.const 8)))))
	  (i64.store (i32.sub (get_global $sp) (i32.const 32)) (i64.and (i64.load (i32.sub (get_global $sp) (i32.const 32))) (i64.load (get_global $sp))))
	)
	(func $LT
	  (local $sp i32)
	
	  (local $a0 i64)
	  (local $a1 i64)
	  (local $a2 i64)
	  (local $a3 i64)
	  (local $b0 i64)
	  (local $b1 i64)
	  (local $b2 i64)
	  (local $b3 i64)
	
	  (set_local $sp (get_global $sp))
	
	  ;; load args from the stack
	  (set_local $a0 (i64.load (i32.add (get_local $sp) (i32.const 24))))
	  (set_local $a1 (i64.load (i32.add (get_local $sp) (i32.const 16))))
	  (set_local $a2 (i64.load (i32.add (get_local $sp) (i32.const 8))))
	  (set_local $a3 (i64.load (get_local $sp)))
	
	  (set_local $sp (i32.sub (get_local $sp) (i32.const 32)))
	
	  (set_local $b0 (i64.load (i32.add (get_local $sp) (i32.const 24))))
	  (set_local $b1 (i64.load (i32.add (get_local $sp) (i32.const 16))))
	  (set_local $b2 (i64.load (i32.add (get_local $sp) (i32.const 8))))
	  (set_local $b3 (i64.load (get_local $sp)))
	
	  (i64.store (get_local $sp) (i64.extend_u/i32 
		(i32.or  (i64.lt_u (get_local $a0) (get_local $b0)) ;; a0 < b0
		(i32.and (i64.eq   (get_local $a0) (get_local $b0)) ;; a0 == b0
		(i32.or  (i64.lt_u (get_local $a1) (get_local $b1)) ;; a1 < b1
		(i32.and (i64.eq   (get_local $a1) (get_local $b1)) ;; a1 == b1
		(i32.or  (i64.lt_u (get_local $a2) (get_local $b2)) ;; a2 < b2
		(i32.and (i64.eq   (get_local $a2) (get_local $b2)) ;; a2 == b2
				 (i64.lt_u (get_local $a3) (get_local $b3)))))))))) ;; a3 < b3
	
	  ;; zero  out the rest of the stack item
	  (i64.store (i32.add (get_local $sp) (i32.const  8)) (i64.const 0))
	  (i64.store (i32.add (get_local $sp) (i32.const 16)) (i64.const 0))
	  (i64.store (i32.add (get_local $sp) (i32.const 24)) (i64.const 0))
	)
	(func $SUB
	  (local $sp i32)
	
	  (local $a i64)
	  (local $b i64)
	  (local $c i64)
	  (local $d i64)
	
	  (local $a1 i64)
	  (local $b1 i64)
	  (local $c1 i64)
	  (local $d1 i64)
	
	  (local $carry i64)
	  (local $temp i64)
	
	  (set_local $a (i64.load (i32.add (get_global $sp) (i32.const 24))))
	  (set_local $b (i64.load (i32.add (get_global $sp) (i32.const 16))))
	  (set_local $c (i64.load (i32.add (get_global $sp) (i32.const  8))))
	  (set_local $d (i64.load          (get_global $sp)))
	  ;; decement the stack pointer
	  (set_local $sp (i32.sub (get_global $sp) (i32.const 32)))
	
	  (set_local $a1 (i64.load (i32.add (get_local $sp) (i32.const 24))))
	  (set_local $b1 (i64.load (i32.add (get_local $sp) (i32.const 16))))
	  (set_local $c1 (i64.load (i32.add (get_local $sp) (i32.const  8))))
	  (set_local $d1 (i64.load          (get_local $sp)))
	
	  ;; a * 64^3 + b*64^2 + c*64 + d 
	  ;; d
	  (set_local $carry (i64.extend_u/i32 (i64.lt_u (get_local $d) (get_local $d1))))
	  (set_local $d (i64.sub (get_local $d) (get_local $d1)))
	
	  ;; c
	  (set_local $temp (i64.sub (get_local $c) (get_local $carry)))
	  (set_local $carry (i64.extend_u/i32 (i64.gt_u (get_local $temp) (get_local $c))))
	  (set_local $c (i64.sub (get_local $temp) (get_local $c1)))
	  (set_local $carry (i64.or (i64.extend_u/i32 (i64.gt_u (get_local $c) (get_local $temp))) (get_local $carry)))
	
	  ;; b
	  (set_local $temp (i64.sub (get_local $b) (get_local $carry)))
	  (set_local $carry (i64.extend_u/i32 (i64.gt_u (get_local $temp) (get_local $b))))
	  (set_local $b (i64.sub (get_local $temp) (get_local $b1)))
	
	  ;; a
	  (set_local $a (i64.sub (i64.sub (get_local $a) (i64.or (i64.extend_u/i32 (i64.gt_u (get_local $b) (get_local $temp))) (get_local $carry))) (get_local $a1)))
	
	  (i64.store (i32.add (get_local $sp) (i32.const 24)) (get_local $a))
	  (i64.store (i32.add (get_local $sp) (i32.const 16)) (get_local $b))
	  (i64.store (i32.add (get_local $sp) (i32.const  8)) (get_local $c))
	  (i64.store          (get_local $sp)                 (get_local $d))
	)
	(func $SHA3
	  (local $dataOffset i32)
	  (local $dataOffset0 i64)
	  (local $dataOffset1 i64)
	  (local $dataOffset2 i64)
	  (local $dataOffset3 i64)
	
	  (local $length i32)
	  (local $length0 i64)
	  (local $length1 i64)
	  (local $length2 i64)
	  (local $length3 i64)
	
	  (local $contextOffset i32)
	  (local $outputOffset i32)
	
	  (set_local $length0 (i64.load (i32.sub (get_global $sp) (i32.const 32))))
	  (set_local $length1 (i64.load (i32.sub (get_global $sp) (i32.const 24))))
	  (set_local $length2 (i64.load (i32.sub (get_global $sp) (i32.const 16))))
	  (set_local $length3 (i64.load (i32.sub (get_global $sp) (i32.const 8))))
	
	  (set_local $dataOffset0 (i64.load (i32.add (get_global $sp) (i32.const 0))))
	  (set_local $dataOffset1 (i64.load (i32.add (get_global $sp) (i32.const 8))))
	  (set_local $dataOffset2 (i64.load (i32.add (get_global $sp) (i32.const 16))))
	  (set_local $dataOffset3 (i64.load (i32.add (get_global $sp) (i32.const 24))))
	
	  (set_local $length 
				 (call $check_overflow (get_local $length0)
									   (get_local $length1)
									   (get_local $length2)
									   (get_local $length3)))
	  (set_local $dataOffset 
				 (call $check_overflow (get_local $dataOffset0)
									   (get_local $dataOffset1)
									   (get_local $dataOffset2)
									   (get_local $dataOffset3)))
	
	  ;; charge copy fee ceil(words/32) * 6 
	  (call $useGas (i64.extend_u/i32 (i32.mul (i32.div_u (i32.add (get_local $length) (i32.const 31)) (i32.const 32)) (i32.const 6))))
	  (call $memusegas (get_local $dataOffset) (get_local $length))
	
	  (set_local $dataOffset (i32.add (get_global $memstart) (get_local $dataOffset)))
	
	  (set_local $contextOffset (i32.const 32808))
	  (set_local $outputOffset (i32.sub (get_global $sp) (i32.const 32)))
	
	  (call $keccak (get_local $contextOffset) (get_local $dataOffset) (get_local $length) (get_local $outputOffset))
	
	  (drop (call $bswap_m256 (get_local $outputOffset)))
	)
	(func $MUL
	  (call $mul_256
			(i64.load (i32.add (get_global $sp) (i32.const 24)))
			(i64.load (i32.add (get_global $sp) (i32.const 16)))
			(i64.load (i32.add (get_global $sp) (i32.const  8)))
			(i64.load          (get_global $sp))
			(i64.load (i32.sub (get_global $sp) (i32.const  8)))
			(i64.load (i32.sub (get_global $sp) (i32.const 16)))
			(i64.load (i32.sub (get_global $sp) (i32.const 24)))
			(i64.load (i32.sub (get_global $sp) (i32.const 32)))
			(i32.sub (get_global $sp) (i32.const 8))
	  )
	)
	(func $NOT
	  ;; FIXME: consider using 0xffffffffffffffff instead of -1?
	  (i64.store (i32.add (get_global $sp) (i32.const 24)) (i64.xor (i64.load (i32.add (get_global $sp) (i32.const 24))) (i64.const -1)))
	  (i64.store (i32.add (get_global $sp) (i32.const 16)) (i64.xor (i64.load (i32.add (get_global $sp) (i32.const 16))) (i64.const -1)))
	  (i64.store (i32.add (get_global $sp) (i32.const  8)) (i64.xor (i64.load (i32.add (get_global $sp) (i32.const  8))) (i64.const -1)))
	  (i64.store (i32.add (get_global $sp) (i32.const  0)) (i64.xor (i64.load (i32.add (get_global $sp) (i32.const  0))) (i64.const -1)))
	)
	(func $OR
	  (i64.store (i32.sub (get_global $sp) (i32.const  8)) (i64.or (i64.load (i32.sub (get_global $sp) (i32.const  8))) (i64.load (i32.add (get_global $sp) (i32.const 24)))))
	  (i64.store (i32.sub (get_global $sp) (i32.const 16)) (i64.or (i64.load (i32.sub (get_global $sp) (i32.const 16))) (i64.load (i32.add (get_global $sp) (i32.const 16)))))
	  (i64.store (i32.sub (get_global $sp) (i32.const 24)) (i64.or (i64.load (i32.sub (get_global $sp) (i32.const 24))) (i64.load (i32.add (get_global $sp) (i32.const  8)))))
	  (i64.store (i32.sub (get_global $sp) (i32.const 32)) (i64.or (i64.load (i32.sub (get_global $sp) (i32.const 32))) (i64.load          (get_global $sp))))
	)
	;; generated by ./wasm/generateInterface.js
	(func $SLOAD   (call $storageLoad(call $bswap_m256 (get_global $sp))(get_global $sp))(drop (call $bswap_m256 (get_global $sp))))(func $GT
	  (local $sp i32)
	
	  (local $a0 i64)
	  (local $a1 i64)
	  (local $a2 i64)
	  (local $a3 i64)
	  (local $b0 i64)
	  (local $b1 i64)
	  (local $b2 i64)
	  (local $b3 i64)
	
	  (set_local $sp (get_global $sp))
	
	  ;; load args from the stack
	  (set_local $a0 (i64.load (i32.add (get_local $sp) (i32.const 24))))
	  (set_local $a1 (i64.load (i32.add (get_local $sp) (i32.const 16))))
	  (set_local $a2 (i64.load (i32.add (get_local $sp) (i32.const 8))))
	  (set_local $a3 (i64.load (get_local $sp)))
	
	  (set_local $sp (i32.sub (get_local $sp) (i32.const 32)))
	
	  (set_local $b0 (i64.load (i32.add (get_local $sp) (i32.const 24))))
	  (set_local $b1 (i64.load (i32.add (get_local $sp) (i32.const 16))))
	  (set_local $b2 (i64.load (i32.add (get_local $sp) (i32.const 8))))
	  (set_local $b3 (i64.load (get_local $sp)))
	
	  (i64.store (get_local $sp) (i64.extend_u/i32 
		(i32.or (i64.gt_u (get_local $a0) (get_local $b0)) ;; a0 > b0
		(i32.and (i64.eq   (get_local $a0) (get_local $b0)) ;; a0 == a1
		(i32.or  (i64.gt_u (get_local $a1) (get_local $b1)) ;; a1 > b1
		(i32.and (i64.eq   (get_local $a1) (get_local $b1)) ;; a1 == b1
		(i32.or  (i64.gt_u (get_local $a2) (get_local $b2)) ;; a2 > b2
		(i32.and (i64.eq   (get_local $a2) (get_local $b2)) ;; a2 == b2
				 (i64.gt_u (get_local $a3) (get_local $b3)))))))))) ;; a3 > b3
	
	  ;; zero  out the rest of the stack item
	  (i64.store (i32.add (get_local $sp) (i32.const  8)) (i64.const 0))
	  (i64.store (i32.add (get_local $sp) (i32.const 16)) (i64.const 0))
	  (i64.store (i32.add (get_local $sp) (i32.const 24)) (i64.const 0))
	)
	(func $EQ
	  (local $sp i32)
	
	  (set_local $sp (i32.sub (get_global $sp) (i32.const 32)))
	  (i64.store (get_local $sp)
		(i64.extend_u/i32
		  (i32.and (i64.eq   (i64.load (i32.add (get_local $sp) (i32.const 56))) (i64.load (i32.add (get_local $sp) (i32.const 24))))
		  (i32.and (i64.eq   (i64.load (i32.add (get_local $sp) (i32.const 48))) (i64.load (i32.add (get_local $sp) (i32.const 16))))
		  (i32.and (i64.eq   (i64.load (i32.add (get_local $sp) (i32.const 40))) (i64.load (i32.add (get_local $sp) (i32.const  8))))
				   (i64.eq   (i64.load (i32.add (get_local $sp) (i32.const 32))) (i64.load          (get_local $sp))))))))
	
	  (i64.store (i32.add (get_local $sp) (i32.const 24)) (i64.const 0))
	  (i64.store (i32.add (get_local $sp) (i32.const 16)) (i64.const 0))
	  (i64.store (i32.add (get_local $sp) (i32.const  8)) (i64.const 0))
	)
	;; generated by ./wasm/generateInterface.js
	(func $CODECOPY (local $offset0 i32)(local $length0 i32) (set_local $offset0 (call $check_overflow
			  (i64.load (get_global $sp))
			  (i64.load (i32.add (get_global $sp) (i32.const 8)))
			  (i64.load (i32.add (get_global $sp) (i32.const 16)))
			  (i64.load (i32.add (get_global $sp) (i32.const 24)))))(set_local $length0 (call $check_overflow
			  (i64.load (i32.add (get_global $sp) (i32.const -64)))
			  (i64.load (i32.add (get_global $sp) (i32.const -56)))
			  (i64.load (i32.add (get_global $sp) (i32.const -48)))
			  (i64.load (i32.add (get_global $sp) (i32.const -40)))))
		(call $memusegas (get_local $offset0) (get_local $length0))
		(set_local $offset0 (i32.add (get_global $memstart) (get_local $offset0))) (call $codeCopy(get_local $offset0)(call $check_overflow
			  (i64.load (i32.add (get_global $sp) (i32.const -32)))
			  (i64.load (i32.add (get_global $sp) (i32.const -24)))
			  (i64.load (i32.add (get_global $sp) (i32.const -16)))
			  (i64.load (i32.add (get_global $sp) (i32.const -8))))(get_local $length0)));; generated by ./wasm/generateInterface.js
	(func $RETURN (local $offset0 i32)(local $length0 i32) (set_local $offset0 (call $check_overflow
			  (i64.load (get_global $sp))
			  (i64.load (i32.add (get_global $sp) (i32.const 8)))
			  (i64.load (i32.add (get_global $sp) (i32.const 16)))
			  (i64.load (i32.add (get_global $sp) (i32.const 24)))))(set_local $length0 (call $check_overflow
			  (i64.load (i32.add (get_global $sp) (i32.const -32)))
			  (i64.load (i32.add (get_global $sp) (i32.const -24)))
			  (i64.load (i32.add (get_global $sp) (i32.const -16)))
			  (i64.load (i32.add (get_global $sp) (i32.const -8)))))
		(call $memusegas (get_local $offset0) (get_local $length0))
		(set_local $offset0 (i32.add (get_global $memstart) (get_local $offset0))) (call $finish(get_local $offset0)(get_local $length0)));; generated by ./wasm/generateInterface.js
	(func $CALLDATASIZE   (i64.store (i32.add (get_global $sp) (i32.const 32)) (i64.extend_u/i32 (call $getCallDataSize)))
		;; zero out mem
		(i64.store (i32.add (get_global $sp) (i32.const 56)) (i64.const 0))
		(i64.store (i32.add (get_global $sp) (i32.const 48)) (i64.const 0))
		(i64.store (i32.add (get_global $sp) (i32.const 40)) (i64.const 0)));; generated by ./wasm/generateInterface.js
	(func $CALLER   (call $getCaller(i32.add (get_global $sp) (i32.const 32)))(drop (call $bswap_m160 (i32.add (get_global $sp) (i32.const 32))))
		;; zero out mem
		(i64.store (i32.add (get_global $sp) (i32.const 56)) (i64.const 0))
		(i32.store (i32.add (get_global $sp) (i32.const 52)) (i32.const 0)))(func $LOG
	  (param $number i32)
	
	  (local $offset i32)
	  (local $offset0 i64)
	  (local $offset1 i64)
	  (local $offset2 i64)
	  (local $offset3 i64)
	
	  (local $length i32)
	  (local $length0 i64)
	  (local $length1 i64)
	  (local $length2 i64)
	  (local $length3 i64)
	
	  (set_local $offset0 (i64.load          (get_global $sp)))
	  (set_local $offset1 (i64.load (i32.add (get_global $sp) (i32.const  8))))
	  (set_local $offset2 (i64.load (i32.add (get_global $sp) (i32.const 16))))
	  (set_local $offset3 (i64.load (i32.add (get_global $sp) (i32.const 24))))
	
	  (set_local $length0 (i64.load (i32.sub (get_global $sp) (i32.const 32))))
	  (set_local $length1 (i64.load (i32.sub (get_global $sp) (i32.const 24))))
	  (set_local $length2 (i64.load (i32.sub (get_global $sp) (i32.const 16))))
	  (set_local $length3 (i64.load (i32.sub (get_global $sp) (i32.const  8))))
	
	  (set_local $offset 
				 (call $check_overflow (get_local $offset0)
									   (get_local $offset1)
									   (get_local $offset2)
									   (get_local $offset3)))
	
	  (set_local $length
				 (call $check_overflow (get_local $length0)
									   (get_local $length1)
									   (get_local $length2)
									   (get_local $length3)))
	
	  (call $memusegas (get_local $offset) (get_local $length))
	
	  (call $log 
				 (get_local $offset)
				 (get_local $length)
				 (get_local $number)
				 (i32.sub (get_global $sp) (i32.const  64))
				 (i32.sub (get_global $sp) (i32.const  96))
				 (i32.sub (get_global $sp) (i32.const 128))
				 (i32.sub (get_global $sp) (i32.const 160)))
	)
	;; stack:
	;;  0: dataOffset
	(func $CALLDATALOAD
	  (local $writeOffset i32)
	  (local $writeOffset0 i64)
	  (local $writeOffset1 i64)
	  (local $writeOffset2 i64)
	  (local $writeOffset3 i64)
	
	  (set_local $writeOffset0 (i64.load (i32.add (get_global $sp) (i32.const  0))))
	  (set_local $writeOffset1 (i64.load (i32.add (get_global $sp) (i32.const  8))))
	  (set_local $writeOffset2 (i64.load (i32.add (get_global $sp) (i32.const 16))))
	  (set_local $writeOffset3 (i64.load (i32.add (get_global $sp) (i32.const 24))))
	
	  (i64.store (i32.add (get_global $sp) (i32.const  0)) (i64.const 0))
	  (i64.store (i32.add (get_global $sp) (i32.const  8)) (i64.const 0))
	  (i64.store (i32.add (get_global $sp) (i32.const 16)) (i64.const 0))
	  (i64.store (i32.add (get_global $sp) (i32.const 24)) (i64.const 0))
	
	  (set_local $writeOffset
				 (call $check_overflow (get_local $writeOffset0)
									   (get_local $writeOffset1)
									   (get_local $writeOffset2)
									   (get_local $writeOffset3)))
	
	  (call $callDataCopy (get_global $sp) (get_local $writeOffset) (i32.const 32))
	  ;; swap top stack item
	  (drop (call $bswap_m256 (get_global $sp)))
	)
	(func $SLT
	  (local $sp i32)
	
	  (local $a0 i64)
	  (local $a1 i64)
	  (local $a2 i64)
	  (local $a3 i64)
	  (local $b0 i64)
	  (local $b1 i64)
	  (local $b2 i64)
	  (local $b3 i64)
	
	  ;; load args from the stack
	  (set_local $a0 (i64.load (i32.add (get_global $sp) (i32.const 24))))
	  (set_local $a1 (i64.load (i32.add (get_global $sp) (i32.const 16))))
	  (set_local $a2 (i64.load (i32.add (get_global $sp) (i32.const 8))))
	  (set_local $a3 (i64.load (get_global $sp)))
	
	  (set_local $sp (i32.sub (get_global $sp) (i32.const 32)))
	
	  (set_local $b0 (i64.load (i32.add (get_local $sp) (i32.const 24))))
	  (set_local $b1 (i64.load (i32.add (get_local $sp) (i32.const 16))))
	  (set_local $b2 (i64.load (i32.add (get_local $sp) (i32.const 8))))
	  (set_local $b3 (i64.load (get_local $sp)))
	
	  (i64.store (get_local $sp) (i64.extend_u/i32 
		(i32.or  (i64.lt_s (get_local $a0) (get_local $b0)) ;; a0 < b0
		(i32.and (i64.eq   (get_local $a0) (get_local $b0)) ;; a0 == b0
		(i32.or  (i64.lt_u (get_local $a1) (get_local $b1)) ;; a1 < b1
		(i32.and (i64.eq   (get_local $a1) (get_local $b1)) ;; a1 == b1
		(i32.or  (i64.lt_u (get_local $a2) (get_local $b2)) ;; a2 < b2
		(i32.and (i64.eq   (get_local $a2) (get_local $b2)) ;; a2 == b2
				 (i64.lt_u (get_local $a3) (get_local $b3)))))))))) ;; a3 < b3
	
	  ;; zero  out the rest of the stack item
	  (i64.store (i32.add (get_local $sp) (i32.const  8)) (i64.const 0))
	  (i64.store (i32.add (get_local $sp) (i32.const 16)) (i64.const 0))
	  (i64.store (i32.add (get_local $sp) (i32.const 24)) (i64.const 0))
	)
	(func $memusegas
	  (param $offset i32)
	  (param $length i32)
	
	  (local $cost i64)
	  ;; the number of new words being allocated
	  (local $newWordCount i64)
	
	  (if (i32.eqz (get_local $length))
		(then (return))
	  )
	
	  ;; const newMemoryWordCount = Math.ceil[[offset + length] / 32]
	  (set_local $newWordCount 
		(i64.div_u (i64.add (i64.const 31) (i64.add (i64.extend_u/i32 (get_local $offset)) (i64.extend_u/i32 (get_local $length))))
				   (i64.const 32)))
	
	  ;;if [runState.highestMem >= highestMem]  return
	  (if (i64.le_u (get_local $newWordCount) (get_global $wordCount))
		(then (return))
	  )
	
	  ;; words * 3 + words ^2 / 512
	  (set_local $cost
		 (i64.add
		   (i64.mul (get_local $newWordCount) (i64.const 3))
		   (i64.div_u
			 (i64.mul (get_local $newWordCount)
					  (get_local $newWordCount))
			 (i64.const 512))))
	
	  (call $useGas  (i64.sub (get_local $cost) (get_global $prevMemCost)))
	  (set_global $prevMemCost (get_local $cost))
	  (set_global $wordCount (get_local $newWordCount))
	
	  ;; grow actual memory
	  ;; the first 31704 bytes are guaranteed to be available
	  ;; adjust for 32 bytes  - the maximal size of MSTORE write
	  ;; TODO it should be current_memory * page_size
	  (set_local $offset (i32.add (get_local $length) (i32.add (get_local $offset) (get_global $memstart))))
	  (if (i32.gt_u (get_local $offset) (i32.mul (i32.const 65536) (current_memory)))
		(then
		  (drop (grow_memory
			(i32.div_u (i32.add (i32.const 65535) (i32.sub (get_local $offset) (current_memory))) (i32.const 65536))))
		)
	  )
	)
	(func $bswap_m256
	  (param $sp i32)
	  (result i32)
	  (local $temp i64)
	
	  (set_local $temp (call $bswap_i64 (i64.load (get_local $sp))))
	  (i64.store (get_local $sp) (call $bswap_i64 (i64.load (i32.add (get_local $sp) (i32.const 24)))))
	  (i64.store (i32.add (get_local $sp) (i32.const 24)) (get_local $temp))
	
	  (set_local $temp (call $bswap_i64 (i64.load (i32.add (get_local $sp) (i32.const 8)))))
	  (i64.store (i32.add (get_local $sp) (i32.const  8)) (call $bswap_i64 (i64.load (i32.add (get_local $sp) (i32.const 16)))))
	  (i64.store (i32.add (get_local $sp) (i32.const 16)) (get_local $temp))
	  (get_local $sp)
	)
	(func $callback
	  (call $main)
	)
	(func $bswap_m128
	  (param $sp i32)
	  (result i32)
	  (local $temp i64)
	
	  (set_local $temp (call $bswap_i64 (i64.load (get_local $sp))))
	  (i64.store (get_local $sp) (call $bswap_i64 (i64.load (i32.add (get_local $sp) (i32.const 8)))))
	  (i64.store (i32.add (get_local $sp) (i32.const 8)) (get_local $temp))
	  (get_local $sp)
	)
	(func $iszero_256
	  (param i64)
	  (param i64)
	  (param i64)
	  (param i64)
	  (result i32)
	
	  (i64.eqz (i64.or (i64.or (i64.or (get_local 0) (get_local 1)) (get_local 2)) (get_local 3))) 
	)
	;; is a less than or equal to b // a >= b
	(func $gte_256
	  (param $a0 i64)
	  (param $a1 i64)
	  (param $a2 i64)
	  (param $a3 i64)
	
	  (param $b0 i64)
	  (param $b1 i64)
	  (param $b2 i64)
	  (param $b3 i64)
	
	  (result i32)
	
	  ;; a0 > b0 || [a0 == b0 && [a1 > b1 || [a1 == b1 && [a2 > b2 || [a2 == b2 && a3 >= b3 ]]]]
	  (i32.or  (i64.gt_u (get_local $a0) (get_local $b0)) ;; a0 > b0
	  (i32.and (i64.eq   (get_local $a0) (get_local $b0))
	  (i32.or  (i64.gt_u (get_local $a1) (get_local $b1)) ;; a1 > b1
	  (i32.and (i64.eq   (get_local $a1) (get_local $b1)) ;; a1 == b1
	  (i32.or  (i64.gt_u (get_local $a2) (get_local $b2)) ;; a2 > b2
	  (i32.and (i64.eq   (get_local $a2) (get_local $b2))
			   (i64.ge_u (get_local $a3) (get_local $b3))))))))
	)
	;;
	;; Copied from https://github.com/axic/keccak-wasm (has more comments)
	;;
	
	(func $keccak_theta
	  (param $context_offset i32)
	
	  (local $C0 i64)
	  (local $C1 i64)
	  (local $C2 i64)
	  (local $C3 i64)
	  (local $C4 i64)
	  (local $D0 i64)
	  (local $D1 i64)
	  (local $D2 i64)
	  (local $D3 i64)
	  (local $D4 i64)
	
	  ;; C[x] = A[x] ^ A[x + 5] ^ A[x + 10] ^ A[x + 15] ^ A[x + 20];
	  (set_local $C0
		(i64.xor
		  (i64.load (i32.add (get_local $context_offset) (i32.const 0)))
		  (i64.xor
			(i64.load (i32.add (get_local $context_offset) (i32.const 40)))
			(i64.xor
			  (i64.load (i32.add (get_local $context_offset) (i32.const 80)))
			  (i64.xor
				(i64.load (i32.add (get_local $context_offset) (i32.const 120)))
				(i64.load (i32.add (get_local $context_offset) (i32.const 160)))
			  )
			)
		  )
		)
	  )
	
	  (set_local $C1
		(i64.xor
		  (i64.load (i32.add (get_local $context_offset) (i32.const 8)))
		  (i64.xor
			(i64.load (i32.add (get_local $context_offset) (i32.const 48)))
			(i64.xor
			  (i64.load (i32.add (get_local $context_offset) (i32.const 88)))
			  (i64.xor
				(i64.load (i32.add (get_local $context_offset) (i32.const 128)))
				(i64.load (i32.add (get_local $context_offset) (i32.const 168)))
			  )
			)
		  )
		)
	  )
	
	  (set_local $C2
		(i64.xor
		  (i64.load (i32.add (get_local $context_offset) (i32.const 16)))
		  (i64.xor
			(i64.load (i32.add (get_local $context_offset) (i32.const 56)))
			(i64.xor
			  (i64.load (i32.add (get_local $context_offset) (i32.const 96)))
			  (i64.xor
				(i64.load (i32.add (get_local $context_offset) (i32.const 136)))
				(i64.load (i32.add (get_local $context_offset) (i32.const 176)))
			  )
			)
		  )
		)
	  )
	
	  (set_local $C3
		(i64.xor
		  (i64.load (i32.add (get_local $context_offset) (i32.const 24)))
		  (i64.xor
			(i64.load (i32.add (get_local $context_offset) (i32.const 64)))
			(i64.xor
			  (i64.load (i32.add (get_local $context_offset) (i32.const 104)))
			  (i64.xor
				(i64.load (i32.add (get_local $context_offset) (i32.const 144)))
				(i64.load (i32.add (get_local $context_offset) (i32.const 184)))
			  )
			)
		  )
		)
	  )
	
	  (set_local $C4
		(i64.xor
		  (i64.load (i32.add (get_local $context_offset) (i32.const 32)))
		  (i64.xor
			(i64.load (i32.add (get_local $context_offset) (i32.const 72)))
			(i64.xor
			  (i64.load (i32.add (get_local $context_offset) (i32.const 112)))
			  (i64.xor
				(i64.load (i32.add (get_local $context_offset) (i32.const 152)))
				(i64.load (i32.add (get_local $context_offset) (i32.const 192)))
			  )
			)
		  )
		)
	  )
	
	  ;; D[0] = ROTL64(C[1], 1) ^ C[4];
	  (set_local $D0
		(i64.xor
		  (get_local $C4)
		  (i64.rotl
			(get_local $C1)
			(i64.const 1)
		  )
		)
	  )
	
	  ;; D[1] = ROTL64(C[2], 1) ^ C[0];
	  (set_local $D1
		(i64.xor
		  (get_local $C0)
		  (i64.rotl
			(get_local $C2)
			(i64.const 1)
		  )
		)
	  )
	
	  ;; D[2] = ROTL64(C[3], 1) ^ C[1];
	  (set_local $D2
		(i64.xor
		  (get_local $C1)
		  (i64.rotl
			(get_local $C3)
			(i64.const 1)
		  )
		)
	  )
	
	  ;; D[3] = ROTL64(C[4], 1) ^ C[2];
	  (set_local $D3
		(i64.xor
		  (get_local $C2)
		  (i64.rotl
			(get_local $C4)
			(i64.const 1)
		  )
		)
	  )
	
	  ;; D[4] = ROTL64(C[0], 1) ^ C[3];
	  (set_local $D4
		(i64.xor
		  (get_local $C3)
		  (i64.rotl
			(get_local $C0)
			(i64.const 1)
		  )
		)
	  )
	
	  ;; A[x]      ^= D[x];
	  ;; A[x + 5]  ^= D[x];
	  ;; A[x + 10] ^= D[x];
	  ;; A[x + 15] ^= D[x];
	  ;; A[x + 20] ^= D[x];
	  
	  ;; x = 0
	  (i64.store (i32.add (get_local $context_offset) (i32.const 0))
		(i64.xor
		  (i64.load (i32.add (get_local $context_offset) (i32.const 0)))
		  (get_local $D0)
		)
	  )
	
	  (i64.store (i32.add (get_local $context_offset) (i32.const 40))
		(i64.xor
		  (i64.load (i32.add (get_local $context_offset) (i32.const 40)))
		  (get_local $D0)
		)
	  )
	
	  (i64.store (i32.add (get_local $context_offset) (i32.const 80))
		(i64.xor
		  (i64.load (i32.add (get_local $context_offset) (i32.const 80)))
		  (get_local $D0)
		)
	  )
	
	  (i64.store (i32.add (get_local $context_offset) (i32.const 120))
		(i64.xor
		  (i64.load (i32.add (get_local $context_offset) (i32.const 120)))
		  (get_local $D0)
		)
	  )
	
	  (i64.store (i32.add (get_local $context_offset) (i32.const 160))
		(i64.xor
		  (i64.load (i32.add (get_local $context_offset) (i32.const 160)))
		  (get_local $D0)
		)
	  )
	
	  ;; x = 1
	  (i64.store (i32.add (get_local $context_offset) (i32.const 8))
		(i64.xor
		  (i64.load (i32.add (get_local $context_offset) (i32.const 8)))
		  (get_local $D1)
		)
	  )
	
	  (i64.store (i32.add (get_local $context_offset) (i32.const 48))
		(i64.xor
		  (i64.load (i32.add (get_local $context_offset) (i32.const 48)))
		  (get_local $D1)
		)
	  )
	
	  (i64.store (i32.add (get_local $context_offset) (i32.const 88))
		(i64.xor
		  (i64.load (i32.add (get_local $context_offset) (i32.const 88)))
		  (get_local $D1)
		)
	  )
	
	  (i64.store (i32.add (get_local $context_offset) (i32.const 128))
		(i64.xor
		  (i64.load (i32.add (get_local $context_offset) (i32.const 128)))
		  (get_local $D1)
		)
	  )
	
	  (i64.store (i32.add (get_local $context_offset) (i32.const 168))
		(i64.xor
		  (i64.load (i32.add (get_local $context_offset) (i32.const 168)))
		  (get_local $D1)
		)
	  )
	
	  ;; x = 2
	  (i64.store (i32.add (get_local $context_offset) (i32.const 16))
		(i64.xor
		  (i64.load (i32.add (get_local $context_offset) (i32.const 16)))
		  (get_local $D2)
		)
	  )
	
	  (i64.store (i32.add (get_local $context_offset) (i32.const 56))
		(i64.xor
		  (i64.load (i32.add (get_local $context_offset) (i32.const 56)))
		  (get_local $D2)
		)
	  )
	
	  (i64.store (i32.add (get_local $context_offset) (i32.const 96))
		(i64.xor
		  (i64.load (i32.add (get_local $context_offset) (i32.const 96)))
		  (get_local $D2)
		)
	  )
	
	  (i64.store (i32.add (get_local $context_offset) (i32.const 136))
		(i64.xor
		  (i64.load (i32.add (get_local $context_offset) (i32.const 136)))
		  (get_local $D2)
		)
	  )
	
	  (i64.store (i32.add (get_local $context_offset) (i32.const 176))
		(i64.xor
		  (i64.load (i32.add (get_local $context_offset) (i32.const 176)))
		  (get_local $D2)
		)
	  )
	
	  ;; x = 3
	  (i64.store (i32.add (get_local $context_offset) (i32.const 24))
		(i64.xor
		  (i64.load (i32.add (get_local $context_offset) (i32.const 24)))
		  (get_local $D3)
		)
	  )
	
	  (i64.store (i32.add (get_local $context_offset) (i32.const 64))
		(i64.xor
		  (i64.load (i32.add (get_local $context_offset) (i32.const 64)))
		  (get_local $D3)
		)
	  )
	
	  (i64.store (i32.add (get_local $context_offset) (i32.const 104))
		(i64.xor
		  (i64.load (i32.add (get_local $context_offset) (i32.const 104)))
		  (get_local $D3)
		)
	  )
	
	  (i64.store (i32.add (get_local $context_offset) (i32.const 144))
		(i64.xor
		  (i64.load (i32.add (get_local $context_offset) (i32.const 144)))
		  (get_local $D3)
		)
	  )
	
	  (i64.store (i32.add (get_local $context_offset) (i32.const 184))
		(i64.xor
		  (i64.load (i32.add (get_local $context_offset) (i32.const 184)))
		  (get_local $D3)
		)
	  )
	
	  ;; x = 4
	  (i64.store (i32.add (get_local $context_offset) (i32.const 32))
		(i64.xor
		  (i64.load (i32.add (get_local $context_offset) (i32.const 32)))
		  (get_local $D4)
		)
	  )
	
	  (i64.store (i32.add (get_local $context_offset) (i32.const 72))
		(i64.xor
		  (i64.load (i32.add (get_local $context_offset) (i32.const 72)))
		  (get_local $D4)
		)
	  )
	
	  (i64.store (i32.add (get_local $context_offset) (i32.const 112))
		(i64.xor
		  (i64.load (i32.add (get_local $context_offset) (i32.const 112)))
		  (get_local $D4)
		)
	  )
	
	  (i64.store (i32.add (get_local $context_offset) (i32.const 152))
		(i64.xor
		  (i64.load (i32.add (get_local $context_offset) (i32.const 152)))
		  (get_local $D4)
		)
	  )
	
	  (i64.store (i32.add (get_local $context_offset) (i32.const 192))
		(i64.xor
		  (i64.load (i32.add (get_local $context_offset) (i32.const 192)))
		  (get_local $D4)
		)
	  )
	)
	
	(func $keccak_rho
	  (param $context_offset i32)
	  (param $rotation_consts i32)
	
	  ;;(local $tmp i32)
	
	  ;; state[ 1] = ROTL64(state[ 1],  1);
	  ;;(set_local $tmp (i32.add (get_local $context_offset) (i32.const 1)))
	  ;;(i64.store (get_local $tmp) (i64.rotl (i64.load (get_local $context_offset)) (i64.const 1)))
	
	  ;;(set_local $tmp (i32.add (get_local $context_offset) (i32.const 2)))
	  ;;(i64.store (get_local $tmp) (i64.rotl (i64.load (get_local $context_offset)) (i64.const 62)))
	
	  (local $tmp i32)
	  (local $i i32)
	
	  ;; for (i = 0; i <= 24; i++)
	  (set_local $i (i32.const 0))
	  (block $done
		(loop $loop
		  (if (i32.ge_u (get_local $i) (i32.const 24))
			(br $done)
		  )
	
		  (set_local $tmp (i32.add (get_local $context_offset) (i32.mul (i32.const 8) (i32.add (i32.const 1) (get_local $i)))))
	
		  (i64.store (get_local $tmp) (i64.rotl (i64.load (get_local $tmp)) (i64.load8_u (i32.add (get_local $rotation_consts) (get_local $i)))))
	
		  (set_local $i (i32.add (get_local $i) (i32.const 1)))
		  (br $loop)
		)
	  )
	)
	
	(func $keccak_pi
	  (param $context_offset i32)
	
	  (local $A1 i64)
	  (set_local $A1 (i64.load (i32.add (get_local $context_offset) (i32.const 8))))
	
	  ;; Swap non-overlapping fields, i.e. $A1 = $A6, etc.
	  ;; NOTE: $A0 is untouched
	  (i64.store (i32.add (get_local $context_offset) (i32.const 8)) (i64.load (i32.add (get_local $context_offset) (i32.const 48))))
	  (i64.store (i32.add (get_local $context_offset) (i32.const 48)) (i64.load (i32.add (get_local $context_offset) (i32.const 72))))
	  (i64.store (i32.add (get_local $context_offset) (i32.const 72)) (i64.load (i32.add (get_local $context_offset) (i32.const 176))))
	  (i64.store (i32.add (get_local $context_offset) (i32.const 176)) (i64.load (i32.add (get_local $context_offset) (i32.const 112))))
	  (i64.store (i32.add (get_local $context_offset) (i32.const 112)) (i64.load (i32.add (get_local $context_offset) (i32.const 160))))
	  (i64.store (i32.add (get_local $context_offset) (i32.const 160)) (i64.load (i32.add (get_local $context_offset) (i32.const 16))))
	  (i64.store (i32.add (get_local $context_offset) (i32.const 16)) (i64.load (i32.add (get_local $context_offset) (i32.const 96))))
	  (i64.store (i32.add (get_local $context_offset) (i32.const 96)) (i64.load (i32.add (get_local $context_offset) (i32.const 104))))
	  (i64.store (i32.add (get_local $context_offset) (i32.const 104)) (i64.load (i32.add (get_local $context_offset) (i32.const 152))))
	  (i64.store (i32.add (get_local $context_offset) (i32.const 152)) (i64.load (i32.add (get_local $context_offset) (i32.const 184))))
	  (i64.store (i32.add (get_local $context_offset) (i32.const 184)) (i64.load (i32.add (get_local $context_offset) (i32.const 120))))
	  (i64.store (i32.add (get_local $context_offset) (i32.const 120)) (i64.load (i32.add (get_local $context_offset) (i32.const 32))))
	  (i64.store (i32.add (get_local $context_offset) (i32.const 32)) (i64.load (i32.add (get_local $context_offset) (i32.const 192))))
	  (i64.store (i32.add (get_local $context_offset) (i32.const 192)) (i64.load (i32.add (get_local $context_offset) (i32.const 168))))
	  (i64.store (i32.add (get_local $context_offset) (i32.const 168)) (i64.load (i32.add (get_local $context_offset) (i32.const 64))))
	  (i64.store (i32.add (get_local $context_offset) (i32.const 64)) (i64.load (i32.add (get_local $context_offset) (i32.const 128))))
	  (i64.store (i32.add (get_local $context_offset) (i32.const 128)) (i64.load (i32.add (get_local $context_offset) (i32.const 40))))
	  (i64.store (i32.add (get_local $context_offset) (i32.const 40)) (i64.load (i32.add (get_local $context_offset) (i32.const 24))))
	  (i64.store (i32.add (get_local $context_offset) (i32.const 24)) (i64.load (i32.add (get_local $context_offset) (i32.const 144))))
	  (i64.store (i32.add (get_local $context_offset) (i32.const 144)) (i64.load (i32.add (get_local $context_offset) (i32.const 136))))
	  (i64.store (i32.add (get_local $context_offset) (i32.const 136)) (i64.load (i32.add (get_local $context_offset) (i32.const 88))))
	  (i64.store (i32.add (get_local $context_offset) (i32.const 88)) (i64.load (i32.add (get_local $context_offset) (i32.const 56))))
	  (i64.store (i32.add (get_local $context_offset) (i32.const 56)) (i64.load (i32.add (get_local $context_offset) (i32.const 80))))
	
	  ;; Place the previously saved overlapping field
	  (i64.store (i32.add (get_local $context_offset) (i32.const 80)) (get_local $A1))
	)
	
	(func $keccak_chi
	  (param $context_offset i32)
	
	  (local $A0 i64)
	  (local $A1 i64)
	  (local $i i32)
	
	  ;; for (round = 0; round < 25; i += 5)
	  (set_local $i (i32.const 0))
	  (block $done
		(loop $loop
		  (if (i32.ge_u (get_local $i) (i32.const 25))
			(br $done)
		  )
	
		  (set_local $A0 (i64.load (i32.add (get_local $context_offset) (i32.mul (i32.const 8) (get_local $i)))))
		  (set_local $A1 (i64.load (i32.add (get_local $context_offset) (i32.mul (i32.const 8) (i32.add (get_local $i) (i32.const 1))))))
	
		  ;; A[0 + i] ^= ~A1 & A[2 + i];
		  (i64.store (i32.add (get_local $context_offset) (i32.mul (i32.const 8) (get_local $i)))
			(i64.xor
			  (i64.load (i32.add (get_local $context_offset) (i32.mul (i32.const 8) (get_local $i))))
			  (i64.and
				(i64.xor (get_local $A1) (i64.const 0xFFFFFFFFFFFFFFFF)) ;; bitwise not
				(i64.load (i32.add (get_local $context_offset) (i32.mul (i32.const 8) (i32.add (get_local $i) (i32.const 2)))))
			  )
			)
		  )
	
		  ;; A[1 + i] ^= ~A[2 + i] & A[3 + i];
		  (i64.store (i32.add (get_local $context_offset) (i32.mul (i32.const 8) (i32.add (get_local $i) (i32.const 1))))
			(i64.xor
			  (i64.load (i32.add (get_local $context_offset) (i32.mul (i32.const 8) (i32.add (get_local $i) (i32.const 1)))))
			  (i64.and
				(i64.xor (i64.load (i32.add (get_local $context_offset) (i32.mul (i32.const 8) (i32.add (get_local $i) (i32.const 2))))) (i64.const 0xFFFFFFFFFFFFFFFF)) ;; bitwise not
				(i64.load (i32.add (get_local $context_offset) (i32.mul (i32.const 8) (i32.add (get_local $i) (i32.const 3)))))
			  )
			)
		  )
	
		  ;; A[2 + i] ^= ~A[3 + i] & A[4 + i];
		  (i64.store (i32.add (get_local $context_offset) (i32.mul (i32.const 8) (i32.add (get_local $i) (i32.const 2))))
			(i64.xor
			  (i64.load (i32.add (get_local $context_offset) (i32.mul (i32.const 8) (i32.add (get_local $i) (i32.const 2)))))
			  (i64.and
				(i64.xor (i64.load (i32.add (get_local $context_offset) (i32.mul (i32.const 8) (i32.add (get_local $i) (i32.const 3))))) (i64.const 0xFFFFFFFFFFFFFFFF)) ;; bitwise not
				(i64.load (i32.add (get_local $context_offset) (i32.mul (i32.const 8) (i32.add (get_local $i) (i32.const 4)))))
			  )
			)
		  )
	
		  ;; A[3 + i] ^= ~A[4 + i] & A0;
		  (i64.store (i32.add (get_local $context_offset) (i32.mul (i32.const 8) (i32.add (get_local $i) (i32.const 3))))
			(i64.xor
			  (i64.load (i32.add (get_local $context_offset) (i32.mul (i32.const 8) (i32.add (get_local $i) (i32.const 3)))))
			  (i64.and
				(i64.xor (i64.load (i32.add (get_local $context_offset) (i32.mul (i32.const 8) (i32.add (get_local $i) (i32.const 4))))) (i64.const 0xFFFFFFFFFFFFFFFF)) ;; bitwise not
				(get_local $A0)
			  )
			)
		  )
	
		  ;; A[4 + i] ^= ~A0 & A1;
		  (i64.store (i32.add (get_local $context_offset) (i32.mul (i32.const 8) (i32.add (get_local $i) (i32.const 4))))
			(i64.xor
			  (i64.load (i32.add (get_local $context_offset) (i32.mul (i32.const 8) (i32.add (get_local $i) (i32.const 4)))))
			  (i64.and
				(i64.xor (get_local $A0) (i64.const 0xFFFFFFFFFFFFFFFF)) ;; bitwise not
				(get_local $A1)
			  )
			)
		  )
	
		  (set_local $i (i32.add (get_local $i) (i32.const 5)))
		  (br $loop)
		)
	  )
	)
	
	(func $keccak_permute
	  (param $context_offset i32)
	
	  (local $rotation_consts i32)
	  (local $round_consts i32)
	  (local $round i32)
	
	  (set_local $round_consts (i32.add (get_local $context_offset) (i32.const 400)))
	  (set_local $rotation_consts (i32.add (get_local $context_offset) (i32.const 592)))
	
	  ;; for (round = 0; round < 24; round++)
	  (set_local $round (i32.const 0))
	  (block $done
		(loop $loop
		  (if (i32.ge_u (get_local $round) (i32.const 24))
			(br $done)
		  )
	
		  ;; theta transform
		  (call $keccak_theta (get_local $context_offset))
	
		  ;; rho transform
		  (call $keccak_rho (get_local $context_offset) (get_local $rotation_consts))
	
		  ;; pi transform
		  (call $keccak_pi (get_local $context_offset))
	
		  ;; chi transform
		  (call $keccak_chi (get_local $context_offset))
	
		  ;; iota transform
		  ;; context_offset[0] ^= KECCAK_ROUND_CONSTANTS[round];
		  (i64.store (get_local $context_offset)
			(i64.xor
			  (i64.load (get_local $context_offset))
			  (i64.load (i32.add (get_local $round_consts) (i32.mul (i32.const 8) (get_local $round))))
			)
		  )
	
		  (set_local $round (i32.add (get_local $round) (i32.const 1)))
		  (br $loop)
		)  
	  ) 
	)
	
	(func $keccak_block
	  (param $input_offset i32)
	  (param $input_length i32) ;; ignored, we expect keccak256
	  (param $context_offset i32)
	
	  ;; read blocks in little-endian order and XOR against context_offset
	
	  (i64.store
		(i32.add (get_local $context_offset) (i32.const 0))
		(i64.xor
		  (i64.load (i32.add (get_local $context_offset) (i32.const 0)))
		  (i64.load (i32.add (get_local $input_offset) (i32.const 0)))
		)
	  )
	
	  (i64.store
		(i32.add (get_local $context_offset) (i32.const 8))
		(i64.xor
		  (i64.load (i32.add (get_local $context_offset) (i32.const 8)))
		  (i64.load (i32.add (get_local $input_offset) (i32.const 8)))
		)
	  )
	
	  (i64.store
		(i32.add (get_local $context_offset) (i32.const 16))
		(i64.xor
		  (i64.load (i32.add (get_local $context_offset) (i32.const 16)))
		  (i64.load (i32.add (get_local $input_offset) (i32.const 16)))
		)
	  )
	
	  (i64.store
		(i32.add (get_local $context_offset) (i32.const 24))
		(i64.xor
		  (i64.load (i32.add (get_local $context_offset) (i32.const 24)))
		  (i64.load (i32.add (get_local $input_offset) (i32.const 24)))
		)
	  )
	
	  (i64.store
		(i32.add (get_local $context_offset) (i32.const 32))
		(i64.xor
		  (i64.load (i32.add (get_local $context_offset) (i32.const 32)))
		  (i64.load (i32.add (get_local $input_offset) (i32.const 32)))
		)
	  )
	
	  (i64.store
		(i32.add (get_local $context_offset) (i32.const 40))
		(i64.xor
		  (i64.load (i32.add (get_local $context_offset) (i32.const 40)))
		  (i64.load (i32.add (get_local $input_offset) (i32.const 40)))
		)
	  )
	
	  (i64.store
		(i32.add (get_local $context_offset) (i32.const 48))
		(i64.xor
		  (i64.load (i32.add (get_local $context_offset) (i32.const 48)))
		  (i64.load (i32.add (get_local $input_offset) (i32.const 48)))
		)
	  )
	
	  (i64.store
		(i32.add (get_local $context_offset) (i32.const 56))
		(i64.xor
		  (i64.load (i32.add (get_local $context_offset) (i32.const 56)))
		  (i64.load (i32.add (get_local $input_offset) (i32.const 56)))
		)
	  )
	
	  (i64.store
		(i32.add (get_local $context_offset) (i32.const 64))
		(i64.xor
		  (i64.load (i32.add (get_local $context_offset) (i32.const 64)))
		  (i64.load (i32.add (get_local $input_offset) (i32.const 64)))
		)
	  )
	
	  (i64.store
		(i32.add (get_local $context_offset) (i32.const 72))
		(i64.xor
		  (i64.load (i32.add (get_local $context_offset) (i32.const 72)))
		  (i64.load (i32.add (get_local $input_offset) (i32.const 72)))
		)
	  )
	
	  (i64.store
		(i32.add (get_local $context_offset) (i32.const 80))
		(i64.xor
		  (i64.load (i32.add (get_local $context_offset) (i32.const 80)))
		  (i64.load (i32.add (get_local $input_offset) (i32.const 80)))
		)
	  )
	
	  (i64.store
		(i32.add (get_local $context_offset) (i32.const 88))
		(i64.xor
		  (i64.load (i32.add (get_local $context_offset) (i32.const 88)))
		  (i64.load (i32.add (get_local $input_offset) (i32.const 88)))
		)
	  )
	
	  (i64.store
		(i32.add (get_local $context_offset) (i32.const 96))
		(i64.xor
		  (i64.load (i32.add (get_local $context_offset) (i32.const 96)))
		  (i64.load (i32.add (get_local $input_offset) (i32.const 96)))
		)
	  )
	
	  (i64.store
		(i32.add (get_local $context_offset) (i32.const 104))
		(i64.xor
		  (i64.load (i32.add (get_local $context_offset) (i32.const 104)))
		  (i64.load (i32.add (get_local $input_offset) (i32.const 104)))
		)
	  )
	
	  (i64.store
		(i32.add (get_local $context_offset) (i32.const 112))
		(i64.xor
		  (i64.load (i32.add (get_local $context_offset) (i32.const 112)))
		  (i64.load (i32.add (get_local $input_offset) (i32.const 112)))
		)
	  )
	
	  (i64.store
		(i32.add (get_local $context_offset) (i32.const 120))
		(i64.xor
		  (i64.load (i32.add (get_local $context_offset) (i32.const 120)))
		  (i64.load (i32.add (get_local $input_offset) (i32.const 120)))
		)
	  )
	
	  (i64.store
		(i32.add (get_local $context_offset) (i32.const 128))
		(i64.xor
		  (i64.load (i32.add (get_local $context_offset) (i32.const 128)))
		  (i64.load (i32.add (get_local $input_offset) (i32.const 128)))
		)
	  )
	  
	  (call $keccak_permute (get_local $context_offset))
	)
	
	;;
	;; Initialise the context
	;;
	(func $keccak_init
	  (param $context_offset i32)
	  (local $round_consts i32)
	  (local $rotation_consts i32)
	
	  (call $keccak_reset (get_local $context_offset))
	
	  ;; insert the round constants (used by $KECCAK_IOTA)
	  (set_local $round_consts (i32.add (get_local $context_offset) (i32.const 400)))
	  (i64.store (i32.add (get_local $round_consts) (i32.const 0)) (i64.const 0x0000000000000001))
	  (i64.store (i32.add (get_local $round_consts) (i32.const 8)) (i64.const 0x0000000000008082))
	  (i64.store (i32.add (get_local $round_consts) (i32.const 16)) (i64.const 0x800000000000808A))
	  (i64.store (i32.add (get_local $round_consts) (i32.const 24)) (i64.const 0x8000000080008000))
	  (i64.store (i32.add (get_local $round_consts) (i32.const 32)) (i64.const 0x000000000000808B))
	  (i64.store (i32.add (get_local $round_consts) (i32.const 40)) (i64.const 0x0000000080000001))
	  (i64.store (i32.add (get_local $round_consts) (i32.const 48)) (i64.const 0x8000000080008081))
	  (i64.store (i32.add (get_local $round_consts) (i32.const 56)) (i64.const 0x8000000000008009))
	  (i64.store (i32.add (get_local $round_consts) (i32.const 64)) (i64.const 0x000000000000008A))
	  (i64.store (i32.add (get_local $round_consts) (i32.const 72)) (i64.const 0x0000000000000088))
	  (i64.store (i32.add (get_local $round_consts) (i32.const 80)) (i64.const 0x0000000080008009))
	  (i64.store (i32.add (get_local $round_consts) (i32.const 88)) (i64.const 0x000000008000000A))
	  (i64.store (i32.add (get_local $round_consts) (i32.const 96)) (i64.const 0x000000008000808B))
	  (i64.store (i32.add (get_local $round_consts) (i32.const 104)) (i64.const 0x800000000000008B))
	  (i64.store (i32.add (get_local $round_consts) (i32.const 112)) (i64.const 0x8000000000008089))
	  (i64.store (i32.add (get_local $round_consts) (i32.const 120)) (i64.const 0x8000000000008003))
	  (i64.store (i32.add (get_local $round_consts) (i32.const 128)) (i64.const 0x8000000000008002))
	  (i64.store (i32.add (get_local $round_consts) (i32.const 136)) (i64.const 0x8000000000000080))
	  (i64.store (i32.add (get_local $round_consts) (i32.const 144)) (i64.const 0x000000000000800A))
	  (i64.store (i32.add (get_local $round_consts) (i32.const 152)) (i64.const 0x800000008000000A))
	  (i64.store (i32.add (get_local $round_consts) (i32.const 160)) (i64.const 0x8000000080008081))
	  (i64.store (i32.add (get_local $round_consts) (i32.const 168)) (i64.const 0x8000000000008080))
	  (i64.store (i32.add (get_local $round_consts) (i32.const 176)) (i64.const 0x0000000080000001))
	  (i64.store (i32.add (get_local $round_consts) (i32.const 184)) (i64.const 0x8000000080008008))
	
	  ;; insert the rotation constants (used by $keccak_rho)
	  (set_local $rotation_consts (i32.add (get_local $context_offset) (i32.const 592)))
	  (i32.store8 (i32.add (get_local $rotation_consts) (i32.const 0)) (i32.const 1))
	  (i32.store8 (i32.add (get_local $rotation_consts) (i32.const 1)) (i32.const 62))
	  (i32.store8 (i32.add (get_local $rotation_consts) (i32.const 2)) (i32.const 28))
	  (i32.store8 (i32.add (get_local $rotation_consts) (i32.const 3)) (i32.const 27))
	  (i32.store8 (i32.add (get_local $rotation_consts) (i32.const 4)) (i32.const 36))
	  (i32.store8 (i32.add (get_local $rotation_consts) (i32.const 5)) (i32.const 44))
	  (i32.store8 (i32.add (get_local $rotation_consts) (i32.const 6)) (i32.const 6))
	  (i32.store8 (i32.add (get_local $rotation_consts) (i32.const 7)) (i32.const 55))
	  (i32.store8 (i32.add (get_local $rotation_consts) (i32.const 8)) (i32.const 20))
	  (i32.store8 (i32.add (get_local $rotation_consts) (i32.const 9)) (i32.const 3))
	  (i32.store8 (i32.add (get_local $rotation_consts) (i32.const 10)) (i32.const 10))
	  (i32.store8 (i32.add (get_local $rotation_consts) (i32.const 11)) (i32.const 43))
	  (i32.store8 (i32.add (get_local $rotation_consts) (i32.const 12)) (i32.const 25))
	  (i32.store8 (i32.add (get_local $rotation_consts) (i32.const 13)) (i32.const 39))
	  (i32.store8 (i32.add (get_local $rotation_consts) (i32.const 14)) (i32.const 41))
	  (i32.store8 (i32.add (get_local $rotation_consts) (i32.const 15)) (i32.const 45))
	  (i32.store8 (i32.add (get_local $rotation_consts) (i32.const 16)) (i32.const 15))
	  (i32.store8 (i32.add (get_local $rotation_consts) (i32.const 17)) (i32.const 21))
	  (i32.store8 (i32.add (get_local $rotation_consts) (i32.const 18)) (i32.const 8))
	  (i32.store8 (i32.add (get_local $rotation_consts) (i32.const 19)) (i32.const 18))
	  (i32.store8 (i32.add (get_local $rotation_consts) (i32.const 20)) (i32.const 2))
	  (i32.store8 (i32.add (get_local $rotation_consts) (i32.const 21)) (i32.const 61))
	  (i32.store8 (i32.add (get_local $rotation_consts) (i32.const 22)) (i32.const 56))
	  (i32.store8 (i32.add (get_local $rotation_consts) (i32.const 23)) (i32.const 14))
	)
	
	;;
	;; Reset the context
	;;
	(func $keccak_reset
	  (param $context_offset i32)
	
	  ;; clear out the context memory
	  (drop (call $memset (get_local $context_offset) (i32.const 0) (i32.const 400)))
	)
	
	;;
	;; Push input to the context
	;;
	(func $keccak_update
	  (param $context_offset i32)
	  (param $input_offset i32)
	  (param $input_length i32)
	
	  (local $residue_offset i32)
	  (local $residue_buffer i32)
	  (local $residue_index i32)
	  (local $tmp i32)
	
	  ;; this is where we store the pointer
	  (set_local $residue_offset (i32.add (get_local $context_offset) (i32.const 200)))
	  ;; this is where the buffer is
	  (set_local $residue_buffer (i32.add (get_local $context_offset) (i32.const 208)))
	
	  (set_local $residue_index (i32.load (get_local $residue_offset)))
	
	  ;; process residue from last block
	  (if (i32.ne (get_local $residue_index) (i32.const 0))
		(then
		  ;; the space left in the residue buffer
		  (set_local $tmp (i32.sub (i32.const 136) (get_local $residue_index)))
	
		  ;; limit to what we have as an input
		  (if (i32.lt_u (get_local $input_length) (get_local $tmp))
			(set_local $tmp (get_local $input_length))
		  )
	
		  ;; fill up the residue buffer
		  (drop (call $memcpy
			(i32.add (get_local $residue_buffer) (get_local $residue_index))
			(get_local $input_offset)
			(get_local $tmp)
		  ))
	
		  (set_local $residue_index (i32.add (get_local $residue_index) (get_local $tmp)))
	
		  ;; block complete
		  (if (i32.eq (get_local $residue_index) (i32.const 136))
			(call $keccak_block (get_local $input_offset) (i32.const 136) (get_local $context_offset))
	
			(set_local $residue_index (i32.const 0))
		  )
	
		  (i32.store (get_local $residue_offset) (get_local $residue_index))
	
		  (set_local $input_length (i32.sub (get_local $input_length) (get_local $tmp)))
		)
	  )
	
	  ;; while (input_length > block_size)
	  (block $done
		(loop $loop
		  (if (i32.lt_u (get_local $input_length) (i32.const 136))
			(br $done)
		  )
	
		  (call $keccak_block (get_local $input_offset) (i32.const 136) (get_local $context_offset))
	
		  (set_local $input_offset (i32.add (get_local $input_offset) (i32.const 136)))
		  (set_local $input_length (i32.sub (get_local $input_length) (i32.const 136)))
		  (br $loop)
		)
	  )
	
	  ;; copy to the residue buffer
	  (if (i32.gt_u (get_local $input_length) (i32.const 0))
		(then
		  (drop (call $memcpy
			(i32.add (get_local $residue_buffer) (get_local $residue_index))
			(get_local $input_offset)
			(get_local $input_length)
		  ))
	
		  (set_local $residue_index (i32.add (get_local $residue_index) (get_local $input_length)))
		  (i32.store (get_local $residue_offset) (get_local $residue_index))
		)
	  )
	)
	
	;;
	;; Finalise and return the hash
	;;
	;; The 256 bit hash is returned at the output offset.
	;;
	(func $keccak_finish
	  (param $context_offset i32)
	  (param $output_offset i32)
	
	  (local $residue_offset i32)
	  (local $residue_buffer i32)
	  (local $residue_index i32)
	  (local $tmp i32)
	
	  ;; this is where we store the pointer
	  (set_local $residue_offset (i32.add (get_local $context_offset) (i32.const 200)))
	  ;; this is where the buffer is
	  (set_local $residue_buffer (i32.add (get_local $context_offset) (i32.const 208)))
	
	  (set_local $residue_index (i32.load (get_local $residue_offset)))
	  (set_local $tmp (get_local $residue_index))
	
	  ;; clear the rest of the residue buffer
	  (drop (call $memset (i32.add (get_local $residue_buffer) (get_local $tmp)) (i32.const 0) (i32.sub (i32.const 136) (get_local $tmp))))
	
	  ;; ((char*)ctx->message)[ctx->rest] |= 0x01;
	  (set_local $tmp (i32.add (get_local $residue_buffer) (get_local $residue_index)))
	  (i32.store8 (get_local $tmp) (i32.or (i32.load8_u (get_local $tmp)) (i32.const 0x01)))
	
	  ;; ((char*)ctx->message)[block_size - 1] |= 0x80;
	  (set_local $tmp (i32.add (get_local $residue_buffer) (i32.const 135)))
	  (i32.store8 (get_local $tmp) (i32.or (i32.load8_u (get_local $tmp)) (i32.const 0x80)))
	
	  (call $keccak_block (get_local $residue_buffer) (i32.const 136) (get_local $context_offset))
	
	  ;; the first 32 bytes pointed at by $output_offset is the final hash
	  (i64.store (get_local $output_offset) (i64.load (get_local $context_offset)))
	  (i64.store (i32.add (get_local $output_offset) (i32.const 8)) (i64.load (i32.add (get_local $context_offset) (i32.const 8))))
	  (i64.store (i32.add (get_local $output_offset) (i32.const 16)) (i64.load (i32.add (get_local $context_offset) (i32.const 16))))
	  (i64.store (i32.add (get_local $output_offset) (i32.const 24)) (i64.load (i32.add (get_local $context_offset) (i32.const 24))))
	)
	
	;;
	;; Calculate the hash. Helper method incorporating the above three.
	;;
	(func $keccak
	  (param $context_offset i32)
	  (param $input_offset i32)
	  (param $input_length i32)
	  (param $output_offset i32)
	
	  (call $keccak_init (get_local $context_offset))
	  (call $keccak_update (get_local $context_offset) (get_local $input_offset) (get_local $input_length))
	  (call $keccak_finish (get_local $context_offset) (get_local $output_offset))
	)
	(func $mul_256
	  ;;  a b c d e f g h
	  ;;* i j k l m n o p
	  ;;----------------
	  (param $a i64)
	  (param $c i64)
	  (param $e i64)
	  (param $g i64)
	
	  (param $i i64)
	  (param $k i64)
	  (param $m i64)
	  (param $o i64)
	
	  (param $sp i32)
	
	  (local $b i64)
	  (local $d i64)
	  (local $f i64)
	  (local $h i64)
	  (local $j i64)
	  (local $l i64)
	  (local $n i64)
	  (local $p i64)
	  (local $temp6 i64)
	  (local $temp5 i64)
	  (local $temp4 i64)
	  (local $temp3 i64)
	  (local $temp2 i64)
	  (local $temp1 i64)
	  (local $temp0 i64)
	
	  ;; split the ops
	  (set_local $b (i64.and (get_local $a) (i64.const 4294967295)))
	  (set_local $a (i64.shr_u (get_local $a) (i64.const 32))) 
	
	  (set_local $d (i64.and (get_local $c) (i64.const 4294967295)))
	  (set_local $c (i64.shr_u (get_local $c) (i64.const 32))) 
	
	  (set_local $f (i64.and (get_local $e) (i64.const 4294967295)))
	  (set_local $e (i64.shr_u (get_local $e) (i64.const 32)))
	
	  (set_local $h (i64.and (get_local $g) (i64.const 4294967295)))
	  (set_local $g (i64.shr_u (get_local $g) (i64.const 32)))
	
	  (set_local $j (i64.and (get_local $i) (i64.const 4294967295)))
	  (set_local $i (i64.shr_u (get_local $i) (i64.const 32))) 
	
	  (set_local $l (i64.and (get_local $k) (i64.const 4294967295)))
	  (set_local $k (i64.shr_u (get_local $k) (i64.const 32))) 
	
	  (set_local $n (i64.and (get_local $m) (i64.const 4294967295)))
	  (set_local $m (i64.shr_u (get_local $m) (i64.const 32)))
	
	  (set_local $p (i64.and (get_local $o) (i64.const 4294967295)))
	  (set_local $o (i64.shr_u (get_local $o) (i64.const 32)))
	  ;; first row multiplication 
	  ;; p * h
	  (set_local $temp0 (i64.mul (get_local $p) (get_local $h)))
	  ;; p * g + carry
	  (set_local $temp1 (i64.add (i64.mul (get_local $p) (get_local $g)) (i64.shr_u (get_local $temp0) (i64.const 32))))
	  ;; p * f + carry
	  (set_local $temp2 (i64.add (i64.mul (get_local $p) (get_local $f)) (i64.shr_u (get_local $temp1) (i64.const 32))))
	  ;; p * e + carry
	  (set_local $temp3 (i64.add (i64.mul (get_local $p) (get_local $e)) (i64.shr_u (get_local $temp2) (i64.const 32))))
	  ;; p * d + carry
	  (set_local $temp4 (i64.add (i64.mul (get_local $p) (get_local $d)) (i64.shr_u (get_local $temp3) (i64.const 32))))
	  ;; p * c + carry
	  (set_local $temp5  (i64.add (i64.mul (get_local $p) (get_local $c)) (i64.shr_u (get_local $temp4) (i64.const 32))))
	  ;; p * b + carry
	  (set_local $temp6  (i64.add (i64.mul (get_local $p) (get_local $b)) (i64.shr_u (get_local $temp5) (i64.const 32))))
	  ;; p * a + carry
	  (set_local $a  (i64.add (i64.mul (get_local $p) (get_local $a)) (i64.shr_u (get_local $temp6) (i64.const 32))))
	  ;; second row
	  ;; o * h + $temp1 "pg"
	  (set_local $temp1 (i64.add (i64.mul (get_local $o) (get_local $h)) (i64.and (get_local $temp1) (i64.const 4294967295))))
	  ;; o * g + $temp2 "pf" + carry
	  (set_local $temp2 (i64.add (i64.add (i64.mul (get_local $o) (get_local $g)) (i64.and (get_local $temp2) (i64.const 4294967295))) (i64.shr_u (get_local $temp1) (i64.const 32))))
	  ;; o * f + $temp3 "pe" + carry
	  (set_local $temp3 (i64.add (i64.add (i64.mul (get_local $o) (get_local $f)) (i64.and (get_local $temp3) (i64.const 4294967295))) (i64.shr_u (get_local $temp2) (i64.const 32))))
	  ;; o * e + $temp4  + carry
	  (set_local $temp4 (i64.add (i64.add (i64.mul (get_local $o) (get_local $e)) (i64.and (get_local $temp4) (i64.const 4294967295))) (i64.shr_u (get_local $temp3) (i64.const 32))))
	  ;; o * d + $temp5  + carry
	  (set_local $temp5 (i64.add (i64.add (i64.mul (get_local $o) (get_local $d)) (i64.and (get_local $temp5) (i64.const 4294967295))) (i64.shr_u (get_local $temp4) (i64.const 32))))
	  ;; o * c + $temp6  + carry
	  (set_local $temp6 (i64.add (i64.add (i64.mul (get_local $o) (get_local $c)) (i64.and (get_local $temp6) (i64.const 4294967295))) (i64.shr_u (get_local $temp5) (i64.const 32))))
	  ;; o * b + $a  + carry
	  (set_local $a (i64.add (i64.add (i64.mul (get_local $o) (get_local $b)) (i64.and (get_local $a) (i64.const 4294967295))) (i64.shr_u (get_local $temp6) (i64.const 32))))
	  ;; third row - n
	  ;; n * h + $temp2 
	  (set_local $temp2 (i64.add (i64.mul (get_local $n) (get_local $h)) (i64.and (get_local $temp2) (i64.const 4294967295))))
	  ;; n * g + $temp3 + carry
	  (set_local $temp3 (i64.add (i64.add (i64.mul (get_local $n) (get_local $g)) (i64.and (get_local $temp3) (i64.const 4294967295))) (i64.shr_u (get_local $temp2) (i64.const 32))))
	  ;; n * f + $temp4 + carry
	  (set_local $temp4 (i64.add (i64.add (i64.mul (get_local $n) (get_local $f)) (i64.and (get_local $temp4) (i64.const 4294967295))) (i64.shr_u (get_local $temp3) (i64.const 32))))
	  ;; n * e + $temp5  + carry
	  (set_local $temp5 (i64.add (i64.add (i64.mul (get_local $n) (get_local $e)) (i64.and (get_local $temp5) (i64.const 4294967295))) (i64.shr_u (get_local $temp4) (i64.const 32))))
	  ;; n * d + $temp6  + carry
	  (set_local $temp6 (i64.add (i64.add (i64.mul (get_local $n) (get_local $d)) (i64.and (get_local $temp6) (i64.const 4294967295))) (i64.shr_u (get_local $temp5) (i64.const 32))))
	  ;; n * c + $a  + carry
	  (set_local $a (i64.add (i64.add (i64.mul (get_local $n) (get_local $c)) (i64.and (get_local $a) (i64.const 4294967295))) (i64.shr_u (get_local $temp6) (i64.const 32))))
	
	  ;; forth row 
	  ;; m * h + $temp3
	  (set_local $temp3 (i64.add (i64.mul (get_local $m) (get_local $h)) (i64.and (get_local $temp3) (i64.const 4294967295))))
	  ;; m * g + $temp4 + carry
	  (set_local $temp4 (i64.add (i64.add (i64.mul (get_local $m) (get_local $g)) (i64.and (get_local $temp4) (i64.const 4294967295))) (i64.shr_u (get_local $temp3) (i64.const 32))))
	  ;; m * f + $temp5 + carry
	  (set_local $temp5 (i64.add (i64.add (i64.mul (get_local $m) (get_local $f)) (i64.and (get_local $temp5) (i64.const 4294967295))) (i64.shr_u (get_local $temp4) (i64.const 32))))
	  ;; m * e + $temp6 + carry
	  (set_local $temp6 (i64.add (i64.add (i64.mul (get_local $m) (get_local $e)) (i64.and (get_local $temp6) (i64.const 4294967295))) (i64.shr_u (get_local $temp5) (i64.const 32))))
	  ;; m * d + $a + carry
	  (set_local $a (i64.add (i64.add (i64.mul (get_local $m) (get_local $d)) (i64.and (get_local $a) (i64.const 4294967295))) (i64.shr_u (get_local $temp6) (i64.const 32))))
	
	  ;; fith row
	  ;; l * h + $temp4
	  (set_local $temp4 (i64.add (i64.mul (get_local $l) (get_local $h)) (i64.and (get_local $temp4) (i64.const 4294967295))))
	  ;; l * g + $temp5 + carry
	  (set_local $temp5 (i64.add (i64.add (i64.mul (get_local $l) (get_local $g)) (i64.and (get_local $temp5) (i64.const 4294967295))) (i64.shr_u (get_local $temp4) (i64.const 32))))
	  ;; l * f + $temp6 + carry
	  (set_local $temp6 (i64.add (i64.add (i64.mul (get_local $l) (get_local $f)) (i64.and (get_local $temp6) (i64.const 4294967295))) (i64.shr_u (get_local $temp5) (i64.const 32))))
	  ;; l * e + $a + carry
	  (set_local $a (i64.add (i64.add (i64.mul (get_local $l) (get_local $e)) (i64.and (get_local $a) (i64.const 4294967295))) (i64.shr_u (get_local $temp6) (i64.const 32))))
	
	  ;; sixth row 
	  ;; k * h + $temp5
	  (set_local $temp5 (i64.add (i64.mul (get_local $k) (get_local $h)) (i64.and (get_local $temp5) (i64.const 4294967295))))
	  ;; k * g + $temp6 + carry
	  (set_local $temp6 (i64.add (i64.add (i64.mul (get_local $k) (get_local $g)) (i64.and (get_local $temp6) (i64.const 4294967295))) (i64.shr_u (get_local $temp5) (i64.const 32))))
	  ;; k * f + $a + carry
	  (set_local $a (i64.add (i64.add (i64.mul (get_local $k) (get_local $f)) (i64.and (get_local $a) (i64.const 4294967295))) (i64.shr_u (get_local $temp6) (i64.const 32))))
	
	  ;; seventh row
	  ;; j * h + $temp6
	  (set_local $temp6 (i64.add (i64.mul (get_local $j) (get_local $h)) (i64.and (get_local $temp6) (i64.const 4294967295))))
	  ;; j * g + $a + carry
	
	  ;; eigth row
	  ;; i * h + $a
	  (set_local $a (i64.add (i64.mul (get_local $i) (get_local $h)) (i64.and (i64.add (i64.add (i64.mul (get_local $j) (get_local $g)) (i64.and (get_local $a) (i64.const 4294967295))) (i64.shr_u (get_local $temp6) (i64.const 32))) (i64.const 4294967295))))
	
	  ;; combine terms
	  (set_local $a (i64.or (i64.shl (get_local $a) (i64.const 32)) (i64.and (get_local $temp6) (i64.const 4294967295))))
	  (set_local $c (i64.or (i64.shl (get_local $temp5) (i64.const 32)) (i64.and (get_local $temp4) (i64.const 4294967295))))
	  (set_local $e (i64.or (i64.shl (get_local $temp3) (i64.const 32)) (i64.and (get_local $temp2) (i64.const 4294967295))))
	  (set_local $g (i64.or (i64.shl (get_local $temp1) (i64.const 32)) (i64.and (get_local $temp0) (i64.const 4294967295))))
	
	  ;; save stack 
	  (i64.store (get_local $sp) (get_local $a))
	  (i64.store (i32.sub (get_local $sp) (i32.const 8)) (get_local $c))
	  (i64.store (i32.sub (get_local $sp) (i32.const 16)) (get_local $e))
	  (i64.store (i32.sub (get_local $sp) (i32.const 24)) (get_local $g))
	)
	(func $callback_256
	  (param $result i32)
	
	  (drop (call $bswap_m256 (get_global $sp)))
	  (call $main)
	)
	;;
	;; memcpy from ewasm-libc/ewasm-cleanup
	;;
	(func $memset
	  (param $ptr i32)
	  (param $value i32)
	  (param $length i32)
	  (result i32)
	  (local $i i32)
	
	  (set_local $i (i32.const 0))
	
	  (block $done
		(loop $loop
		  (if (i32.ge_u (get_local $i) (get_local $length))
			(br $done)
		  )
	
		  (i32.store8 (i32.add (get_local $ptr) (get_local $i)) (get_local $value))
	
		  (set_local $i (i32.add (get_local $i) (i32.const 1)))
		  (br $loop)
		)
	  )
	  (get_local $ptr)
	)
	(func $bswap_m160
	  (param $sp i32)
	  (result i32)
	  (local $temp i64)
	
	  (set_local $temp (call $bswap_i64 (i64.load (get_local $sp))))
	  (i64.store (get_local $sp) (call $bswap_i64 (i64.load (i32.add (get_local $sp) (i32.const 12)))))
	  (i64.store (i32.add (get_local $sp) (i32.const 12)) (get_local $temp))
	
	  (i32.store (i32.add (get_local $sp) (i32.const 8)) (call $bswap_i32 (i32.load (i32.add (get_local $sp) (i32.const 8)))))
	  (get_local $sp)
	)
	(func $bswap_i64
	  (param $int i64)
	  (result i64)
	
	  (i64.or
		(i64.or
		  (i64.or
			(i64.and (i64.shr_u (get_local $int) (i64.const 56)) (i64.const 0xff)) ;; 7 -> 0
			(i64.and (i64.shr_u (get_local $int) (i64.const 40)) (i64.const 0xff00))) ;; 6 -> 1
		  (i64.or
			(i64.and (i64.shr_u (get_local $int) (i64.const 24)) (i64.const 0xff0000)) ;; 5 -> 2
			(i64.and (i64.shr_u (get_local $int) (i64.const  8)) (i64.const 0xff000000)))) ;; 4 -> 3
		(i64.or
		  (i64.or
			(i64.and (i64.shl (get_local $int) (i64.const 8))   (i64.const 0xff00000000)) ;; 3 -> 4
			(i64.and (i64.shl (get_local $int) (i64.const 24))   (i64.const 0xff0000000000))) ;; 2 -> 5
		  (i64.or
			(i64.and (i64.shl (get_local $int) (i64.const 40))   (i64.const 0xff000000000000)) ;; 1 -> 6
			(i64.and (i64.shl (get_local $int) (i64.const 56))   (i64.const 0xff00000000000000))))) ;; 0 -> 7
	)
	;;
	;; memcpy from ewasm-libc/ewasm-cleanup
	;;
	(func $memcpy
	  (param $dst i32)
	  (param $src i32)
	  (param $length i32)
	  (result i32)
	
	  (local $i i32)
	
	  (set_local $i (i32.const 0))
	
	  (block $done
		(loop $loop
		  (if (i32.ge_u (get_local $i) (get_local $length))
			(br $done)
		  )
	
		  (i32.store8 (i32.add (get_local $dst) (get_local $i)) (i32.load8_u (i32.add (get_local $src) (get_local $i))))
	
		  (set_local $i (i32.add (get_local $i) (i32.const 1)))
		  (br $loop)
		)
	  )
	
	  (return (get_local $dst))
	)
	(func $bswap_i32
	  (param $int i32)
	  (result i32)
	
	  (i32.or
		(i32.or
		  (i32.and (i32.shr_u (get_local $int) (i32.const 24)) (i32.const 0xff)) ;; 7 -> 0
		  (i32.and (i32.shr_u (get_local $int) (i32.const 8)) (i32.const 0xff00))) ;; 6 -> 1
		(i32.or
		  (i32.and (i32.shl (get_local $int) (i32.const 8)) (i32.const 0xff0000)) ;; 5 -> 2
		  (i32.and (i32.shl (get_local $int) (i32.const 24)) (i32.const 0xff000000)))) ;; 4 -> 3
	)
	
	  (func $main
		(export "main")
		(local $jump_dest i32) (local $jump_map_switch i32)
		(set_local $jump_dest (i32.const -1))
	
		(block $done
		  (loop $loop
			(block $173 (block $172 (block $171 (block $170 (block $169 (block $168 (block $167 (block $166 (block $165 (block $164 (block $163 (block $162 (block $161 (block $160 (block $159 (block $158 (block $157 (block $156 (block $155 (block $154 (block $153 (block $152 (block $151 (block $150 (block $149 (block $148 (block $147 (block $146 (block $145 (block $144 (block $143 (block $142 (block $141 (block $140 (block $139 (block $138 (block $137 (block $136 (block $135 (block $134 (block $133 (block $132 (block $131 (block $130 (block $129 (block $128 (block $127 (block $126 (block $125 (block $124 (block $123 (block $122 (block $121 (block $120 (block $119 (block $118 (block $117 (block $116 (block $115 (block $114 (block $113 (block $112 (block $111 (block $110 (block $109 (block $108 (block $107 (block $106 (block $105 (block $104 (block $103 (block $102 (block $101 (block $100 (block $99 (block $98 (block $97 (block $96 (block $95 (block $94 (block $93 (block $92 (block $91 (block $90 (block $89 (block $88 (block $87 (block $86 (block $85 (block $84 (block $83 (block $82 (block $81 (block $80 (block $79 (block $78 (block $77 (block $76 (block $75 (block $74 (block $73 (block $72 (block $71 (block $70 (block $69 (block $68 (block $67 (block $66 (block $65 (block $64 (block $63 (block $62 (block $61 (block $60 (block $59 (block $58 (block $57 (block $56 (block $55 (block $54 (block $53 (block $52 (block $51 (block $50 (block $49 (block $48 (block $47 (block $46 (block $45 (block $44 (block $43 (block $42 (block $41 (block $40 (block $39 (block $38 (block $37 (block $36 (block $35 (block $34 (block $33 (block $32 (block $31 (block $30 (block $29 (block $28 (block $27 (block $26 (block $25 (block $24 (block $23 (block $22 (block $21 (block $20 (block $19 (block $18 (block $17 (block $16 (block $15 (block $14 (block $13 (block $12 (block $11 (block $10 (block $9 (block $8 (block $7 (block $6 (block $5 (block $4 (block $3 (block $2 (block $1 
	  (block $0 
		(if
		  (i32.eqz (get_global $init))
		  (then
			(set_global $init (i32.const 1))
			(br $0))
		  (else
			;; the callback dest can never be in the first block
			(if (i32.eq (get_global $cb_dest) (i32.const 0)) 
			  (then
				(if (i32.eq (get_local $jump_dest) (i32.const 2558))
					(then (br $173))
					(else (if (i32.eq (get_local $jump_dest) (i32.const 2557))
					(then (br $172))
					(else (if (i32.eq (get_local $jump_dest) (i32.const 2539))
					(then (br $171))
					(else (if (i32.eq (get_local $jump_dest) (i32.const 2515))
					(then (br $170))
					(else (if (i32.eq (get_local $jump_dest) (i32.const 2468))
					(then (br $169))
					(else (if (i32.eq (get_local $jump_dest) (i32.const 2459))
					(then (br $168))
					(else (if (i32.eq (get_local $jump_dest) (i32.const 2446))
					(then (br $167))
					(else (if (i32.eq (get_local $jump_dest) (i32.const 2433))
					(then (br $166))
					(else (if (i32.eq (get_local $jump_dest) (i32.const 2420))
					(then (br $165))
					(else (if (i32.eq (get_local $jump_dest) (i32.const 2405))
					(then (br $164))
					(else (if (i32.eq (get_local $jump_dest) (i32.const 2380))
					(then (br $163))
					(else (if (i32.eq (get_local $jump_dest) (i32.const 2374))
					(then (br $162))
					(else (if (i32.eq (get_local $jump_dest) (i32.const 2365))
					(then (br $161))
					(else (if (i32.eq (get_local $jump_dest) (i32.const 2354))
					(then (br $160))
					(else (if (i32.eq (get_local $jump_dest) (i32.const 2343))
					(then (br $159))
					(else (if (i32.eq (get_local $jump_dest) (i32.const 2330))
					(then (br $158))
					(else (if (i32.eq (get_local $jump_dest) (i32.const 2289))
					(then (br $157))
					(else (if (i32.eq (get_local $jump_dest) (i32.const 2281))
					(then (br $156))
					(else (if (i32.eq (get_local $jump_dest) (i32.const 2255))
					(then (br $155))
					(else (if (i32.eq (get_local $jump_dest) (i32.const 2244))
					(then (br $154))
					(else (if (i32.eq (get_local $jump_dest) (i32.const 2235))
					(then (br $153))
					(else (if (i32.eq (get_local $jump_dest) (i32.const 2219))
					(then (br $152))
					(else (if (i32.eq (get_local $jump_dest) (i32.const 2209))
					(then (br $151))
					(else (if (i32.eq (get_local $jump_dest) (i32.const 2198))
					(then (br $150))
					(else (if (i32.eq (get_local $jump_dest) (i32.const 2181))
					(then (br $149))
					(else (if (i32.eq (get_local $jump_dest) (i32.const 2169))
					(then (br $148))
					(else (if (i32.eq (get_local $jump_dest) (i32.const 2142))
					(then (br $147))
					(else (if (i32.eq (get_local $jump_dest) (i32.const 2139))
					(then (br $146))
					(else (if (i32.eq (get_local $jump_dest) (i32.const 2122))
					(then (br $145))
					(else (if (i32.eq (get_local $jump_dest) (i32.const 2111))
					(then (br $144))
					(else (if (i32.eq (get_local $jump_dest) (i32.const 2101))
					(then (br $143))
					(else (if (i32.eq (get_local $jump_dest) (i32.const 2084))
					(then (br $142))
					(else (if (i32.eq (get_local $jump_dest) (i32.const 2067))
					(then (br $141))
					(else (if (i32.eq (get_local $jump_dest) (i32.const 2053))
					(then (br $140))
					(else (if (i32.eq (get_local $jump_dest) (i32.const 2052))
					(then (br $139))
					(else (if (i32.eq (get_local $jump_dest) (i32.const 2028))
					(then (br $138))
					(else (if (i32.eq (get_local $jump_dest) (i32.const 2022))
					(then (br $137))
					(else (if (i32.eq (get_local $jump_dest) (i32.const 2007))
					(then (br $136))
					(else (if (i32.eq (get_local $jump_dest) (i32.const 2004))
					(then (br $135))
					(else (if (i32.eq (get_local $jump_dest) (i32.const 1993))
					(then (br $134))
					(else (if (i32.eq (get_local $jump_dest) (i32.const 1984))
					(then (br $133))
					(else (if (i32.eq (get_local $jump_dest) (i32.const 1968))
					(then (br $132))
					(else (if (i32.eq (get_local $jump_dest) (i32.const 1962))
					(then (br $131))
					(else (if (i32.eq (get_local $jump_dest) (i32.const 1947))
					(then (br $130))
					(else (if (i32.eq (get_local $jump_dest) (i32.const 1944))
					(then (br $129))
					(else (if (i32.eq (get_local $jump_dest) (i32.const 1933))
					(then (br $128))
					(else (if (i32.eq (get_local $jump_dest) (i32.const 1924))
					(then (br $127))
					(else (if (i32.eq (get_local $jump_dest) (i32.const 1915))
					(then (br $126))
					(else (if (i32.eq (get_local $jump_dest) (i32.const 1901))
					(then (br $125))
					(else (if (i32.eq (get_local $jump_dest) (i32.const 1900))
					(then (br $124))
					(else (if (i32.eq (get_local $jump_dest) (i32.const 1879))
					(then (br $123))
					(else (if (i32.eq (get_local $jump_dest) (i32.const 1873))
					(then (br $122))
					(else (if (i32.eq (get_local $jump_dest) (i32.const 1858))
					(then (br $121))
					(else (if (i32.eq (get_local $jump_dest) (i32.const 1855))
					(then (br $120))
					(else (if (i32.eq (get_local $jump_dest) (i32.const 1844))
					(then (br $119))
					(else (if (i32.eq (get_local $jump_dest) (i32.const 1835))
					(then (br $118))
					(else (if (i32.eq (get_local $jump_dest) (i32.const 1823))
					(then (br $117))
					(else (if (i32.eq (get_local $jump_dest) (i32.const 1818))
					(then (br $116))
					(else (if (i32.eq (get_local $jump_dest) (i32.const 1812))
					(then (br $115))
					(else (if (i32.eq (get_local $jump_dest) (i32.const 1791))
					(then (br $114))
					(else (if (i32.eq (get_local $jump_dest) (i32.const 1785))
					(then (br $113))
					(else (if (i32.eq (get_local $jump_dest) (i32.const 1776))
					(then (br $112))
					(else (if (i32.eq (get_local $jump_dest) (i32.const 1766))
					(then (br $111))
					(else (if (i32.eq (get_local $jump_dest) (i32.const 1758))
					(then (br $110))
					(else (if (i32.eq (get_local $jump_dest) (i32.const 1729))
					(then (br $109))
					(else (if (i32.eq (get_local $jump_dest) (i32.const 1715))
					(then (br $108))
					(else (if (i32.eq (get_local $jump_dest) (i32.const 1681))
					(then (br $107))
					(else (if (i32.eq (get_local $jump_dest) (i32.const 1637))
					(then (br $106))
					(else (if (i32.eq (get_local $jump_dest) (i32.const 1624))
					(then (br $105))
					(else (if (i32.eq (get_local $jump_dest) (i32.const 1618))
					(then (br $104))
					(else (if (i32.eq (get_local $jump_dest) (i32.const 1612))
					(then (br $103))
					(else (if (i32.eq (get_local $jump_dest) (i32.const 1604))
					(then (br $102))
					(else (if (i32.eq (get_local $jump_dest) (i32.const 1598))
					(then (br $101))
					(else (if (i32.eq (get_local $jump_dest) (i32.const 1566))
					(then (br $100))
					(else (if (i32.eq (get_local $jump_dest) (i32.const 1555))
					(then (br $99))
					(else (if (i32.eq (get_local $jump_dest) (i32.const 1477))
					(then (br $98))
					(else (if (i32.eq (get_local $jump_dest) (i32.const 1471))
					(then (br $97))
					(else (if (i32.eq (get_local $jump_dest) (i32.const 1462))
					(then (br $96))
					(else (if (i32.eq (get_local $jump_dest) (i32.const 1449))
					(then (br $95))
					(else (if (i32.eq (get_local $jump_dest) (i32.const 1440))
					(then (br $94))
					(else (if (i32.eq (get_local $jump_dest) (i32.const 1428))
					(then (br $93))
					(else (if (i32.eq (get_local $jump_dest) (i32.const 1419))
					(then (br $92))
					(else (if (i32.eq (get_local $jump_dest) (i32.const 1406))
					(then (br $91))
					(else (if (i32.eq (get_local $jump_dest) (i32.const 1397))
					(then (br $90))
					(else (if (i32.eq (get_local $jump_dest) (i32.const 1385))
					(then (br $89))
					(else (if (i32.eq (get_local $jump_dest) (i32.const 1376))
					(then (br $88))
					(else (if (i32.eq (get_local $jump_dest) (i32.const 1363))
					(then (br $87))
					(else (if (i32.eq (get_local $jump_dest) (i32.const 1354))
					(then (br $86))
					(else (if (i32.eq (get_local $jump_dest) (i32.const 1342))
					(then (br $85))
					(else (if (i32.eq (get_local $jump_dest) (i32.const 1333))
					(then (br $84))
					(else (if (i32.eq (get_local $jump_dest) (i32.const 1320))
					(then (br $83))
					(else (if (i32.eq (get_local $jump_dest) (i32.const 1311))
					(then (br $82))
					(else (if (i32.eq (get_local $jump_dest) (i32.const 1299))
					(then (br $81))
					(else (if (i32.eq (get_local $jump_dest) (i32.const 1290))
					(then (br $80))
					(else (if (i32.eq (get_local $jump_dest) (i32.const 1277))
					(then (br $79))
					(else (if (i32.eq (get_local $jump_dest) (i32.const 1268))
					(then (br $78))
					(else (if (i32.eq (get_local $jump_dest) (i32.const 1256))
					(then (br $77))
					(else (if (i32.eq (get_local $jump_dest) (i32.const 1254))
					(then (br $76))
					(else (if (i32.eq (get_local $jump_dest) (i32.const 1249))
					(then (br $75))
					(else (if (i32.eq (get_local $jump_dest) (i32.const 1227))
					(then (br $74))
					(else (if (i32.eq (get_local $jump_dest) (i32.const 1215))
					(then (br $73))
					(else (if (i32.eq (get_local $jump_dest) (i32.const 1213))
					(then (br $72))
					(else (if (i32.eq (get_local $jump_dest) (i32.const 1208))
					(then (br $71))
					(else (if (i32.eq (get_local $jump_dest) (i32.const 1187))
					(then (br $70))
					(else (if (i32.eq (get_local $jump_dest) (i32.const 1178))
					(then (br $69))
					(else (if (i32.eq (get_local $jump_dest) (i32.const 1165))
					(then (br $68))
					(else (if (i32.eq (get_local $jump_dest) (i32.const 1156))
					(then (br $67))
					(else (if (i32.eq (get_local $jump_dest) (i32.const 1144))
					(then (br $66))
					(else (if (i32.eq (get_local $jump_dest) (i32.const 1139))
					(then (br $65))
					(else (if (i32.eq (get_local $jump_dest) (i32.const 1132))
					(then (br $64))
					(else (if (i32.eq (get_local $jump_dest) (i32.const 1083))
					(then (br $63))
					(else (if (i32.eq (get_local $jump_dest) (i32.const 989))
					(then (br $62))
					(else (if (i32.eq (get_local $jump_dest) (i32.const 981))
					(then (br $61))
					(else (if (i32.eq (get_local $jump_dest) (i32.const 968))
					(then (br $60))
					(else (if (i32.eq (get_local $jump_dest) (i32.const 964))
					(then (br $59))
					(else (if (i32.eq (get_local $jump_dest) (i32.const 936))
					(then (br $58))
					(else (if (i32.eq (get_local $jump_dest) (i32.const 897))
					(then (br $57))
					(else (if (i32.eq (get_local $jump_dest) (i32.const 894))
					(then (br $56))
					(else (if (i32.eq (get_local $jump_dest) (i32.const 878))
					(then (br $55))
					(else (if (i32.eq (get_local $jump_dest) (i32.const 869))
					(then (br $54))
					(else (if (i32.eq (get_local $jump_dest) (i32.const 857))
					(then (br $53))
					(else (if (i32.eq (get_local $jump_dest) (i32.const 822))
					(then (br $52))
					(else (if (i32.eq (get_local $jump_dest) (i32.const 809))
					(then (br $51))
					(else (if (i32.eq (get_local $jump_dest) (i32.const 797))
					(then (br $50))
					(else (if (i32.eq (get_local $jump_dest) (i32.const 796))
					(then (br $49))
					(else (if (i32.eq (get_local $jump_dest) (i32.const 769))
					(then (br $48))
					(else (if (i32.eq (get_local $jump_dest) (i32.const 758))
					(then (br $47))
					(else (if (i32.eq (get_local $jump_dest) (i32.const 742))
					(then (br $46))
					(else (if (i32.eq (get_local $jump_dest) (i32.const 728))
					(then (br $45))
					(else (if (i32.eq (get_local $jump_dest) (i32.const 715))
					(then (br $44))
					(else (if (i32.eq (get_local $jump_dest) (i32.const 696))
					(then (br $43))
					(else (if (i32.eq (get_local $jump_dest) (i32.const 683))
					(then (br $42))
					(else (if (i32.eq (get_local $jump_dest) (i32.const 678))
					(then (br $41))
					(else (if (i32.eq (get_local $jump_dest) (i32.const 675))
					(then (br $40))
					(else (if (i32.eq (get_local $jump_dest) (i32.const 666))
					(then (br $39))
					(else (if (i32.eq (get_local $jump_dest) (i32.const 651))
					(then (br $38))
					(else (if (i32.eq (get_local $jump_dest) (i32.const 635))
					(then (br $37))
					(else (if (i32.eq (get_local $jump_dest) (i32.const 624))
					(then (br $36))
					(else (if (i32.eq (get_local $jump_dest) (i32.const 603))
					(then (br $35))
					(else (if (i32.eq (get_local $jump_dest) (i32.const 599))
					(then (br $34))
					(else (if (i32.eq (get_local $jump_dest) (i32.const 587))
					(then (br $33))
					(else (if (i32.eq (get_local $jump_dest) (i32.const 565))
					(then (br $32))
					(else (if (i32.eq (get_local $jump_dest) (i32.const 564))
					(then (br $31))
					(else (if (i32.eq (get_local $jump_dest) (i32.const 559))
					(then (br $30))
					(else (if (i32.eq (get_local $jump_dest) (i32.const 546))
					(then (br $29))
					(else (if (i32.eq (get_local $jump_dest) (i32.const 536))
					(then (br $28))
					(else (if (i32.eq (get_local $jump_dest) (i32.const 531))
					(then (br $27))
					(else (if (i32.eq (get_local $jump_dest) (i32.const 523))
					(then (br $26))
					(else (if (i32.eq (get_local $jump_dest) (i32.const 514))
					(then (br $25))
					(else (if (i32.eq (get_local $jump_dest) (i32.const 499))
					(then (br $24))
					(else (if (i32.eq (get_local $jump_dest) (i32.const 488))
					(then (br $23))
					(else (if (i32.eq (get_local $jump_dest) (i32.const 478))
					(then (br $22))
					(else (if (i32.eq (get_local $jump_dest) (i32.const 471))
					(then (br $21))
					(else (if (i32.eq (get_local $jump_dest) (i32.const 465))
					(then (br $20))
					(else (if (i32.eq (get_local $jump_dest) (i32.const 459))
					(then (br $19))
					(else (if (i32.eq (get_local $jump_dest) (i32.const 438))
					(then (br $18))
					(else (if (i32.eq (get_local $jump_dest) (i32.const 428))
					(then (br $17))
					(else (if (i32.eq (get_local $jump_dest) (i32.const 418))
					(then (br $16))
					(else (if (i32.eq (get_local $jump_dest) (i32.const 394))
					(then (br $15))
					(else (if (i32.eq (get_local $jump_dest) (i32.const 382))
					(then (br $14))
					(else (if (i32.eq (get_local $jump_dest) (i32.const 332))
					(then (br $13))
					(else (if (i32.eq (get_local $jump_dest) (i32.const 319))
					(then (br $12))
					(else (if (i32.eq (get_local $jump_dest) (i32.const 303))
					(then (br $11))
					(else (if (i32.eq (get_local $jump_dest) (i32.const 282))
					(then (br $10))
					(else (if (i32.eq (get_local $jump_dest) (i32.const 276))
					(then (br $9))
					(else (if (i32.eq (get_local $jump_dest) (i32.const 275))
					(then (br $8))
					(else (if (i32.eq (get_local $jump_dest) (i32.const 254))
					(then (br $7))
					(else (if (i32.eq (get_local $jump_dest) (i32.const 229))
					(then (br $6))
					(else (if (i32.eq (get_local $jump_dest) (i32.const 182))
					(then (br $5))
					(else (if (i32.eq (get_local $jump_dest) (i32.const 135))
					(then (br $4))
					(else (if (i32.eq (get_local $jump_dest) (i32.const 124))
					(then (br $3))
					(else (if (i32.eq (get_local $jump_dest) (i32.const 117))
					(then (br $2))
					(else (if (i32.eq (get_local $jump_dest) (i32.const 74))
					(then (br $1))
					(else (unreachable)))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))
			  )
			  (else 
				;; return callback destination and zero out $cb_dest 
				(set_local $jump_map_switch (get_global $cb_dest))
				(set_global $cb_dest (i32.const 0))
				(br_table $0  $1 $2 $3 $4 $5 $6 $7 $8 $9 $10 $11 $12 $13 $14 $15 $16 $17 $18 $19 $20 $21 $22 $23 $24 $25 $26 $27 $28 $29 $30 $31 $32 $33 $34 $35 $36 $37 $38 $39 $40 $41 $42 $43 $44 $45 $46 $47 $48 $49 $50 $51 $52 $53 $54 $55 $56 $57 $58 $59 $60 $61 $62 $63 $64 $65 $66 $67 $68 $69 $70 $71 $72 $73 $74 $75 $76 $77 $78 $79 $80 $81 $82 $83 $84 $85 $86 $87 $88 $89 $90 $91 $92 $93 $94 $95 $96 $97 $98 $99 $100 $101 $102 $103 $104 $105 $106 $107 $108 $109 $110 $111 $112 $113 $114 $115 $116 $117 $118 $119 $120 $121 $122 $123 $124 $125 $126 $127 $128 $129 $130 $131 $132 $133 $134 $135 $136 $137 $138 $139 $140 $141 $142 $143 $144 $145 $146 $147 $148 $149 $150 $151 $152 $153 $154 $155 $156 $157 $158 $159 $160 $161 $162 $163 $164 $165 $166 $167 $168 $169 $170 $171 $172 $173 (get_local $jump_map_switch))
			  )))))(call $useGas (i64.const 88)) (if (i32.gt_s (get_global $sp) (i32.const 32576)) 
					 (then (unreachable)))(call $PUSH (i64.const 0)(i64.const 0)(i64.const 0)(i64.const 128))(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $PUSH (i64.const 0)(i64.const 0)(i64.const 0)(i64.const 64))(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $MSTORE)
	(set_global $sp (i32.add (get_global $sp) (i32.const -64)))
	(call $PUSH (i64.const 0)(i64.const 0)(i64.const 0)(i64.const 64))(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $MLOAD)
	(call $DUP (i32.const 0))
	(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $PUSH (i64.const 0)(i64.const 0)(i64.const 0)(i64.const 64))(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $ADD)
	(set_global $sp (i32.add (get_global $sp) (i32.const -32)))
	(call $PUSH (i64.const 0)(i64.const 0)(i64.const 0)(i64.const 64))(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $MSTORE)
	(set_global $sp (i32.add (get_global $sp) (i32.const -64)))
	(call $DUP (i32.const 0))
	(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $PUSH (i64.const 0)(i64.const 0)(i64.const 0)(i64.const 1))(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $DUP (i32.const 1))
	(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $MSTORE)
	(set_global $sp (i32.add (get_global $sp) (i32.const -64)))
	(call $PUSH (i64.const 0)(i64.const 0)(i64.const 0)(i64.const 32))(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $ADD)
	(set_global $sp (i32.add (get_global $sp) (i32.const -32)))
	(call $PUSH (i64.const 3530822107858468864)(i64.const 0)(i64.const 0)(i64.const 0))(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $DUP (i32.const 1))
	(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $MSTORE)
	(set_global $sp (i32.add (get_global $sp) (i32.const -64)))
	(set_global $sp (i32.add (get_global $sp) (i32.const -32)))
	(call $PUSH (i64.const 0)(i64.const 0)(i64.const 0)(i64.const 0))(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $SWAP (i32.const 0))
	(call $DUP (i32.const 1))
	(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $PUSH (i64.const 0)(i64.const 0)(i64.const 0)(i64.const 74))(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $SWAP (i32.const 1))
	(call $SWAP (i32.const 0))
	(call $PUSH (i64.const 0)(i64.const 0)(i64.const 0)(i64.const 758))(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	;; jump
						  (set_local $jump_dest (call $check_overflow 
												 (i64.load (get_global $sp))
												 (i64.load (i32.add (get_global $sp) (i32.const 8)))
												 (i64.load (i32.add (get_global $sp) (i32.const 16)))
												 (i64.load (i32.add (get_global $sp) (i32.const 24)))))
						  (set_global $sp (i32.sub (get_global $sp) (i32.const 32)))
						  (br $loop))(call $useGas (i64.const 46)) (if (i32.gt_s (get_global $sp) (i32.const 32672)) 
					 (then (unreachable)))(if (i32.lt_s (get_global $sp) (i32.const 0)) 
					  (then (unreachable)))(set_global $sp (i32.add (get_global $sp) (i32.const -32)))
	(call $PUSH (i64.const 0)(i64.const 0)(i64.const 0)(i64.const 90))(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $PUSH (i64.const 0)(i64.const 0)(i64.const 0)(i64.const 1))(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $SSTORE)
	(set_global $sp (i32.add (get_global $sp) (i32.const -64)))
	(call $PUSH (i64.const 0)(i64.const 0)(i64.const 0)(i64.const -8446744073709551616))(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $PUSH (i64.const 0)(i64.const 0)(i64.const 0)(i64.const 2))(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $SSTORE)
	(set_global $sp (i32.add (get_global $sp) (i32.const -64)))
	(call $PUSH (i64.const 0)(i64.const 0)(i64.const 0)(i64.const 100000))(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $PUSH (i64.const 0)(i64.const 0)(i64.const 0)(i64.const 3))(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $SSTORE)
	(set_global $sp (i32.add (get_global $sp) (i32.const -64)))
	(call $PUSH (i64.const 0)(i64.const 0)(i64.const 0)(i64.const 0))(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $PUSH (i64.const 0)(i64.const 0)(i64.const 0)(i64.const 4))(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $SSTORE)
	(set_global $sp (i32.add (get_global $sp) (i32.const -64)))
	(call $CALLVALUE)
	(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $DUP (i32.const 0))
	(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $ISZERO)
	(call $PUSH (i64.const 0)(i64.const 0)(i64.const 0)(i64.const 117))(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(set_local $jump_dest (call $check_overflow 
												 (i64.load (get_global $sp))
												 (i64.load (i32.add (get_global $sp) (i32.const 8)))
												 (i64.load (i32.add (get_global $sp) (i32.const 16)))
												 (i64.load (i32.add (get_global $sp) (i32.const 24)))))
	
						(set_global $sp (i32.sub (get_global $sp) (i32.const 64)))
						(br_if $loop (i32.eqz (i64.eqz (i64.or
						  (i64.load (i32.add (get_global $sp) (i32.const 32)))
						  (i64.or
							(i64.load (i32.add (get_global $sp) (i32.const 40)))
							(i64.or
							  (i64.load (i32.add (get_global $sp) (i32.const 48)))
							  (i64.load (i32.add (get_global $sp) (i32.const 56)))
							)
						  )
						))))
	(call $useGas (i64.const 6)) (if (i32.gt_s (get_global $sp) (i32.const 32672)) 
					 (then (unreachable)))(call $PUSH (i64.const 0)(i64.const 0)(i64.const 0)(i64.const 0))(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $DUP (i32.const 0))
	(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $REVERT) (br $done)
	(set_global $sp (i32.add (get_global $sp) (i32.const -64)))
	)(call $useGas (i64.const 14)) (if (i32.lt_s (get_global $sp) (i32.const 0)) 
					  (then (unreachable)))(set_global $sp (i32.add (get_global $sp) (i32.const -32)))
	(call $PUSH (i64.const 0)(i64.const 0)(i64.const 0)(i64.const 989))(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	;; jump
						  (set_local $jump_dest (call $check_overflow 
												 (i64.load (get_global $sp))
												 (i64.load (i32.add (get_global $sp) (i32.const 8)))
												 (i64.load (i32.add (get_global $sp) (i32.const 16)))
												 (i64.load (i32.add (get_global $sp) (i32.const 24)))))
						  (set_global $sp (i32.sub (get_global $sp) (i32.const 32)))
						  (br $loop))(call $useGas (i64.const 31)) (if (i32.gt_s (get_global $sp) (i32.const 32640)) 
					 (then (unreachable)))(call $PUSH (i64.const 0)(i64.const 0)(i64.const 0)(i64.const 0))(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $DUP (i32.const 1))
	(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $MLOAD)
	(call $SWAP (i32.const 0))
	(set_global $sp (i32.add (get_global $sp) (i32.const -32)))
	(call $SWAP (i32.const 1))
	(call $SWAP (i32.const 0))
	(set_global $sp (i32.add (get_global $sp) (i32.const -32)))
	;; jump
						  (set_local $jump_dest (call $check_overflow 
												 (i64.load (get_global $sp))
												 (i64.load (i32.add (get_global $sp) (i32.const 8)))
												 (i64.load (i32.add (get_global $sp) (i32.const 16)))
												 (i64.load (i32.add (get_global $sp) (i32.const 24)))))
						  (set_global $sp (i32.sub (get_global $sp) (i32.const 32)))
						  (br $loop))(call $useGas (i64.const 25)) (if (i32.gt_s (get_global $sp) (i32.const 32672)) 
					 (then (unreachable)))(call $PUSH (i64.const 5640894258543067136)(i64.const 0)(i64.const 0)(i64.const 0))(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $PUSH (i64.const 0)(i64.const 0)(i64.const 0)(i64.const 0))(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $MSTORE)
	(set_global $sp (i32.add (get_global $sp) (i32.const -64)))
	(call $PUSH (i64.const 0)(i64.const 0)(i64.const 0)(i64.const 65))(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $PUSH (i64.const 0)(i64.const 0)(i64.const 0)(i64.const 4))(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $MSTORE)
	(set_global $sp (i32.add (get_global $sp) (i32.const -64)))
	(call $PUSH (i64.const 0)(i64.const 0)(i64.const 0)(i64.const 36))(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $PUSH (i64.const 0)(i64.const 0)(i64.const 0)(i64.const 0))(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $REVERT) (br $done)
	(set_global $sp (i32.add (get_global $sp) (i32.const -64)))
	)(call $useGas (i64.const 25)) (if (i32.gt_s (get_global $sp) (i32.const 32672)) 
					 (then (unreachable)))(call $PUSH (i64.const 5640894258543067136)(i64.const 0)(i64.const 0)(i64.const 0))(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $PUSH (i64.const 0)(i64.const 0)(i64.const 0)(i64.const 0))(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $MSTORE)
	(set_global $sp (i32.add (get_global $sp) (i32.const -64)))
	(call $PUSH (i64.const 0)(i64.const 0)(i64.const 0)(i64.const 34))(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $PUSH (i64.const 0)(i64.const 0)(i64.const 0)(i64.const 4))(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $MSTORE)
	(set_global $sp (i32.add (get_global $sp) (i32.const -64)))
	(call $PUSH (i64.const 0)(i64.const 0)(i64.const 0)(i64.const 36))(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $PUSH (i64.const 0)(i64.const 0)(i64.const 0)(i64.const 0))(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $REVERT) (br $done)
	(set_global $sp (i32.add (get_global $sp) (i32.const -64)))
	)(call $useGas (i64.const 45)) (if (i32.gt_s (get_global $sp) (i32.const 32608)) 
					 (then (unreachable)))(call $PUSH (i64.const 0)(i64.const 0)(i64.const 0)(i64.const 0))(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $PUSH (i64.const 0)(i64.const 0)(i64.const 0)(i64.const 2))(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $DUP (i32.const 2))
	(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $DIV)
	(set_global $sp (i32.add (get_global $sp) (i32.const -32)))
	(call $SWAP (i32.const 0))
	(set_global $sp (i32.add (get_global $sp) (i32.const -32)))
	(call $PUSH (i64.const 0)(i64.const 0)(i64.const 0)(i64.const 1))(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $DUP (i32.const 2))
	(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $AND)
	(set_global $sp (i32.add (get_global $sp) (i32.const -32)))
	(call $DUP (i32.const 0))
	(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $PUSH (i64.const 0)(i64.const 0)(i64.const 0)(i64.const 254))(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(set_local $jump_dest (call $check_overflow 
												 (i64.load (get_global $sp))
												 (i64.load (i32.add (get_global $sp) (i32.const 8)))
												 (i64.load (i32.add (get_global $sp) (i32.const 16)))
												 (i64.load (i32.add (get_global $sp) (i32.const 24)))))
	
						(set_global $sp (i32.sub (get_global $sp) (i32.const 64)))
						(br_if $loop (i32.eqz (i64.eqz (i64.or
						  (i64.load (i32.add (get_global $sp) (i32.const 32)))
						  (i64.or
							(i64.load (i32.add (get_global $sp) (i32.const 40)))
							(i64.or
							  (i64.load (i32.add (get_global $sp) (i32.const 48)))
							  (i64.load (i32.add (get_global $sp) (i32.const 56)))
							)
						  )
						))))
	(call $useGas (i64.const 14)) (if (i32.gt_s (get_global $sp) (i32.const 32640)) 
					 (then (unreachable)))(call $PUSH (i64.const 0)(i64.const 0)(i64.const 0)(i64.const 127))(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $DUP (i32.const 2))
	(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $AND)
	(set_global $sp (i32.add (get_global $sp) (i32.const -32)))
	(call $SWAP (i32.const 1))
	(set_global $sp (i32.add (get_global $sp) (i32.const -32)))
	)(call $useGas (i64.const 29)) (if (i32.gt_s (get_global $sp) (i32.const 32640)) 
					 (then (unreachable)))(call $PUSH (i64.const 0)(i64.const 0)(i64.const 0)(i64.const 32))(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $DUP (i32.const 2))
	(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $LT)
	(set_global $sp (i32.add (get_global $sp) (i32.const -32)))
	(call $DUP (i32.const 1))
	(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $SUB)
	(set_global $sp (i32.add (get_global $sp) (i32.const -32)))
	(call $PUSH (i64.const 0)(i64.const 0)(i64.const 0)(i64.const 276))(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(set_local $jump_dest (call $check_overflow 
												 (i64.load (get_global $sp))
												 (i64.load (i32.add (get_global $sp) (i32.const 8)))
												 (i64.load (i32.add (get_global $sp) (i32.const 16)))
												 (i64.load (i32.add (get_global $sp) (i32.const 24)))))
	
						(set_global $sp (i32.sub (get_global $sp) (i32.const 64)))
						(br_if $loop (i32.eqz (i64.eqz (i64.or
						  (i64.load (i32.add (get_global $sp) (i32.const 32)))
						  (i64.or
							(i64.load (i32.add (get_global $sp) (i32.const 40)))
							(i64.or
							  (i64.load (i32.add (get_global $sp) (i32.const 48)))
							  (i64.load (i32.add (get_global $sp) (i32.const 56)))
							)
						  )
						))))
	(call $useGas (i64.const 14)) (if (i32.gt_s (get_global $sp) (i32.const 32672)) 
					 (then (unreachable)))(call $PUSH (i64.const 0)(i64.const 0)(i64.const 0)(i64.const 275))(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $PUSH (i64.const 0)(i64.const 0)(i64.const 0)(i64.const 182))(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	;; jump
						  (set_local $jump_dest (call $check_overflow 
												 (i64.load (get_global $sp))
												 (i64.load (i32.add (get_global $sp) (i32.const 8)))
												 (i64.load (i32.add (get_global $sp) (i32.const 16)))
												 (i64.load (i32.add (get_global $sp) (i32.const 24)))))
						  (set_global $sp (i32.sub (get_global $sp) (i32.const 32)))
						  (br $loop))(call $useGas (i64.const 1)) )(call $useGas (i64.const 19)) (if (i32.lt_s (get_global $sp) (i32.const 32)) 
					  (then (unreachable)))(set_global $sp (i32.add (get_global $sp) (i32.const -32)))
	(call $SWAP (i32.const 1))
	(call $SWAP (i32.const 0))
	(set_global $sp (i32.add (get_global $sp) (i32.const -32)))
	;; jump
						  (set_local $jump_dest (call $check_overflow 
												 (i64.load (get_global $sp))
												 (i64.load (i32.add (get_global $sp) (i32.const 8)))
												 (i64.load (i32.add (get_global $sp) (i32.const 16)))
												 (i64.load (i32.add (get_global $sp) (i32.const 24)))))
						  (set_global $sp (i32.sub (get_global $sp) (i32.const 32)))
						  (br $loop))(call $useGas (i64.const 78)) (if (i32.gt_s (get_global $sp) (i32.const 32608)) 
					 (then (unreachable)))(call $PUSH (i64.const 0)(i64.const 0)(i64.const 0)(i64.const 0))(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $DUP (i32.const 1))
	(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $SWAP (i32.const 0))
	(set_global $sp (i32.add (get_global $sp) (i32.const -32)))
	(call $DUP (i32.const 1))
	(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $PUSH (i64.const 0)(i64.const 0)(i64.const 0)(i64.const 0))(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $MSTORE)
	(set_global $sp (i32.add (get_global $sp) (i32.const -64)))
	(call $PUSH (i64.const 0)(i64.const 0)(i64.const 0)(i64.const 32))(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $PUSH (i64.const 0)(i64.const 0)(i64.const 0)(i64.const 0))(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $SHA3)
	(set_global $sp (i32.add (get_global $sp) (i32.const -32)))
	(call $SWAP (i32.const 0))
	(set_global $sp (i32.add (get_global $sp) (i32.const -32)))
	(call $SWAP (i32.const 1))
	(call $SWAP (i32.const 0))
	(set_global $sp (i32.add (get_global $sp) (i32.const -32)))
	;; jump
						  (set_local $jump_dest (call $check_overflow 
												 (i64.load (get_global $sp))
												 (i64.load (i32.add (get_global $sp) (i32.const 8)))
												 (i64.load (i32.add (get_global $sp) (i32.const 16)))
												 (i64.load (i32.add (get_global $sp) (i32.const 24)))))
						  (set_global $sp (i32.sub (get_global $sp) (i32.const 32)))
						  (br $loop))(call $useGas (i64.const 42)) (if (i32.gt_s (get_global $sp) (i32.const 32576)) 
					 (then (unreachable)))(call $PUSH (i64.const 0)(i64.const 0)(i64.const 0)(i64.const 0))(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $PUSH (i64.const 0)(i64.const 0)(i64.const 0)(i64.const 32))(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $PUSH (i64.const 0)(i64.const 0)(i64.const 0)(i64.const 31))(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $DUP (i32.const 3))
	(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $ADD)
	(set_global $sp (i32.add (get_global $sp) (i32.const -32)))
	(call $DIV)
	(set_global $sp (i32.add (get_global $sp) (i32.const -32)))
	(call $SWAP (i32.const 0))
	(set_global $sp (i32.add (get_global $sp) (i32.const -32)))
	(call $SWAP (i32.const 1))
	(call $SWAP (i32.const 0))
	(set_global $sp (i32.add (get_global $sp) (i32.const -32)))
	;; jump
						  (set_local $jump_dest (call $check_overflow 
												 (i64.load (get_global $sp))
												 (i64.load (i32.add (get_global $sp) (i32.const 8)))
												 (i64.load (i32.add (get_global $sp) (i32.const 16)))
												 (i64.load (i32.add (get_global $sp) (i32.const 24)))))
						  (set_global $sp (i32.sub (get_global $sp) (i32.const 32)))
						  (br $loop))(call $useGas (i64.const 10)) (if (i32.gt_s (get_global $sp) (i32.const 32640)) 
					 (then (unreachable)))(unreachable))(call $useGas (i64.const 35)) (if (i32.gt_s (get_global $sp) (i32.const 32544)) 
					 (then (unreachable)))(call $PUSH (i64.const 0)(i64.const 0)(i64.const 0)(i64.const 0))(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $PUSH (i64.const 0)(i64.const 0)(i64.const 0)(i64.const 8))(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $DUP (i32.const 3))
	(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $MUL)
	(set_global $sp (i32.add (get_global $sp) (i32.const -32)))
	(call $PUSH (i64.const 0)(i64.const 0)(i64.const 0)(i64.const 382))(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $PUSH (i64.const -1)(i64.const -1)(i64.const -1)(i64.const -1))(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $DUP (i32.const 2))
	(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $PUSH (i64.const 0)(i64.const 0)(i64.const 0)(i64.const 319))(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	;; jump
						  (set_local $jump_dest (call $check_overflow 
												 (i64.load (get_global $sp))
												 (i64.load (i32.add (get_global $sp) (i32.const 8)))
												 (i64.load (i32.add (get_global $sp) (i32.const 16)))
												 (i64.load (i32.add (get_global $sp) (i32.const 24)))))
						  (set_global $sp (i32.sub (get_global $sp) (i32.const 32)))
						  (br $loop))(call $useGas (i64.const 21)) (if (i32.gt_s (get_global $sp) (i32.const 32608)) 
					 (then (unreachable)))(call $PUSH (i64.const 0)(i64.const 0)(i64.const 0)(i64.const 394))(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $DUP (i32.const 6))
	(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $DUP (i32.const 3))
	(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $PUSH (i64.const 0)(i64.const 0)(i64.const 0)(i64.const 319))(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	;; jump
						  (set_local $jump_dest (call $check_overflow 
												 (i64.load (get_global $sp))
												 (i64.load (i32.add (get_global $sp) (i32.const 8)))
												 (i64.load (i32.add (get_global $sp) (i32.const 16)))
												 (i64.load (i32.add (get_global $sp) (i32.const 24)))))
						  (set_global $sp (i32.sub (get_global $sp) (i32.const 32)))
						  (br $loop))(call $useGas (i64.const 67)) (if (i32.gt_s (get_global $sp) (i32.const 32672)) 
					 (then (unreachable)))(if (i32.lt_s (get_global $sp) (i32.const 160)) 
					  (then (unreachable)))(call $SWAP (i32.const 5))
	(set_global $sp (i32.add (get_global $sp) (i32.const -32)))
	(call $DUP (i32.const 0))
	(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $NOT)
	(call $DUP (i32.const 4))
	(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $AND)
	(set_global $sp (i32.add (get_global $sp) (i32.const -32)))
	(call $SWAP (i32.const 3))
	(set_global $sp (i32.add (get_global $sp) (i32.const -32)))
	(call $DUP (i32.const 0))
	(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $DUP (i32.const 6))
	(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $AND)
	(set_global $sp (i32.add (get_global $sp) (i32.const -32)))
	(call $DUP (i32.const 4))
	(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $OR)
	(set_global $sp (i32.add (get_global $sp) (i32.const -32)))
	(call $SWAP (i32.const 2))
	(set_global $sp (i32.add (get_global $sp) (i32.const -32)))
	(set_global $sp (i32.add (get_global $sp) (i32.const -32)))
	(set_global $sp (i32.add (get_global $sp) (i32.const -32)))
	(call $SWAP (i32.const 3))
	(call $SWAP (i32.const 2))
	(set_global $sp (i32.add (get_global $sp) (i32.const -32)))
	(set_global $sp (i32.add (get_global $sp) (i32.const -32)))
	(set_global $sp (i32.add (get_global $sp) (i32.const -32)))
	;; jump
						  (set_local $jump_dest (call $check_overflow 
												 (i64.load (get_global $sp))
												 (i64.load (i32.add (get_global $sp) (i32.const 8)))
												 (i64.load (i32.add (get_global $sp) (i32.const 16)))
												 (i64.load (i32.add (get_global $sp) (i32.const 24)))))
						  (set_global $sp (i32.sub (get_global $sp) (i32.const 32)))
						  (br $loop))(call $useGas (i64.const 28)) (if (i32.gt_s (get_global $sp) (i32.const 32672)) 
					 (then (unreachable)))(call $PUSH (i64.const 0)(i64.const 0)(i64.const 0)(i64.const 0))(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $DUP (i32.const 1))
	(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $SWAP (i32.const 0))
	(set_global $sp (i32.add (get_global $sp) (i32.const -32)))
	(call $SWAP (i32.const 1))
	(call $SWAP (i32.const 0))
	(set_global $sp (i32.add (get_global $sp) (i32.const -32)))
	;; jump
						  (set_local $jump_dest (call $check_overflow 
												 (i64.load (get_global $sp))
												 (i64.load (i32.add (get_global $sp) (i32.const 8)))
												 (i64.load (i32.add (get_global $sp) (i32.const 16)))
												 (i64.load (i32.add (get_global $sp) (i32.const 24)))))
						  (set_global $sp (i32.sub (get_global $sp) (i32.const 32)))
						  (br $loop))(call $useGas (i64.const 28)) (if (i32.gt_s (get_global $sp) (i32.const 32672)) 
					 (then (unreachable)))(call $PUSH (i64.const 0)(i64.const 0)(i64.const 0)(i64.const 0))(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $DUP (i32.const 1))
	(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $SWAP (i32.const 0))
	(set_global $sp (i32.add (get_global $sp) (i32.const -32)))
	(call $SWAP (i32.const 1))
	(call $SWAP (i32.const 0))
	(set_global $sp (i32.add (get_global $sp) (i32.const -32)))
	;; jump
						  (set_local $jump_dest (call $check_overflow 
												 (i64.load (get_global $sp))
												 (i64.load (i32.add (get_global $sp) (i32.const 8)))
												 (i64.load (i32.add (get_global $sp) (i32.const 16)))
												 (i64.load (i32.add (get_global $sp) (i32.const 24)))))
						  (set_global $sp (i32.sub (get_global $sp) (i32.const 32)))
						  (br $loop))(call $useGas (i64.const 27)) (if (i32.gt_s (get_global $sp) (i32.const 32544)) 
					 (then (unreachable)))(call $PUSH (i64.const 0)(i64.const 0)(i64.const 0)(i64.const 0))(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $PUSH (i64.const 0)(i64.const 0)(i64.const 0)(i64.const 471))(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $PUSH (i64.const 0)(i64.const 0)(i64.const 0)(i64.const 465))(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $PUSH (i64.const 0)(i64.const 0)(i64.const 0)(i64.const 459))(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $DUP (i32.const 4))
	(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $PUSH (i64.const 0)(i64.const 0)(i64.const 0)(i64.const 418))(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	;; jump
						  (set_local $jump_dest (call $check_overflow 
												 (i64.load (get_global $sp))
												 (i64.load (i32.add (get_global $sp) (i32.const 8)))
												 (i64.load (i32.add (get_global $sp) (i32.const 16)))
												 (i64.load (i32.add (get_global $sp) (i32.const 24)))))
						  (set_global $sp (i32.sub (get_global $sp) (i32.const 32)))
						  (br $loop))(call $useGas (i64.const 12)) (if (i32.gt_s (get_global $sp) (i32.const 32704)) 
					 (then (unreachable)))(call $PUSH (i64.const 0)(i64.const 0)(i64.const 0)(i64.const 428))(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	;; jump
						  (set_local $jump_dest (call $check_overflow 
												 (i64.load (get_global $sp))
												 (i64.load (i32.add (get_global $sp) (i32.const 8)))
												 (i64.load (i32.add (get_global $sp) (i32.const 16)))
												 (i64.load (i32.add (get_global $sp) (i32.const 24)))))
						  (set_global $sp (i32.sub (get_global $sp) (i32.const 32)))
						  (br $loop))(call $useGas (i64.const 12)) (if (i32.gt_s (get_global $sp) (i32.const 32704)) 
					 (then (unreachable)))(call $PUSH (i64.const 0)(i64.const 0)(i64.const 0)(i64.const 418))(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	;; jump
						  (set_local $jump_dest (call $check_overflow 
												 (i64.load (get_global $sp))
												 (i64.load (i32.add (get_global $sp) (i32.const 8)))
												 (i64.load (i32.add (get_global $sp) (i32.const 16)))
												 (i64.load (i32.add (get_global $sp) (i32.const 24)))))
						  (set_global $sp (i32.sub (get_global $sp) (i32.const 32)))
						  (br $loop))(call $useGas (i64.const 22)) (if (i32.lt_s (get_global $sp) (i32.const 32)) 
					  (then (unreachable)))(call $SWAP (i32.const 0))
	(set_global $sp (i32.add (get_global $sp) (i32.const -32)))
	(call $SWAP (i32.const 1))
	(call $SWAP (i32.const 0))
	(set_global $sp (i32.add (get_global $sp) (i32.const -32)))
	;; jump
						  (set_local $jump_dest (call $check_overflow 
												 (i64.load (get_global $sp))
												 (i64.load (i32.add (get_global $sp) (i32.const 8)))
												 (i64.load (i32.add (get_global $sp) (i32.const 16)))
												 (i64.load (i32.add (get_global $sp) (i32.const 24)))))
						  (set_global $sp (i32.sub (get_global $sp) (i32.const 32)))
						  (br $loop))(call $useGas (i64.const 28)) (if (i32.gt_s (get_global $sp) (i32.const 32672)) 
					 (then (unreachable)))(call $PUSH (i64.const 0)(i64.const 0)(i64.const 0)(i64.const 0))(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $DUP (i32.const 1))
	(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $SWAP (i32.const 0))
	(set_global $sp (i32.add (get_global $sp) (i32.const -32)))
	(call $SWAP (i32.const 1))
	(call $SWAP (i32.const 0))
	(set_global $sp (i32.add (get_global $sp) (i32.const -32)))
	;; jump
						  (set_local $jump_dest (call $check_overflow 
												 (i64.load (get_global $sp))
												 (i64.load (i32.add (get_global $sp) (i32.const 8)))
												 (i64.load (i32.add (get_global $sp) (i32.const 16)))
												 (i64.load (i32.add (get_global $sp) (i32.const 24)))))
						  (set_global $sp (i32.sub (get_global $sp) (i32.const 32)))
						  (br $loop))(call $useGas (i64.const 18)) (if (i32.gt_s (get_global $sp) (i32.const 32640)) 
					 (then (unreachable)))(call $PUSH (i64.const 0)(i64.const 0)(i64.const 0)(i64.const 499))(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $DUP (i32.const 3))
	(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $PUSH (i64.const 0)(i64.const 0)(i64.const 0)(i64.const 438))(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	;; jump
						  (set_local $jump_dest (call $check_overflow 
												 (i64.load (get_global $sp))
												 (i64.load (i32.add (get_global $sp) (i32.const 8)))
												 (i64.load (i32.add (get_global $sp) (i32.const 16)))
												 (i64.load (i32.add (get_global $sp) (i32.const 24)))))
						  (set_global $sp (i32.sub (get_global $sp) (i32.const 32)))
						  (br $loop))(call $useGas (i64.const 21)) (if (i32.gt_s (get_global $sp) (i32.const 32608)) 
					 (then (unreachable)))(call $PUSH (i64.const 0)(i64.const 0)(i64.const 0)(i64.const 523))(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $PUSH (i64.const 0)(i64.const 0)(i64.const 0)(i64.const 514))(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $DUP (i32.const 2))
	(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $PUSH (i64.const 0)(i64.const 0)(i64.const 0)(i64.const 478))(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	;; jump
						  (set_local $jump_dest (call $check_overflow 
												 (i64.load (get_global $sp))
												 (i64.load (i32.add (get_global $sp) (i32.const 8)))
												 (i64.load (i32.add (get_global $sp) (i32.const 16)))
												 (i64.load (i32.add (get_global $sp) (i32.const 24)))))
						  (set_global $sp (i32.sub (get_global $sp) (i32.const 32)))
						  (br $loop))(call $useGas (i64.const 18)) (if (i32.gt_s (get_global $sp) (i32.const 32640)) 
					 (then (unreachable)))(call $DUP (i32.const 4))
	(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $DUP (i32.const 4))
	(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $SLOAD)
	(call $PUSH (i64.const 0)(i64.const 0)(i64.const 0)(i64.const 332))(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	;; jump
						  (set_local $jump_dest (call $check_overflow 
												 (i64.load (get_global $sp))
												 (i64.load (i32.add (get_global $sp) (i32.const 8)))
												 (i64.load (i32.add (get_global $sp) (i32.const 16)))
												 (i64.load (i32.add (get_global $sp) (i32.const 24)))))
						  (set_global $sp (i32.sub (get_global $sp) (i32.const 32)))
						  (br $loop))(call $useGas (i64.const 20)) (if (i32.gt_s (get_global $sp) (i32.const 32704)) 
					 (then (unreachable)))(if (i32.lt_s (get_global $sp) (i32.const 128)) 
					  (then (unreachable)))(call $DUP (i32.const 2))
	(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $SSTORE)
	(set_global $sp (i32.add (get_global $sp) (i32.const -64)))
	(set_global $sp (i32.add (get_global $sp) (i32.const -32)))
	(set_global $sp (i32.add (get_global $sp) (i32.const -32)))
	(set_global $sp (i32.add (get_global $sp) (i32.const -32)))
	(set_global $sp (i32.add (get_global $sp) (i32.const -32)))
	;; jump
						  (set_local $jump_dest (call $check_overflow 
												 (i64.load (get_global $sp))
												 (i64.load (i32.add (get_global $sp) (i32.const 8)))
												 (i64.load (i32.add (get_global $sp) (i32.const 16)))
												 (i64.load (i32.add (get_global $sp) (i32.const 24)))))
						  (set_global $sp (i32.sub (get_global $sp) (i32.const 32)))
						  (br $loop))(call $useGas (i64.const 15)) (if (i32.gt_s (get_global $sp) (i32.const 32704)) 
					 (then (unreachable)))(call $PUSH (i64.const 0)(i64.const 0)(i64.const 0)(i64.const 0))(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $SWAP (i32.const 0))
	;; jump
						  (set_local $jump_dest (call $check_overflow 
												 (i64.load (get_global $sp))
												 (i64.load (i32.add (get_global $sp) (i32.const 8)))
												 (i64.load (i32.add (get_global $sp) (i32.const 16)))
												 (i64.load (i32.add (get_global $sp) (i32.const 24)))))
						  (set_global $sp (i32.sub (get_global $sp) (i32.const 32)))
						  (br $loop))(call $useGas (i64.const 15)) (if (i32.gt_s (get_global $sp) (i32.const 32672)) 
					 (then (unreachable)))(call $PUSH (i64.const 0)(i64.const 0)(i64.const 0)(i64.const 546))(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $PUSH (i64.const 0)(i64.const 0)(i64.const 0)(i64.const 531))(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	;; jump
						  (set_local $jump_dest (call $check_overflow 
												 (i64.load (get_global $sp))
												 (i64.load (i32.add (get_global $sp) (i32.const 8)))
												 (i64.load (i32.add (get_global $sp) (i32.const 16)))
												 (i64.load (i32.add (get_global $sp) (i32.const 24)))))
						  (set_global $sp (i32.sub (get_global $sp) (i32.const 32)))
						  (br $loop))(call $useGas (i64.const 24)) (if (i32.gt_s (get_global $sp) (i32.const 32576)) 
					 (then (unreachable)))(call $PUSH (i64.const 0)(i64.const 0)(i64.const 0)(i64.const 559))(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $DUP (i32.const 1))
	(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $DUP (i32.const 4))
	(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $DUP (i32.const 4))
	(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $PUSH (i64.const 0)(i64.const 0)(i64.const 0)(i64.const 488))(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	;; jump
						  (set_local $jump_dest (call $check_overflow 
												 (i64.load (get_global $sp))
												 (i64.load (i32.add (get_global $sp) (i32.const 8)))
												 (i64.load (i32.add (get_global $sp) (i32.const 16)))
												 (i64.load (i32.add (get_global $sp) (i32.const 24)))))
						  (set_global $sp (i32.sub (get_global $sp) (i32.const 32)))
						  (br $loop))(call $useGas (i64.const 15)) (if (i32.lt_s (get_global $sp) (i32.const 64)) 
					  (then (unreachable)))(set_global $sp (i32.add (get_global $sp) (i32.const -32)))
	(set_global $sp (i32.add (get_global $sp) (i32.const -32)))
	(set_global $sp (i32.add (get_global $sp) (i32.const -32)))
	;; jump
						  (set_local $jump_dest (call $check_overflow 
												 (i64.load (get_global $sp))
												 (i64.load (i32.add (get_global $sp) (i32.const 8)))
												 (i64.load (i32.add (get_global $sp) (i32.const 16)))
												 (i64.load (i32.add (get_global $sp) (i32.const 24)))))
						  (set_global $sp (i32.sub (get_global $sp) (i32.const 32)))
						  (br $loop))(call $useGas (i64.const 1)) )(call $useGas (i64.const 26)) (if (i32.gt_s (get_global $sp) (i32.const 32640)) 
					 (then (unreachable)))(call $DUP (i32.const 1))
	(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $DUP (i32.const 1))
	(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $LT)
	(set_global $sp (i32.add (get_global $sp) (i32.const -32)))
	(call $ISZERO)
	(call $PUSH (i64.const 0)(i64.const 0)(i64.const 0)(i64.const 599))(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(set_local $jump_dest (call $check_overflow 
												 (i64.load (get_global $sp))
												 (i64.load (i32.add (get_global $sp) (i32.const 8)))
												 (i64.load (i32.add (get_global $sp) (i32.const 16)))
												 (i64.load (i32.add (get_global $sp) (i32.const 24)))))
	
						(set_global $sp (i32.sub (get_global $sp) (i32.const 64)))
						(br_if $loop (i32.eqz (i64.eqz (i64.or
						  (i64.load (i32.add (get_global $sp) (i32.const 32)))
						  (i64.or
							(i64.load (i32.add (get_global $sp) (i32.const 40)))
							(i64.or
							  (i64.load (i32.add (get_global $sp) (i32.const 48)))
							  (i64.load (i32.add (get_global $sp) (i32.const 56)))
							)
						  )
						))))
	(call $useGas (i64.const 20)) (if (i32.gt_s (get_global $sp) (i32.const 32608)) 
					 (then (unreachable)))(call $PUSH (i64.const 0)(i64.const 0)(i64.const 0)(i64.const 587))(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $PUSH (i64.const 0)(i64.const 0)(i64.const 0)(i64.const 0))(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $DUP (i32.const 2))
	(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $PUSH (i64.const 0)(i64.const 0)(i64.const 0)(i64.const 536))(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	;; jump
						  (set_local $jump_dest (call $check_overflow 
												 (i64.load (get_global $sp))
												 (i64.load (i32.add (get_global $sp) (i32.const 8)))
												 (i64.load (i32.add (get_global $sp) (i32.const 16)))
												 (i64.load (i32.add (get_global $sp) (i32.const 24)))))
						  (set_global $sp (i32.sub (get_global $sp) (i32.const 32)))
						  (br $loop))(call $useGas (i64.const 26)) (if (i32.gt_s (get_global $sp) (i32.const 32640)) 
					 (then (unreachable)))(call $PUSH (i64.const 0)(i64.const 0)(i64.const 0)(i64.const 1))(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $DUP (i32.const 1))
	(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $ADD)
	(set_global $sp (i32.add (get_global $sp) (i32.const -32)))
	(call $SWAP (i32.const 0))
	(set_global $sp (i32.add (get_global $sp) (i32.const -32)))
	(call $PUSH (i64.const 0)(i64.const 0)(i64.const 0)(i64.const 565))(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	;; jump
						  (set_local $jump_dest (call $check_overflow 
												 (i64.load (get_global $sp))
												 (i64.load (i32.add (get_global $sp) (i32.const 8)))
												 (i64.load (i32.add (get_global $sp) (i32.const 16)))
												 (i64.load (i32.add (get_global $sp) (i32.const 24)))))
						  (set_global $sp (i32.sub (get_global $sp) (i32.const 32)))
						  (br $loop))(call $useGas (i64.const 13)) (if (i32.lt_s (get_global $sp) (i32.const 32)) 
					  (then (unreachable)))(set_global $sp (i32.add (get_global $sp) (i32.const -32)))
	(set_global $sp (i32.add (get_global $sp) (i32.const -32)))
	;; jump
						  (set_local $jump_dest (call $check_overflow 
												 (i64.load (get_global $sp))
												 (i64.load (i32.add (get_global $sp) (i32.const 8)))
												 (i64.load (i32.add (get_global $sp) (i32.const 16)))
												 (i64.load (i32.add (get_global $sp) (i32.const 24)))))
						  (set_global $sp (i32.sub (get_global $sp) (i32.const 32)))
						  (br $loop))(call $useGas (i64.const 26)) (if (i32.gt_s (get_global $sp) (i32.const 32640)) 
					 (then (unreachable)))(call $PUSH (i64.const 0)(i64.const 0)(i64.const 0)(i64.const 31))(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $DUP (i32.const 2))
	(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $GT)
	(set_global $sp (i32.add (get_global $sp) (i32.const -32)))
	(call $ISZERO)
	(call $PUSH (i64.const 0)(i64.const 0)(i64.const 0)(i64.const 678))(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(set_local $jump_dest (call $check_overflow 
												 (i64.load (get_global $sp))
												 (i64.load (i32.add (get_global $sp) (i32.const 8)))
												 (i64.load (i32.add (get_global $sp) (i32.const 16)))
												 (i64.load (i32.add (get_global $sp) (i32.const 24)))))
	
						(set_global $sp (i32.sub (get_global $sp) (i32.const 64)))
						(br_if $loop (i32.eqz (i64.eqz (i64.or
						  (i64.load (i32.add (get_global $sp) (i32.const 32)))
						  (i64.or
							(i64.load (i32.add (get_global $sp) (i32.const 40)))
							(i64.or
							  (i64.load (i32.add (get_global $sp) (i32.const 48)))
							  (i64.load (i32.add (get_global $sp) (i32.const 56)))
							)
						  )
						))))
	(call $useGas (i64.const 17)) (if (i32.gt_s (get_global $sp) (i32.const 32640)) 
					 (then (unreachable)))(call $PUSH (i64.const 0)(i64.const 0)(i64.const 0)(i64.const 624))(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $DUP (i32.const 1))
	(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $PUSH (i64.const 0)(i64.const 0)(i64.const 0)(i64.const 282))(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	;; jump
						  (set_local $jump_dest (call $check_overflow 
												 (i64.load (get_global $sp))
												 (i64.load (i32.add (get_global $sp) (i32.const 8)))
												 (i64.load (i32.add (get_global $sp) (i32.const 16)))
												 (i64.load (i32.add (get_global $sp) (i32.const 24)))))
						  (set_global $sp (i32.sub (get_global $sp) (i32.const 32)))
						  (br $loop))(call $useGas (i64.const 18)) (if (i32.gt_s (get_global $sp) (i32.const 32640)) 
					 (then (unreachable)))(call $PUSH (i64.const 0)(i64.const 0)(i64.const 0)(i64.const 635))(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $DUP (i32.const 4))
	(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $PUSH (i64.const 0)(i64.const 0)(i64.const 0)(i64.const 303))(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	;; jump
						  (set_local $jump_dest (call $check_overflow 
												 (i64.load (get_global $sp))
												 (i64.load (i32.add (get_global $sp) (i32.const 8)))
												 (i64.load (i32.add (get_global $sp) (i32.const 16)))
												 (i64.load (i32.add (get_global $sp) (i32.const 24)))))
						  (set_global $sp (i32.sub (get_global $sp) (i32.const 32)))
						  (br $loop))(call $useGas (i64.const 32)) (if (i32.gt_s (get_global $sp) (i32.const 32640)) 
					 (then (unreachable)))(call $DUP (i32.const 1))
	(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $ADD)
	(set_global $sp (i32.add (get_global $sp) (i32.const -32)))
	(call $PUSH (i64.const 0)(i64.const 0)(i64.const 0)(i64.const 32))(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $DUP (i32.const 5))
	(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $LT)
	(set_global $sp (i32.add (get_global $sp) (i32.const -32)))
	(call $ISZERO)
	(call $PUSH (i64.const 0)(i64.const 0)(i64.const 0)(i64.const 651))(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(set_local $jump_dest (call $check_overflow 
												 (i64.load (get_global $sp))
												 (i64.load (i32.add (get_global $sp) (i32.const 8)))
												 (i64.load (i32.add (get_global $sp) (i32.const 16)))
												 (i64.load (i32.add (get_global $sp) (i32.const 24)))))
	
						(set_global $sp (i32.sub (get_global $sp) (i32.const 64)))
						(br_if $loop (i32.eqz (i64.eqz (i64.or
						  (i64.load (i32.add (get_global $sp) (i32.const 32)))
						  (i64.or
							(i64.load (i32.add (get_global $sp) (i32.const 40)))
							(i64.or
							  (i64.load (i32.add (get_global $sp) (i32.const 48)))
							  (i64.load (i32.add (get_global $sp) (i32.const 56)))
							)
						  )
						))))
	(call $useGas (i64.const 8)) (if (i32.gt_s (get_global $sp) (i32.const 32704)) 
					 (then (unreachable)))(call $DUP (i32.const 1))
	(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $SWAP (i32.const 0))
	(set_global $sp (i32.add (get_global $sp) (i32.const -32)))
	)(call $useGas (i64.const 21)) (if (i32.gt_s (get_global $sp) (i32.const 32608)) 
					 (then (unreachable)))(call $PUSH (i64.const 0)(i64.const 0)(i64.const 0)(i64.const 675))(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $PUSH (i64.const 0)(i64.const 0)(i64.const 0)(i64.const 666))(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $DUP (i32.const 5))
	(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $PUSH (i64.const 0)(i64.const 0)(i64.const 0)(i64.const 303))(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	;; jump
						  (set_local $jump_dest (call $check_overflow 
												 (i64.load (get_global $sp))
												 (i64.load (i32.add (get_global $sp) (i32.const 8)))
												 (i64.load (i32.add (get_global $sp) (i32.const 16)))
												 (i64.load (i32.add (get_global $sp) (i32.const 24)))))
						  (set_global $sp (i32.sub (get_global $sp) (i32.const 32)))
						  (br $loop))(call $useGas (i64.const 21)) (if (i32.gt_s (get_global $sp) (i32.const 32672)) 
					 (then (unreachable)))(call $DUP (i32.const 3))
	(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $ADD)
	(set_global $sp (i32.add (get_global $sp) (i32.const -32)))
	(call $DUP (i32.const 2))
	(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $PUSH (i64.const 0)(i64.const 0)(i64.const 0)(i64.const 564))(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	;; jump
						  (set_local $jump_dest (call $check_overflow 
												 (i64.load (get_global $sp))
												 (i64.load (i32.add (get_global $sp) (i32.const 8)))
												 (i64.load (i32.add (get_global $sp) (i32.const 16)))
												 (i64.load (i32.add (get_global $sp) (i32.const 24)))))
						  (set_global $sp (i32.sub (get_global $sp) (i32.const 32)))
						  (br $loop))(call $useGas (i64.const 5)) (if (i32.lt_s (get_global $sp) (i32.const 32)) 
					  (then (unreachable)))(set_global $sp (i32.add (get_global $sp) (i32.const -32)))
	(set_global $sp (i32.add (get_global $sp) (i32.const -32)))
	)(call $useGas (i64.const 15)) (if (i32.lt_s (get_global $sp) (i32.const 64)) 
					  (then (unreachable)))(set_global $sp (i32.add (get_global $sp) (i32.const -32)))
	(set_global $sp (i32.add (get_global $sp) (i32.const -32)))
	(set_global $sp (i32.add (get_global $sp) (i32.const -32)))
	;; jump
						  (set_local $jump_dest (call $check_overflow 
												 (i64.load (get_global $sp))
												 (i64.load (i32.add (get_global $sp) (i32.const 8)))
												 (i64.load (i32.add (get_global $sp) (i32.const 16)))
												 (i64.load (i32.add (get_global $sp) (i32.const 24)))))
						  (set_global $sp (i32.sub (get_global $sp) (i32.const 32)))
						  (br $loop))(call $useGas (i64.const 10)) (if (i32.gt_s (get_global $sp) (i32.const 32640)) 
					 (then (unreachable)))(unreachable))(call $useGas (i64.const 35)) (if (i32.gt_s (get_global $sp) (i32.const 32544)) 
					 (then (unreachable)))(call $PUSH (i64.const 0)(i64.const 0)(i64.const 0)(i64.const 0))(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $PUSH (i64.const 0)(i64.const 0)(i64.const 0)(i64.const 715))(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $PUSH (i64.const 0)(i64.const 0)(i64.const 0)(i64.const 0))(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $NOT)
	(call $DUP (i32.const 4))
	(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $PUSH (i64.const 0)(i64.const 0)(i64.const 0)(i64.const 8))(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $MUL)
	(set_global $sp (i32.add (get_global $sp) (i32.const -32)))
	(call $PUSH (i64.const 0)(i64.const 0)(i64.const 0)(i64.const 683))(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	;; jump
						  (set_local $jump_dest (call $check_overflow 
												 (i64.load (get_global $sp))
												 (i64.load (i32.add (get_global $sp) (i32.const 8)))
												 (i64.load (i32.add (get_global $sp) (i32.const 16)))
												 (i64.load (i32.add (get_global $sp) (i32.const 24)))))
						  (set_global $sp (i32.sub (get_global $sp) (i32.const 32)))
						  (br $loop))(call $useGas (i64.const 38)) (if (i32.gt_s (get_global $sp) (i32.const 32640)) 
					 (then (unreachable)))(if (i32.lt_s (get_global $sp) (i32.const 64)) 
					  (then (unreachable)))(call $NOT)
	(call $DUP (i32.const 0))
	(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $DUP (i32.const 3))
	(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $AND)
	(set_global $sp (i32.add (get_global $sp) (i32.const -32)))
	(call $SWAP (i32.const 1))
	(set_global $sp (i32.add (get_global $sp) (i32.const -32)))
	(set_global $sp (i32.add (get_global $sp) (i32.const -32)))
	(call $SWAP (i32.const 2))
	(call $SWAP (i32.const 1))
	(set_global $sp (i32.add (get_global $sp) (i32.const -32)))
	(set_global $sp (i32.add (get_global $sp) (i32.const -32)))
	;; jump
						  (set_local $jump_dest (call $check_overflow 
												 (i64.load (get_global $sp))
												 (i64.load (i32.add (get_global $sp) (i32.const 8)))
												 (i64.load (i32.add (get_global $sp) (i32.const 16)))
												 (i64.load (i32.add (get_global $sp) (i32.const 24)))))
						  (set_global $sp (i32.sub (get_global $sp) (i32.const 32)))
						  (br $loop))(call $useGas (i64.const 24)) (if (i32.gt_s (get_global $sp) (i32.const 32576)) 
					 (then (unreachable)))(call $PUSH (i64.const 0)(i64.const 0)(i64.const 0)(i64.const 0))(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $PUSH (i64.const 0)(i64.const 0)(i64.const 0)(i64.const 742))(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $DUP (i32.const 3))
	(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $DUP (i32.const 3))
	(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $PUSH (i64.const 0)(i64.const 0)(i64.const 0)(i64.const 696))(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	;; jump
						  (set_local $jump_dest (call $check_overflow 
												 (i64.load (get_global $sp))
												 (i64.load (i32.add (get_global $sp) (i32.const 8)))
												 (i64.load (i32.add (get_global $sp) (i32.const 16)))
												 (i64.load (i32.add (get_global $sp) (i32.const 24)))))
						  (set_global $sp (i32.sub (get_global $sp) (i32.const 32)))
						  (br $loop))(call $useGas (i64.const 46)) (if (i32.gt_s (get_global $sp) (i32.const 32672)) 
					 (then (unreachable)))(if (i32.lt_s (get_global $sp) (i32.const 64)) 
					  (then (unreachable)))(call $SWAP (i32.const 1))
	(set_global $sp (i32.add (get_global $sp) (i32.const -32)))
	(call $DUP (i32.const 2))
	(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $PUSH (i64.const 0)(i64.const 0)(i64.const 0)(i64.const 2))(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $MUL)
	(set_global $sp (i32.add (get_global $sp) (i32.const -32)))
	(call $DUP (i32.const 2))
	(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $OR)
	(set_global $sp (i32.add (get_global $sp) (i32.const -32)))
	(call $SWAP (i32.const 0))
	(set_global $sp (i32.add (get_global $sp) (i32.const -32)))
	(call $SWAP (i32.const 2))
	(call $SWAP (i32.const 1))
	(set_global $sp (i32.add (get_global $sp) (i32.const -32)))
	(set_global $sp (i32.add (get_global $sp) (i32.const -32)))
	;; jump
						  (set_local $jump_dest (call $check_overflow 
												 (i64.load (get_global $sp))
												 (i64.load (i32.add (get_global $sp) (i32.const 8)))
												 (i64.load (i32.add (get_global $sp) (i32.const 16)))
												 (i64.load (i32.add (get_global $sp) (i32.const 24)))))
						  (set_global $sp (i32.sub (get_global $sp) (i32.const 32)))
						  (br $loop))(call $useGas (i64.const 18)) (if (i32.gt_s (get_global $sp) (i32.const 32640)) 
					 (then (unreachable)))(call $PUSH (i64.const 0)(i64.const 0)(i64.const 0)(i64.const 769))(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $DUP (i32.const 2))
	(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $PUSH (i64.const 0)(i64.const 0)(i64.const 0)(i64.const 124))(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	;; jump
						  (set_local $jump_dest (call $check_overflow 
												 (i64.load (get_global $sp))
												 (i64.load (i32.add (get_global $sp) (i32.const 8)))
												 (i64.load (i32.add (get_global $sp) (i32.const 16)))
												 (i64.load (i32.add (get_global $sp) (i32.const 24)))))
						  (set_global $sp (i32.sub (get_global $sp) (i32.const 32)))
						  (br $loop))(call $useGas (i64.const 26)) (if (i32.gt_s (get_global $sp) (i32.const 32640)) 
					 (then (unreachable)))(call $PUSH (i64.const 0)(i64.const 0)(i64.const 0)(i64.const -1))(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $DUP (i32.const 1))
	(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $GT)
	(set_global $sp (i32.add (get_global $sp) (i32.const -32)))
	(call $ISZERO)
	(call $PUSH (i64.const 0)(i64.const 0)(i64.const 0)(i64.const 797))(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(set_local $jump_dest (call $check_overflow 
												 (i64.load (get_global $sp))
												 (i64.load (i32.add (get_global $sp) (i32.const 8)))
												 (i64.load (i32.add (get_global $sp) (i32.const 16)))
												 (i64.load (i32.add (get_global $sp) (i32.const 24)))))
	
						(set_global $sp (i32.sub (get_global $sp) (i32.const 64)))
						(br_if $loop (i32.eqz (i64.eqz (i64.or
						  (i64.load (i32.add (get_global $sp) (i32.const 32)))
						  (i64.or
							(i64.load (i32.add (get_global $sp) (i32.const 40)))
							(i64.or
							  (i64.load (i32.add (get_global $sp) (i32.const 48)))
							  (i64.load (i32.add (get_global $sp) (i32.const 56)))
							)
						  )
						))))
	(call $useGas (i64.const 14)) (if (i32.gt_s (get_global $sp) (i32.const 32672)) 
					 (then (unreachable)))(call $PUSH (i64.const 0)(i64.const 0)(i64.const 0)(i64.const 796))(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $PUSH (i64.const 0)(i64.const 0)(i64.const 0)(i64.const 135))(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	;; jump
						  (set_local $jump_dest (call $check_overflow 
												 (i64.load (get_global $sp))
												 (i64.load (i32.add (get_global $sp) (i32.const 8)))
												 (i64.load (i32.add (get_global $sp) (i32.const 16)))
												 (i64.load (i32.add (get_global $sp) (i32.const 24)))))
						  (set_global $sp (i32.sub (get_global $sp) (i32.const 32)))
						  (br $loop))(call $useGas (i64.const 1)) )(call $useGas (i64.const 18)) (if (i32.gt_s (get_global $sp) (i32.const 32640)) 
					 (then (unreachable)))(call $PUSH (i64.const 0)(i64.const 0)(i64.const 0)(i64.const 809))(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $DUP (i32.const 2))
	(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $SLOAD)
	(call $PUSH (i64.const 0)(i64.const 0)(i64.const 0)(i64.const 229))(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	;; jump
						  (set_local $jump_dest (call $check_overflow 
												 (i64.load (get_global $sp))
												 (i64.load (i32.add (get_global $sp) (i32.const 8)))
												 (i64.load (i32.add (get_global $sp) (i32.const 16)))
												 (i64.load (i32.add (get_global $sp) (i32.const 24)))))
						  (set_global $sp (i32.sub (get_global $sp) (i32.const 32)))
						  (br $loop))(call $useGas (i64.const 24)) (if (i32.gt_s (get_global $sp) (i32.const 32576)) 
					 (then (unreachable)))(call $PUSH (i64.const 0)(i64.const 0)(i64.const 0)(i64.const 822))(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $DUP (i32.const 2))
	(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $DUP (i32.const 2))
	(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $DUP (i32.const 5))
	(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $PUSH (i64.const 0)(i64.const 0)(i64.const 0)(i64.const 603))(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	;; jump
						  (set_local $jump_dest (call $check_overflow 
												 (i64.load (get_global $sp))
												 (i64.load (i32.add (get_global $sp) (i32.const 8)))
												 (i64.load (i32.add (get_global $sp) (i32.const 16)))
												 (i64.load (i32.add (get_global $sp) (i32.const 24)))))
						  (set_global $sp (i32.sub (get_global $sp) (i32.const 32)))
						  (br $loop))(call $useGas (i64.const 43)) (if (i32.gt_s (get_global $sp) (i32.const 32576)) 
					 (then (unreachable)))(call $PUSH (i64.const 0)(i64.const 0)(i64.const 0)(i64.const 0))(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $PUSH (i64.const 0)(i64.const 0)(i64.const 0)(i64.const 32))(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $SWAP (i32.const 0))
	(set_global $sp (i32.add (get_global $sp) (i32.const -32)))
	(call $PUSH (i64.const 0)(i64.const 0)(i64.const 0)(i64.const 31))(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $DUP (i32.const 3))
	(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $GT)
	(set_global $sp (i32.add (get_global $sp) (i32.const -32)))
	(call $PUSH (i64.const 0)(i64.const 0)(i64.const 0)(i64.const 1))(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $DUP (i32.const 1))
	(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $EQ)
	(set_global $sp (i32.add (get_global $sp) (i32.const -32)))
	(call $PUSH (i64.const 0)(i64.const 0)(i64.const 0)(i64.const 878))(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(set_local $jump_dest (call $check_overflow 
												 (i64.load (get_global $sp))
												 (i64.load (i32.add (get_global $sp) (i32.const 8)))
												 (i64.load (i32.add (get_global $sp) (i32.const 16)))
												 (i64.load (i32.add (get_global $sp) (i32.const 24)))))
	
						(set_global $sp (i32.sub (get_global $sp) (i32.const 64)))
						(br_if $loop (i32.eqz (i64.eqz (i64.or
						  (i64.load (i32.add (get_global $sp) (i32.const 32)))
						  (i64.or
							(i64.load (i32.add (get_global $sp) (i32.const 40)))
							(i64.or
							  (i64.load (i32.add (get_global $sp) (i32.const 48)))
							  (i64.load (i32.add (get_global $sp) (i32.const 56)))
							)
						  )
						))))
	(call $useGas (i64.const 22)) (if (i32.gt_s (get_global $sp) (i32.const 32640)) 
					 (then (unreachable)))(call $PUSH (i64.const 0)(i64.const 0)(i64.const 0)(i64.const 0))(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $DUP (i32.const 4))
	(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $ISZERO)
	(call $PUSH (i64.const 0)(i64.const 0)(i64.const 0)(i64.const 857))(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(set_local $jump_dest (call $check_overflow 
												 (i64.load (get_global $sp))
												 (i64.load (i32.add (get_global $sp) (i32.const 8)))
												 (i64.load (i32.add (get_global $sp) (i32.const 16)))
												 (i64.load (i32.add (get_global $sp) (i32.const 24)))))
	
						(set_global $sp (i32.sub (get_global $sp) (i32.const 64)))
						(br_if $loop (i32.eqz (i64.eqz (i64.or
						  (i64.load (i32.add (get_global $sp) (i32.const 32)))
						  (i64.or
							(i64.load (i32.add (get_global $sp) (i32.const 40)))
							(i64.or
							  (i64.load (i32.add (get_global $sp) (i32.const 48)))
							  (i64.load (i32.add (get_global $sp) (i32.const 56)))
							)
						  )
						))))
	(call $useGas (i64.const 17)) (if (i32.gt_s (get_global $sp) (i32.const 32640)) 
					 (then (unreachable)))(call $DUP (i32.const 2))
	(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $DUP (i32.const 7))
	(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $ADD)
	(set_global $sp (i32.add (get_global $sp) (i32.const -32)))
	(call $MLOAD)
	(call $SWAP (i32.const 0))
	(set_global $sp (i32.add (get_global $sp) (i32.const -32)))
	)(call $useGas (i64.const 21)) (if (i32.gt_s (get_global $sp) (i32.const 32608)) 
					 (then (unreachable)))(call $PUSH (i64.const 0)(i64.const 0)(i64.const 0)(i64.const 869))(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $DUP (i32.const 5))
	(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $DUP (i32.const 2))
	(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $PUSH (i64.const 0)(i64.const 0)(i64.const 0)(i64.const 728))(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	;; jump
						  (set_local $jump_dest (call $check_overflow 
												 (i64.load (get_global $sp))
												 (i64.load (i32.add (get_global $sp) (i32.const 8)))
												 (i64.load (i32.add (get_global $sp) (i32.const 16)))
												 (i64.load (i32.add (get_global $sp) (i32.const 24)))))
						  (set_global $sp (i32.sub (get_global $sp) (i32.const 32)))
						  (br $loop))(call $useGas (i64.const 17)) (if (i32.gt_s (get_global $sp) (i32.const 32704)) 
					 (then (unreachable)))(if (i32.lt_s (get_global $sp) (i32.const 32)) 
					  (then (unreachable)))(call $DUP (i32.const 6))
	(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $SSTORE)
	(set_global $sp (i32.add (get_global $sp) (i32.const -64)))
	(set_global $sp (i32.add (get_global $sp) (i32.const -32)))
	(call $PUSH (i64.const 0)(i64.const 0)(i64.const 0)(i64.const 981))(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	;; jump
						  (set_local $jump_dest (call $check_overflow 
												 (i64.load (get_global $sp))
												 (i64.load (i32.add (get_global $sp) (i32.const 8)))
												 (i64.load (i32.add (get_global $sp) (i32.const 16)))
												 (i64.load (i32.add (get_global $sp) (i32.const 24)))))
						  (set_global $sp (i32.sub (get_global $sp) (i32.const 32)))
						  (br $loop))(call $useGas (i64.const 30)) (if (i32.gt_s (get_global $sp) (i32.const 32608)) 
					 (then (unreachable)))(call $PUSH (i64.const 0)(i64.const 0)(i64.const 0)(i64.const 31))(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $NOT)
	(call $DUP (i32.const 4))
	(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $AND)
	(set_global $sp (i32.add (get_global $sp) (i32.const -32)))
	(call $PUSH (i64.const 0)(i64.const 0)(i64.const 0)(i64.const 894))(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $DUP (i32.const 6))
	(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $PUSH (i64.const 0)(i64.const 0)(i64.const 0)(i64.const 282))(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	;; jump
						  (set_local $jump_dest (call $check_overflow 
												 (i64.load (get_global $sp))
												 (i64.load (i32.add (get_global $sp) (i32.const 8)))
												 (i64.load (i32.add (get_global $sp) (i32.const 16)))
												 (i64.load (i32.add (get_global $sp) (i32.const 24)))))
						  (set_global $sp (i32.sub (get_global $sp) (i32.const 32)))
						  (br $loop))(call $useGas (i64.const 4)) (if (i32.gt_s (get_global $sp) (i32.const 32704)) 
					 (then (unreachable)))(call $PUSH (i64.const 0)(i64.const 0)(i64.const 0)(i64.const 0))(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	)(call $useGas (i64.const 26)) (if (i32.gt_s (get_global $sp) (i32.const 32640)) 
					 (then (unreachable)))(call $DUP (i32.const 2))
	(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $DUP (i32.const 1))
	(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $LT)
	(set_global $sp (i32.add (get_global $sp) (i32.const -32)))
	(call $ISZERO)
	(call $PUSH (i64.const 0)(i64.const 0)(i64.const 0)(i64.const 936))(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(set_local $jump_dest (call $check_overflow 
												 (i64.load (get_global $sp))
												 (i64.load (i32.add (get_global $sp) (i32.const 8)))
												 (i64.load (i32.add (get_global $sp) (i32.const 16)))
												 (i64.load (i32.add (get_global $sp) (i32.const 24)))))
	
						(set_global $sp (i32.sub (get_global $sp) (i32.const 64)))
						(br_if $loop (i32.eqz (i64.eqz (i64.or
						  (i64.load (i32.add (get_global $sp) (i32.const 32)))
						  (i64.or
							(i64.load (i32.add (get_global $sp) (i32.const 40)))
							(i64.or
							  (i64.load (i32.add (get_global $sp) (i32.const 48)))
							  (i64.load (i32.add (get_global $sp) (i32.const 56)))
							)
						  )
						))))
	(call $useGas (i64.const 68)) (if (i32.gt_s (get_global $sp) (i32.const 32640)) 
					 (then (unreachable)))(call $DUP (i32.const 4))
	(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $DUP (i32.const 9))
	(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $ADD)
	(set_global $sp (i32.add (get_global $sp) (i32.const -32)))
	(call $MLOAD)
	(call $DUP (i32.const 2))
	(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $SSTORE)
	(set_global $sp (i32.add (get_global $sp) (i32.const -64)))
	(call $PUSH (i64.const 0)(i64.const 0)(i64.const 0)(i64.const 1))(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $DUP (i32.const 2))
	(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $ADD)
	(set_global $sp (i32.add (get_global $sp) (i32.const -32)))
	(call $SWAP (i32.const 1))
	(set_global $sp (i32.add (get_global $sp) (i32.const -32)))
	(call $PUSH (i64.const 0)(i64.const 0)(i64.const 0)(i64.const 32))(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $DUP (i32.const 5))
	(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $ADD)
	(set_global $sp (i32.add (get_global $sp) (i32.const -32)))
	(call $SWAP (i32.const 4))
	(set_global $sp (i32.add (get_global $sp) (i32.const -32)))
	(call $PUSH (i64.const 0)(i64.const 0)(i64.const 0)(i64.const 32))(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $DUP (i32.const 1))
	(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $ADD)
	(set_global $sp (i32.add (get_global $sp) (i32.const -32)))
	(call $SWAP (i32.const 0))
	(set_global $sp (i32.add (get_global $sp) (i32.const -32)))
	(call $PUSH (i64.const 0)(i64.const 0)(i64.const 0)(i64.const 897))(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	;; jump
						  (set_local $jump_dest (call $check_overflow 
												 (i64.load (get_global $sp))
												 (i64.load (i32.add (get_global $sp) (i32.const 8)))
												 (i64.load (i32.add (get_global $sp) (i32.const 16)))
												 (i64.load (i32.add (get_global $sp) (i32.const 24)))))
						  (set_global $sp (i32.sub (get_global $sp) (i32.const 32)))
						  (br $loop))(call $useGas (i64.const 26)) (if (i32.gt_s (get_global $sp) (i32.const 32640)) 
					 (then (unreachable)))(call $DUP (i32.const 6))
	(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $DUP (i32.const 3))
	(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $LT)
	(set_global $sp (i32.add (get_global $sp) (i32.const -32)))
	(call $ISZERO)
	(call $PUSH (i64.const 0)(i64.const 0)(i64.const 0)(i64.const 968))(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(set_local $jump_dest (call $check_overflow 
												 (i64.load (get_global $sp))
												 (i64.load (i32.add (get_global $sp) (i32.const 8)))
												 (i64.load (i32.add (get_global $sp) (i32.const 16)))
												 (i64.load (i32.add (get_global $sp) (i32.const 24)))))
	
						(set_global $sp (i32.sub (get_global $sp) (i32.const 64)))
						(br_if $loop (i32.eqz (i64.eqz (i64.or
						  (i64.load (i32.add (get_global $sp) (i32.const 32)))
						  (i64.or
							(i64.load (i32.add (get_global $sp) (i32.const 40)))
							(i64.or
							  (i64.load (i32.add (get_global $sp) (i32.const 48)))
							  (i64.load (i32.add (get_global $sp) (i32.const 56)))
							)
						  )
						))))
	(call $useGas (i64.const 38)) (if (i32.gt_s (get_global $sp) (i32.const 32576)) 
					 (then (unreachable)))(call $DUP (i32.const 4))
	(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $DUP (i32.const 9))
	(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $ADD)
	(set_global $sp (i32.add (get_global $sp) (i32.const -32)))
	(call $MLOAD)
	(call $PUSH (i64.const 0)(i64.const 0)(i64.const 0)(i64.const 964))(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $PUSH (i64.const 0)(i64.const 0)(i64.const 0)(i64.const 31))(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $DUP (i32.const 9))
	(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $AND)
	(set_global $sp (i32.add (get_global $sp) (i32.const -32)))
	(call $DUP (i32.const 2))
	(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $PUSH (i64.const 0)(i64.const 0)(i64.const 0)(i64.const 696))(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	;; jump
						  (set_local $jump_dest (call $check_overflow 
												 (i64.load (get_global $sp))
												 (i64.load (i32.add (get_global $sp) (i32.const 8)))
												 (i64.load (i32.add (get_global $sp) (i32.const 16)))
												 (i64.load (i32.add (get_global $sp) (i32.const 24)))))
						  (set_global $sp (i32.sub (get_global $sp) (i32.const 32)))
						  (br $loop))(call $useGas (i64.const 6)) (if (i32.gt_s (get_global $sp) (i32.const 32704)) 
					 (then (unreachable)))(if (i32.lt_s (get_global $sp) (i32.const 32)) 
					  (then (unreachable)))(call $DUP (i32.const 3))
	(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $SSTORE)
	(set_global $sp (i32.add (get_global $sp) (i32.const -64)))
	(set_global $sp (i32.add (get_global $sp) (i32.const -32)))
	)(call $useGas (i64.const 27)) (if (i32.gt_s (get_global $sp) (i32.const 32608)) 
					 (then (unreachable)))(if (i32.lt_s (get_global $sp) (i32.const 64)) 
					  (then (unreachable)))(call $PUSH (i64.const 0)(i64.const 0)(i64.const 0)(i64.const 1))(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $PUSH (i64.const 0)(i64.const 0)(i64.const 0)(i64.const 2))(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $DUP (i32.const 8))
	(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $MUL)
	(set_global $sp (i32.add (get_global $sp) (i32.const -32)))
	(call $ADD)
	(set_global $sp (i32.add (get_global $sp) (i32.const -32)))
	(call $DUP (i32.const 8))
	(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $SSTORE)
	(set_global $sp (i32.add (get_global $sp) (i32.const -64)))
	(set_global $sp (i32.add (get_global $sp) (i32.const -32)))
	(set_global $sp (i32.add (get_global $sp) (i32.const -32)))
	(set_global $sp (i32.add (get_global $sp) (i32.const -32)))
	)(call $useGas (i64.const 21)) (if (i32.lt_s (get_global $sp) (i32.const 160)) 
					  (then (unreachable)))(set_global $sp (i32.add (get_global $sp) (i32.const -32)))
	(set_global $sp (i32.add (get_global $sp) (i32.const -32)))
	(set_global $sp (i32.add (get_global $sp) (i32.const -32)))
	(set_global $sp (i32.add (get_global $sp) (i32.const -32)))
	(set_global $sp (i32.add (get_global $sp) (i32.const -32)))
	(set_global $sp (i32.add (get_global $sp) (i32.const -32)))
	;; jump
						  (set_local $jump_dest (call $check_overflow 
												 (i64.load (get_global $sp))
												 (i64.load (i32.add (get_global $sp) (i32.const 8)))
												 (i64.load (i32.add (get_global $sp) (i32.const 16)))
												 (i64.load (i32.add (get_global $sp) (i32.const 24)))))
						  (set_global $sp (i32.sub (get_global $sp) (i32.const 32)))
						  (br $loop))(call $useGas (i64.const 16)) (if (i32.gt_s (get_global $sp) (i32.const 32608)) 
					 (then (unreachable)))(call $PUSH (i64.const 0)(i64.const 0)(i64.const 0)(i64.const 1655))(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $DUP (i32.const 0))
	(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $PUSH (i64.const 0)(i64.const 0)(i64.const 0)(i64.const 1005))(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $PUSH (i64.const 0)(i64.const 0)(i64.const 0)(i64.const 0))(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $CODECOPY)
	(set_global $sp (i32.add (get_global $sp) (i32.const -96)))
	(call $PUSH (i64.const 0)(i64.const 0)(i64.const 0)(i64.const 0))(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $RETURN) (br $done)
	(set_global $sp (i32.add (get_global $sp) (i32.const -64)))
	)(call $useGas (i64.const 23)) (if (i32.gt_s (get_global $sp) (i32.const 32640)) 
					 (then (unreachable)))(call $DUP (i32.const 0))
	(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $PUSH (i64.const 0)(i64.const 0)(i64.const 0)(i64.const 153386437))(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $EQ)
	(set_global $sp (i32.add (get_global $sp) (i32.const -32)))
	(call $PUSH (i64.const 0)(i64.const 0)(i64.const 0)(i64.const 139))(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(set_local $jump_dest (call $check_overflow 
												 (i64.load (get_global $sp))
												 (i64.load (i32.add (get_global $sp) (i32.const 8)))
												 (i64.load (i32.add (get_global $sp) (i32.const 16)))
												 (i64.load (i32.add (get_global $sp) (i32.const 24)))))
	
						(set_global $sp (i32.sub (get_global $sp) (i32.const 64)))
						(br_if $loop (i32.eqz (i64.eqz (i64.or
						  (i64.load (i32.add (get_global $sp) (i32.const 32)))
						  (i64.or
							(i64.load (i32.add (get_global $sp) (i32.const 40)))
							(i64.or
							  (i64.load (i32.add (get_global $sp) (i32.const 48)))
							  (i64.load (i32.add (get_global $sp) (i32.const 56)))
							)
						  )
						))))
	(call $useGas (i64.const 22)) (if (i32.gt_s (get_global $sp) (i32.const 32640)) 
					 (then (unreachable)))(call $DUP (i32.const 0))
	(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $PUSH (i64.const 0)(i64.const 0)(i64.const 0)(i64.const 438170516))(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $EQ)
	(set_global $sp (i32.add (get_global $sp) (i32.const -32)))
	(call $PUSH (i64.const 0)(i64.const 0)(i64.const 0)(i64.const 182))(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(set_local $jump_dest (call $check_overflow 
												 (i64.load (get_global $sp))
												 (i64.load (i32.add (get_global $sp) (i32.const 8)))
												 (i64.load (i32.add (get_global $sp) (i32.const 16)))
												 (i64.load (i32.add (get_global $sp) (i32.const 24)))))
	
						(set_global $sp (i32.sub (get_global $sp) (i32.const 64)))
						(br_if $loop (i32.eqz (i64.eqz (i64.or
						  (i64.load (i32.add (get_global $sp) (i32.const 32)))
						  (i64.or
							(i64.load (i32.add (get_global $sp) (i32.const 40)))
							(i64.or
							  (i64.load (i32.add (get_global $sp) (i32.const 48)))
							  (i64.load (i32.add (get_global $sp) (i32.const 56)))
							)
						  )
						))))
	(call $useGas (i64.const 22)) (if (i32.gt_s (get_global $sp) (i32.const 32640)) 
					 (then (unreachable)))(call $DUP (i32.const 0))
	(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $PUSH (i64.const 0)(i64.const 0)(i64.const 0)(i64.const 528873070))(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $EQ)
	(set_global $sp (i32.add (get_global $sp) (i32.const -32)))
	(call $PUSH (i64.const 0)(i64.const 0)(i64.const 0)(i64.const 210))(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(set_local $jump_dest (call $check_overflow 
												 (i64.load (get_global $sp))
												 (i64.load (i32.add (get_global $sp) (i32.const 8)))
												 (i64.load (i32.add (get_global $sp) (i32.const 16)))
												 (i64.load (i32.add (get_global $sp) (i32.const 24)))))
	
						(set_global $sp (i32.sub (get_global $sp) (i32.const 64)))
						(br_if $loop (i32.eqz (i64.eqz (i64.or
						  (i64.load (i32.add (get_global $sp) (i32.const 32)))
						  (i64.or
							(i64.load (i32.add (get_global $sp) (i32.const 40)))
							(i64.or
							  (i64.load (i32.add (get_global $sp) (i32.const 48)))
							  (i64.load (i32.add (get_global $sp) (i32.const 56)))
							)
						  )
						))))
	(call $useGas (i64.const 22)) (if (i32.gt_s (get_global $sp) (i32.const 32640)) 
					 (then (unreachable)))(call $DUP (i32.const 0))
	(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $PUSH (i64.const 0)(i64.const 0)(i64.const 0)(i64.const 777724264))(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $EQ)
	(set_global $sp (i32.add (get_global $sp) (i32.const -32)))
	(call $PUSH (i64.const 0)(i64.const 0)(i64.const 0)(i64.const 251))(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(set_local $jump_dest (call $check_overflow 
												 (i64.load (get_global $sp))
												 (i64.load (i32.add (get_global $sp) (i32.const 8)))
												 (i64.load (i32.add (get_global $sp) (i32.const 16)))
												 (i64.load (i32.add (get_global $sp) (i32.const 24)))))
	
						(set_global $sp (i32.sub (get_global $sp) (i32.const 64)))
						(br_if $loop (i32.eqz (i64.eqz (i64.or
						  (i64.load (i32.add (get_global $sp) (i32.const 32)))
						  (i64.or
							(i64.load (i32.add (get_global $sp) (i32.const 40)))
							(i64.or
							  (i64.load (i32.add (get_global $sp) (i32.const 48)))
							  (i64.load (i32.add (get_global $sp) (i32.const 56)))
							)
						  )
						))))
	(call $useGas (i64.const 11)) (if (i32.gt_s (get_global $sp) (i32.const 32704)) 
					 (then (unreachable)))(call $PUSH (i64.const 0)(i64.const 0)(i64.const 0)(i64.const 134))(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	;; jump
						  (set_local $jump_dest (call $check_overflow 
												 (i64.load (get_global $sp))
												 (i64.load (i32.add (get_global $sp) (i32.const 8)))
												 (i64.load (i32.add (get_global $sp) (i32.const 16)))
												 (i64.load (i32.add (get_global $sp) (i32.const 24)))))
						  (set_global $sp (i32.sub (get_global $sp) (i32.const 32)))
						  (br $loop))(call $useGas (i64.const 14)) (if (i32.gt_s (get_global $sp) (i32.const 32672)) 
					 (then (unreachable)))(call $CALLDATASIZE)
	(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $PUSH (i64.const 0)(i64.const 0)(i64.const 0)(i64.const 134))(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(set_local $jump_dest (call $check_overflow 
												 (i64.load (get_global $sp))
												 (i64.load (i32.add (get_global $sp) (i32.const 8)))
												 (i64.load (i32.add (get_global $sp) (i32.const 16)))
												 (i64.load (i32.add (get_global $sp) (i32.const 24)))))
	
						(set_global $sp (i32.sub (get_global $sp) (i32.const 64)))
						(br_if $loop (i32.eqz (i64.eqz (i64.or
						  (i64.load (i32.add (get_global $sp) (i32.const 32)))
						  (i64.or
							(i64.load (i32.add (get_global $sp) (i32.const 40)))
							(i64.or
							  (i64.load (i32.add (get_global $sp) (i32.const 48)))
							  (i64.load (i32.add (get_global $sp) (i32.const 56)))
							)
						  )
						))))
	(br $done))(call $useGas (i64.const 7)) (if (i32.gt_s (get_global $sp) (i32.const 32672)) 
					 (then (unreachable)))(call $PUSH (i64.const 0)(i64.const 0)(i64.const 0)(i64.const 0))(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $DUP (i32.const 0))
	(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $REVERT) (br $done)
	(set_global $sp (i32.add (get_global $sp) (i32.const -64)))
	)(call $useGas (i64.const 20)) (if (i32.gt_s (get_global $sp) (i32.const 32640)) 
					 (then (unreachable)))(call $CALLVALUE)
	(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $DUP (i32.const 0))
	(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $ISZERO)
	(call $PUSH (i64.const 0)(i64.const 0)(i64.const 0)(i64.const 151))(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(set_local $jump_dest (call $check_overflow 
												 (i64.load (get_global $sp))
												 (i64.load (i32.add (get_global $sp) (i32.const 8)))
												 (i64.load (i32.add (get_global $sp) (i32.const 16)))
												 (i64.load (i32.add (get_global $sp) (i32.const 24)))))
	
						(set_global $sp (i32.sub (get_global $sp) (i32.const 64)))
						(br_if $loop (i32.eqz (i64.eqz (i64.or
						  (i64.load (i32.add (get_global $sp) (i32.const 32)))
						  (i64.or
							(i64.load (i32.add (get_global $sp) (i32.const 40)))
							(i64.or
							  (i64.load (i32.add (get_global $sp) (i32.const 48)))
							  (i64.load (i32.add (get_global $sp) (i32.const 56)))
							)
						  )
						))))
	(call $useGas (i64.const 6)) (if (i32.gt_s (get_global $sp) (i32.const 32672)) 
					 (then (unreachable)))(call $PUSH (i64.const 0)(i64.const 0)(i64.const 0)(i64.const 0))(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $DUP (i32.const 0))
	(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $REVERT) (br $done)
	(set_global $sp (i32.add (get_global $sp) (i32.const -64)))
	)(call $useGas (i64.const 17)) (if (i32.gt_s (get_global $sp) (i32.const 32704)) 
					 (then (unreachable)))(if (i32.lt_s (get_global $sp) (i32.const 0)) 
					  (then (unreachable)))(set_global $sp (i32.add (get_global $sp) (i32.const -32)))
	(call $PUSH (i64.const 0)(i64.const 0)(i64.const 0)(i64.const 160))(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $PUSH (i64.const 0)(i64.const 0)(i64.const 0)(i64.const 466))(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	;; jump
						  (set_local $jump_dest (call $check_overflow 
												 (i64.load (get_global $sp))
												 (i64.load (i32.add (get_global $sp) (i32.const 8)))
												 (i64.load (i32.add (get_global $sp) (i32.const 16)))
												 (i64.load (i32.add (get_global $sp) (i32.const 24)))))
						  (set_global $sp (i32.sub (get_global $sp) (i32.const 32)))
						  (br $loop))(call $useGas (i64.const 27)) (if (i32.gt_s (get_global $sp) (i32.const 32640)) 
					 (then (unreachable)))(call $PUSH (i64.const 0)(i64.const 0)(i64.const 0)(i64.const 64))(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $MLOAD)
	(call $PUSH (i64.const 0)(i64.const 0)(i64.const 0)(i64.const 173))(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $SWAP (i32.const 1))
	(call $SWAP (i32.const 0))
	(call $PUSH (i64.const 0)(i64.const 0)(i64.const 0)(i64.const 786))(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	;; jump
						  (set_local $jump_dest (call $check_overflow 
												 (i64.load (get_global $sp))
												 (i64.load (i32.add (get_global $sp) (i32.const 8)))
												 (i64.load (i32.add (get_global $sp) (i32.const 16)))
												 (i64.load (i32.add (get_global $sp) (i32.const 24)))))
						  (set_global $sp (i32.sub (get_global $sp) (i32.const 32)))
						  (br $loop))(call $useGas (i64.const 19)) (if (i32.gt_s (get_global $sp) (i32.const 32640)) 
					 (then (unreachable)))(if (i32.lt_s (get_global $sp) (i32.const 0)) 
					  (then (unreachable)))(call $PUSH (i64.const 0)(i64.const 0)(i64.const 0)(i64.const 64))(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $MLOAD)
	(call $DUP (i32.const 0))
	(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $SWAP (i32.const 1))
	(call $SUB)
	(set_global $sp (i32.add (get_global $sp) (i32.const -32)))
	(call $SWAP (i32.const 0))
	(call $RETURN) (br $done)
	(set_global $sp (i32.add (get_global $sp) (i32.const -64)))
	)(call $useGas (i64.const 42)) (if (i32.gt_s (get_global $sp) (i32.const 32576)) 
					 (then (unreachable)))(call $PUSH (i64.const 0)(i64.const 0)(i64.const 0)(i64.const 208))(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $PUSH (i64.const 0)(i64.const 0)(i64.const 0)(i64.const 4))(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $DUP (i32.const 0))
	(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $CALLDATASIZE)
	(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $SUB)
	(set_global $sp (i32.add (get_global $sp) (i32.const -32)))
	(call $DUP (i32.const 1))
	(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $ADD)
	(set_global $sp (i32.add (get_global $sp) (i32.const -32)))
	(call $SWAP (i32.const 0))
	(call $PUSH (i64.const 0)(i64.const 0)(i64.const 0)(i64.const 203))(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $SWAP (i32.const 1))
	(call $SWAP (i32.const 0))
	(call $PUSH (i64.const 0)(i64.const 0)(i64.const 0)(i64.const 874))(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	;; jump
						  (set_local $jump_dest (call $check_overflow 
												 (i64.load (get_global $sp))
												 (i64.load (i32.add (get_global $sp) (i32.const 8)))
												 (i64.load (i32.add (get_global $sp) (i32.const 16)))
												 (i64.load (i32.add (get_global $sp) (i32.const 24)))))
						  (set_global $sp (i32.sub (get_global $sp) (i32.const 32)))
						  (br $loop))(call $useGas (i64.const 12)) (if (i32.gt_s (get_global $sp) (i32.const 32704)) 
					 (then (unreachable)))(call $PUSH (i64.const 0)(i64.const 0)(i64.const 0)(i64.const 472))(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	;; jump
						  (set_local $jump_dest (call $check_overflow 
												 (i64.load (get_global $sp))
												 (i64.load (i32.add (get_global $sp) (i32.const 8)))
												 (i64.load (i32.add (get_global $sp) (i32.const 16)))
												 (i64.load (i32.add (get_global $sp) (i32.const 24)))))
						  (set_global $sp (i32.sub (get_global $sp) (i32.const 32)))
						  (br $loop))(call $useGas (i64.const 1)) (br $done))(call $useGas (i64.const 20)) (if (i32.gt_s (get_global $sp) (i32.const 32640)) 
					 (then (unreachable)))(call $CALLVALUE)
	(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $DUP (i32.const 0))
	(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $ISZERO)
	(call $PUSH (i64.const 0)(i64.const 0)(i64.const 0)(i64.const 222))(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(set_local $jump_dest (call $check_overflow 
												 (i64.load (get_global $sp))
												 (i64.load (i32.add (get_global $sp) (i32.const 8)))
												 (i64.load (i32.add (get_global $sp) (i32.const 16)))
												 (i64.load (i32.add (get_global $sp) (i32.const 24)))))
	
						(set_global $sp (i32.sub (get_global $sp) (i32.const 64)))
						(br_if $loop (i32.eqz (i64.eqz (i64.or
						  (i64.load (i32.add (get_global $sp) (i32.const 32)))
						  (i64.or
							(i64.load (i32.add (get_global $sp) (i32.const 40)))
							(i64.or
							  (i64.load (i32.add (get_global $sp) (i32.const 48)))
							  (i64.load (i32.add (get_global $sp) (i32.const 56)))
							)
						  )
						))))
	(call $useGas (i64.const 6)) (if (i32.gt_s (get_global $sp) (i32.const 32672)) 
					 (then (unreachable)))(call $PUSH (i64.const 0)(i64.const 0)(i64.const 0)(i64.const 0))(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $DUP (i32.const 0))
	(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $REVERT) (br $done)
	(set_global $sp (i32.add (get_global $sp) (i32.const -64)))
	)(call $useGas (i64.const 44)) (if (i32.gt_s (get_global $sp) (i32.const 32608)) 
					 (then (unreachable)))(if (i32.lt_s (get_global $sp) (i32.const 0)) 
					  (then (unreachable)))(set_global $sp (i32.add (get_global $sp) (i32.const -32)))
	(call $PUSH (i64.const 0)(i64.const 0)(i64.const 0)(i64.const 249))(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $PUSH (i64.const 0)(i64.const 0)(i64.const 0)(i64.const 4))(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $DUP (i32.const 0))
	(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $CALLDATASIZE)
	(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $SUB)
	(set_global $sp (i32.add (get_global $sp) (i32.const -32)))
	(call $DUP (i32.const 1))
	(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $ADD)
	(set_global $sp (i32.add (get_global $sp) (i32.const -32)))
	(call $SWAP (i32.const 0))
	(call $PUSH (i64.const 0)(i64.const 0)(i64.const 0)(i64.const 244))(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $SWAP (i32.const 1))
	(call $SWAP (i32.const 0))
	(call $PUSH (i64.const 0)(i64.const 0)(i64.const 0)(i64.const 1023))(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	;; jump
						  (set_local $jump_dest (call $check_overflow 
												 (i64.load (get_global $sp))
												 (i64.load (i32.add (get_global $sp) (i32.const 8)))
												 (i64.load (i32.add (get_global $sp) (i32.const 16)))
												 (i64.load (i32.add (get_global $sp) (i32.const 24)))))
						  (set_global $sp (i32.sub (get_global $sp) (i32.const 32)))
						  (br $loop))(call $useGas (i64.const 12)) (if (i32.gt_s (get_global $sp) (i32.const 32704)) 
					 (then (unreachable)))(call $PUSH (i64.const 0)(i64.const 0)(i64.const 0)(i64.const 561))(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	;; jump
						  (set_local $jump_dest (call $check_overflow 
												 (i64.load (get_global $sp))
												 (i64.load (i32.add (get_global $sp) (i32.const 8)))
												 (i64.load (i32.add (get_global $sp) (i32.const 16)))
												 (i64.load (i32.add (get_global $sp) (i32.const 24)))))
						  (set_global $sp (i32.sub (get_global $sp) (i32.const 32)))
						  (br $loop))(call $useGas (i64.const 1)) (br $done))(call $useGas (i64.const 20)) (if (i32.gt_s (get_global $sp) (i32.const 32640)) 
					 (then (unreachable)))(call $CALLVALUE)
	(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $DUP (i32.const 0))
	(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $ISZERO)
	(call $PUSH (i64.const 0)(i64.const 0)(i64.const 0)(i64.const 263))(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(set_local $jump_dest (call $check_overflow 
												 (i64.load (get_global $sp))
												 (i64.load (i32.add (get_global $sp) (i32.const 8)))
												 (i64.load (i32.add (get_global $sp) (i32.const 16)))
												 (i64.load (i32.add (get_global $sp) (i32.const 24)))))
	
						(set_global $sp (i32.sub (get_global $sp) (i32.const 64)))
						(br_if $loop (i32.eqz (i64.eqz (i64.or
						  (i64.load (i32.add (get_global $sp) (i32.const 32)))
						  (i64.or
							(i64.load (i32.add (get_global $sp) (i32.const 40)))
							(i64.or
							  (i64.load (i32.add (get_global $sp) (i32.const 48)))
							  (i64.load (i32.add (get_global $sp) (i32.const 56)))
							)
						  )
						))))
	(call $useGas (i64.const 6)) (if (i32.gt_s (get_global $sp) (i32.const 32672)) 
					 (then (unreachable)))(call $PUSH (i64.const 0)(i64.const 0)(i64.const 0)(i64.const 0))(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $DUP (i32.const 0))
	(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $REVERT) (br $done)
	(set_global $sp (i32.add (get_global $sp) (i32.const -64)))
	)(call $useGas (i64.const 17)) (if (i32.gt_s (get_global $sp) (i32.const 32704)) 
					 (then (unreachable)))(if (i32.lt_s (get_global $sp) (i32.const 0)) 
					  (then (unreachable)))(set_global $sp (i32.add (get_global $sp) (i32.const -32)))
	(call $PUSH (i64.const 0)(i64.const 0)(i64.const 0)(i64.const 272))(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $PUSH (i64.const 0)(i64.const 0)(i64.const 0)(i64.const 593))(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	;; jump
						  (set_local $jump_dest (call $check_overflow 
												 (i64.load (get_global $sp))
												 (i64.load (i32.add (get_global $sp) (i32.const 8)))
												 (i64.load (i32.add (get_global $sp) (i32.const 16)))
												 (i64.load (i32.add (get_global $sp) (i32.const 24)))))
						  (set_global $sp (i32.sub (get_global $sp) (i32.const 32)))
						  (br $loop))(call $useGas (i64.const 27)) (if (i32.gt_s (get_global $sp) (i32.const 32640)) 
					 (then (unreachable)))(call $PUSH (i64.const 0)(i64.const 0)(i64.const 0)(i64.const 64))(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $MLOAD)
	(call $PUSH (i64.const 0)(i64.const 0)(i64.const 0)(i64.const 285))(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $SWAP (i32.const 1))
	(call $SWAP (i32.const 0))
	(call $PUSH (i64.const 0)(i64.const 0)(i64.const 0)(i64.const 786))(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	;; jump
						  (set_local $jump_dest (call $check_overflow 
												 (i64.load (get_global $sp))
												 (i64.load (i32.add (get_global $sp) (i32.const 8)))
												 (i64.load (i32.add (get_global $sp) (i32.const 16)))
												 (i64.load (i32.add (get_global $sp) (i32.const 24)))))
						  (set_global $sp (i32.sub (get_global $sp) (i32.const 32)))
						  (br $loop))(call $useGas (i64.const 19)) (if (i32.gt_s (get_global $sp) (i32.const 32640)) 
					 (then (unreachable)))(if (i32.lt_s (get_global $sp) (i32.const 0)) 
					  (then (unreachable)))(call $PUSH (i64.const 0)(i64.const 0)(i64.const 0)(i64.const 64))(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $MLOAD)
	(call $DUP (i32.const 0))
	(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $SWAP (i32.const 1))
	(call $SUB)
	(set_global $sp (i32.add (get_global $sp) (i32.const -32)))
	(call $SWAP (i32.const 0))
	(call $RETURN) (br $done)
	(set_global $sp (i32.add (get_global $sp) (i32.const -64)))
	)(call $useGas (i64.const 20)) (if (i32.gt_s (get_global $sp) (i32.const 32640)) 
					 (then (unreachable)))(call $CALLVALUE)
	(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $DUP (i32.const 0))
	(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $ISZERO)
	(call $PUSH (i64.const 0)(i64.const 0)(i64.const 0)(i64.const 306))(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(set_local $jump_dest (call $check_overflow 
												 (i64.load (get_global $sp))
												 (i64.load (i32.add (get_global $sp) (i32.const 8)))
												 (i64.load (i32.add (get_global $sp) (i32.const 16)))
												 (i64.load (i32.add (get_global $sp) (i32.const 24)))))
	
						(set_global $sp (i32.sub (get_global $sp) (i32.const 64)))
						(br_if $loop (i32.eqz (i64.eqz (i64.or
						  (i64.load (i32.add (get_global $sp) (i32.const 32)))
						  (i64.or
							(i64.load (i32.add (get_global $sp) (i32.const 40)))
							(i64.or
							  (i64.load (i32.add (get_global $sp) (i32.const 48)))
							  (i64.load (i32.add (get_global $sp) (i32.const 56)))
							)
						  )
						))))
	(call $useGas (i64.const 6)) (if (i32.gt_s (get_global $sp) (i32.const 32672)) 
					 (then (unreachable)))(call $PUSH (i64.const 0)(i64.const 0)(i64.const 0)(i64.const 0))(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $DUP (i32.const 0))
	(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $REVERT) (br $done)
	(set_global $sp (i32.add (get_global $sp) (i32.const -64)))
	)(call $useGas (i64.const 17)) (if (i32.gt_s (get_global $sp) (i32.const 32704)) 
					 (then (unreachable)))(if (i32.lt_s (get_global $sp) (i32.const 0)) 
					  (then (unreachable)))(set_global $sp (i32.add (get_global $sp) (i32.const -32)))
	(call $PUSH (i64.const 0)(i64.const 0)(i64.const 0)(i64.const 315))(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $PUSH (i64.const 0)(i64.const 0)(i64.const 0)(i64.const 599))(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	;; jump
						  (set_local $jump_dest (call $check_overflow 
												 (i64.load (get_global $sp))
												 (i64.load (i32.add (get_global $sp) (i32.const 8)))
												 (i64.load (i32.add (get_global $sp) (i32.const 16)))
												 (i64.load (i32.add (get_global $sp) (i32.const 24)))))
						  (set_global $sp (i32.sub (get_global $sp) (i32.const 32)))
						  (br $loop))(call $useGas (i64.const 27)) (if (i32.gt_s (get_global $sp) (i32.const 32640)) 
					 (then (unreachable)))(call $PUSH (i64.const 0)(i64.const 0)(i64.const 0)(i64.const 64))(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $MLOAD)
	(call $PUSH (i64.const 0)(i64.const 0)(i64.const 0)(i64.const 328))(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $SWAP (i32.const 1))
	(call $SWAP (i32.const 0))
	(call $PUSH (i64.const 0)(i64.const 0)(i64.const 0)(i64.const 786))(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	;; jump
						  (set_local $jump_dest (call $check_overflow 
												 (i64.load (get_global $sp))
												 (i64.load (i32.add (get_global $sp) (i32.const 8)))
												 (i64.load (i32.add (get_global $sp) (i32.const 16)))
												 (i64.load (i32.add (get_global $sp) (i32.const 24)))))
						  (set_global $sp (i32.sub (get_global $sp) (i32.const 32)))
						  (br $loop))(call $useGas (i64.const 19)) (if (i32.gt_s (get_global $sp) (i32.const 32640)) 
					 (then (unreachable)))(if (i32.lt_s (get_global $sp) (i32.const 0)) 
					  (then (unreachable)))(call $PUSH (i64.const 0)(i64.const 0)(i64.const 0)(i64.const 64))(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $MLOAD)
	(call $DUP (i32.const 0))
	(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $SWAP (i32.const 1))
	(call $SUB)
	(set_global $sp (i32.add (get_global $sp) (i32.const -32)))
	(call $SWAP (i32.const 0))
	(call $RETURN) (br $done)
	(set_global $sp (i32.add (get_global $sp) (i32.const -64)))
	)(call $useGas (i64.const 20)) (if (i32.gt_s (get_global $sp) (i32.const 32640)) 
					 (then (unreachable)))(call $CALLVALUE)
	(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $DUP (i32.const 0))
	(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $ISZERO)
	(call $PUSH (i64.const 0)(i64.const 0)(i64.const 0)(i64.const 349))(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(set_local $jump_dest (call $check_overflow 
												 (i64.load (get_global $sp))
												 (i64.load (i32.add (get_global $sp) (i32.const 8)))
												 (i64.load (i32.add (get_global $sp) (i32.const 16)))
												 (i64.load (i32.add (get_global $sp) (i32.const 24)))))
	
						(set_global $sp (i32.sub (get_global $sp) (i32.const 64)))
						(br_if $loop (i32.eqz (i64.eqz (i64.or
						  (i64.load (i32.add (get_global $sp) (i32.const 32)))
						  (i64.or
							(i64.load (i32.add (get_global $sp) (i32.const 40)))
							(i64.or
							  (i64.load (i32.add (get_global $sp) (i32.const 48)))
							  (i64.load (i32.add (get_global $sp) (i32.const 56)))
							)
						  )
						))))
	(call $useGas (i64.const 6)) (if (i32.gt_s (get_global $sp) (i32.const 32672)) 
					 (then (unreachable)))(call $PUSH (i64.const 0)(i64.const 0)(i64.const 0)(i64.const 0))(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $DUP (i32.const 0))
	(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $REVERT) (br $done)
	(set_global $sp (i32.add (get_global $sp) (i32.const -64)))
	)(call $useGas (i64.const 17)) (if (i32.gt_s (get_global $sp) (i32.const 32704)) 
					 (then (unreachable)))(if (i32.lt_s (get_global $sp) (i32.const 0)) 
					  (then (unreachable)))(set_global $sp (i32.add (get_global $sp) (i32.const -32)))
	(call $PUSH (i64.const 0)(i64.const 0)(i64.const 0)(i64.const 358))(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $PUSH (i64.const 0)(i64.const 0)(i64.const 0)(i64.const 607))(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	;; jump
						  (set_local $jump_dest (call $check_overflow 
												 (i64.load (get_global $sp))
												 (i64.load (i32.add (get_global $sp) (i32.const 8)))
												 (i64.load (i32.add (get_global $sp) (i32.const 16)))
												 (i64.load (i32.add (get_global $sp) (i32.const 24)))))
						  (set_global $sp (i32.sub (get_global $sp) (i32.const 32)))
						  (br $loop))(call $useGas (i64.const 27)) (if (i32.gt_s (get_global $sp) (i32.const 32640)) 
					 (then (unreachable)))(call $PUSH (i64.const 0)(i64.const 0)(i64.const 0)(i64.const 64))(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $MLOAD)
	(call $PUSH (i64.const 0)(i64.const 0)(i64.const 0)(i64.const 371))(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $SWAP (i32.const 1))
	(call $SWAP (i32.const 0))
	(call $PUSH (i64.const 0)(i64.const 0)(i64.const 0)(i64.const 786))(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	;; jump
						  (set_local $jump_dest (call $check_overflow 
												 (i64.load (get_global $sp))
												 (i64.load (i32.add (get_global $sp) (i32.const 8)))
												 (i64.load (i32.add (get_global $sp) (i32.const 16)))
												 (i64.load (i32.add (get_global $sp) (i32.const 24)))))
						  (set_global $sp (i32.sub (get_global $sp) (i32.const 32)))
						  (br $loop))(call $useGas (i64.const 19)) (if (i32.gt_s (get_global $sp) (i32.const 32640)) 
					 (then (unreachable)))(if (i32.lt_s (get_global $sp) (i32.const 0)) 
					  (then (unreachable)))(call $PUSH (i64.const 0)(i64.const 0)(i64.const 0)(i64.const 64))(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $MLOAD)
	(call $DUP (i32.const 0))
	(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $SWAP (i32.const 1))
	(call $SUB)
	(set_global $sp (i32.add (get_global $sp) (i32.const -32)))
	(call $SWAP (i32.const 0))
	(call $RETURN) (br $done)
	(set_global $sp (i32.add (get_global $sp) (i32.const -64)))
	)(call $useGas (i64.const 20)) (if (i32.gt_s (get_global $sp) (i32.const 32640)) 
					 (then (unreachable)))(call $CALLVALUE)
	(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $DUP (i32.const 0))
	(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $ISZERO)
	(call $PUSH (i64.const 0)(i64.const 0)(i64.const 0)(i64.const 392))(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(set_local $jump_dest (call $check_overflow 
												 (i64.load (get_global $sp))
												 (i64.load (i32.add (get_global $sp) (i32.const 8)))
												 (i64.load (i32.add (get_global $sp) (i32.const 16)))
												 (i64.load (i32.add (get_global $sp) (i32.const 24)))))
	
						(set_global $sp (i32.sub (get_global $sp) (i32.const 64)))
						(br_if $loop (i32.eqz (i64.eqz (i64.or
						  (i64.load (i32.add (get_global $sp) (i32.const 32)))
						  (i64.or
							(i64.load (i32.add (get_global $sp) (i32.const 40)))
							(i64.or
							  (i64.load (i32.add (get_global $sp) (i32.const 48)))
							  (i64.load (i32.add (get_global $sp) (i32.const 56)))
							)
						  )
						))))
	(call $useGas (i64.const 6)) (if (i32.gt_s (get_global $sp) (i32.const 32672)) 
					 (then (unreachable)))(call $PUSH (i64.const 0)(i64.const 0)(i64.const 0)(i64.const 0))(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $DUP (i32.const 0))
	(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $REVERT) (br $done)
	(set_global $sp (i32.add (get_global $sp) (i32.const -64)))
	)(call $useGas (i64.const 17)) (if (i32.gt_s (get_global $sp) (i32.const 32704)) 
					 (then (unreachable)))(if (i32.lt_s (get_global $sp) (i32.const 0)) 
					  (then (unreachable)))(set_global $sp (i32.add (get_global $sp) (i32.const -32)))
	(call $PUSH (i64.const 0)(i64.const 0)(i64.const 0)(i64.const 401))(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $PUSH (i64.const 0)(i64.const 0)(i64.const 0)(i64.const 613))(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	;; jump
						  (set_local $jump_dest (call $check_overflow 
												 (i64.load (get_global $sp))
												 (i64.load (i32.add (get_global $sp) (i32.const 8)))
												 (i64.load (i32.add (get_global $sp) (i32.const 16)))
												 (i64.load (i32.add (get_global $sp) (i32.const 24)))))
						  (set_global $sp (i32.sub (get_global $sp) (i32.const 32)))
						  (br $loop))(call $useGas (i64.const 27)) (if (i32.gt_s (get_global $sp) (i32.const 32640)) 
					 (then (unreachable)))(call $PUSH (i64.const 0)(i64.const 0)(i64.const 0)(i64.const 64))(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $MLOAD)
	(call $PUSH (i64.const 0)(i64.const 0)(i64.const 0)(i64.const 414))(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $SWAP (i32.const 1))
	(call $SWAP (i32.const 0))
	(call $PUSH (i64.const 0)(i64.const 0)(i64.const 0)(i64.const 786))(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	;; jump
						  (set_local $jump_dest (call $check_overflow 
												 (i64.load (get_global $sp))
												 (i64.load (i32.add (get_global $sp) (i32.const 8)))
												 (i64.load (i32.add (get_global $sp) (i32.const 16)))
												 (i64.load (i32.add (get_global $sp) (i32.const 24)))))
						  (set_global $sp (i32.sub (get_global $sp) (i32.const 32)))
						  (br $loop))(call $useGas (i64.const 19)) (if (i32.gt_s (get_global $sp) (i32.const 32640)) 
					 (then (unreachable)))(if (i32.lt_s (get_global $sp) (i32.const 0)) 
					  (then (unreachable)))(call $PUSH (i64.const 0)(i64.const 0)(i64.const 0)(i64.const 64))(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $MLOAD)
	(call $DUP (i32.const 0))
	(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $SWAP (i32.const 1))
	(call $SUB)
	(set_global $sp (i32.add (get_global $sp) (i32.const -32)))
	(call $SWAP (i32.const 0))
	(call $RETURN) (br $done)
	(set_global $sp (i32.add (get_global $sp) (i32.const -64)))
	)(call $useGas (i64.const 20)) (if (i32.gt_s (get_global $sp) (i32.const 32640)) 
					 (then (unreachable)))(call $CALLVALUE)
	(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $DUP (i32.const 0))
	(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $ISZERO)
	(call $PUSH (i64.const 0)(i64.const 0)(i64.const 0)(i64.const 435))(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(set_local $jump_dest (call $check_overflow 
												 (i64.load (get_global $sp))
												 (i64.load (i32.add (get_global $sp) (i32.const 8)))
												 (i64.load (i32.add (get_global $sp) (i32.const 16)))
												 (i64.load (i32.add (get_global $sp) (i32.const 24)))))
	
						(set_global $sp (i32.sub (get_global $sp) (i32.const 64)))
						(br_if $loop (i32.eqz (i64.eqz (i64.or
						  (i64.load (i32.add (get_global $sp) (i32.const 32)))
						  (i64.or
							(i64.load (i32.add (get_global $sp) (i32.const 40)))
							(i64.or
							  (i64.load (i32.add (get_global $sp) (i32.const 48)))
							  (i64.load (i32.add (get_global $sp) (i32.const 56)))
							)
						  )
						))))
	(call $useGas (i64.const 6)) (if (i32.gt_s (get_global $sp) (i32.const 32672)) 
					 (then (unreachable)))(call $PUSH (i64.const 0)(i64.const 0)(i64.const 0)(i64.const 0))(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $DUP (i32.const 0))
	(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $REVERT) (br $done)
	(set_global $sp (i32.add (get_global $sp) (i32.const -64)))
	)(call $useGas (i64.const 17)) (if (i32.gt_s (get_global $sp) (i32.const 32704)) 
					 (then (unreachable)))(if (i32.lt_s (get_global $sp) (i32.const 0)) 
					  (then (unreachable)))(set_global $sp (i32.add (get_global $sp) (i32.const -32)))
	(call $PUSH (i64.const 0)(i64.const 0)(i64.const 0)(i64.const 444))(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $PUSH (i64.const 0)(i64.const 0)(i64.const 0)(i64.const 619))(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	;; jump
						  (set_local $jump_dest (call $check_overflow 
												 (i64.load (get_global $sp))
												 (i64.load (i32.add (get_global $sp) (i32.const 8)))
												 (i64.load (i32.add (get_global $sp) (i32.const 16)))
												 (i64.load (i32.add (get_global $sp) (i32.const 24)))))
						  (set_global $sp (i32.sub (get_global $sp) (i32.const 32)))
						  (br $loop))(call $useGas (i64.const 27)) (if (i32.gt_s (get_global $sp) (i32.const 32640)) 
					 (then (unreachable)))(call $PUSH (i64.const 0)(i64.const 0)(i64.const 0)(i64.const 64))(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $MLOAD)
	(call $PUSH (i64.const 0)(i64.const 0)(i64.const 0)(i64.const 457))(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $SWAP (i32.const 1))
	(call $SWAP (i32.const 0))
	(call $PUSH (i64.const 0)(i64.const 0)(i64.const 0)(i64.const 1250))(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	;; jump
						  (set_local $jump_dest (call $check_overflow 
												 (i64.load (get_global $sp))
												 (i64.load (i32.add (get_global $sp) (i32.const 8)))
												 (i64.load (i32.add (get_global $sp) (i32.const 16)))
												 (i64.load (i32.add (get_global $sp) (i32.const 24)))))
						  (set_global $sp (i32.sub (get_global $sp) (i32.const 32)))
						  (br $loop))(call $useGas (i64.const 19)) (if (i32.gt_s (get_global $sp) (i32.const 32640)) 
					 (then (unreachable)))(if (i32.lt_s (get_global $sp) (i32.const 0)) 
					  (then (unreachable)))(call $PUSH (i64.const 0)(i64.const 0)(i64.const 0)(i64.const 64))(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $MLOAD)
	(call $DUP (i32.const 0))
	(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $SWAP (i32.const 1))
	(call $SUB)
	(set_global $sp (i32.add (get_global $sp) (i32.const -32)))
	(call $SWAP (i32.const 0))
	(call $RETURN) (br $done)
	(set_global $sp (i32.add (get_global $sp) (i32.const -64)))
	)(call $useGas (i64.const 15)) (if (i32.gt_s (get_global $sp) (i32.const 32672)) 
					 (then (unreachable)))(call $PUSH (i64.const 0)(i64.const 0)(i64.const 0)(i64.const 4))(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $SLOAD)
	(call $DUP (i32.const 1))
	(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	;; jump
						  (set_local $jump_dest (call $check_overflow 
												 (i64.load (get_global $sp))
												 (i64.load (i32.add (get_global $sp) (i32.const 8)))
												 (i64.load (i32.add (get_global $sp) (i32.const 16)))
												 (i64.load (i32.add (get_global $sp) (i32.const 24)))))
						  (set_global $sp (i32.sub (get_global $sp) (i32.const 32)))
						  (br $loop))(call $useGas (i64.const 54)) (if (i32.gt_s (get_global $sp) (i32.const 32448)) 
					 (then (unreachable)))(call $CALLER)
	(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $PUSH (i64.const 0)(i64.const 4294967295)(i64.const -1)(i64.const -1))(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $AND)
	(set_global $sp (i32.add (get_global $sp) (i32.const -32)))
	(call $PUSH (i64.const 7952373897392706876)(i64.const -2503809304192850280)(i64.const -742890452874458446)(i64.const 5316802987019006303))(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $CALLVALUE)
	(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $PUSH (i64.const 0)(i64.const 0)(i64.const 0)(i64.const 1))(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $PUSH (i64.const 0)(i64.const 0)(i64.const 0)(i64.const 0))(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $DUP (i32.const 5))
	(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $PUSH (i64.const 0)(i64.const 0)(i64.const 0)(i64.const 64))(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $MLOAD)
	(call $PUSH (i64.const 0)(i64.const 0)(i64.const 0)(i64.const 550))(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $SWAP (i32.const 4))
	(call $SWAP (i32.const 3))
	(call $SWAP (i32.const 2))
	(call $SWAP (i32.const 1))
	(call $SWAP (i32.const 0))
	(call $PUSH (i64.const 0)(i64.const 0)(i64.const 0)(i64.const 1375))(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	;; jump
						  (set_local $jump_dest (call $check_overflow 
												 (i64.load (get_global $sp))
												 (i64.load (i32.add (get_global $sp) (i32.const 8)))
												 (i64.load (i32.add (get_global $sp) (i32.const 16)))
												 (i64.load (i32.add (get_global $sp) (i32.const 24)))))
						  (set_global $sp (i32.sub (get_global $sp) (i32.const 32)))
						  (br $loop))(call $useGas (i64.const 29)) (if (i32.gt_s (get_global $sp) (i32.const 32640)) 
					 (then (unreachable)))(if (i32.lt_s (get_global $sp) (i32.const 96)) 
					  (then (unreachable)))(call $PUSH (i64.const 0)(i64.const 0)(i64.const 0)(i64.const 64))(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $MLOAD)
	(call $DUP (i32.const 0))
	(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $SWAP (i32.const 1))
	(call $SUB)
	(set_global $sp (i32.add (get_global $sp) (i32.const -32)))
	(call $SWAP (i32.const 0))
	(call $LOG (i32.const 2))
	(set_global $sp (i32.add (get_global $sp) (i32.const -128)))
	(set_global $sp (i32.add (get_global $sp) (i32.const -32)))
	;; jump
						  (set_local $jump_dest (call $check_overflow 
												 (i64.load (get_global $sp))
												 (i64.load (i32.add (get_global $sp) (i32.const 8)))
												 (i64.load (i32.add (get_global $sp) (i32.const 16)))
												 (i64.load (i32.add (get_global $sp) (i32.const 24)))))
						  (set_global $sp (i32.sub (get_global $sp) (i32.const 32)))
						  (br $loop))(call $useGas (i64.const 63)) (if (i32.gt_s (get_global $sp) (i32.const 32640)) 
					 (then (unreachable)))(if (i32.lt_s (get_global $sp) (i32.const 64)) 
					  (then (unreachable)))(call $DUP (i32.const 2))
	(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $PUSH (i64.const 0)(i64.const 0)(i64.const 0)(i64.const 2))(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $DUP (i32.const 1))
	(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $SWAP (i32.const 0))
	(call $SSTORE)
	(set_global $sp (i32.add (get_global $sp) (i32.const -64)))
	(set_global $sp (i32.add (get_global $sp) (i32.const -32)))
	(call $DUP (i32.const 1))
	(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $PUSH (i64.const 0)(i64.const 0)(i64.const 0)(i64.const 3))(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $DUP (i32.const 1))
	(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $SWAP (i32.const 0))
	(call $SSTORE)
	(set_global $sp (i32.add (get_global $sp) (i32.const -64)))
	(set_global $sp (i32.add (get_global $sp) (i32.const -32)))
	(call $DUP (i32.const 0))
	(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $PUSH (i64.const 0)(i64.const 0)(i64.const 0)(i64.const 4294967295))(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $AND)
	(set_global $sp (i32.add (get_global $sp) (i32.const -32)))
	(call $PUSH (i64.const 0)(i64.const 0)(i64.const 0)(i64.const 1))(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $DUP (i32.const 1))
	(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $SWAP (i32.const 0))
	(call $SSTORE)
	(set_global $sp (i32.add (get_global $sp) (i32.const -64)))
	(set_global $sp (i32.add (get_global $sp) (i32.const -32)))
	(set_global $sp (i32.add (get_global $sp) (i32.const -32)))
	(set_global $sp (i32.add (get_global $sp) (i32.const -32)))
	(set_global $sp (i32.add (get_global $sp) (i32.const -32)))
	;; jump
						  (set_local $jump_dest (call $check_overflow 
												 (i64.load (get_global $sp))
												 (i64.load (i32.add (get_global $sp) (i32.const 8)))
												 (i64.load (i32.add (get_global $sp) (i32.const 16)))
												 (i64.load (i32.add (get_global $sp) (i32.const 24)))))
						  (set_global $sp (i32.sub (get_global $sp) (i32.const 32)))
						  (br $loop))(call $useGas (i64.const 15)) (if (i32.gt_s (get_global $sp) (i32.const 32672)) 
					 (then (unreachable)))(call $PUSH (i64.const 0)(i64.const 0)(i64.const 0)(i64.const 2))(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $SLOAD)
	(call $DUP (i32.const 1))
	(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	;; jump
						  (set_local $jump_dest (call $check_overflow 
												 (i64.load (get_global $sp))
												 (i64.load (i32.add (get_global $sp) (i32.const 8)))
												 (i64.load (i32.add (get_global $sp) (i32.const 16)))
												 (i64.load (i32.add (get_global $sp) (i32.const 24)))))
						  (set_global $sp (i32.sub (get_global $sp) (i32.const 32)))
						  (br $loop))(call $useGas (i64.const 4)) (if (i32.gt_s (get_global $sp) (i32.const 32704)) 
					 (then (unreachable)))(unreachable))(call $useGas (i64.const 15)) (if (i32.gt_s (get_global $sp) (i32.const 32672)) 
					 (then (unreachable)))(call $PUSH (i64.const 0)(i64.const 0)(i64.const 0)(i64.const 1))(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $SLOAD)
	(call $DUP (i32.const 1))
	(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	;; jump
						  (set_local $jump_dest (call $check_overflow 
												 (i64.load (get_global $sp))
												 (i64.load (i32.add (get_global $sp) (i32.const 8)))
												 (i64.load (i32.add (get_global $sp) (i32.const 16)))
												 (i64.load (i32.add (get_global $sp) (i32.const 24)))))
						  (set_global $sp (i32.sub (get_global $sp) (i32.const 32)))
						  (br $loop))(call $useGas (i64.const 15)) (if (i32.gt_s (get_global $sp) (i32.const 32672)) 
					 (then (unreachable)))(call $PUSH (i64.const 0)(i64.const 0)(i64.const 0)(i64.const 3))(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $SLOAD)
	(call $DUP (i32.const 1))
	(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	;; jump
						  (set_local $jump_dest (call $check_overflow 
												 (i64.load (get_global $sp))
												 (i64.load (i32.add (get_global $sp) (i32.const 8)))
												 (i64.load (i32.add (get_global $sp) (i32.const 16)))
												 (i64.load (i32.add (get_global $sp) (i32.const 24)))))
						  (set_global $sp (i32.sub (get_global $sp) (i32.const 32)))
						  (br $loop))(call $useGas (i64.const 24)) (if (i32.gt_s (get_global $sp) (i32.const 32608)) 
					 (then (unreachable)))(call $PUSH (i64.const 0)(i64.const 0)(i64.const 0)(i64.const 0))(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $DUP (i32.const 0))
	(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $SLOAD)
	(call $PUSH (i64.const 0)(i64.const 0)(i64.const 0)(i64.const 632))(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $SWAP (i32.const 0))
	(call $PUSH (i64.const 0)(i64.const 0)(i64.const 0)(i64.const 1510))(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	;; jump
						  (set_local $jump_dest (call $check_overflow 
												 (i64.load (get_global $sp))
												 (i64.load (i32.add (get_global $sp) (i32.const 8)))
												 (i64.load (i32.add (get_global $sp) (i32.const 16)))
												 (i64.load (i32.add (get_global $sp) (i32.const 24)))))
						  (set_global $sp (i32.sub (get_global $sp) (i32.const 32)))
						  (br $loop))(call $useGas (i64.const 106)) (if (i32.gt_s (get_global $sp) (i32.const 32544)) 
					 (then (unreachable)))(call $DUP (i32.const 0))
	(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $PUSH (i64.const 0)(i64.const 0)(i64.const 0)(i64.const 31))(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $ADD)
	(set_global $sp (i32.add (get_global $sp) (i32.const -32)))
	(call $PUSH (i64.const 0)(i64.const 0)(i64.const 0)(i64.const 32))(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $DUP (i32.const 0))
	(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $SWAP (i32.const 1))
	(call $DIV)
	(set_global $sp (i32.add (get_global $sp) (i32.const -32)))
	(call $MUL)
	(set_global $sp (i32.add (get_global $sp) (i32.const -32)))
	(call $PUSH (i64.const 0)(i64.const 0)(i64.const 0)(i64.const 32))(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $ADD)
	(set_global $sp (i32.add (get_global $sp) (i32.const -32)))
	(call $PUSH (i64.const 0)(i64.const 0)(i64.const 0)(i64.const 64))(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $MLOAD)
	(call $SWAP (i32.const 0))
	(call $DUP (i32.const 1))
	(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $ADD)
	(set_global $sp (i32.add (get_global $sp) (i32.const -32)))
	(call $PUSH (i64.const 0)(i64.const 0)(i64.const 0)(i64.const 64))(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $MSTORE)
	(set_global $sp (i32.add (get_global $sp) (i32.const -64)))
	(call $DUP (i32.const 0))
	(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $SWAP (i32.const 2))
	(call $SWAP (i32.const 1))
	(call $SWAP (i32.const 0))
	(call $DUP (i32.const 1))
	(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $DUP (i32.const 1))
	(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $MSTORE)
	(set_global $sp (i32.add (get_global $sp) (i32.const -64)))
	(call $PUSH (i64.const 0)(i64.const 0)(i64.const 0)(i64.const 32))(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $ADD)
	(set_global $sp (i32.add (get_global $sp) (i32.const -32)))
	(call $DUP (i32.const 2))
	(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $DUP (i32.const 0))
	(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $SLOAD)
	(call $PUSH (i64.const 0)(i64.const 0)(i64.const 0)(i64.const 676))(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $SWAP (i32.const 0))
	(call $PUSH (i64.const 0)(i64.const 0)(i64.const 0)(i64.const 1510))(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	;; jump
						  (set_local $jump_dest (call $check_overflow 
												 (i64.load (get_global $sp))
												 (i64.load (i32.add (get_global $sp) (i32.const 8)))
												 (i64.load (i32.add (get_global $sp) (i32.const 16)))
												 (i64.load (i32.add (get_global $sp) (i32.const 24)))))
						  (set_global $sp (i32.sub (get_global $sp) (i32.const 32)))
						  (br $loop))(call $useGas (i64.const 20)) (if (i32.gt_s (get_global $sp) (i32.const 32672)) 
					 (then (unreachable)))(call $DUP (i32.const 0))
	(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $ISZERO)
	(call $PUSH (i64.const 0)(i64.const 0)(i64.const 0)(i64.const 753))(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(set_local $jump_dest (call $check_overflow 
												 (i64.load (get_global $sp))
												 (i64.load (i32.add (get_global $sp) (i32.const 8)))
												 (i64.load (i32.add (get_global $sp) (i32.const 16)))
												 (i64.load (i32.add (get_global $sp) (i32.const 24)))))
	
						(set_global $sp (i32.sub (get_global $sp) (i32.const 64)))
						(br_if $loop (i32.eqz (i64.eqz (i64.or
						  (i64.load (i32.add (get_global $sp) (i32.const 32)))
						  (i64.or
							(i64.load (i32.add (get_global $sp) (i32.const 40)))
							(i64.or
							  (i64.load (i32.add (get_global $sp) (i32.const 48)))
							  (i64.load (i32.add (get_global $sp) (i32.const 56)))
							)
						  )
						))))
	(call $useGas (i64.const 22)) (if (i32.gt_s (get_global $sp) (i32.const 32640)) 
					 (then (unreachable)))(call $DUP (i32.const 0))
	(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $PUSH (i64.const 0)(i64.const 0)(i64.const 0)(i64.const 31))(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $LT)
	(set_global $sp (i32.add (get_global $sp) (i32.const -32)))
	(call $PUSH (i64.const 0)(i64.const 0)(i64.const 0)(i64.const 710))(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(set_local $jump_dest (call $check_overflow 
												 (i64.load (get_global $sp))
												 (i64.load (i32.add (get_global $sp) (i32.const 8)))
												 (i64.load (i32.add (get_global $sp) (i32.const 16)))
												 (i64.load (i32.add (get_global $sp) (i32.const 24)))))
	
						(set_global $sp (i32.sub (get_global $sp) (i32.const 64)))
						(br_if $loop (i32.eqz (i64.eqz (i64.or
						  (i64.load (i32.add (get_global $sp) (i32.const 32)))
						  (i64.or
							(i64.load (i32.add (get_global $sp) (i32.const 40)))
							(i64.or
							  (i64.load (i32.add (get_global $sp) (i32.const 48)))
							  (i64.load (i32.add (get_global $sp) (i32.const 56)))
							)
						  )
						))))
	(call $useGas (i64.const 48)) (if (i32.gt_s (get_global $sp) (i32.const 32608)) 
					 (then (unreachable)))(call $PUSH (i64.const 0)(i64.const 0)(i64.const 0)(i64.const 256))(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $DUP (i32.const 0))
	(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $DUP (i32.const 3))
	(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $SLOAD)
	(call $DIV)
	(set_global $sp (i32.add (get_global $sp) (i32.const -32)))
	(call $MUL)
	(set_global $sp (i32.add (get_global $sp) (i32.const -32)))
	(call $DUP (i32.const 3))
	(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $MSTORE)
	(set_global $sp (i32.add (get_global $sp) (i32.const -64)))
	(call $SWAP (i32.const 1))
	(call $PUSH (i64.const 0)(i64.const 0)(i64.const 0)(i64.const 32))(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $ADD)
	(set_global $sp (i32.add (get_global $sp) (i32.const -32)))
	(call $SWAP (i32.const 1))
	(call $PUSH (i64.const 0)(i64.const 0)(i64.const 0)(i64.const 753))(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	;; jump
						  (set_local $jump_dest (call $check_overflow 
												 (i64.load (get_global $sp))
												 (i64.load (i32.add (get_global $sp) (i32.const 8)))
												 (i64.load (i32.add (get_global $sp) (i32.const 16)))
												 (i64.load (i32.add (get_global $sp) (i32.const 24)))))
						  (set_global $sp (i32.sub (get_global $sp) (i32.const 32)))
						  (br $loop))(call $useGas (i64.const 58)) (if (i32.gt_s (get_global $sp) (i32.const 32672)) 
					 (then (unreachable)))(if (i32.lt_s (get_global $sp) (i32.const 0)) 
					  (then (unreachable)))(call $DUP (i32.const 2))
	(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $ADD)
	(set_global $sp (i32.add (get_global $sp) (i32.const -32)))
	(call $SWAP (i32.const 1))
	(call $SWAP (i32.const 0))
	(call $PUSH (i64.const 0)(i64.const 0)(i64.const 0)(i64.const 0))(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $MSTORE)
	(set_global $sp (i32.add (get_global $sp) (i32.const -64)))
	(call $PUSH (i64.const 0)(i64.const 0)(i64.const 0)(i64.const 32))(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $PUSH (i64.const 0)(i64.const 0)(i64.const 0)(i64.const 0))(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $SHA3)
	(set_global $sp (i32.add (get_global $sp) (i32.const -32)))
	(call $SWAP (i32.const 0))
	)(call $useGas (i64.const 50)) (if (i32.gt_s (get_global $sp) (i32.const 32640)) 
					 (then (unreachable)))(call $DUP (i32.const 1))
	(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $SLOAD)
	(call $DUP (i32.const 1))
	(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $MSTORE)
	(set_global $sp (i32.add (get_global $sp) (i32.const -64)))
	(call $SWAP (i32.const 0))
	(call $PUSH (i64.const 0)(i64.const 0)(i64.const 0)(i64.const 1))(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $ADD)
	(set_global $sp (i32.add (get_global $sp) (i32.const -32)))
	(call $SWAP (i32.const 0))
	(call $PUSH (i64.const 0)(i64.const 0)(i64.const 0)(i64.const 32))(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $ADD)
	(set_global $sp (i32.add (get_global $sp) (i32.const -32)))
	(call $DUP (i32.const 0))
	(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $DUP (i32.const 3))
	(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $GT)
	(set_global $sp (i32.add (get_global $sp) (i32.const -32)))
	(call $PUSH (i64.const 0)(i64.const 0)(i64.const 0)(i64.const 724))(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(set_local $jump_dest (call $check_overflow 
												 (i64.load (get_global $sp))
												 (i64.load (i32.add (get_global $sp) (i32.const 8)))
												 (i64.load (i32.add (get_global $sp) (i32.const 16)))
												 (i64.load (i32.add (get_global $sp) (i32.const 24)))))
	
						(set_global $sp (i32.sub (get_global $sp) (i32.const 64)))
						(br_if $loop (i32.eqz (i64.eqz (i64.or
						  (i64.load (i32.add (get_global $sp) (i32.const 32)))
						  (i64.or
							(i64.load (i32.add (get_global $sp) (i32.const 40)))
							(i64.or
							  (i64.load (i32.add (get_global $sp) (i32.const 48)))
							  (i64.load (i32.add (get_global $sp) (i32.const 56)))
							)
						  )
						))))
	(call $useGas (i64.const 24)) (if (i32.gt_s (get_global $sp) (i32.const 32672)) 
					 (then (unreachable)))(call $DUP (i32.const 2))
	(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $SWAP (i32.const 0))
	(call $SUB)
	(set_global $sp (i32.add (get_global $sp) (i32.const -32)))
	(call $PUSH (i64.const 0)(i64.const 0)(i64.const 0)(i64.const 31))(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $AND)
	(set_global $sp (i32.add (get_global $sp) (i32.const -32)))
	(call $DUP (i32.const 2))
	(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $ADD)
	(set_global $sp (i32.add (get_global $sp) (i32.const -32)))
	(call $SWAP (i32.const 1))
	)(call $useGas (i64.const 22)) (if (i32.lt_s (get_global $sp) (i32.const 128)) 
					  (then (unreachable)))(set_global $sp (i32.add (get_global $sp) (i32.const -32)))
	(set_global $sp (i32.add (get_global $sp) (i32.const -32)))
	(set_global $sp (i32.add (get_global $sp) (i32.const -32)))
	(set_global $sp (i32.add (get_global $sp) (i32.const -32)))
	(set_global $sp (i32.add (get_global $sp) (i32.const -32)))
	(call $DUP (i32.const 1))
	(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	;; jump
						  (set_local $jump_dest (call $check_overflow 
												 (i64.load (get_global $sp))
												 (i64.load (i32.add (get_global $sp) (i32.const 8)))
												 (i64.load (i32.add (get_global $sp) (i32.const 16)))
												 (i64.load (i32.add (get_global $sp) (i32.const 24)))))
						  (set_global $sp (i32.sub (get_global $sp) (i32.const 32)))
						  (br $loop))(call $useGas (i64.const 28)) (if (i32.gt_s (get_global $sp) (i32.const 32672)) 
					 (then (unreachable)))(call $PUSH (i64.const 0)(i64.const 0)(i64.const 0)(i64.const 0))(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $DUP (i32.const 1))
	(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $SWAP (i32.const 0))
	(set_global $sp (i32.add (get_global $sp) (i32.const -32)))
	(call $SWAP (i32.const 1))
	(call $SWAP (i32.const 0))
	(set_global $sp (i32.add (get_global $sp) (i32.const -32)))
	;; jump
						  (set_local $jump_dest (call $check_overflow 
												 (i64.load (get_global $sp))
												 (i64.load (i32.add (get_global $sp) (i32.const 8)))
												 (i64.load (i32.add (get_global $sp) (i32.const 16)))
												 (i64.load (i32.add (get_global $sp) (i32.const 24)))))
						  (set_global $sp (i32.sub (get_global $sp) (i32.const 32)))
						  (br $loop))(call $useGas (i64.const 18)) (if (i32.gt_s (get_global $sp) (i32.const 32640)) 
					 (then (unreachable)))(call $PUSH (i64.const 0)(i64.const 0)(i64.const 0)(i64.const 780))(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $DUP (i32.const 1))
	(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $PUSH (i64.const 0)(i64.const 0)(i64.const 0)(i64.const 761))(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	;; jump
						  (set_local $jump_dest (call $check_overflow 
												 (i64.load (get_global $sp))
												 (i64.load (i32.add (get_global $sp) (i32.const 8)))
												 (i64.load (i32.add (get_global $sp) (i32.const 16)))
												 (i64.load (i32.add (get_global $sp) (i32.const 24)))))
						  (set_global $sp (i32.sub (get_global $sp) (i32.const 32)))
						  (br $loop))(call $useGas (i64.const 19)) (if (i32.gt_s (get_global $sp) (i32.const 32704)) 
					 (then (unreachable)))(if (i32.lt_s (get_global $sp) (i32.const 64)) 
					  (then (unreachable)))(call $DUP (i32.const 2))
	(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $MSTORE)
	(set_global $sp (i32.add (get_global $sp) (i32.const -64)))
	(set_global $sp (i32.add (get_global $sp) (i32.const -32)))
	(set_global $sp (i32.add (get_global $sp) (i32.const -32)))
	;; jump
						  (set_local $jump_dest (call $check_overflow 
												 (i64.load (get_global $sp))
												 (i64.load (i32.add (get_global $sp) (i32.const 8)))
												 (i64.load (i32.add (get_global $sp) (i32.const 16)))
												 (i64.load (i32.add (get_global $sp) (i32.const 24)))))
						  (set_global $sp (i32.sub (get_global $sp) (i32.const 32)))
						  (br $loop))(call $useGas (i64.const 44)) (if (i32.gt_s (get_global $sp) (i32.const 32576)) 
					 (then (unreachable)))(call $PUSH (i64.const 0)(i64.const 0)(i64.const 0)(i64.const 0))(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $PUSH (i64.const 0)(i64.const 0)(i64.const 0)(i64.const 32))(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $DUP (i32.const 2))
	(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $ADD)
	(set_global $sp (i32.add (get_global $sp) (i32.const -32)))
	(call $SWAP (i32.const 0))
	(set_global $sp (i32.add (get_global $sp) (i32.const -32)))
	(call $PUSH (i64.const 0)(i64.const 0)(i64.const 0)(i64.const 807))(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $PUSH (i64.const 0)(i64.const 0)(i64.const 0)(i64.const 0))(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $DUP (i32.const 3))
	(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $ADD)
	(set_global $sp (i32.add (get_global $sp) (i32.const -32)))
	(call $DUP (i32.const 4))
	(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $PUSH (i64.const 0)(i64.const 0)(i64.const 0)(i64.const 771))(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	;; jump
						  (set_local $jump_dest (call $check_overflow 
												 (i64.load (get_global $sp))
												 (i64.load (i32.add (get_global $sp) (i32.const 8)))
												 (i64.load (i32.add (get_global $sp) (i32.const 16)))
												 (i64.load (i32.add (get_global $sp) (i32.const 24)))))
						  (set_global $sp (i32.sub (get_global $sp) (i32.const 32)))
						  (br $loop))(call $useGas (i64.const 19)) (if (i32.lt_s (get_global $sp) (i32.const 32)) 
					  (then (unreachable)))(call $SWAP (i32.const 2))
	(call $SWAP (i32.const 1))
	(set_global $sp (i32.add (get_global $sp) (i32.const -32)))
	(set_global $sp (i32.add (get_global $sp) (i32.const -32)))
	;; jump
						  (set_local $jump_dest (call $check_overflow 
												 (i64.load (get_global $sp))
												 (i64.load (i32.add (get_global $sp) (i32.const 8)))
												 (i64.load (i32.add (get_global $sp) (i32.const 16)))
												 (i64.load (i32.add (get_global $sp) (i32.const 24)))))
						  (set_global $sp (i32.sub (get_global $sp) (i32.const 32)))
						  (br $loop))(call $useGas (i64.const 7)) (if (i32.gt_s (get_global $sp) (i32.const 32672)) 
					 (then (unreachable)))(call $PUSH (i64.const 0)(i64.const 0)(i64.const 0)(i64.const 0))(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $DUP (i32.const 0))
	(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $REVERT) (br $done)
	(set_global $sp (i32.add (get_global $sp) (i32.const -64)))
	)(call $useGas (i64.const 34)) (if (i32.gt_s (get_global $sp) (i32.const 32640)) 
					 (then (unreachable)))(call $PUSH (i64.const 0)(i64.const 0)(i64.const 0)(i64.const 0))(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $DUP (i32.const 1))
	(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $ISZERO)
	(call $ISZERO)
	(call $SWAP (i32.const 0))
	(set_global $sp (i32.add (get_global $sp) (i32.const -32)))
	(call $SWAP (i32.const 1))
	(call $SWAP (i32.const 0))
	(set_global $sp (i32.add (get_global $sp) (i32.const -32)))
	;; jump
						  (set_local $jump_dest (call $check_overflow 
												 (i64.load (get_global $sp))
												 (i64.load (i32.add (get_global $sp) (i32.const 8)))
												 (i64.load (i32.add (get_global $sp) (i32.const 16)))
												 (i64.load (i32.add (get_global $sp) (i32.const 24)))))
						  (set_global $sp (i32.sub (get_global $sp) (i32.const 32)))
						  (br $loop))(call $useGas (i64.const 18)) (if (i32.gt_s (get_global $sp) (i32.const 32640)) 
					 (then (unreachable)))(call $PUSH (i64.const 0)(i64.const 0)(i64.const 0)(i64.const 839))(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $DUP (i32.const 1))
	(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $PUSH (i64.const 0)(i64.const 0)(i64.const 0)(i64.const 818))(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	;; jump
						  (set_local $jump_dest (call $check_overflow 
												 (i64.load (get_global $sp))
												 (i64.load (i32.add (get_global $sp) (i32.const 8)))
												 (i64.load (i32.add (get_global $sp) (i32.const 16)))
												 (i64.load (i32.add (get_global $sp) (i32.const 24)))))
						  (set_global $sp (i32.sub (get_global $sp) (i32.const 32)))
						  (br $loop))(call $useGas (i64.const 20)) (if (i32.gt_s (get_global $sp) (i32.const 32672)) 
					 (then (unreachable)))(call $DUP (i32.const 1))
	(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $EQ)
	(set_global $sp (i32.add (get_global $sp) (i32.const -32)))
	(call $PUSH (i64.const 0)(i64.const 0)(i64.const 0)(i64.const 850))(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(set_local $jump_dest (call $check_overflow 
												 (i64.load (get_global $sp))
												 (i64.load (i32.add (get_global $sp) (i32.const 8)))
												 (i64.load (i32.add (get_global $sp) (i32.const 16)))
												 (i64.load (i32.add (get_global $sp) (i32.const 24)))))
	
						(set_global $sp (i32.sub (get_global $sp) (i32.const 64)))
						(br_if $loop (i32.eqz (i64.eqz (i64.or
						  (i64.load (i32.add (get_global $sp) (i32.const 32)))
						  (i64.or
							(i64.load (i32.add (get_global $sp) (i32.const 40)))
							(i64.or
							  (i64.load (i32.add (get_global $sp) (i32.const 48)))
							  (i64.load (i32.add (get_global $sp) (i32.const 56)))
							)
						  )
						))))
	(call $useGas (i64.const 6)) (if (i32.gt_s (get_global $sp) (i32.const 32672)) 
					 (then (unreachable)))(call $PUSH (i64.const 0)(i64.const 0)(i64.const 0)(i64.const 0))(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $DUP (i32.const 0))
	(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $REVERT) (br $done)
	(set_global $sp (i32.add (get_global $sp) (i32.const -64)))
	)(call $useGas (i64.const 11)) (if (i32.lt_s (get_global $sp) (i32.const 0)) 
					  (then (unreachable)))(set_global $sp (i32.add (get_global $sp) (i32.const -32)))
	;; jump
						  (set_local $jump_dest (call $check_overflow 
												 (i64.load (get_global $sp))
												 (i64.load (i32.add (get_global $sp) (i32.const 8)))
												 (i64.load (i32.add (get_global $sp) (i32.const 16)))
												 (i64.load (i32.add (get_global $sp) (i32.const 24)))))
						  (set_global $sp (i32.sub (get_global $sp) (i32.const 32)))
						  (br $loop))(call $useGas (i64.const 29)) (if (i32.gt_s (get_global $sp) (i32.const 32608)) 
					 (then (unreachable)))(call $PUSH (i64.const 0)(i64.const 0)(i64.const 0)(i64.const 0))(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $DUP (i32.const 1))
	(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $CALLDATALOAD)
	(call $SWAP (i32.const 0))
	(set_global $sp (i32.add (get_global $sp) (i32.const -32)))
	(call $PUSH (i64.const 0)(i64.const 0)(i64.const 0)(i64.const 868))(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $DUP (i32.const 1))
	(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $PUSH (i64.const 0)(i64.const 0)(i64.const 0)(i64.const 830))(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	;; jump
						  (set_local $jump_dest (call $check_overflow 
												 (i64.load (get_global $sp))
												 (i64.load (i32.add (get_global $sp) (i32.const 8)))
												 (i64.load (i32.add (get_global $sp) (i32.const 16)))
												 (i64.load (i32.add (get_global $sp) (i32.const 24)))))
						  (set_global $sp (i32.sub (get_global $sp) (i32.const 32)))
						  (br $loop))(call $useGas (i64.const 19)) (if (i32.lt_s (get_global $sp) (i32.const 32)) 
					  (then (unreachable)))(call $SWAP (i32.const 2))
	(call $SWAP (i32.const 1))
	(set_global $sp (i32.add (get_global $sp) (i32.const -32)))
	(set_global $sp (i32.add (get_global $sp) (i32.const -32)))
	;; jump
						  (set_local $jump_dest (call $check_overflow 
												 (i64.load (get_global $sp))
												 (i64.load (i32.add (get_global $sp) (i32.const 8)))
												 (i64.load (i32.add (get_global $sp) (i32.const 16)))
												 (i64.load (i32.add (get_global $sp) (i32.const 24)))))
						  (set_global $sp (i32.sub (get_global $sp) (i32.const 32)))
						  (br $loop))(call $useGas (i64.const 35)) (if (i32.gt_s (get_global $sp) (i32.const 32576)) 
					 (then (unreachable)))(call $PUSH (i64.const 0)(i64.const 0)(i64.const 0)(i64.const 0))(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $PUSH (i64.const 0)(i64.const 0)(i64.const 0)(i64.const 32))(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $DUP (i32.const 2))
	(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $DUP (i32.const 4))
	(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $SUB)
	(set_global $sp (i32.add (get_global $sp) (i32.const -32)))
	(call $SLT)
	(set_global $sp (i32.add (get_global $sp) (i32.const -32)))
	(call $ISZERO)
	(call $PUSH (i64.const 0)(i64.const 0)(i64.const 0)(i64.const 896))(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(set_local $jump_dest (call $check_overflow 
												 (i64.load (get_global $sp))
												 (i64.load (i32.add (get_global $sp) (i32.const 8)))
												 (i64.load (i32.add (get_global $sp) (i32.const 16)))
												 (i64.load (i32.add (get_global $sp) (i32.const 24)))))
	
						(set_global $sp (i32.sub (get_global $sp) (i32.const 64)))
						(br_if $loop (i32.eqz (i64.eqz (i64.or
						  (i64.load (i32.add (get_global $sp) (i32.const 32)))
						  (i64.or
							(i64.load (i32.add (get_global $sp) (i32.const 40)))
							(i64.or
							  (i64.load (i32.add (get_global $sp) (i32.const 48)))
							  (i64.load (i32.add (get_global $sp) (i32.const 56)))
							)
						  )
						))))
	(call $useGas (i64.const 14)) (if (i32.gt_s (get_global $sp) (i32.const 32672)) 
					 (then (unreachable)))(call $PUSH (i64.const 0)(i64.const 0)(i64.const 0)(i64.const 895))(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $PUSH (i64.const 0)(i64.const 0)(i64.const 0)(i64.const 813))(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	;; jump
						  (set_local $jump_dest (call $check_overflow 
												 (i64.load (get_global $sp))
												 (i64.load (i32.add (get_global $sp) (i32.const 8)))
												 (i64.load (i32.add (get_global $sp) (i32.const 16)))
												 (i64.load (i32.add (get_global $sp) (i32.const 24)))))
						  (set_global $sp (i32.sub (get_global $sp) (i32.const 32)))
						  (br $loop))(call $useGas (i64.const 1)) )(call $useGas (i64.const 30)) (if (i32.gt_s (get_global $sp) (i32.const 32544)) 
					 (then (unreachable)))(call $PUSH (i64.const 0)(i64.const 0)(i64.const 0)(i64.const 0))(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $PUSH (i64.const 0)(i64.const 0)(i64.const 0)(i64.const 910))(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $DUP (i32.const 4))
	(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $DUP (i32.const 2))
	(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $DUP (i32.const 5))
	(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $ADD)
	(set_global $sp (i32.add (get_global $sp) (i32.const -32)))
	(call $PUSH (i64.const 0)(i64.const 0)(i64.const 0)(i64.const 853))(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	;; jump
						  (set_local $jump_dest (call $check_overflow 
												 (i64.load (get_global $sp))
												 (i64.load (i32.add (get_global $sp) (i32.const 8)))
												 (i64.load (i32.add (get_global $sp) (i32.const 16)))
												 (i64.load (i32.add (get_global $sp) (i32.const 24)))))
						  (set_global $sp (i32.sub (get_global $sp) (i32.const 32)))
						  (br $loop))(call $useGas (i64.const 26)) (if (i32.lt_s (get_global $sp) (i32.const 96)) 
					  (then (unreachable)))(call $SWAP (i32.const 1))
	(set_global $sp (i32.add (get_global $sp) (i32.const -32)))
	(set_global $sp (i32.add (get_global $sp) (i32.const -32)))
	(call $SWAP (i32.const 2))
	(call $SWAP (i32.const 1))
	(set_global $sp (i32.add (get_global $sp) (i32.const -32)))
	(set_global $sp (i32.add (get_global $sp) (i32.const -32)))
	;; jump
						  (set_local $jump_dest (call $check_overflow 
												 (i64.load (get_global $sp))
												 (i64.load (i32.add (get_global $sp) (i32.const 8)))
												 (i64.load (i32.add (get_global $sp) (i32.const 16)))
												 (i64.load (i32.add (get_global $sp) (i32.const 24)))))
						  (set_global $sp (i32.sub (get_global $sp) (i32.const 32)))
						  (br $loop))(call $useGas (i64.const 18)) (if (i32.gt_s (get_global $sp) (i32.const 32640)) 
					 (then (unreachable)))(call $PUSH (i64.const 0)(i64.const 0)(i64.const 0)(i64.const 928))(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $DUP (i32.const 1))
	(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $PUSH (i64.const 0)(i64.const 0)(i64.const 0)(i64.const 761))(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	;; jump
						  (set_local $jump_dest (call $check_overflow 
												 (i64.load (get_global $sp))
												 (i64.load (i32.add (get_global $sp) (i32.const 8)))
												 (i64.load (i32.add (get_global $sp) (i32.const 16)))
												 (i64.load (i32.add (get_global $sp) (i32.const 24)))))
						  (set_global $sp (i32.sub (get_global $sp) (i32.const 32)))
						  (br $loop))(call $useGas (i64.const 20)) (if (i32.gt_s (get_global $sp) (i32.const 32672)) 
					 (then (unreachable)))(call $DUP (i32.const 1))
	(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $EQ)
	(set_global $sp (i32.add (get_global $sp) (i32.const -32)))
	(call $PUSH (i64.const 0)(i64.const 0)(i64.const 0)(i64.const 939))(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(set_local $jump_dest (call $check_overflow 
												 (i64.load (get_global $sp))
												 (i64.load (i32.add (get_global $sp) (i32.const 8)))
												 (i64.load (i32.add (get_global $sp) (i32.const 16)))
												 (i64.load (i32.add (get_global $sp) (i32.const 24)))))
	
						(set_global $sp (i32.sub (get_global $sp) (i32.const 64)))
						(br_if $loop (i32.eqz (i64.eqz (i64.or
						  (i64.load (i32.add (get_global $sp) (i32.const 32)))
						  (i64.or
							(i64.load (i32.add (get_global $sp) (i32.const 40)))
							(i64.or
							  (i64.load (i32.add (get_global $sp) (i32.const 48)))
							  (i64.load (i32.add (get_global $sp) (i32.const 56)))
							)
						  )
						))))
	(call $useGas (i64.const 6)) (if (i32.gt_s (get_global $sp) (i32.const 32672)) 
					 (then (unreachable)))(call $PUSH (i64.const 0)(i64.const 0)(i64.const 0)(i64.const 0))(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $DUP (i32.const 0))
	(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $REVERT) (br $done)
	(set_global $sp (i32.add (get_global $sp) (i32.const -64)))
	)(call $useGas (i64.const 11)) (if (i32.lt_s (get_global $sp) (i32.const 0)) 
					  (then (unreachable)))(set_global $sp (i32.add (get_global $sp) (i32.const -32)))
	;; jump
						  (set_local $jump_dest (call $check_overflow 
												 (i64.load (get_global $sp))
												 (i64.load (i32.add (get_global $sp) (i32.const 8)))
												 (i64.load (i32.add (get_global $sp) (i32.const 16)))
												 (i64.load (i32.add (get_global $sp) (i32.const 24)))))
						  (set_global $sp (i32.sub (get_global $sp) (i32.const 32)))
						  (br $loop))(call $useGas (i64.const 29)) (if (i32.gt_s (get_global $sp) (i32.const 32608)) 
					 (then (unreachable)))(call $PUSH (i64.const 0)(i64.const 0)(i64.const 0)(i64.const 0))(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $DUP (i32.const 1))
	(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $CALLDATALOAD)
	(call $SWAP (i32.const 0))
	(set_global $sp (i32.add (get_global $sp) (i32.const -32)))
	(call $PUSH (i64.const 0)(i64.const 0)(i64.const 0)(i64.const 957))(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $DUP (i32.const 1))
	(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $PUSH (i64.const 0)(i64.const 0)(i64.const 0)(i64.const 919))(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	;; jump
						  (set_local $jump_dest (call $check_overflow 
												 (i64.load (get_global $sp))
												 (i64.load (i32.add (get_global $sp) (i32.const 8)))
												 (i64.load (i32.add (get_global $sp) (i32.const 16)))
												 (i64.load (i32.add (get_global $sp) (i32.const 24)))))
						  (set_global $sp (i32.sub (get_global $sp) (i32.const 32)))
						  (br $loop))(call $useGas (i64.const 19)) (if (i32.lt_s (get_global $sp) (i32.const 32)) 
					  (then (unreachable)))(call $SWAP (i32.const 2))
	(call $SWAP (i32.const 1))
	(set_global $sp (i32.add (get_global $sp) (i32.const -32)))
	(set_global $sp (i32.add (get_global $sp) (i32.const -32)))
	;; jump
						  (set_local $jump_dest (call $check_overflow 
												 (i64.load (get_global $sp))
												 (i64.load (i32.add (get_global $sp) (i32.const 8)))
												 (i64.load (i32.add (get_global $sp) (i32.const 16)))
												 (i64.load (i32.add (get_global $sp) (i32.const 24)))))
						  (set_global $sp (i32.sub (get_global $sp) (i32.const 32)))
						  (br $loop))(call $useGas (i64.const 34)) (if (i32.gt_s (get_global $sp) (i32.const 32608)) 
					 (then (unreachable)))(call $PUSH (i64.const 0)(i64.const 0)(i64.const 0)(i64.const 0))(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $PUSH (i64.const 0)(i64.const 0)(i64.const 0)(i64.const 4294967295))(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $DUP (i32.const 2))
	(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $AND)
	(set_global $sp (i32.add (get_global $sp) (i32.const -32)))
	(call $SWAP (i32.const 0))
	(set_global $sp (i32.add (get_global $sp) (i32.const -32)))
	(call $SWAP (i32.const 1))
	(call $SWAP (i32.const 0))
	(set_global $sp (i32.add (get_global $sp) (i32.const -32)))
	;; jump
						  (set_local $jump_dest (call $check_overflow 
												 (i64.load (get_global $sp))
												 (i64.load (i32.add (get_global $sp) (i32.const 8)))
												 (i64.load (i32.add (get_global $sp) (i32.const 16)))
												 (i64.load (i32.add (get_global $sp) (i32.const 24)))))
						  (set_global $sp (i32.sub (get_global $sp) (i32.const 32)))
						  (br $loop))(call $useGas (i64.const 18)) (if (i32.gt_s (get_global $sp) (i32.const 32640)) 
					 (then (unreachable)))(call $PUSH (i64.const 0)(i64.const 0)(i64.const 0)(i64.const 988))(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $DUP (i32.const 1))
	(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $PUSH (i64.const 0)(i64.const 0)(i64.const 0)(i64.const 963))(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	;; jump
						  (set_local $jump_dest (call $check_overflow 
												 (i64.load (get_global $sp))
												 (i64.load (i32.add (get_global $sp) (i32.const 8)))
												 (i64.load (i32.add (get_global $sp) (i32.const 16)))
												 (i64.load (i32.add (get_global $sp) (i32.const 24)))))
						  (set_global $sp (i32.sub (get_global $sp) (i32.const 32)))
						  (br $loop))(call $useGas (i64.const 20)) (if (i32.gt_s (get_global $sp) (i32.const 32672)) 
					 (then (unreachable)))(call $DUP (i32.const 1))
	(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $EQ)
	(set_global $sp (i32.add (get_global $sp) (i32.const -32)))
	(call $PUSH (i64.const 0)(i64.const 0)(i64.const 0)(i64.const 999))(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(set_local $jump_dest (call $check_overflow 
												 (i64.load (get_global $sp))
												 (i64.load (i32.add (get_global $sp) (i32.const 8)))
												 (i64.load (i32.add (get_global $sp) (i32.const 16)))
												 (i64.load (i32.add (get_global $sp) (i32.const 24)))))
	
						(set_global $sp (i32.sub (get_global $sp) (i32.const 64)))
						(br_if $loop (i32.eqz (i64.eqz (i64.or
						  (i64.load (i32.add (get_global $sp) (i32.const 32)))
						  (i64.or
							(i64.load (i32.add (get_global $sp) (i32.const 40)))
							(i64.or
							  (i64.load (i32.add (get_global $sp) (i32.const 48)))
							  (i64.load (i32.add (get_global $sp) (i32.const 56)))
							)
						  )
						))))
	(call $useGas (i64.const 6)) (if (i32.gt_s (get_global $sp) (i32.const 32672)) 
					 (then (unreachable)))(call $PUSH (i64.const 0)(i64.const 0)(i64.const 0)(i64.const 0))(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $DUP (i32.const 0))
	(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $REVERT) (br $done)
	(set_global $sp (i32.add (get_global $sp) (i32.const -64)))
	)(call $useGas (i64.const 11)) (if (i32.lt_s (get_global $sp) (i32.const 0)) 
					  (then (unreachable)))(set_global $sp (i32.add (get_global $sp) (i32.const -32)))
	;; jump
						  (set_local $jump_dest (call $check_overflow 
												 (i64.load (get_global $sp))
												 (i64.load (i32.add (get_global $sp) (i32.const 8)))
												 (i64.load (i32.add (get_global $sp) (i32.const 16)))
												 (i64.load (i32.add (get_global $sp) (i32.const 24)))))
						  (set_global $sp (i32.sub (get_global $sp) (i32.const 32)))
						  (br $loop))(call $useGas (i64.const 29)) (if (i32.gt_s (get_global $sp) (i32.const 32608)) 
					 (then (unreachable)))(call $PUSH (i64.const 0)(i64.const 0)(i64.const 0)(i64.const 0))(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $DUP (i32.const 1))
	(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $CALLDATALOAD)
	(call $SWAP (i32.const 0))
	(set_global $sp (i32.add (get_global $sp) (i32.const -32)))
	(call $PUSH (i64.const 0)(i64.const 0)(i64.const 0)(i64.const 1017))(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $DUP (i32.const 1))
	(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $PUSH (i64.const 0)(i64.const 0)(i64.const 0)(i64.const 979))(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	;; jump
						  (set_local $jump_dest (call $check_overflow 
												 (i64.load (get_global $sp))
												 (i64.load (i32.add (get_global $sp) (i32.const 8)))
												 (i64.load (i32.add (get_global $sp) (i32.const 16)))
												 (i64.load (i32.add (get_global $sp) (i32.const 24)))))
						  (set_global $sp (i32.sub (get_global $sp) (i32.const 32)))
						  (br $loop))(call $useGas (i64.const 19)) (if (i32.lt_s (get_global $sp) (i32.const 32)) 
					  (then (unreachable)))(call $SWAP (i32.const 2))
	(call $SWAP (i32.const 1))
	(set_global $sp (i32.add (get_global $sp) (i32.const -32)))
	(set_global $sp (i32.add (get_global $sp) (i32.const -32)))
	;; jump
						  (set_local $jump_dest (call $check_overflow 
												 (i64.load (get_global $sp))
												 (i64.load (i32.add (get_global $sp) (i32.const 8)))
												 (i64.load (i32.add (get_global $sp) (i32.const 16)))
												 (i64.load (i32.add (get_global $sp) (i32.const 24)))))
						  (set_global $sp (i32.sub (get_global $sp) (i32.const 32)))
						  (br $loop))(call $useGas (i64.const 41)) (if (i32.gt_s (get_global $sp) (i32.const 32512)) 
					 (then (unreachable)))(call $PUSH (i64.const 0)(i64.const 0)(i64.const 0)(i64.const 0))(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $DUP (i32.const 0))
	(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $PUSH (i64.const 0)(i64.const 0)(i64.const 0)(i64.const 0))(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $PUSH (i64.const 0)(i64.const 0)(i64.const 0)(i64.const 96))(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $DUP (i32.const 4))
	(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $DUP (i32.const 6))
	(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $SUB)
	(set_global $sp (i32.add (get_global $sp) (i32.const -32)))
	(call $SLT)
	(set_global $sp (i32.add (get_global $sp) (i32.const -32)))
	(call $ISZERO)
	(call $PUSH (i64.const 0)(i64.const 0)(i64.const 0)(i64.const 1048))(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(set_local $jump_dest (call $check_overflow 
												 (i64.load (get_global $sp))
												 (i64.load (i32.add (get_global $sp) (i32.const 8)))
												 (i64.load (i32.add (get_global $sp) (i32.const 16)))
												 (i64.load (i32.add (get_global $sp) (i32.const 24)))))
	
						(set_global $sp (i32.sub (get_global $sp) (i32.const 64)))
						(br_if $loop (i32.eqz (i64.eqz (i64.or
						  (i64.load (i32.add (get_global $sp) (i32.const 32)))
						  (i64.or
							(i64.load (i32.add (get_global $sp) (i32.const 40)))
							(i64.or
							  (i64.load (i32.add (get_global $sp) (i32.const 48)))
							  (i64.load (i32.add (get_global $sp) (i32.const 56)))
							)
						  )
						))))
	(call $useGas (i64.const 14)) (if (i32.gt_s (get_global $sp) (i32.const 32672)) 
					 (then (unreachable)))(call $PUSH (i64.const 0)(i64.const 0)(i64.const 0)(i64.const 1047))(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $PUSH (i64.const 0)(i64.const 0)(i64.const 0)(i64.const 813))(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	;; jump
						  (set_local $jump_dest (call $check_overflow 
												 (i64.load (get_global $sp))
												 (i64.load (i32.add (get_global $sp) (i32.const 8)))
												 (i64.load (i32.add (get_global $sp) (i32.const 16)))
												 (i64.load (i32.add (get_global $sp) (i32.const 24)))))
						  (set_global $sp (i32.sub (get_global $sp) (i32.const 32)))
						  (br $loop))(call $useGas (i64.const 1)) )(call $useGas (i64.const 30)) (if (i32.gt_s (get_global $sp) (i32.const 32544)) 
					 (then (unreachable)))(call $PUSH (i64.const 0)(i64.const 0)(i64.const 0)(i64.const 0))(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $PUSH (i64.const 0)(i64.const 0)(i64.const 0)(i64.const 1062))(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $DUP (i32.const 6))
	(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $DUP (i32.const 2))
	(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $DUP (i32.const 7))
	(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $ADD)
	(set_global $sp (i32.add (get_global $sp) (i32.const -32)))
	(call $PUSH (i64.const 0)(i64.const 0)(i64.const 0)(i64.const 942))(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	;; jump
						  (set_local $jump_dest (call $check_overflow 
												 (i64.load (get_global $sp))
												 (i64.load (i32.add (get_global $sp) (i32.const 8)))
												 (i64.load (i32.add (get_global $sp) (i32.const 16)))
												 (i64.load (i32.add (get_global $sp) (i32.const 24)))))
						  (set_global $sp (i32.sub (get_global $sp) (i32.const 32)))
						  (br $loop))(call $useGas (i64.const 37)) (if (i32.gt_s (get_global $sp) (i32.const 32608)) 
					 (then (unreachable)))(if (i32.lt_s (get_global $sp) (i32.const 32)) 
					  (then (unreachable)))(call $SWAP (i32.const 3))
	(set_global $sp (i32.add (get_global $sp) (i32.const -32)))
	(set_global $sp (i32.add (get_global $sp) (i32.const -32)))
	(call $PUSH (i64.const 0)(i64.const 0)(i64.const 0)(i64.const 32))(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $PUSH (i64.const 0)(i64.const 0)(i64.const 0)(i64.const 1079))(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $DUP (i32.const 6))
	(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $DUP (i32.const 2))
	(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $DUP (i32.const 7))
	(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $ADD)
	(set_global $sp (i32.add (get_global $sp) (i32.const -32)))
	(call $PUSH (i64.const 0)(i64.const 0)(i64.const 0)(i64.const 942))(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	;; jump
						  (set_local $jump_dest (call $check_overflow 
												 (i64.load (get_global $sp))
												 (i64.load (i32.add (get_global $sp) (i32.const 8)))
												 (i64.load (i32.add (get_global $sp) (i32.const 16)))
												 (i64.load (i32.add (get_global $sp) (i32.const 24)))))
						  (set_global $sp (i32.sub (get_global $sp) (i32.const 32)))
						  (br $loop))(call $useGas (i64.const 37)) (if (i32.gt_s (get_global $sp) (i32.const 32608)) 
					 (then (unreachable)))(if (i32.lt_s (get_global $sp) (i32.const 32)) 
					  (then (unreachable)))(call $SWAP (i32.const 2))
	(set_global $sp (i32.add (get_global $sp) (i32.const -32)))
	(set_global $sp (i32.add (get_global $sp) (i32.const -32)))
	(call $PUSH (i64.const 0)(i64.const 0)(i64.const 0)(i64.const 64))(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $PUSH (i64.const 0)(i64.const 0)(i64.const 0)(i64.const 1096))(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $DUP (i32.const 6))
	(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $DUP (i32.const 2))
	(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $DUP (i32.const 7))
	(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $ADD)
	(set_global $sp (i32.add (get_global $sp) (i32.const -32)))
	(call $PUSH (i64.const 0)(i64.const 0)(i64.const 0)(i64.const 1002))(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	;; jump
						  (set_local $jump_dest (call $check_overflow 
												 (i64.load (get_global $sp))
												 (i64.load (i32.add (get_global $sp) (i32.const 8)))
												 (i64.load (i32.add (get_global $sp) (i32.const 16)))
												 (i64.load (i32.add (get_global $sp) (i32.const 24)))))
						  (set_global $sp (i32.sub (get_global $sp) (i32.const 32)))
						  (br $loop))(call $useGas (i64.const 29)) (if (i32.lt_s (get_global $sp) (i32.const 96)) 
					  (then (unreachable)))(call $SWAP (i32.const 1))
	(set_global $sp (i32.add (get_global $sp) (i32.const -32)))
	(set_global $sp (i32.add (get_global $sp) (i32.const -32)))
	(call $SWAP (i32.const 2))
	(set_global $sp (i32.add (get_global $sp) (i32.const -32)))
	(call $SWAP (i32.const 2))
	(set_global $sp (i32.add (get_global $sp) (i32.const -32)))
	(call $SWAP (i32.const 2))
	;; jump
						  (set_local $jump_dest (call $check_overflow 
												 (i64.load (get_global $sp))
												 (i64.load (i32.add (get_global $sp) (i32.const 8)))
												 (i64.load (i32.add (get_global $sp) (i32.const 16)))
												 (i64.load (i32.add (get_global $sp) (i32.const 24)))))
						  (set_global $sp (i32.sub (get_global $sp) (i32.const 32)))
						  (br $loop))(call $useGas (i64.const 31)) (if (i32.gt_s (get_global $sp) (i32.const 32640)) 
					 (then (unreachable)))(call $PUSH (i64.const 0)(i64.const 0)(i64.const 0)(i64.const 0))(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $DUP (i32.const 1))
	(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $MLOAD)
	(call $SWAP (i32.const 0))
	(set_global $sp (i32.add (get_global $sp) (i32.const -32)))
	(call $SWAP (i32.const 1))
	(call $SWAP (i32.const 0))
	(set_global $sp (i32.add (get_global $sp) (i32.const -32)))
	;; jump
						  (set_local $jump_dest (call $check_overflow 
												 (i64.load (get_global $sp))
												 (i64.load (i32.add (get_global $sp) (i32.const 8)))
												 (i64.load (i32.add (get_global $sp) (i32.const 16)))
												 (i64.load (i32.add (get_global $sp) (i32.const 24)))))
						  (set_global $sp (i32.sub (get_global $sp) (i32.const 32)))
						  (br $loop))(call $useGas (i64.const 45)) (if (i32.gt_s (get_global $sp) (i32.const 32608)) 
					 (then (unreachable)))(if (i32.lt_s (get_global $sp) (i32.const 0)) 
					  (then (unreachable)))(call $PUSH (i64.const 0)(i64.const 0)(i64.const 0)(i64.const 0))(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $DUP (i32.const 2))
	(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $DUP (i32.const 2))
	(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $MSTORE)
	(set_global $sp (i32.add (get_global $sp) (i32.const -64)))
	(call $PUSH (i64.const 0)(i64.const 0)(i64.const 0)(i64.const 32))(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $DUP (i32.const 2))
	(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $ADD)
	(set_global $sp (i32.add (get_global $sp) (i32.const -32)))
	(call $SWAP (i32.const 0))
	(set_global $sp (i32.add (get_global $sp) (i32.const -32)))
	(call $SWAP (i32.const 2))
	(call $SWAP (i32.const 1))
	(set_global $sp (i32.add (get_global $sp) (i32.const -32)))
	(set_global $sp (i32.add (get_global $sp) (i32.const -32)))
	;; jump
						  (set_local $jump_dest (call $check_overflow 
												 (i64.load (get_global $sp))
												 (i64.load (i32.add (get_global $sp) (i32.const 8)))
												 (i64.load (i32.add (get_global $sp) (i32.const 16)))
												 (i64.load (i32.add (get_global $sp) (i32.const 24)))))
						  (set_global $sp (i32.sub (get_global $sp) (i32.const 32)))
						  (br $loop))(call $useGas (i64.const 4)) (if (i32.gt_s (get_global $sp) (i32.const 32704)) 
					 (then (unreachable)))(call $PUSH (i64.const 0)(i64.const 0)(i64.const 0)(i64.const 0))(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	)(call $useGas (i64.const 26)) (if (i32.gt_s (get_global $sp) (i32.const 32640)) 
					 (then (unreachable)))(call $DUP (i32.const 3))
	(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $DUP (i32.const 1))
	(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $LT)
	(set_global $sp (i32.add (get_global $sp) (i32.const -32)))
	(call $ISZERO)
	(call $PUSH (i64.const 0)(i64.const 0)(i64.const 0)(i64.const 1164))(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(set_local $jump_dest (call $check_overflow 
												 (i64.load (get_global $sp))
												 (i64.load (i32.add (get_global $sp) (i32.const 8)))
												 (i64.load (i32.add (get_global $sp) (i32.const 16)))
												 (i64.load (i32.add (get_global $sp) (i32.const 24)))))
	
						(set_global $sp (i32.sub (get_global $sp) (i32.const 64)))
						(br_if $loop (i32.eqz (i64.eqz (i64.or
						  (i64.load (i32.add (get_global $sp) (i32.const 32)))
						  (i64.or
							(i64.load (i32.add (get_global $sp) (i32.const 40)))
							(i64.or
							  (i64.load (i32.add (get_global $sp) (i32.const 48)))
							  (i64.load (i32.add (get_global $sp) (i32.const 56)))
							)
						  )
						))))
	(call $useGas (i64.const 49)) (if (i32.gt_s (get_global $sp) (i32.const 32608)) 
					 (then (unreachable)))(call $DUP (i32.const 0))
	(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $DUP (i32.const 2))
	(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $ADD)
	(set_global $sp (i32.add (get_global $sp) (i32.const -32)))
	(call $MLOAD)
	(call $DUP (i32.const 1))
	(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $DUP (i32.const 4))
	(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $ADD)
	(set_global $sp (i32.add (get_global $sp) (i32.const -32)))
	(call $MSTORE)
	(set_global $sp (i32.add (get_global $sp) (i32.const -64)))
	(call $PUSH (i64.const 0)(i64.const 0)(i64.const 0)(i64.const 32))(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $DUP (i32.const 1))
	(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $ADD)
	(set_global $sp (i32.add (get_global $sp) (i32.const -32)))
	(call $SWAP (i32.const 0))
	(set_global $sp (i32.add (get_global $sp) (i32.const -32)))
	(call $PUSH (i64.const 0)(i64.const 0)(i64.const 0)(i64.const 1137))(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	;; jump
						  (set_local $jump_dest (call $check_overflow 
												 (i64.load (get_global $sp))
												 (i64.load (i32.add (get_global $sp) (i32.const 8)))
												 (i64.load (i32.add (get_global $sp) (i32.const 16)))
												 (i64.load (i32.add (get_global $sp) (i32.const 24)))))
						  (set_global $sp (i32.sub (get_global $sp) (i32.const 32)))
						  (br $loop))(call $useGas (i64.const 32)) (if (i32.gt_s (get_global $sp) (i32.const 32608)) 
					 (then (unreachable)))(if (i32.lt_s (get_global $sp) (i32.const 96)) 
					  (then (unreachable)))(call $PUSH (i64.const 0)(i64.const 0)(i64.const 0)(i64.const 0))(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $DUP (i32.const 4))
	(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $DUP (i32.const 4))
	(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $ADD)
	(set_global $sp (i32.add (get_global $sp) (i32.const -32)))
	(call $MSTORE)
	(set_global $sp (i32.add (get_global $sp) (i32.const -64)))
	(set_global $sp (i32.add (get_global $sp) (i32.const -32)))
	(set_global $sp (i32.add (get_global $sp) (i32.const -32)))
	(set_global $sp (i32.add (get_global $sp) (i32.const -32)))
	(set_global $sp (i32.add (get_global $sp) (i32.const -32)))
	;; jump
						  (set_local $jump_dest (call $check_overflow 
												 (i64.load (get_global $sp))
												 (i64.load (i32.add (get_global $sp) (i32.const 8)))
												 (i64.load (i32.add (get_global $sp) (i32.const 16)))
												 (i64.load (i32.add (get_global $sp) (i32.const 24)))))
						  (set_global $sp (i32.sub (get_global $sp) (i32.const 32)))
						  (br $loop))(call $useGas (i64.const 43)) (if (i32.gt_s (get_global $sp) (i32.const 32576)) 
					 (then (unreachable)))(call $PUSH (i64.const 0)(i64.const 0)(i64.const 0)(i64.const 0))(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $PUSH (i64.const 0)(i64.const 0)(i64.const 0)(i64.const 31))(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $NOT)
	(call $PUSH (i64.const 0)(i64.const 0)(i64.const 0)(i64.const 31))(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $DUP (i32.const 3))
	(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $ADD)
	(set_global $sp (i32.add (get_global $sp) (i32.const -32)))
	(call $AND)
	(set_global $sp (i32.add (get_global $sp) (i32.const -32)))
	(call $SWAP (i32.const 0))
	(set_global $sp (i32.add (get_global $sp) (i32.const -32)))
	(call $SWAP (i32.const 1))
	(call $SWAP (i32.const 0))
	(set_global $sp (i32.add (get_global $sp) (i32.const -32)))
	;; jump
						  (set_local $jump_dest (call $check_overflow 
												 (i64.load (get_global $sp))
												 (i64.load (i32.add (get_global $sp) (i32.const 8)))
												 (i64.load (i32.add (get_global $sp) (i32.const 16)))
												 (i64.load (i32.add (get_global $sp) (i32.const 24)))))
						  (set_global $sp (i32.sub (get_global $sp) (i32.const 32)))
						  (br $loop))(call $useGas (i64.const 21)) (if (i32.gt_s (get_global $sp) (i32.const 32608)) 
					 (then (unreachable)))(call $PUSH (i64.const 0)(i64.const 0)(i64.const 0)(i64.const 0))(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $PUSH (i64.const 0)(i64.const 0)(i64.const 0)(i64.const 1204))(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $DUP (i32.const 2))
	(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $PUSH (i64.const 0)(i64.const 0)(i64.const 0)(i64.const 1106))(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	;; jump
						  (set_local $jump_dest (call $check_overflow 
												 (i64.load (get_global $sp))
												 (i64.load (i32.add (get_global $sp) (i32.const 8)))
												 (i64.load (i32.add (get_global $sp) (i32.const 16)))
												 (i64.load (i32.add (get_global $sp) (i32.const 24)))))
						  (set_global $sp (i32.sub (get_global $sp) (i32.const 32)))
						  (br $loop))(call $useGas (i64.const 21)) (if (i32.gt_s (get_global $sp) (i32.const 32608)) 
					 (then (unreachable)))(call $PUSH (i64.const 0)(i64.const 0)(i64.const 0)(i64.const 1214))(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $DUP (i32.const 1))
	(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $DUP (i32.const 5))
	(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $PUSH (i64.const 0)(i64.const 0)(i64.const 0)(i64.const 1117))(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	;; jump
						  (set_local $jump_dest (call $check_overflow 
												 (i64.load (get_global $sp))
												 (i64.load (i32.add (get_global $sp) (i32.const 8)))
												 (i64.load (i32.add (get_global $sp) (i32.const 16)))
												 (i64.load (i32.add (get_global $sp) (i32.const 24)))))
						  (set_global $sp (i32.sub (get_global $sp) (i32.const 32)))
						  (br $loop))(call $useGas (i64.const 35)) (if (i32.gt_s (get_global $sp) (i32.const 32576)) 
					 (then (unreachable)))(if (i32.lt_s (get_global $sp) (i32.const 0)) 
					  (then (unreachable)))(call $SWAP (i32.const 3))
	(set_global $sp (i32.add (get_global $sp) (i32.const -32)))
	(call $PUSH (i64.const 0)(i64.const 0)(i64.const 0)(i64.const 1230))(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $DUP (i32.const 1))
	(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $DUP (i32.const 5))
	(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $PUSH (i64.const 0)(i64.const 0)(i64.const 0)(i64.const 32))(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $DUP (i32.const 6))
	(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $ADD)
	(set_global $sp (i32.add (get_global $sp) (i32.const -32)))
	(call $PUSH (i64.const 0)(i64.const 0)(i64.const 0)(i64.const 1134))(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	;; jump
						  (set_local $jump_dest (call $check_overflow 
												 (i64.load (get_global $sp))
												 (i64.load (i32.add (get_global $sp) (i32.const 8)))
												 (i64.load (i32.add (get_global $sp) (i32.const 16)))
												 (i64.load (i32.add (get_global $sp) (i32.const 24)))))
						  (set_global $sp (i32.sub (get_global $sp) (i32.const 32)))
						  (br $loop))(call $useGas (i64.const 18)) (if (i32.gt_s (get_global $sp) (i32.const 32640)) 
					 (then (unreachable)))(call $PUSH (i64.const 0)(i64.const 0)(i64.const 0)(i64.const 1239))(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $DUP (i32.const 1))
	(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $PUSH (i64.const 0)(i64.const 0)(i64.const 0)(i64.const 1176))(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	;; jump
						  (set_local $jump_dest (call $check_overflow 
												 (i64.load (get_global $sp))
												 (i64.load (i32.add (get_global $sp) (i32.const 8)))
												 (i64.load (i32.add (get_global $sp) (i32.const 16)))
												 (i64.load (i32.add (get_global $sp) (i32.const 24)))))
						  (set_global $sp (i32.sub (get_global $sp) (i32.const 32)))
						  (br $loop))(call $useGas (i64.const 32)) (if (i32.gt_s (get_global $sp) (i32.const 32672)) 
					 (then (unreachable)))(if (i32.lt_s (get_global $sp) (i32.const 96)) 
					  (then (unreachable)))(call $DUP (i32.const 4))
	(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $ADD)
	(set_global $sp (i32.add (get_global $sp) (i32.const -32)))
	(call $SWAP (i32.const 1))
	(set_global $sp (i32.add (get_global $sp) (i32.const -32)))
	(set_global $sp (i32.add (get_global $sp) (i32.const -32)))
	(call $SWAP (i32.const 2))
	(call $SWAP (i32.const 1))
	(set_global $sp (i32.add (get_global $sp) (i32.const -32)))
	(set_global $sp (i32.add (get_global $sp) (i32.const -32)))
	;; jump
						  (set_local $jump_dest (call $check_overflow 
												 (i64.load (get_global $sp))
												 (i64.load (i32.add (get_global $sp) (i32.const 8)))
												 (i64.load (i32.add (get_global $sp) (i32.const 16)))
												 (i64.load (i32.add (get_global $sp) (i32.const 24)))))
						  (set_global $sp (i32.sub (get_global $sp) (i32.const 32)))
						  (br $loop))(call $useGas (i64.const 59)) (if (i32.gt_s (get_global $sp) (i32.const 32576)) 
					 (then (unreachable)))(call $PUSH (i64.const 0)(i64.const 0)(i64.const 0)(i64.const 0))(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $PUSH (i64.const 0)(i64.const 0)(i64.const 0)(i64.const 32))(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $DUP (i32.const 2))
	(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $ADD)
	(set_global $sp (i32.add (get_global $sp) (i32.const -32)))
	(call $SWAP (i32.const 0))
	(set_global $sp (i32.add (get_global $sp) (i32.const -32)))
	(call $DUP (i32.const 1))
	(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $DUP (i32.const 1))
	(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $SUB)
	(set_global $sp (i32.add (get_global $sp) (i32.const -32)))
	(call $PUSH (i64.const 0)(i64.const 0)(i64.const 0)(i64.const 0))(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $DUP (i32.const 3))
	(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $ADD)
	(set_global $sp (i32.add (get_global $sp) (i32.const -32)))
	(call $MSTORE)
	(set_global $sp (i32.add (get_global $sp) (i32.const -64)))
	(call $PUSH (i64.const 0)(i64.const 0)(i64.const 0)(i64.const 1276))(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $DUP (i32.const 1))
	(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $DUP (i32.const 4))
	(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $PUSH (i64.const 0)(i64.const 0)(i64.const 0)(i64.const 1193))(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	;; jump
						  (set_local $jump_dest (call $check_overflow 
												 (i64.load (get_global $sp))
												 (i64.load (i32.add (get_global $sp) (i32.const 8)))
												 (i64.load (i32.add (get_global $sp) (i32.const 16)))
												 (i64.load (i32.add (get_global $sp) (i32.const 24)))))
						  (set_global $sp (i32.sub (get_global $sp) (i32.const 32)))
						  (br $loop))(call $useGas (i64.const 24)) (if (i32.lt_s (get_global $sp) (i32.const 64)) 
					  (then (unreachable)))(call $SWAP (i32.const 0))
	(set_global $sp (i32.add (get_global $sp) (i32.const -32)))
	(call $SWAP (i32.const 2))
	(call $SWAP (i32.const 1))
	(set_global $sp (i32.add (get_global $sp) (i32.const -32)))
	(set_global $sp (i32.add (get_global $sp) (i32.const -32)))
	;; jump
						  (set_local $jump_dest (call $check_overflow 
												 (i64.load (get_global $sp))
												 (i64.load (i32.add (get_global $sp) (i32.const 8)))
												 (i64.load (i32.add (get_global $sp) (i32.const 16)))
												 (i64.load (i32.add (get_global $sp) (i32.const 24)))))
						  (set_global $sp (i32.sub (get_global $sp) (i32.const 32)))
						  (br $loop))(call $useGas (i64.const 26)) (if (i32.gt_s (get_global $sp) (i32.const 32608)) 
					 (then (unreachable)))(if (i32.lt_s (get_global $sp) (i32.const 0)) 
					  (then (unreachable)))(call $PUSH (i64.const 4859223913535730803)(i64.const 3179674856536957800)(i64.const 8030873750313333362)(i64.const 7305811029763424256))(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $PUSH (i64.const 0)(i64.const 0)(i64.const 0)(i64.const 0))(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $DUP (i32.const 2))
	(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $ADD)
	(set_global $sp (i32.add (get_global $sp) (i32.const -32)))
	(call $MSTORE)
	(set_global $sp (i32.add (get_global $sp) (i32.const -64)))
	(set_global $sp (i32.add (get_global $sp) (i32.const -32)))
	;; jump
						  (set_local $jump_dest (call $check_overflow 
												 (i64.load (get_global $sp))
												 (i64.load (i32.add (get_global $sp) (i32.const 8)))
												 (i64.load (i32.add (get_global $sp) (i32.const 16)))
												 (i64.load (i32.add (get_global $sp) (i32.const 24)))))
						  (set_global $sp (i32.sub (get_global $sp) (i32.const 32)))
						  (br $loop))(call $useGas (i64.const 24)) (if (i32.gt_s (get_global $sp) (i32.const 32576)) 
					 (then (unreachable)))(call $PUSH (i64.const 0)(i64.const 0)(i64.const 0)(i64.const 0))(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $PUSH (i64.const 0)(i64.const 0)(i64.const 0)(i64.const 1338))(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $PUSH (i64.const 0)(i64.const 0)(i64.const 0)(i64.const 30))(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $DUP (i32.const 3))
	(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $PUSH (i64.const 0)(i64.const 0)(i64.const 0)(i64.const 1117))(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	;; jump
						  (set_local $jump_dest (call $check_overflow 
												 (i64.load (get_global $sp))
												 (i64.load (i32.add (get_global $sp) (i32.const 8)))
												 (i64.load (i32.add (get_global $sp) (i32.const 16)))
												 (i64.load (i32.add (get_global $sp) (i32.const 24)))))
						  (set_global $sp (i32.sub (get_global $sp) (i32.const 32)))
						  (br $loop))(call $useGas (i64.const 23)) (if (i32.gt_s (get_global $sp) (i32.const 32672)) 
					 (then (unreachable)))(if (i32.lt_s (get_global $sp) (i32.const 0)) 
					  (then (unreachable)))(call $SWAP (i32.const 1))
	(set_global $sp (i32.add (get_global $sp) (i32.const -32)))
	(call $PUSH (i64.const 0)(i64.const 0)(i64.const 0)(i64.const 1349))(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $DUP (i32.const 2))
	(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $PUSH (i64.const 0)(i64.const 0)(i64.const 0)(i64.const 1284))(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	;; jump
						  (set_local $jump_dest (call $check_overflow 
												 (i64.load (get_global $sp))
												 (i64.load (i32.add (get_global $sp) (i32.const 8)))
												 (i64.load (i32.add (get_global $sp) (i32.const 16)))
												 (i64.load (i32.add (get_global $sp) (i32.const 24)))))
						  (set_global $sp (i32.sub (get_global $sp) (i32.const 32)))
						  (br $loop))(call $useGas (i64.const 31)) (if (i32.gt_s (get_global $sp) (i32.const 32640)) 
					 (then (unreachable)))(if (i32.lt_s (get_global $sp) (i32.const 0)) 
					  (then (unreachable)))(call $PUSH (i64.const 0)(i64.const 0)(i64.const 0)(i64.const 32))(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $DUP (i32.const 2))
	(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $ADD)
	(set_global $sp (i32.add (get_global $sp) (i32.const -32)))
	(call $SWAP (i32.const 0))
	(set_global $sp (i32.add (get_global $sp) (i32.const -32)))
	(call $SWAP (i32.const 1))
	(call $SWAP (i32.const 0))
	(set_global $sp (i32.add (get_global $sp) (i32.const -32)))
	;; jump
						  (set_local $jump_dest (call $check_overflow 
												 (i64.load (get_global $sp))
												 (i64.load (i32.add (get_global $sp) (i32.const 8)))
												 (i64.load (i32.add (get_global $sp) (i32.const 16)))
												 (i64.load (i32.add (get_global $sp) (i32.const 24)))))
						  (set_global $sp (i32.sub (get_global $sp) (i32.const 32)))
						  (br $loop))(call $useGas (i64.const 18)) (if (i32.gt_s (get_global $sp) (i32.const 32640)) 
					 (then (unreachable)))(call $PUSH (i64.const 0)(i64.const 0)(i64.const 0)(i64.const 1369))(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $DUP (i32.const 1))
	(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $PUSH (i64.const 0)(i64.const 0)(i64.const 0)(i64.const 818))(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	;; jump
						  (set_local $jump_dest (call $check_overflow 
												 (i64.load (get_global $sp))
												 (i64.load (i32.add (get_global $sp) (i32.const 8)))
												 (i64.load (i32.add (get_global $sp) (i32.const 16)))
												 (i64.load (i32.add (get_global $sp) (i32.const 24)))))
						  (set_global $sp (i32.sub (get_global $sp) (i32.const 32)))
						  (br $loop))(call $useGas (i64.const 19)) (if (i32.gt_s (get_global $sp) (i32.const 32704)) 
					 (then (unreachable)))(if (i32.lt_s (get_global $sp) (i32.const 64)) 
					  (then (unreachable)))(call $DUP (i32.const 2))
	(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $MSTORE)
	(set_global $sp (i32.add (get_global $sp) (i32.const -64)))
	(set_global $sp (i32.add (get_global $sp) (i32.const -32)))
	(set_global $sp (i32.add (get_global $sp) (i32.const -32)))
	;; jump
						  (set_local $jump_dest (call $check_overflow 
												 (i64.load (get_global $sp))
												 (i64.load (i32.add (get_global $sp) (i32.const 8)))
												 (i64.load (i32.add (get_global $sp) (i32.const 16)))
												 (i64.load (i32.add (get_global $sp) (i32.const 24)))))
						  (set_global $sp (i32.sub (get_global $sp) (i32.const 32)))
						  (br $loop))(call $useGas (i64.const 56)) (if (i32.gt_s (get_global $sp) (i32.const 32576)) 
					 (then (unreachable)))(call $PUSH (i64.const 0)(i64.const 0)(i64.const 0)(i64.const 0))(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $PUSH (i64.const 0)(i64.const 0)(i64.const 0)(i64.const 160))(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $DUP (i32.const 2))
	(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $ADD)
	(set_global $sp (i32.add (get_global $sp) (i32.const -32)))
	(call $SWAP (i32.const 0))
	(set_global $sp (i32.add (get_global $sp) (i32.const -32)))
	(call $DUP (i32.const 1))
	(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $DUP (i32.const 1))
	(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $SUB)
	(set_global $sp (i32.add (get_global $sp) (i32.const -32)))
	(call $PUSH (i64.const 0)(i64.const 0)(i64.const 0)(i64.const 0))(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $DUP (i32.const 3))
	(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $ADD)
	(set_global $sp (i32.add (get_global $sp) (i32.const -32)))
	(call $MSTORE)
	(set_global $sp (i32.add (get_global $sp) (i32.const -64)))
	(call $PUSH (i64.const 0)(i64.const 0)(i64.const 0)(i64.const 1400))(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $DUP (i32.const 1))
	(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $PUSH (i64.const 0)(i64.const 0)(i64.const 0)(i64.const 1325))(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	;; jump
						  (set_local $jump_dest (call $check_overflow 
												 (i64.load (get_global $sp))
												 (i64.load (i32.add (get_global $sp) (i32.const 8)))
												 (i64.load (i32.add (get_global $sp) (i32.const 16)))
												 (i64.load (i32.add (get_global $sp) (i32.const 24)))))
						  (set_global $sp (i32.sub (get_global $sp) (i32.const 32)))
						  (br $loop))(call $useGas (i64.const 32)) (if (i32.gt_s (get_global $sp) (i32.const 32640)) 
					 (then (unreachable)))(if (i32.lt_s (get_global $sp) (i32.const 0)) 
					  (then (unreachable)))(call $SWAP (i32.const 0))
	(set_global $sp (i32.add (get_global $sp) (i32.const -32)))
	(call $PUSH (i64.const 0)(i64.const 0)(i64.const 0)(i64.const 1415))(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $PUSH (i64.const 0)(i64.const 0)(i64.const 0)(i64.const 32))(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $DUP (i32.const 3))
	(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $ADD)
	(set_global $sp (i32.add (get_global $sp) (i32.const -32)))
	(call $DUP (i32.const 7))
	(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $PUSH (i64.const 0)(i64.const 0)(i64.const 0)(i64.const 771))(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	;; jump
						  (set_local $jump_dest (call $check_overflow 
												 (i64.load (get_global $sp))
												 (i64.load (i32.add (get_global $sp) (i32.const 8)))
												 (i64.load (i32.add (get_global $sp) (i32.const 16)))
												 (i64.load (i32.add (get_global $sp) (i32.const 24)))))
						  (set_global $sp (i32.sub (get_global $sp) (i32.const 32)))
						  (br $loop))(call $useGas (i64.const 27)) (if (i32.gt_s (get_global $sp) (i32.const 32608)) 
					 (then (unreachable)))(call $PUSH (i64.const 0)(i64.const 0)(i64.const 0)(i64.const 1428))(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $PUSH (i64.const 0)(i64.const 0)(i64.const 0)(i64.const 64))(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $DUP (i32.const 3))
	(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $ADD)
	(set_global $sp (i32.add (get_global $sp) (i32.const -32)))
	(call $DUP (i32.const 6))
	(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $PUSH (i64.const 0)(i64.const 0)(i64.const 0)(i64.const 1360))(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	;; jump
						  (set_local $jump_dest (call $check_overflow 
												 (i64.load (get_global $sp))
												 (i64.load (i32.add (get_global $sp) (i32.const 8)))
												 (i64.load (i32.add (get_global $sp) (i32.const 16)))
												 (i64.load (i32.add (get_global $sp) (i32.const 24)))))
						  (set_global $sp (i32.sub (get_global $sp) (i32.const 32)))
						  (br $loop))(call $useGas (i64.const 27)) (if (i32.gt_s (get_global $sp) (i32.const 32608)) 
					 (then (unreachable)))(call $PUSH (i64.const 0)(i64.const 0)(i64.const 0)(i64.const 1441))(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $PUSH (i64.const 0)(i64.const 0)(i64.const 0)(i64.const 96))(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $DUP (i32.const 3))
	(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $ADD)
	(set_global $sp (i32.add (get_global $sp) (i32.const -32)))
	(call $DUP (i32.const 5))
	(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $PUSH (i64.const 0)(i64.const 0)(i64.const 0)(i64.const 1360))(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	;; jump
						  (set_local $jump_dest (call $check_overflow 
												 (i64.load (get_global $sp))
												 (i64.load (i32.add (get_global $sp) (i32.const 8)))
												 (i64.load (i32.add (get_global $sp) (i32.const 16)))
												 (i64.load (i32.add (get_global $sp) (i32.const 24)))))
						  (set_global $sp (i32.sub (get_global $sp) (i32.const 32)))
						  (br $loop))(call $useGas (i64.const 27)) (if (i32.gt_s (get_global $sp) (i32.const 32608)) 
					 (then (unreachable)))(call $PUSH (i64.const 0)(i64.const 0)(i64.const 0)(i64.const 1454))(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $PUSH (i64.const 0)(i64.const 0)(i64.const 0)(i64.const 128))(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $DUP (i32.const 3))
	(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $ADD)
	(set_global $sp (i32.add (get_global $sp) (i32.const -32)))
	(call $DUP (i32.const 4))
	(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $PUSH (i64.const 0)(i64.const 0)(i64.const 0)(i64.const 1360))(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	;; jump
						  (set_local $jump_dest (call $check_overflow 
												 (i64.load (get_global $sp))
												 (i64.load (i32.add (get_global $sp) (i32.const 8)))
												 (i64.load (i32.add (get_global $sp) (i32.const 16)))
												 (i64.load (i32.add (get_global $sp) (i32.const 24)))))
						  (set_global $sp (i32.sub (get_global $sp) (i32.const 32)))
						  (br $loop))(call $useGas (i64.const 25)) (if (i32.lt_s (get_global $sp) (i32.const 128)) 
					  (then (unreachable)))(call $SWAP (i32.const 5))
	(call $SWAP (i32.const 4))
	(set_global $sp (i32.add (get_global $sp) (i32.const -32)))
	(set_global $sp (i32.add (get_global $sp) (i32.const -32)))
	(set_global $sp (i32.add (get_global $sp) (i32.const -32)))
	(set_global $sp (i32.add (get_global $sp) (i32.const -32)))
	(set_global $sp (i32.add (get_global $sp) (i32.const -32)))
	;; jump
						  (set_local $jump_dest (call $check_overflow 
												 (i64.load (get_global $sp))
												 (i64.load (i32.add (get_global $sp) (i32.const 8)))
												 (i64.load (i32.add (get_global $sp) (i32.const 16)))
												 (i64.load (i32.add (get_global $sp) (i32.const 24)))))
						  (set_global $sp (i32.sub (get_global $sp) (i32.const 32)))
						  (br $loop))(call $useGas (i64.const 25)) (if (i32.gt_s (get_global $sp) (i32.const 32672)) 
					 (then (unreachable)))(call $PUSH (i64.const 5640894258543067136)(i64.const 0)(i64.const 0)(i64.const 0))(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $PUSH (i64.const 0)(i64.const 0)(i64.const 0)(i64.const 0))(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $MSTORE)
	(set_global $sp (i32.add (get_global $sp) (i32.const -64)))
	(call $PUSH (i64.const 0)(i64.const 0)(i64.const 0)(i64.const 34))(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $PUSH (i64.const 0)(i64.const 0)(i64.const 0)(i64.const 4))(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $MSTORE)
	(set_global $sp (i32.add (get_global $sp) (i32.const -64)))
	(call $PUSH (i64.const 0)(i64.const 0)(i64.const 0)(i64.const 36))(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $PUSH (i64.const 0)(i64.const 0)(i64.const 0)(i64.const 0))(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $REVERT) (br $done)
	(set_global $sp (i32.add (get_global $sp) (i32.const -64)))
	)(call $useGas (i64.const 45)) (if (i32.gt_s (get_global $sp) (i32.const 32608)) 
					 (then (unreachable)))(call $PUSH (i64.const 0)(i64.const 0)(i64.const 0)(i64.const 0))(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $PUSH (i64.const 0)(i64.const 0)(i64.const 0)(i64.const 2))(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $DUP (i32.const 2))
	(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $DIV)
	(set_global $sp (i32.add (get_global $sp) (i32.const -32)))
	(call $SWAP (i32.const 0))
	(set_global $sp (i32.add (get_global $sp) (i32.const -32)))
	(call $PUSH (i64.const 0)(i64.const 0)(i64.const 0)(i64.const 1))(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $DUP (i32.const 2))
	(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $AND)
	(set_global $sp (i32.add (get_global $sp) (i32.const -32)))
	(call $DUP (i32.const 0))
	(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $PUSH (i64.const 0)(i64.const 0)(i64.const 0)(i64.const 1534))(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(set_local $jump_dest (call $check_overflow 
												 (i64.load (get_global $sp))
												 (i64.load (i32.add (get_global $sp) (i32.const 8)))
												 (i64.load (i32.add (get_global $sp) (i32.const 16)))
												 (i64.load (i32.add (get_global $sp) (i32.const 24)))))
	
						(set_global $sp (i32.sub (get_global $sp) (i32.const 64)))
						(br_if $loop (i32.eqz (i64.eqz (i64.or
						  (i64.load (i32.add (get_global $sp) (i32.const 32)))
						  (i64.or
							(i64.load (i32.add (get_global $sp) (i32.const 40)))
							(i64.or
							  (i64.load (i32.add (get_global $sp) (i32.const 48)))
							  (i64.load (i32.add (get_global $sp) (i32.const 56)))
							)
						  )
						))))
	(call $useGas (i64.const 14)) (if (i32.gt_s (get_global $sp) (i32.const 32640)) 
					 (then (unreachable)))(call $PUSH (i64.const 0)(i64.const 0)(i64.const 0)(i64.const 127))(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $DUP (i32.const 2))
	(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $AND)
	(set_global $sp (i32.add (get_global $sp) (i32.const -32)))
	(call $SWAP (i32.const 1))
	(set_global $sp (i32.add (get_global $sp) (i32.const -32)))
	)(call $useGas (i64.const 29)) (if (i32.gt_s (get_global $sp) (i32.const 32640)) 
					 (then (unreachable)))(call $PUSH (i64.const 0)(i64.const 0)(i64.const 0)(i64.const 32))(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $DUP (i32.const 2))
	(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $LT)
	(set_global $sp (i32.add (get_global $sp) (i32.const -32)))
	(call $DUP (i32.const 1))
	(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $SUB)
	(set_global $sp (i32.add (get_global $sp) (i32.const -32)))
	(call $PUSH (i64.const 0)(i64.const 0)(i64.const 0)(i64.const 1553))(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(set_local $jump_dest (call $check_overflow 
												 (i64.load (get_global $sp))
												 (i64.load (i32.add (get_global $sp) (i32.const 8)))
												 (i64.load (i32.add (get_global $sp) (i32.const 16)))
												 (i64.load (i32.add (get_global $sp) (i32.const 24)))))
	
						(set_global $sp (i32.sub (get_global $sp) (i32.const 64)))
						(br_if $loop (i32.eqz (i64.eqz (i64.or
						  (i64.load (i32.add (get_global $sp) (i32.const 32)))
						  (i64.or
							(i64.load (i32.add (get_global $sp) (i32.const 40)))
							(i64.or
							  (i64.load (i32.add (get_global $sp) (i32.const 48)))
							  (i64.load (i32.add (get_global $sp) (i32.const 56)))
							)
						  )
						))))
	(call $useGas (i64.const 14)) (if (i32.gt_s (get_global $sp) (i32.const 32672)) 
					 (then (unreachable)))(call $PUSH (i64.const 0)(i64.const 0)(i64.const 0)(i64.const 1552))(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	(call $PUSH (i64.const 0)(i64.const 0)(i64.const 0)(i64.const 1463))(set_global $sp (i32.add (get_global $sp) (i32.const 32)))
	;; jump
						  (set_local $jump_dest (call $check_overflow 
												 (i64.load (get_global $sp))
												 (i64.load (i32.add (get_global $sp) (i32.const 8)))
												 (i64.load (i32.add (get_global $sp) (i32.const 16)))
												 (i64.load (i32.add (get_global $sp) (i32.const 24)))))
						  (set_global $sp (i32.sub (get_global $sp) (i32.const 32)))
						  (br $loop))(call $useGas (i64.const 1)) )(call $useGas (i64.const 19)) (if (i32.lt_s (get_global $sp) (i32.const 32)) 
					  (then (unreachable)))(set_global $sp (i32.add (get_global $sp) (i32.const -32)))
	(call $SWAP (i32.const 1))
	(call $SWAP (i32.const 0))
	(set_global $sp (i32.add (get_global $sp) (i32.const -32)))
	;; jump
						  (set_local $jump_dest (call $check_overflow 
												 (i64.load (get_global $sp))
												 (i64.load (i32.add (get_global $sp) (i32.const 8)))
												 (i64.load (i32.add (get_global $sp) (i32.const 16)))
												 (i64.load (i32.add (get_global $sp) (i32.const 24)))))
						  (set_global $sp (i32.sub (get_global $sp) (i32.const 32)))
						  (br $loop))))
	)
	`
