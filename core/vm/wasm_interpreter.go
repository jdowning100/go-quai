package vm

import (
	"fmt"
	"log"

	"github.com/bytecodealliance/wasmtime-go"
)

type terminationType int

// List of termination reasons
const (
	TerminateFinish = iota
	TerminateRevert
	TerminateSuicide
	TerminateInvalid
)

type WASMInterpreter struct {
	evm *EVM
	cfg Config

	vm       *WasmVM
	Contract *Contract

	returnData []byte // Last CALL's return data for subsequent reuse

	TxContext
	Context BlockContext
	// StateDB gives access to the underlying state
	StateDB StateDB
	// Depth is the current call stack
	depth int

	staticMode bool

	terminationType int

	Config Config
}

func NewWASMInterpreter(evm *EVM, cfg Config) Interpreter {

	inter := WASMInterpreter{
		StateDB: evm.StateDB,
		evm:     evm,
	}

	return &inter
}

func (in *WASMInterpreter) Run(contract *Contract, input []byte, readOnly bool) (ret []byte, err error) {
	// Check if it can run
	if len(contract.Code) < 4 || string(contract.Code[:4]) != "\000asm" {
		return nil, nil
	}

	// Increment the call depth which is restricted to 1024
	in.evm.depth++
	defer func() { in.evm.depth-- }()

	in.Contract = contract
	in.Contract.Input = input

	// Create VM with the configure.
	vm := InstantiateWASMVM(in)

	in.vm = vm

	err = vm.LoadWasm(contract.Code)
	if err != nil {
		return nil, err
	}

	return in.returnData, nil
}

// CanRun checks the binary for a WASM header and accepts the binary blob
// if it matches.
func (in *WASMInterpreter) CanRun(file []byte) bool {
	// Check the header
	if len(file) < 4 || string(file[:4]) != "\000asm" {
		return false
	}

	return true
}

func (in *WASMInterpreter) validateModule(wasmBytes []byte) (int, error) {
	module, err := wasmtime.NewModule(in.vm.engine, wasmBytes)
	if err != nil {
		return -1, err
	}

	instance, err := wasmtime.NewInstance(in.vm.store, module, nil)
	if err != nil {
		log.Fatal(err)
	}

	// Next we poke around a bit to extract the `run` function from the module.
	run := instance.GetFunc(in.vm.store, "start")
	if run == nil {
		return -1, fmt.Errorf("Module has a start section")
	}

	// Check exports
	exports := module.Exports()
	if len(exports) != 2 {
		return -1, fmt.Errorf("Module has %d exports instead of 2", len(exports))
	}

	mainIndex := -1
	// for _, export := range exports {
	// 	switch export.Name() {
	// 	case "main":
	// 		if export.Type() != wasmtime.ExternType {
	// 			return -1, fmt.Errorf("Main is not a function in module")
	// 		}
	// 		mainIndex = int(export.Index())
	// 	case "memory":
	// 		if export.Type().Kind() != wasmtime.ExternTypeMemory {
	// 			return -1, fmt.Errorf("'memory' is not a memory in module")
	// 		}
	// 	default:
	// 		return -1, fmt.Errorf("A symbol named %s has been exported. Only main and memory should exist", export.Name())
	// 	}
	// }

	// // Check imports
	// imports := module.Imports()
	// for _, imp := range imports {
	// 	if imp.Module() == "quai" && imp.Type() == wasmtime.ExternType {
	// 		found := false
	// 		for _, name := range qeiFunctionList {
	// 			if name == *imp.Name() {
	// 				found = true
	// 				break
	// 			}
	// 		}
	// 		if !found {
	// 			return -1, fmt.Errorf("%s could not be found in the list of quai-provided functions", imp.Name())
	// 		}
	// 	}
	// }

	return mainIndex, nil
}

// PostContractCreation meters the contract once its init code has
// been run. It also validates the module's format before it is to
// be committed to disk.
func (in *WASMInterpreter) PostContractCreation(code []byte) ([]byte, error) {
	// If a REVERT has been encountered, then return the code and
	if in.terminationType == TerminateRevert {
		return nil, ErrExecutionReverted
	}

	if in.CanRun(code) {
		if len(code) > 8 {
			// Check the validity of the module
			_, err := in.validateModule(code)
			if err != nil {
				in.terminationType = TerminateInvalid
				return nil, err
			}
		}
	}

	return code, nil
}
