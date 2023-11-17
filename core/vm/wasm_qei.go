package vm

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"log"
	"math/big"

	"github.com/bytecodealliance/wasmtime-go"
	"github.com/dominant-strategies/go-quai/common"
	"github.com/dominant-strategies/go-quai/core/types"
)

/**
The code in this file is based on WASM code developed by Guillaume Ballet, which is
available under the GPL-3.0 license at https://github.com/gballet/go-ethereum.
**/

const (
	// QEICallSuccess is the return value in case of a successful contract execution
	QEICallSuccess = 0
	// ErrQEICallFailure is the return value in case of a contract execution failture
	ErrQEICallFailure = 1
	// ErrQEICallRevert is the return value in case a contract calls `revert`
	ErrQEICallRevert = 2

	// Max recursion depth for contracts
	maxCallDepth = 1024

	u256Len = 32

	u128Len = 16
)

// List of gas costs
const (
	GasCostZero           = 0
	GasCostBase           = 2
	GasCostVeryLow        = 3
	GasCostLow            = 5
	GasCostMid            = 8
	GasCostHigh           = 10
	GasCostExtCode        = 700
	GasCostBalance        = 400
	GasCostSLoad          = 200
	GasCostJumpDest       = 1
	GasCostSSet           = 20000
	GasCostSReset         = 5000
	GasRefundSClear       = 15000
	GasRefundSelfDestruct = 24000
	GasCostCreate         = 32000
	GasCostCall           = 700
	GasCostCallValue      = 9000
	GasCostCallStipend    = 2300
	GasCostNewAccount     = 25000
	GasCostLog            = 375
	GasCostLogData        = 8
	GasCostLogTopic       = 375
	GasCostCopy           = 3
	GasCostBlockHash      = 800
)

var qeiFunctionList = []string{
	"useGas",
	"getAddress",
	"getExternalBalance",
	"getBlockHash",
	"call",
	"callDataCopy",
	"getCallDataSize",
	"callCode",
	"callDelegate",
	"callStatic",
	"storageStore",
	"storageLoad",
	"getCaller",
	"getCallValue",
	"codeCopy",
	"getCodeSize",
	"getBlockCoinbase",
	"create",
	"getBlockDifficulty",
	"externalCodeCopy",
	"getExternalCodeSize",
	"getGasLeft",
	"getBlockGasLimit",
	"getTxGasPrice",
	"log",
	"getBlockNumber",
	"getTxOrigin",
	"finish",
	"revert",
	"getReturnDataSize",
	"returnDataCopy",
	"selfDestruct",
	"getBlockTimestamp",
}

type WasmVM struct {
	evm *EVM

	engine   *wasmtime.Engine
	instance *wasmtime.Instance
	linker   *wasmtime.Linker
	memory   *wasmtime.Memory
	module   *wasmtime.Module
	store    *wasmtime.Store

	Contract *Contract

	cachedResult   []byte // result from the previous call
	panicErr       error
	timeoutStarted bool
}

func InstantiateWASMVM(in *WASMInterpreter) *WasmVM {
	config := wasmtime.NewConfig()
	// no need to be interruptable by WasmVMBase
	// config.SetInterruptable(true)
	config.SetConsumeFuel(true)

	vm := &WasmVM{engine: wasmtime.NewEngineWithConfig(config)}
	// prevent WasmVMBase from starting timeout interrupting,
	// instead we simply let WasmTime run out of fuel
	vm.timeoutStarted = true // DisableWasmTimeout

	vm.LinkHost(in)

	return vm
}

func (vm *WasmVM) LinkHost(in *WASMInterpreter) (err error) {
	vm.store = wasmtime.NewStore(vm.engine)
	vm.store.AddFuel(in.Contract.Gas)
	vm.linker = wasmtime.NewLinker(vm.engine)

	// Create a new memory instance.
	memoryType := wasmtime.NewMemoryType(300, true, 300)
	vm.memory, err = wasmtime.NewMemory(vm.store, memoryType)
	if err != nil {
		return err
	}

	err = vm.linker.DefineFunc(vm.store, "", "logHelloWorld", logHelloWorld)
	if err != nil {
		return err
	}

	err = vm.linker.DefineFunc(vm.store, "", "useGas", in.useGas)
	if err != nil {
		return err
	}

	err = vm.linker.DefineFunc(vm.store, "", "getAddress", in.getAddress)
	if err != nil {
		return err
	}

	err = vm.linker.DefineFunc(vm.store, "", "getExternalBalance", in.getExternalBalance)
	if err != nil {
		return err
	}

	err = vm.linker.DefineFunc(vm.store, "", "getBlockNumber", in.getBlockNumber)
	if err != nil {
		return err
	}

	err = vm.linker.DefineFunc(vm.store, "", "getBlockHash", in.getBlockHash)
	if err != nil {
		return err
	}

	err = vm.linker.DefineFunc(vm.store, "", "call", in.call)
	if err != nil {
		return err
	}

	err = vm.linker.DefineFunc(vm.store, "", "create", in.create)
	if err != nil {
		return err
	}

	err = vm.linker.DefineFunc(vm.store, "", "getCallDataSize", in.getCallDataSize)
	if err != nil {
		return err
	}

	err = vm.linker.DefineFunc(vm.store, "", "callDataCopy", in.callDataCopy)
	if err != nil {
		return err
	}

	err = vm.linker.Define("", "memory", vm.memory)
	if err != nil {
		return err
	}

	return nil
}

func (vm *WasmVM) LoadWasm(wasm []byte) (err error) {
	defer func() {
		if r := recover(); r != nil {
			// Optionally, you can set 'err' to a custom error value here.
			err = fmt.Errorf("panic: %v", r)
		}
	}()

	module, err := wasmtime.NewModule(vm.engine, wasm)
	if err != nil {
		return err
	}
	bytes, err := module.Serialize()
	if err != nil {
		return err
	}

	// Deserialize the compiled module.
	module, err = wasmtime.NewModuleDeserialize(vm.store.Engine, bytes)
	if err != nil {
		return err
	}

	vm.instance, err = vm.linker.Instantiate(vm.store, module)
	if err != nil {
		return err
	}

	// After we've instantiated we can lookup our `run` function and call
	// it.
	run := vm.instance.GetFunc(vm.store, "run")
	if run == nil {
		panic("not a function")
	}

	_, err = run.Call(vm.store)
	if err != nil {
		return err
	}

	return nil
}

func (vm *WasmVM) UnsafeMemory() []byte {
	return vm.memory.UnsafeData(vm.store)
}

func logHelloWorld() {
	fmt.Println("🤖: Hello World")
}

func (in *WASMInterpreter) gasAccounting(cost uint64) {
	if in.Contract == nil {
		panic("nil contract")
	}
	_, err := in.vm.store.ConsumeFuel(100)
	if err != nil {
		panic("out of gas")
	}
}

func (in *WASMInterpreter) useGas(amount int64) {
	in.gasAccounting(uint64(amount))
}

func (in *WASMInterpreter) getCallDataSize() int32 {
	in.gasAccounting(100)
	return int32(len(in.Contract.Input))
}

func (in *WASMInterpreter) callDataCopy(resultOffset int32, dataOffset int32, length int32) {
	in.gasAccounting(100)
	memoryData := in.vm.memory.UnsafeData(in.vm.store)
	copy(memoryData[resultOffset:], in.Contract.Input[dataOffset:dataOffset+length])
}

func (in *WASMInterpreter) getCodeSize() int32 {
	in.gasAccounting(100)
	return int32(len(in.Contract.Code))
}

func (in *WASMInterpreter) codeCopy(resultOffset int32, codeOffset int32, length int32) {
	in.gasAccounting(100)
	memoryData := in.vm.memory.UnsafeData(in.vm.store)
	copy(memoryData[resultOffset:], in.Contract.Code[codeOffset:codeOffset+length])
}

func (in *WASMInterpreter) getCaller(resultOffset int32) {
	in.gasAccounting(100)
	memoryData := in.vm.memory.UnsafeData(in.vm.store)
	copy(memoryData[resultOffset:], in.Contract.Caller().Bytes())
}

func (in *WASMInterpreter) getCallValue(resultOffset int32) {
	in.gasAccounting(100)
	memoryData := in.vm.memory.UnsafeData(in.vm.store)
	copy(memoryData[resultOffset:], in.Contract.Value().Bytes())
}

func (in *WASMInterpreter) getTxOrigin(resultOffset int32) {
	in.gasAccounting(100)
	memoryData := in.vm.memory.UnsafeData(in.vm.store)
	copy(memoryData[resultOffset:], in.evm.TxContext.Origin.Bytes())
}

func (in *WASMInterpreter) getReturnDataSize() int32 {
	in.gasAccounting(100)
	return int32(len(in.vm.cachedResult))
}

func (in *WASMInterpreter) returnDataCopy(resultOffset int32, dataOffset int32, length int32) {
	in.gasAccounting(100)
	memoryData := in.vm.memory.UnsafeData(in.vm.store)
	copy(memoryData[resultOffset:], in.vm.cachedResult[dataOffset:dataOffset+length])
}

func (in *WASMInterpreter) callCode(gas int64, addressOffset int32, valueOffset int32, dataOffset int32, dataLength int32, resultOffset int32) int32 {
	in.gasAccounting(100)
	return in.call(gas, addressOffset, valueOffset, dataOffset, dataLength)
}

func (in *WASMInterpreter) callDelegate(gas int64, addressOffset int32, dataOffset int32, dataLength int32, resultOffset int32) int32 {
	in.gasAccounting(100)
	return in.call(gas, addressOffset, 0, dataOffset, dataLength)
}

func (in *WASMInterpreter) callStatic(gas int64, addressOffset int32, dataOffset int32, dataLength int32, resultOffset int32) int32 {
	in.gasAccounting(100)
	return in.call(gas, addressOffset, 0, dataOffset, dataLength)
}

func (in *WASMInterpreter) storageStore(pathOffset int32, valueOffset int32) {
	in.gasAccounting(100)
	memoryData := in.vm.memory.UnsafeData(in.vm.store)
	path := memoryData[pathOffset : pathOffset+u256Len]
	value := memoryData[valueOffset : valueOffset+u256Len]
	internal, err := in.Contract.Address().InternalAddress()
	if err != nil {
		log.Panicf(err.Error())
	}
	in.StateDB.SetState(internal, common.BytesToHash(path), common.BytesToHash(value))
}

func (in *WASMInterpreter) storageLoad(pathOffset int32, resultOffset int32) {
	in.gasAccounting(100)
	memoryData := in.vm.memory.UnsafeData(in.vm.store)
	path := memoryData[pathOffset : pathOffset+u256Len]
	internal, err := in.Contract.Address().InternalAddress()
	if err != nil {
		log.Panicf(err.Error())
	}
	value := in.StateDB.GetState(internal, common.BytesToHash(path))
	copy(memoryData[resultOffset:], value.Bytes())
}

func (in *WASMInterpreter) externalCodeCopy(addressOffset int32, resultOffset int32, codeOffset int32, length int32) {
	in.gasAccounting(100)
	memoryData := in.vm.memory.UnsafeData(in.vm.store)
	addr, err := common.BytesToAddress(memoryData[addressOffset : addressOffset+common.AddressLength]).InternalAddress()
	if err != nil {
		log.Panicf(err.Error())
	}
	code := in.StateDB.GetCode(addr)
	copy(memoryData[resultOffset:], code[codeOffset:codeOffset+length])
}

func (in *WASMInterpreter) getExternalCodeSize(addressOffset int32) int32 {
	in.gasAccounting(100)
	memoryData := in.vm.memory.UnsafeData(in.vm.store)
	addr, err := common.BytesToAddress(memoryData[addressOffset : addressOffset+common.AddressLength]).InternalAddress()
	if err != nil {
		log.Panicf(err.Error())
	}
	code := in.StateDB.GetCode(addr)
	return int32(len(code))
}

func (in *WASMInterpreter) getGasLeft() int64 {
	in.gasAccounting(100)
	return int64(in.Contract.Gas)
}

func (in *WASMInterpreter) getBlockCoinbase(resultOffset int32) {
	in.gasAccounting(100)
	memoryData := in.vm.memory.UnsafeData(in.vm.store)
	copy(memoryData[resultOffset:], in.evm.Context.Coinbase.Bytes())
}

func (in *WASMInterpreter) getBlockDifficulty(resultOffset int32) {
	in.gasAccounting(100)
	memoryData := in.vm.memory.UnsafeData(in.vm.store)
	diff := in.evm.Context.Difficulty.Bytes()
	copy(memoryData[resultOffset:], diff)
}

func (in *WASMInterpreter) getBlockGasLimit() int64 {
	in.gasAccounting(100)
	return int64(in.evm.Context.GasLimit)
}

func (in *WASMInterpreter) getBlockTimestamp() int64 {
	in.gasAccounting(100)
	return in.Context.Time.Int64()
}

func (in *WASMInterpreter) getTxGasPrice(resultOffset int32) {
	in.gasAccounting(100)
	memoryData := in.vm.memory.UnsafeData(in.vm.store)
	copy(memoryData[resultOffset:], in.evm.GasPrice.Bytes())
}

func (in *WASMInterpreter) getBlockNumber() int64 {
	in.gasAccounting(100)
	return in.evm.Context.BlockNumber.Int64()
}

func (in *WASMInterpreter) log(dataOffset int32, dataLength int32, numberOfTopics int32, topic1 int32, topic2 int32, topic3 int32, topic4 int32) {
	in.gasAccounting(100)
	memoryData := in.vm.memory.UnsafeData(in.vm.store)
	topics := make([]common.Hash, numberOfTopics)
	for i := int32(0); i < numberOfTopics; i++ {
		topics[i] = common.BytesToHash(memoryData[topic1+i*32 : topic1+i*32+32])
	}
	data := memoryData[dataOffset : dataOffset+dataLength]
	in.StateDB.AddLog(&types.Log{
		Address:     in.Contract.Address(),
		Topics:      topics,
		Data:        data,
		BlockNumber: in.evm.Context.BlockNumber.Uint64(),
	})
}

func (in *WASMInterpreter) getBlockHash(number int64, resultOffset int32) int32 {
	in.gasAccounting(100)
	n := big.NewInt(number)
	n.Sub(in.evm.Context.BlockNumber, n)
	if n.Cmp(big.NewInt(256)) > 0 || n.Cmp(big.NewInt(0)) <= 0 {
		return 1
	}
	h := in.evm.Context.GetHash(uint64(number))
	memoryData := in.vm.memory.UnsafeData(in.vm.store)
	copy(memoryData[resultOffset:], h.Bytes())
	return 0
}

func (in *WASMInterpreter) finish(dataOffset int32, dataLength int32) {
	in.gasAccounting(100)
	memoryData := in.vm.memory.UnsafeData(in.vm.store)
	in.vm.cachedResult = memoryData[dataOffset : dataOffset+dataLength]
	in.vm.panicErr = nil
	in.vm.timeoutStarted = false
	in.terminationType = TerminateFinish
}

func (in *WASMInterpreter) revert(dataOffset int32, dataLength int32) {
	in.gasAccounting(100)
	memoryData := in.vm.memory.UnsafeData(in.vm.store)
	in.vm.cachedResult = memoryData[dataOffset : dataOffset+dataLength]
	in.vm.panicErr = nil
	in.vm.timeoutStarted = false
	in.terminationType = TerminateRevert
}

func (in *WASMInterpreter) selfDestruct(addressOffset int32) {
	in.gasAccounting(100)
	internal, err := in.Contract.Address().InternalAddress()
	if err != nil {
		log.Panicf(err.Error())
	}
	balance := in.StateDB.GetBalance(internal)
	memoryData := in.vm.memory.UnsafeData(in.vm.store)
	addr, err := common.BytesToAddress(memoryData[addressOffset : addressOffset+common.AddressLength]).InternalAddress()
	if err != nil {
		log.Panicf(err.Error())
	}
	in.StateDB.AddBalance(addr, balance)
	in.StateDB.Suicide(internal)
	in.terminationType = TerminateSuicide
	in.StateDB.AddRefund(GasRefundSelfDestruct)
}

func (in *WASMInterpreter) getAddress(resultOffset int32) {
	in.gasAccounting(100)
	memoryData := in.vm.memory.UnsafeData(in.vm.store)
	copy(memoryData[resultOffset:], in.Contract.Address().Bytes())
}

func (in *WASMInterpreter) getExternalBalance(addressOffset uint32, resultOffset int32) {
	in.gasAccounting(100)
	memoryData := in.vm.memory.UnsafeData(in.vm.store)
	addr := common.BytesToAddress(memoryData[addressOffset : addressOffset+common.AddressLength])
	internal, err := addr.InternalAddress()
	if err != nil {
		log.Panicf(err.Error())
	}
	balance := swapEndian(in.StateDB.GetBalance(internal).Bytes())
	copy(memoryData[resultOffset:], balance)
}

func swapEndian(src []byte) []byte {
	ret := make([]byte, len(src))
	for i, v := range src {
		ret[len(src)-i-1] = v
	}
	return ret
}

// Helper function to convert int64 to []byte
func int64ToBytes(i int64) []byte {
	buf := new(bytes.Buffer)
	binary.Write(buf, binary.LittleEndian, i)
	return buf.Bytes()
}

func (in *WASMInterpreter) call(gas int64, addressOffset int32, valueOffset int32, dataOffset int32, dataLength int32) int32 {
	contract := in.Contract

	// Get the address of the contract to call
	memoryData := in.vm.memory.UnsafeData(in.vm.store)
	addrInterface := common.BytesToAddress(memoryData[addressOffset : addressOffset+common.AddressLength])
	addr, err := addrInterface.InternalAddress()
	if err != nil {
		return ErrQEICallFailure
	}
	// Get the value. The [spec](https://github.com/ewasm/design/blob/master/eth_interface.md#call)
	// requires this operation to be U128, which is incompatible with the EVM version that expects
	// a u256.
	// To be compatible with hera, one must read a u256 value, then check that this is a u128.
	value := big.NewInt(0).SetBytes(swapEndian(memoryData[valueOffset : addressOffset+u256Len]))
	check128bits := big.NewInt(1)
	check128bits.Lsh(check128bits, 128)
	if value.Cmp(check128bits) > 0 {
		return ErrQEICallFailure
	}

	internal, err := contract.Address().InternalAddress()
	if err != nil {
		return ErrQEICallFailure
	}

	// Fail if the account's balance is greater than 128bits as discussed
	// in https://github.com/ewasm/hera/issues/456
	if in.StateDB.GetBalance(internal).Cmp(check128bits) > 0 {
		in.gasAccounting(contract.Gas)
		return ErrQEICallRevert
	}

	if in.staticMode == true && value.Cmp(big.NewInt(0)) != 0 {
		in.gasAccounting(in.Contract.Gas)
		return ErrQEICallFailure
	}

	in.gasAccounting(GasCostCall)

	if in.evm.depth > maxCallDepth {
		return ErrQEICallFailure
	}

	if value.Cmp(big.NewInt(0)) != 0 {
		in.gasAccounting(GasCostCallValue)
	}

	// Get the arguments.
	// TODO check the need for callvalue (seems not, a lot of that stuff is
	// already accounted for in the functions that I already called - need to
	// refactor all that)
	input := memoryData[dataOffset : addressOffset+dataLength]
	snapshot := in.StateDB.Snapshot()

	// Check that there is enough balance to transfer the value
	if in.StateDB.GetBalance(internal).Cmp(value) < 0 {
		return ErrQEICallFailure
	}

	// Check that the contract exists
	if !in.StateDB.Exist(addr) {
		in.gasAccounting(GasCostNewAccount)
		in.StateDB.CreateAccount(addr)
	}

	var calleeGas uint64
	if uint64(gas) > ((63 * contract.Gas) / 64) {
		calleeGas = contract.Gas - (contract.Gas / 64)
	} else {
		calleeGas = uint64(gas)
	}
	in.gasAccounting(calleeGas)

	if value.Cmp(big.NewInt(0)) != 0 {
		calleeGas += GasCostCallStipend
	}

	// TODO tracing

	// Add amount to recipient
	in.evm.Context.Transfer(in.StateDB, contract.Address(), addrInterface, value)

	// Load the contract code in a new VM structure
	targetContract := NewContract(contract, AccountRef(addrInterface), value, calleeGas)
	code := in.StateDB.GetCode(addr)
	if len(code) == 0 {
		in.Contract.Gas += calleeGas
		return QEICallSuccess
	}
	targetContract.SetCallCode(&addrInterface, in.StateDB.GetCodeHash(addr), code)

	savedVM := in.vm

	in.Run(targetContract, input, false)

	in.vm = savedVM
	in.Contract = contract

	// Add leftover gas
	in.Contract.Gas += targetContract.Gas
	defer func() { in.terminationType = TerminateFinish }()

	switch in.terminationType {
	case TerminateFinish:
		return QEICallSuccess
	case TerminateRevert:
		in.StateDB.RevertToSnapshot(snapshot)
		return ErrQEICallRevert
	default:
		in.StateDB.RevertToSnapshot(snapshot)
		contract.UseGas(targetContract.Gas)
		return ErrQEICallFailure
	}
}

func (in *WASMInterpreter) create(valueOffset int32, codeOffset int32, length int32, resultOffset int32) int32 {
	in.gasAccounting(GasCostCreate)
	savedVM := in.vm
	savedContract := in.Contract
	defer func() {
		in.vm = savedVM
		in.Contract = savedContract
	}()
	in.terminationType = TerminateInvalid

	memorySize := in.vm.memory.Size(in.vm.store)
	if uint64(codeOffset+length) > memorySize {
		return ErrQEICallFailure
	}

	memoryData := in.vm.memory.UnsafeData(in.vm.store)

	input := memoryData[codeOffset : codeOffset+length]

	if uint64(valueOffset+u128Len) > memorySize {
		return ErrQEICallFailure
	}

	value := swapEndian(memoryData[valueOffset : valueOffset+u128Len])

	in.terminationType = TerminateFinish

	// EIP150 says that the calling contract should keep 1/64th of the
	// leftover gas.
	gas := in.Contract.Gas - in.Contract.Gas/64
	in.gasAccounting(gas)

	_, addr, gasLeft, err := in.evm.Create(in.Contract, input, gas, big.NewInt(0).SetBytes(value))
	if err != nil {
		return ErrQEICallFailure
	}

	switch in.terminationType {
	case TerminateFinish:
		savedContract.Gas += gasLeft
		copy(memoryData[resultOffset:], addr.Bytes())
		return QEICallSuccess
	case TerminateRevert:
		savedContract.Gas += gas
		return ErrQEICallRevert
	default:
		savedContract.Gas += gasLeft
		return ErrQEICallFailure
	}
}
