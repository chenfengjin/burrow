package wasm

import (
	"encoding/binary"
	"fmt"

	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/hyperledger/burrow/acm"
	"github.com/hyperledger/burrow/acm/acmstate"
	"github.com/hyperledger/burrow/crypto"
	"github.com/hyperledger/burrow/execution/defaults"
	"github.com/hyperledger/burrow/execution/engine"
	"github.com/hyperledger/burrow/execution/errors"
	"github.com/hyperledger/burrow/execution/exec"
	"github.com/hyperledger/burrow/execution/native"
	lifeExec "github.com/perlin-network/life/exec"
)

// Implements ewasm, see https://github.com/ewasm/design
// WASM
var DefaultVMConfig = lifeExec.VMConfig{
	DisableFloatingPoint: true,
	MaxMemoryPages:       16,
	DefaultMemoryPages:   16,
}

type WVM struct {
	engine.Externals
	options            engine.Options
	vmConfig           lifeExec.VMConfig
	externalDispatcher engine.Dispatcher
}

func New(options engine.Options) *WVM {
	vm := &WVM{
		options:  defaults.CompleteOptions(options),
		vmConfig: DefaultVMConfig,
	}
	vm.externalDispatcher = engine.Dispatchers{&vm.Externals, options.Natives, vm}
	return vm
}

func Default() *WVM {
	return New(engine.Options{})
}

// RunWASM creates a WASM VM, and executes the given WASM contract code
func (vm *WVM) Execute(st acmstate.ReaderWriter, blockchain engine.Blockchain, eventSink exec.EventSink,
	params engine.CallParams, code []byte) (output []byte, cerr error) {
	defer func() {
		if r := recover(); r != nil {
			cerr = errors.Codes.ExecutionAborted
		}
	}()

	st = native.NewState(vm.options.Natives, st)

	state := engine.State{
		CallFrame:  engine.NewCallFrame(st).WithMaxCallStackDepth(vm.options.CallStackMaxDepth),
		Blockchain: blockchain,
		EventSink:  eventSink,
	}

	output, err := vm.Contract(code).Call(state, params)

	if err == nil {
		// Only sync back when there was no exception
		err = state.CallFrame.Sync()
	}
	// Always return output - we may have a reverted exception for which the return is meaningful
	return output, err
}

func (vm *WVM) Dispatch(acc *acm.Account) engine.Callable {
	if len(acc.WASMCode) == 0 {
		return nil
	}
	return vm.Contract(acc.WASMCode)
}

// func (e *execContext) ResolveFunc(module, field string) exec.FunctionImport {
// 	if module != "ethereum" {
// 		panic(fmt.Sprintf("unknown module %s", module))
// 	}

// 	switch field {
// 	case "getCallDataSize":
// 		return func(vm *exec.VirtualMachine) int64 {
// 			return int64(len(e.params.Input))
// 		}

// 	case "callDataCopy":
// 		return func(vm *exec.VirtualMachine) int64 {
// 			destPtr := int(uint32(vm.GetCurrentFrame().Locals[0]))
// 			dataOffset := int(uint32(vm.GetCurrentFrame().Locals[1]))
// 			dataLen := int(uint32(vm.GetCurrentFrame().Locals[2]))

// 			if dataLen > 0 {
// 				copy(vm.Memory[destPtr:], e.params.Input[dataOffset:dataOffset+dataLen])
// 			}

// 			return 0
// 		}

// 	case "getReturnDataSize":
// 		return func(vm *exec.VirtualMachine) int64 {
// 			return int64(len(e.returnData))
// 		}

// 	case "returnDataCopy":
// 		return func(vm *exec.VirtualMachine) int64 {
// 			destPtr := int(uint32(vm.GetCurrentFrame().Locals[0]))
// 			dataOffset := int(uint32(vm.GetCurrentFrame().Locals[1]))
// 			dataLen := int(uint32(vm.GetCurrentFrame().Locals[2]))

// 			if dataLen > 0 {
// 				copy(vm.Memory[destPtr:], e.returnData[dataOffset:dataOffset+dataLen])
// 			}

// 			return 0
// 		}

// 	case "getCodeSize":
// 		return func(vm *exec.VirtualMachine) int64 {
// 			return int64(len(e.code))
// 		}

// 	case "codeCopy":
// 		return func(vm *exec.VirtualMachine) int64 {
// 			destPtr := int(uint32(vm.GetCurrentFrame().Locals[0]))
// 			dataOffset := int(uint32(vm.GetCurrentFrame().Locals[1]))
// 			dataLen := int(uint32(vm.GetCurrentFrame().Locals[2]))

// 			if dataLen > 0 {
// 				copy(vm.Memory[destPtr:], e.code[dataOffset:dataOffset+dataLen])
// 			}

// 			return 0
// 		}

// 	case "storageStore":
// 		return func(vm *exec.VirtualMachine) int64 {
// 			keyPtr := int(uint32(vm.GetCurrentFrame().Locals[0]))
// 			dataPtr := int(uint32(vm.GetCurrentFrame().Locals[1]))

// 			key := burrow_binary.Word256{}

// 			copy(key[:], vm.Memory[keyPtr:keyPtr+32])

// 			e.Void(e.state.SetStorage(e.params.Callee, key, vm.Memory[dataPtr:dataPtr+32]))
// 			return 0
// 		}

// 	case "storageLoad":
// 		return func(vm *exec.VirtualMachine) int64 {

// 			keyPtr := int(uint32(vm.GetCurrentFrame().Locals[0]))
// 			dataPtr := int(uint32(vm.GetCurrentFrame().Locals[1]))

// 			key := burrow_binary.Word256{}

// 			copy(key[:], vm.Memory[keyPtr:keyPtr+32])

// 			val := e.Bytes(e.state.GetStorage(e.params.Callee, key))
// 			copy(vm.Memory[dataPtr:], val)

// 			return 0
// 		}

// 	case "finish":
// 		return func(vm *exec.VirtualMachine) int64 {
// 			dataPtr := int(uint32(vm.GetCurrentFrame().Locals[0]))
// 			dataLen := int(uint32(vm.GetCurrentFrame().Locals[1]))

// 			e.output = vm.Memory[dataPtr : dataPtr+dataLen]

// 			panic(errors.Codes.None)
// 		}

// 	case "revert":
// 		return func(vm *exec.VirtualMachine) int64 {

// 			dataPtr := int(uint32(vm.GetCurrentFrame().Locals[0]))
// 			dataLen := int(uint32(vm.GetCurrentFrame().Locals[1]))

// 			e.output = vm.Memory[dataPtr : dataPtr+dataLen]

// 			panic(errors.Codes.ExecutionReverted)
// 		}

// 	case "getAddress":
// 		return func(vm *exec.VirtualMachine) int64 {
// 			addressPtr := int(uint32(vm.GetCurrentFrame().Locals[0]))

// 			copy(vm.Memory[addressPtr:], e.params.Callee.Bytes())

// 			return 0
// 		}

// 	case "getCallValue":
// 		return func(vm *exec.VirtualMachine) int64 {

// 			valuePtr := int(uint32(vm.GetCurrentFrame().Locals[0]))

// 			// ewasm value is little endian 128 bit value
// 			bs := make([]byte, 16)
// 			binary.LittleEndian.PutUint64(bs, e.params.Value.Uint64())

// 			copy(vm.Memory[valuePtr:], bs)

// 			return 0
// 		}

// 	case "getExternalBalance":
// 		return func(vm *exec.VirtualMachine) int64 {
// 			addressPtr := int(uint32(vm.GetCurrentFrame().Locals[0]))
// 			balancePtr := int(uint32(vm.GetCurrentFrame().Locals[1]))

// 			address := crypto.Address{}

// 			copy(address[:], vm.Memory[addressPtr:addressPtr+crypto.AddressLength])
// 			acc, err := e.state.GetAccount(address)
// 			if err != nil {
// 				panic(errors.Codes.InvalidAddress)
// 			}

// 			// ewasm value is little endian 128 bit value
// 			bs := make([]byte, 16)
// 			binary.LittleEndian.PutUint64(bs, acc.Balance.Uint64())

// 			copy(vm.Memory[balancePtr:], bs)

// 			return 0
// 		}

// 	default:
// 		panic(fmt.Sprintf("unknown function %s", field))
// 	}
// 	return vm.Contract(acc.WASMCode)
// }

func (vm *WVM) Contract(code []byte) *Contract {
	return &Contract{
		vm:   vm,
		code: code,
	}
}
