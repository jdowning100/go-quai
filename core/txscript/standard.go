package txscript

import "github.com/dominant-strategies/go-quai/common"

// payToPubkeyScript creates a new script to pay a transaction output to a
// public key. It is expected that the input is a valid pubkey.
func payToPubKeyScript(serializedPubKey []byte) ([]byte, error) {
	return NewScriptBuilder().AddData(serializedPubKey).
		AddOp(OP_CHECKSIG).Script()
}

// PayToAddrScript creates a new script to pay a transaction output to a the
// specified address.
func PayToAddrScript(addr common.Address) ([]byte, error) {
	const nilAddrErrStr = "unable to generate payment script for nil address"

	if (addr == common.Address{}) {
		// return nil, scriptError(ErrUnsupportedAddress,
		// 	nilAddrErrStr)
	}
	return payToPubKeyScript(addr.Bytes())

	// switch addr := addr.(type) {
	// case *btcutil.AddressPubKeyHash:
	// 	if addr == nil {
	// 		return nil, scriptError(ErrUnsupportedAddress,
	// 			nilAddrErrStr)
	// 	}
	// 	return payToPubKeyHashScript(addr.ScriptAddress())

	// case *btcutil.AddressScriptHash:
	// 	if addr == nil {
	// 		return nil, scriptError(ErrUnsupportedAddress,
	// 			nilAddrErrStr)
	// 	}
	// 	return payToScriptHashScript(addr.ScriptAddress())

	// case *btcutil.AddressPubKey:
	// 	if addr == nil {
	// 		return nil, scriptError(ErrUnsupportedAddress,
	// 			nilAddrErrStr)
	// 	}
	// 	return payToPubKeyScript(addr.ScriptAddress())

	// case *btcutil.AddressWitnessPubKeyHash:
	// 	if addr == nil {
	// 		return nil, scriptError(ErrUnsupportedAddress,
	// 			nilAddrErrStr)
	// 	}
	// 	return payToWitnessPubKeyHashScript(addr.ScriptAddress())
	// case *btcutil.AddressWitnessScriptHash:
	// 	if addr == nil {
	// 		return nil, scriptError(ErrUnsupportedAddress,
	// 			nilAddrErrStr)
	// 	}
	// 	return payToWitnessScriptHashScript(addr.ScriptAddress())
	// case *btcutil.AddressTaproot:
	// 	if addr == nil {
	// 		return nil, scriptError(ErrUnsupportedAddress,
	// 			nilAddrErrStr)
	// 	}
	// 	return payToWitnessTaprootScript(addr.ScriptAddress())
	// }

	// str := fmt.Sprintf("unable to generate payment script for unsupported "+
	// 	"address type %T", addr)
	// return nil, scriptError(ErrUnsupportedAddress, str)
}
