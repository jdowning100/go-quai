// Copyright (c) 2013-2018 The btcsuite developers
// Copyright (c) 2015-2018 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package txscript

// ScriptFlags is a bitmask defining additional operations or tests that will be
// done when executing a script pair.
type ScriptFlags uint32

const (
	// ScriptBip16 defines whether the bip16 threshold has passed and thus
	// pay-to-script hash transactions will be fully validated.
	ScriptBip16 ScriptFlags = 1 << iota

	// ScriptStrictMultiSig defines whether to verify the stack item
	// used by CHECKMULTISIG is zero length.
	ScriptStrictMultiSig

	// ScriptDiscourageUpgradableNops defines whether to verify that
	// NOP1 through NOP10 are reserved for future soft-fork upgrades.  This
	// flag must not be used for consensus critical code nor applied to
	// blocks as this flag is only for stricter standard transaction
	// checks.  This flag is only applied when the above opcodes are
	// executed.
	ScriptDiscourageUpgradableNops

	// ScriptVerifyCheckLockTimeVerify defines whether to verify that
	// a transaction output is spendable based on the locktime.
	// This is BIP0065.
	ScriptVerifyCheckLockTimeVerify

	// ScriptVerifyCheckSequenceVerify defines whether to allow execution
	// pathways of a script to be restricted based on the age of the output
	// being spent.  This is BIP0112.
	ScriptVerifyCheckSequenceVerify

	// ScriptVerifyCleanStack defines that the stack must contain only
	// one stack element after evaluation and that the element must be
	// true if interpreted as a boolean.  This is rule 6 of BIP0062.
	// This flag should never be used without the ScriptBip16 flag nor the
	// ScriptVerifyWitness flag.
	ScriptVerifyCleanStack

	// ScriptVerifyDERSignatures defines that signatures are required
	// to compily with the DER format.
	ScriptVerifyDERSignatures

	// ScriptVerifyLowS defines that signtures are required to comply with
	// the DER format and whose S value is <= order / 2.  This is rule 5
	// of BIP0062.
	ScriptVerifyLowS

	// ScriptVerifyMinimalData defines that signatures must use the smallest
	// push operator. This is both rules 3 and 4 of BIP0062.
	ScriptVerifyMinimalData

	// ScriptVerifyNullFail defines that signatures must be empty if
	// a CHECKSIG or CHECKMULTISIG operation fails.
	ScriptVerifyNullFail

	// ScriptVerifySigPushOnly defines that signature scripts must contain
	// only pushed data.  This is rule 2 of BIP0062.
	ScriptVerifySigPushOnly

	// ScriptVerifyStrictEncoding defines that signature scripts and
	// public keys must follow the strict encoding requirements.
	ScriptVerifyStrictEncoding

	// ScriptVerifyWitness defines whether or not to verify a transaction
	// output using a witness program template.
	ScriptVerifyWitness

	// ScriptVerifyDiscourageUpgradeableWitnessProgram makes witness
	// program with versions 2-16 non-standard.
	ScriptVerifyDiscourageUpgradeableWitnessProgram

	// ScriptVerifyMinimalIf makes a script with an OP_IF/OP_NOTIF whose
	// operand is anything other than empty vector or [0x01] non-standard.
	ScriptVerifyMinimalIf

	// ScriptVerifyWitnessPubKeyType makes a script within a check-sig
	// operation whose public key isn't serialized in a compressed format
	// non-standard.
	ScriptVerifyWitnessPubKeyType

	// ScriptVerifyTaproot defines whether or not to verify a transaction
	// output using the new taproot validation rules.
	ScriptVerifyTaproot

	// ScriptVerifyDiscourageUpgradeableWitnessProgram defines whether or
	// not to consider any new/unknown taproot leaf versions as
	// non-standard.
	ScriptVerifyDiscourageUpgradeableTaprootVersion

	// ScriptVerifyDiscourageOpSuccess defines whether or not to consider
	// usage of OP_SUCCESS op codes during tapscript execution as
	// non-standard.
	ScriptVerifyDiscourageOpSuccess

	// ScriptVerifyDiscourageUpgradeablePubkeyType defines if unknown
	// public key versions (during tapscript execution) is non-standard.
	ScriptVerifyDiscourageUpgradeablePubkeyType
)

const (
	// MaxStackSize is the maximum combined height of stack and alt stack
	// during execution.
	MaxStackSize = 1000

	// MaxScriptSize is the maximum allowed length of a raw script.
	MaxScriptSize = 10000

	// payToWitnessPubKeyHashDataSize is the size of the witness program's
	// data push for a pay-to-witness-pub-key-hash output.
	payToWitnessPubKeyHashDataSize = 20

	// payToWitnessScriptHashDataSize is the size of the witness program's
	// data push for a pay-to-witness-script-hash output.
	payToWitnessScriptHashDataSize = 32

	// payToTaprootDataSize is the size of the witness program push for
	// taproot spends. This will be the serialized x-coordinate of the
	// top-level taproot output public key.
	payToTaprootDataSize = 32
)
