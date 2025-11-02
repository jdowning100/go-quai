package types

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	btcchainhash "github.com/btcsuite/btcd/chaincfg/chainhash"
	btcdwire "github.com/btcsuite/btcd/wire"
	"github.com/dominant-strategies/go-quai/common"
	"github.com/dominant-strategies/go-quai/common/hexutil"
	"github.com/dominant-strategies/go-quai/crypto/musig2"
	"github.com/dominant-strategies/go-quai/log"
	ltcchainhash "github.com/dominant-strategies/ltcd/chaincfg/chainhash"
	ltcdwire "github.com/dominant-strategies/ltcd/wire"
	bchchainhash "github.com/gcash/bchd/chaincfg/chainhash"
	bchdwire "github.com/gcash/bchd/wire"
	"google.golang.org/protobuf/proto"
)

// PowID represents a unique identifier for a proof-of-work algorithm
type PowID uint32

const (
	Progpow PowID = iota
	Kawpow
	SHA_BTC
	SHA_BCH
	Scrypt
)

func (p PowID) String() string {
	switch p {
	case Progpow:
		return "Progpow"
	case Kawpow:
		return "Kawpow"
	case SHA_BTC:
		return "SHA_BTC"
	case SHA_BCH:
		return "SHA_BCH"
	case Scrypt:
		return "Scrypt"
	default:
		return "Unknown"
	}
}

// NTimeMask represents a time mask for mining operations
type NTimeMask uint32

// SignerEnvelope contains a signer ID and their signature
type SignerEnvelope struct {
	signerID  string
	signature []byte
}

// Getters for SignerEnvelope
func (se *SignerEnvelope) SignerID() string  { return se.signerID }
func (se *SignerEnvelope) Signature() []byte { return se.signature }

// Setters for SignerEnvelope
func (se *SignerEnvelope) SetSignerID(id string)   { se.signerID = id }
func (se *SignerEnvelope) SetSignature(sig []byte) { se.signature = sig }

// NewSignerEnvelope creates a new SignerEnvelope with the given ID and signature
func NewSignerEnvelope(id string, signature []byte) SignerEnvelope {
	return SignerEnvelope{
		signerID:  id,
		signature: signature,
	}
}

// ProtoEncode converts SignerEnvelope to its protobuf representation
func (se *SignerEnvelope) ProtoEncode() *ProtoSignerEnvelope {
	if se == nil {
		return nil
	}
	signerID := se.signerID
	return &ProtoSignerEnvelope{
		SignerId:  &signerID,
		Signature: se.signature,
	}
}

// ProtoDecode populates SignerEnvelope from its protobuf representation
func (se *SignerEnvelope) ProtoDecode(data *ProtoSignerEnvelope) error {
	if data == nil {
		return nil
	}
	se.signerID = data.GetSignerId()
	se.signature = data.GetSignature()
	return nil
}

// AuxTemplate defines the template structure for auxiliary proof-of-work
type AuxTemplate struct {
	// === Consensus-correspondence (signed; Quai validators check against AuxPoW) ===
	powID    PowID    // must match ap.Chain (RVN)
	prevHash [32]byte // must equal donor_header.hashPrevBlock
	auxPow2  []byte

	// === Header/DAA knobs for job construction (signed) ===
	version   uint32    // header.nVersion to use
	nBits     uint32    // header.nBits
	nTimeMask NTimeMask // allowed time range/step (e.g., {start, end, step})
	height    uint32    // BIP34 height (needed for scriptSig + KAWPOW epoch hint)

	// CoinbaseOut is the coinbase payout
	coinbaseOut []byte // coinbase out contains the tail of the coinbase transaction including the length of the outputs

	// Mode B: LOCKED TX SET (miners get fees; template is larger & updated more often)
	merkleBranch [][]byte // siblings for coinbase index=0 up to root (little endian 32-byte hashes)

	// === Quorum signatures over CanonicalEncode(template WITHOUT Sigs) ===
	sigs []byte
}

func NewAuxTemplate() *AuxTemplate {
	return &AuxTemplate{}
}

func EmptyAuxTemplate() *AuxTemplate {
	return &AuxTemplate{
		powID:        Kawpow,
		prevHash:     [32]byte{},
		auxPow2:      nil,
		version:      536870912, // 0x20000000 (RVN)
		nBits:        0,
		nTimeMask:    0,
		height:       0,
		coinbaseOut:  []byte{},
		merkleBranch: [][]byte{},
		sigs:         []byte{},
	}
}

// Getters for AuxTemplate fields
func (at *AuxTemplate) PowID() PowID           { return at.powID }
func (at *AuxTemplate) PrevHash() [32]byte     { return at.prevHash }
func (at *AuxTemplate) AuxPow2() []byte        { return at.auxPow2 }
func (at *AuxTemplate) Version() uint32        { return at.version }
func (at *AuxTemplate) NBits() uint32          { return at.nBits }
func (at *AuxTemplate) NTimeMask() NTimeMask   { return at.nTimeMask }
func (at *AuxTemplate) Height() uint32         { return at.height }
func (at *AuxTemplate) CoinbaseOut() []byte    { return at.coinbaseOut }
func (at *AuxTemplate) MerkleBranch() [][]byte { return at.merkleBranch }
func (at *AuxTemplate) Sigs() []byte           { return at.sigs }

// Setters for AuxTemplate fields
func (at *AuxTemplate) SetPowID(id PowID)               { at.powID = id }
func (at *AuxTemplate) SetPrevHash(hash [32]byte)       { at.prevHash = hash }
func (at *AuxTemplate) SetAuxPow2(auxPow2 []byte)       { at.auxPow2 = auxPow2 }
func (at *AuxTemplate) SetVersion(v uint32)             { at.version = v }
func (at *AuxTemplate) SetNBits(bits uint32)            { at.nBits = bits }
func (at *AuxTemplate) SetNTimeMask(mask NTimeMask)     { at.nTimeMask = mask }
func (at *AuxTemplate) SetHeight(h uint32)              { at.height = h }
func (at *AuxTemplate) SetCoinbaseOut(out []byte)       { at.coinbaseOut = out }
func (at *AuxTemplate) SetMerkleBranch(branch [][]byte) { at.merkleBranch = branch }
func (at *AuxTemplate) SetSigs(sigs []byte)             { at.sigs = sigs }

// ProtoEncode converts AuxTemplate to its protobuf representation
func (at *AuxTemplate) ProtoEncode() *ProtoAuxTemplate {
	if at == nil {
		return nil
	}

	powID := uint32(at.powID)
	version := at.version
	nbits := at.nBits
	ntimeMask := uint32(at.nTimeMask)
	height := at.height
	coinbaseOut := at.coinbaseOut

	// Convert merkle branch
	merkleBranch := make([][]byte, len(at.merkleBranch))
	copy(merkleBranch, at.merkleBranch)

	return &ProtoAuxTemplate{
		ChainId:      &powID,
		PrevHash:     at.prevHash[:],
		AuxPow2:      at.auxPow2,
		Version:      &version,
		Nbits:        &nbits,
		NtimeMask:    &ntimeMask,
		Height:       &height,
		CoinbaseOut:  coinbaseOut,
		MerkleBranch: merkleBranch,
		Sigs:         at.Sigs(),
	}
}

// ProtoDecode populates AuxTemplate from its protobuf representation
func (at *AuxTemplate) ProtoDecode(data *ProtoAuxTemplate) error {
	if data == nil {
		return nil
	}

	at.powID = PowID(data.GetChainId())

	// Copy PrevHash (32 bytes)
	if len(data.GetPrevHash()) == 32 {
		copy(at.prevHash[:], data.GetPrevHash())
	}

	at.auxPow2 = data.GetAuxPow2()
	at.version = data.GetVersion()
	at.nBits = data.GetNbits()
	at.nTimeMask = NTimeMask(data.GetNtimeMask())
	at.height = data.GetHeight()
	at.coinbaseOut = data.GetCoinbaseOut()

	// Copy merkle branch
	at.merkleBranch = make([][]byte, len(data.GetMerkleBranch()))
	for i, hash := range data.GetMerkleBranch() {
		at.merkleBranch[i] = make([]byte, len(hash))
		copy(at.merkleBranch[i], hash)
	}

	// Decode signer envelopes
	at.sigs = make([]byte, len(data.GetSigs()))
	copy(at.sigs, data.GetSigs())

	return nil
}

// Hash returns the SHA256 hash of the AuxTemplate with signature fields set to nil
// This is the same hash used for signing and verification
func (at *AuxTemplate) Hash() [32]byte {
	// Create a copy of the template without signatures for message hash calculation
	// We need to work with the protobuf representation to properly exclude signature fields
	protoTemplate := at.ProtoEncode()
	tempTemplate := proto.Clone(protoTemplate).(*ProtoAuxTemplate)
	tempTemplate.Sigs = nil

	// Since for chains other than ravencoin, version can be grinded for mining,
	// need to mask them before signing
	versionMask := uint32(0xE0000000)
	if at.powID != Kawpow {
		tempTemplate.Version = proto.Uint32(*tempTemplate.Version & versionMask)
	}

	// Marshal the template without signatures to get the message hash
	templateData, err := proto.Marshal(tempTemplate)
	if err != nil {
		// Return zero hash on error - this should be handled by the caller
		return [32]byte{}
	}

	// Calculate and return the message hash
	return sha256.Sum256(templateData)
}

// VerifySignature verifies the composite MuSig2 signature over this AuxTemplate.
// It tries all possible 2-of-3 signer index combinations. If 'signature' is nil or empty,
// it falls back to using the embedded at.sigs. Returns true on any valid combination.
func (at *AuxTemplate) VerifySignature() bool {
	// Check Signature presence
	if len(at.sigs) == 0 {
		log.Global.Warn("Sig is empty, signature failed")
		return false
	}

	// Build the canonical message from the template (Sigs excluded internally)
	msgHash := at.Hash()
	message := msgHash[:]

	// Try all 2-of-3 combinations in both orders (order-dependent)
	combinations := [][]int{
		{0, 1}, {1, 0},
		{0, 2}, {2, 0},
		{1, 2}, {2, 1},
	}
	for _, signerIndices := range combinations {
		if err := musig2.VerifyCompositeSignature(message, at.sigs, signerIndices); err == nil {
			return true
		}
	}

	log.Global.Warn("Signature verification failed for all signer combinations", at)

	return false
}

type AuxPowBlock struct {
	inner AuxPowBlockData
}

type AuxPowBlockData interface {
	Serialize(w io.Writer) error
	AddTransaction(tx *AuxPowTx) error
	Copy() AuxPowBlockData

	Header() AuxHeaderData

	// MWEB methods (only supported for Litecoin blocks)
	SetMwebBlock(header *ltcdwire.MwebHeader, txBody *ltcdwire.MwebTxBody) error
}

func NewAuxPowBlock(header *AuxPowHeader) *AuxPowBlock {
	auxBlock := &AuxPowBlock{}
	if header.inner == nil {
		return auxBlock
	}
	switch inner := header.inner.(type) {
	case *RavencoinBlockHeader:
		auxBlock.inner = NewRavencoinBlock(inner)
	case *BitcoinHeaderWrapper:
		auxBlock.inner = NewBitcoinBlockWrapper(inner.BlockHeader)
	case *BitcoinCashHeaderWrapper:
		auxBlock.inner = NewBitcoinCashBlockWrapper(inner.BlockHeader)
	case *LitecoinHeaderWrapper:
		auxBlock.inner = NewLitecoinBlockWrapper(inner.BlockHeader)
	default:
		return nil
	}
	return auxBlock
}

func (auxBlock *AuxPowBlock) Header() AuxHeaderData {
	if auxBlock.inner == nil {
		return &BitcoinHeaderWrapper{}
	}
	return auxBlock.inner.Header()
}

func (auxBlock *AuxPowBlock) AddTransaction(tx *AuxPowTx) error {
	if auxBlock.inner == nil {
		return fmt.Errorf("cannot add transaction: block is nil")
	}
	return auxBlock.inner.AddTransaction(tx)
}

func (auxBlock *AuxPowBlock) Serialize(w io.Writer) error {
	if auxBlock.inner == nil {
		return fmt.Errorf("cannot serialize AuxPowBlock: inner block is nil")
	}
	return auxBlock.inner.Serialize(w)
}

// MWEB methods - delegate to inner implementation with type checking
func (auxBlock *AuxPowBlock) SetMwebBlock(header *ltcdwire.MwebHeader, txBody *ltcdwire.MwebTxBody) error {
	if auxBlock.inner == nil {
		return fmt.Errorf("cannot set MWEB header: inner block is nil")
	}
	return auxBlock.inner.SetMwebBlock(header, txBody)
}

type AuxPowHeader struct {
	inner AuxHeaderData
}

type AuxHeaderData interface {
	Serialize(w io.Writer) error
	Deserialize(r io.Reader) error
	PowHash() common.Hash
	Copy() AuxHeaderData

	// Common blockchain header fields
	GetVersion() int32
	GetPrevBlock() [32]byte
	GetMerkleRoot() [32]byte
	GetTimestamp() uint32
	GetBits() uint32
	GetNonce() uint32
	GetHeight() uint32        // For chains that include height in header (e.g., KAWPOW)
	GetNonce64() uint64       // Only implemented for kawpow
	GetMixHash() common.Hash  // Only implemented for kawpow
	GetSealHash() common.Hash // Only implemented for kawpow, this is the hash on which PoW is done

	SetNonce(nonce uint32)

	SetNonce64(nonce uint64)        // Only implemented for kawpow
	SetMixHash(mixHash common.Hash) // Only implemented for kawpow
	SetHeight(height uint32)        // Only implemented for kawpow
}

func NewBlockHeader(powid PowID, version int32, prevBlockHash [32]byte, merkleRootHash [32]byte, time uint32, bits uint32, nonce uint32, height uint32) *AuxPowHeader {
	ah := &AuxPowHeader{}
	switch powid {
	case Kawpow:
		ah.inner = NewRavencoinBlockHeader(version, prevBlockHash, merkleRootHash, time, bits, height)
	case SHA_BTC:
		ah.inner = NewBitcoinBlockHeader(version, prevBlockHash, merkleRootHash, time, bits, nonce)
	case SHA_BCH:
		ah.inner = NewBitcoinCashBlockHeader(version, prevBlockHash, merkleRootHash, time, bits, nonce)
	case Scrypt:
		ah.inner = NewLitecoinBlockHeader(version, prevBlockHash, merkleRootHash, time, bits, nonce)
	default:
		return nil
	}
	return ah
}

func (ah *AuxPowHeader) PowHash() common.Hash {
	if ah.inner == nil {
		return common.Hash{}
	}
	return ah.inner.PowHash()
}

// Accessor methods that delegate to the inner header
func (ah *AuxPowHeader) Version() int32 {
	if ah.inner == nil {
		return 0
	}
	return ah.inner.GetVersion()
}

func (ah *AuxPowHeader) PrevBlock() [32]byte {
	if ah.inner == nil {
		return [32]byte{}
	}
	return ah.inner.GetPrevBlock()
}

func (ah *AuxPowHeader) MerkleRoot() [32]byte {
	if ah.inner == nil {
		return [32]byte{}
	}
	return ah.inner.GetMerkleRoot()
}

func (ah *AuxPowHeader) Timestamp() uint32 {
	if ah.inner == nil {
		return 0
	}
	return ah.inner.GetTimestamp()
}

func (ah *AuxPowHeader) Bits() uint32 {
	if ah.inner == nil {
		return 0
	}
	return ah.inner.GetBits()
}

func (ah *AuxPowHeader) Nonce() uint32 {
	if ah.inner == nil {
		return 0
	}
	return ah.inner.GetNonce()
}

func (ah *AuxPowHeader) Nonce64() uint64 {
	if ah.inner == nil {
		return 0
	}
	return ah.inner.GetNonce64()
}

func (ah *AuxPowHeader) SealHash() common.Hash {
	if ah.inner == nil {
		return common.Hash{}
	}
	return ah.inner.GetSealHash()
}

func (ah *AuxPowHeader) MixHash() common.Hash {
	if ah.inner == nil {
		return common.Hash{}
	}
	return ah.inner.GetMixHash()
}

func (ah *AuxPowHeader) Height() uint32 {
	if ah.inner == nil {
		return 0
	}
	return ah.inner.GetHeight()
}

func (ah *AuxPowHeader) Bytes() []byte {
	if ah.inner == nil {
		return nil
	}
	var buffer bytes.Buffer
	ah.inner.Serialize(&buffer)
	return buffer.Bytes()
}

func (ah *AuxPowHeader) SetNonce64(nonce uint64) {
	if ah.inner == nil {
		return
	}
	ah.inner.SetNonce64(nonce)
}

func (ah *AuxPowHeader) SetMixHash(mixHash common.Hash) {
	if ah.inner == nil {
		return
	}
	ah.inner.SetMixHash(mixHash)
}

func (ah *AuxPowHeader) SetHeight(height uint32) {
	if ah.inner == nil {
		return
	}
	ah.inner.SetHeight(height)
}

func (ah *AuxPowHeader) SetNonce(nonce uint32) {
	if ah.inner == nil {
		return
	}
	ah.inner.SetNonce(nonce)
}

func (ah *AuxPowHeader) setInner(inner AuxHeaderData) {
	ah.inner = inner
}

func (ah *AuxPowHeader) Copy() *AuxPowHeader {
	if ah.inner == nil {
		return &AuxPowHeader{}
	}
	return &AuxPowHeader{inner: ah.inner.Copy()}
}

func NewAuxPowHeader(inner AuxHeaderData) *AuxPowHeader {
	auxHeader := new(AuxPowHeader)
	auxHeader.setInner(inner)
	return auxHeader
}

type AuxPowTx struct {
	inner AuxPowTxData
}

type AuxPowTxData interface {
	Serialize(w io.Writer) error
	SerializeNoWitness(w io.Writer) error
	Deserialize(r io.Reader) error
	DeserializeNoWitness(r io.Reader) error
	Copy() AuxPowTxData
	txHash() [32]byte
	txOut() []*AuxPowCoinbaseOut

	scriptSig() []byte
	value() int64
	version() int32
	pkScript() []byte
}

func NewAuxPowCoinbaseTx(powId PowID, height uint32, coinbaseOut []byte, auxMerkleRoot common.Hash, signatureTime uint32, witness bool) []byte {
	switch powId {
	case Kawpow:
		return NewRavencoinCoinbaseTx(height, coinbaseOut, auxMerkleRoot, signatureTime, witness)
	case SHA_BTC:
		return NewBitcoinCoinbaseTxWrapper(height, coinbaseOut, auxMerkleRoot, signatureTime, witness)
	case SHA_BCH:
		return NewBitcoinCashCoinbaseTxWrapper(height, coinbaseOut, auxMerkleRoot, signatureTime)
	case Scrypt:
		return NewLitecoinCoinbaseTxWrapper(height, coinbaseOut, auxMerkleRoot, signatureTime, witness)
	default:
		return []byte{}
	}
}

// NewAuxPowTx creates an AuxPowTx from an AuxPowTxData implementation
func NewAuxPowTx(inner AuxPowTxData) *AuxPowTx {
	return &AuxPowTx{inner: inner}
}

func (ac *AuxPowTx) Bytes() []byte {
	if ac.inner == nil {
		return nil
	}
	var buffer bytes.Buffer
	ac.inner.SerializeNoWitness(&buffer)
	return buffer.Bytes()
}

func (ac *AuxPowTx) Copy() *AuxPowTx {
	if ac.inner == nil {
		return &AuxPowTx{}
	}
	return &AuxPowTx{inner: ac.inner.Copy()}
}

func (ac *AuxPowTx) Serialize(w io.Writer, witness bool) error {
	if ac.inner == nil {
		return errors.New("inner transaction is nil")
	}
	if witness {
		return ac.inner.Serialize(w)
	}
	return ac.inner.SerializeNoWitness(w)
}

func (ac *AuxPowTx) Deserialize(r io.Reader, witness bool) error {
	if ac.inner == nil {
		return errors.New("inner transaction is nil")
	}
	if witness {
		return ac.inner.Deserialize(r)
	}
	return ac.inner.DeserializeNoWitness(r)
}

func (ac *AuxPowTx) ScriptSig() []byte {
	if ac.inner == nil {
		return nil
	}
	return ac.inner.scriptSig()
}

func (ac *AuxPowTx) Value() int64 {
	if ac.inner == nil {
		return 0
	}
	return ac.inner.value()
}

func (ac *AuxPowTx) Version() int32 {
	if ac.inner == nil {
		return 0
	}
	return ac.inner.version()
}

func (ac *AuxPowTx) TxHash() [common.HashLength]byte {
	if ac.inner == nil {
		return common.Hash{}
	}
	return ac.inner.txHash()
}

func (ac *AuxPowTx) PkScript() []byte {
	if ac.inner == nil {
		return nil
	}
	return ac.inner.pkScript()
}

func (ac *AuxPowTx) TxOut() []*AuxPowCoinbaseOut {
	if ac.inner == nil {
		return nil
	}
	return ac.inner.txOut()
}

type AuxPowCoinbaseOut struct {
	inner AuxPowCoinbaseOutData
}

type AuxPowCoinbaseOutData interface {
	Value() int64
	PkScript() []byte
}

func NewAuxPowCoinbaseOut(powId PowID, value int64, pkScript []byte) *AuxPowCoinbaseOut {
	switch powId {
	case Kawpow:
		return &AuxPowCoinbaseOut{inner: NewRavencoinCoinbaseTxOut(value, pkScript)}
	case SHA_BTC:
		return &AuxPowCoinbaseOut{inner: NewBitcoinCoinbaseTxOut(value, pkScript)}
	case SHA_BCH:
		return &AuxPowCoinbaseOut{inner: NewBitcoinCashCoinbaseTxOut(value, pkScript)}
	case Scrypt:
		return &AuxPowCoinbaseOut{inner: NewLitecoinCoinbaseTxOut(value, pkScript)}
	default:
		return &AuxPowCoinbaseOut{}
	}
}

func (aco *AuxPowCoinbaseOut) Value() int64 {
	if aco.inner == nil {
		return 0
	}
	return aco.inner.Value()
}

func (aco *AuxPowCoinbaseOut) PkScript() []byte {
	if aco.inner == nil {
		return nil
	}
	return aco.inner.PkScript()
}

func (aco *AuxPowCoinbaseOut) RPCMarshal() map[string]interface{} {
	if aco == nil || aco.inner == nil {
		return nil
	}

	return map[string]interface{}{
		"powid":        hexutil.Uint64(aco.PowId()),
		"value":        hexutil.Uint64(aco.Value()),
		"scriptPubKey": hexutil.Bytes(aco.inner.PkScript()),
	}
}

func (aco *AuxPowCoinbaseOut) PowId() PowID {
	if aco == nil || aco.inner == nil {
		return 0
	}

	switch aco.inner.(type) {
	case *RavencoinCoinbaseTxOut:
		return Kawpow
	case *BitcoinCoinbaseTxOutWrapper:
		return SHA_BTC
	case *BitcoinCashCoinbaseTxOutWrapper:
		return SHA_BCH
	case *LitecoinCoinbaseTxOutWrapper:
		return Scrypt
	default:
		return 0
	}
}

func (aco *AuxPowCoinbaseOut) MarshalJSON() ([]byte, error) {
	return json.Marshal(aco.RPCMarshal())
}

func (aco *AuxPowCoinbaseOut) UnmarshalJSON(data []byte) error {

	var dec struct {
		PowId  *hexutil.Uint64 `json:"powid"`
		Value  *hexutil.Uint64 `json:"value"`
		Script hexutil.Bytes   `json:"scriptPubKey"`
	}

	if err := json.Unmarshal(data, &dec); err != nil {
		return err
	}

	if dec.PowId == nil || dec.Value == nil || dec.Script == nil {
		return errors.New("missing required fields in AuxPowCoinbaseOut")
	}

	powId := PowID(*dec.PowId)
	value := *dec.Value
	scriptHex := dec.Script

	// Initialize inner
	aco.inner = &AuxPowCoinbaseOut{}

	switch powId {
	case Kawpow:
		txOut := *btcdwire.NewTxOut(int64(value), scriptHex)
		// Here we assume RavencoinCoinbaseTxOut for simplicity; adapt as needed
		aco.inner = &RavencoinCoinbaseTxOut{TxOut: &txOut}
	case SHA_BTC:
		txOut := *btcdwire.NewTxOut(int64(value), scriptHex)
		// Here we assume BitcoinCoinbaseTxOutWrapper for simplicity; adapt as needed
		aco.inner = &BitcoinCoinbaseTxOutWrapper{TxOut: &txOut}
	case SHA_BCH:
		txOut := *bchdwire.NewTxOut(int64(value), scriptHex, bchdwire.TokenData{})
		// Here we assume BitcoinCashCoinbaseTxOutWrapper for simplicity; adapt as needed
		aco.inner = &BitcoinCashCoinbaseTxOutWrapper{TxOut: &txOut}
	case Scrypt:
		txOut := *ltcdwire.NewTxOut(int64(value), scriptHex)
		// Here we assume LitecoinCoinbaseTxOutWrapper for simplicity; adapt as needed
		aco.inner = &LitecoinCoinbaseTxOutWrapper{TxOut: &txOut}
	}

	return nil
}

// AuxPow represents auxiliary proof-of-work data
type AuxPow struct {
	powID        PowID         // PoW algorithm identifier
	auxPow2      []byte        // Auxiliary proof-of-work data
	header       *AuxPowHeader // 120B donor header for KAWPOW
	signature    []byte        // Signature proving the work
	merkleBranch [][]byte      // siblings for coinbase index=0 up to root (little endian 32-byte hashes)
	transaction  []byte        // Full coinbase transaction (contains value in TxOut[0])
}

func NewAuxPow(powID PowID, header *AuxPowHeader, auxPow2 []byte, signature []byte, merkleBranch [][]byte, transaction []byte) *AuxPow {
	return &AuxPow{
		powID:        powID,
		auxPow2:      auxPow2,
		header:       header,
		signature:    signature,
		merkleBranch: merkleBranch,
		transaction:  transaction,
	}
}

func (ap *AuxPow) ConvertToTemplate() *AuxTemplate {
	auxTemplate := &AuxTemplate{}
	auxTemplate.SetPowID(ap.powID)
	auxTemplate.SetPrevHash(ap.header.PrevBlock())
	auxTemplate.SetVersion(uint32(ap.header.Version()))
	auxTemplate.SetNBits(ap.header.Bits())
	auxTemplate.SetAuxPow2(ap.auxPow2)

	scriptSig := ExtractScriptSigFromCoinbaseTx(ap.transaction)

	signatureTime, err := ExtractSignatureTimeFromCoinbase(scriptSig)
	if err != nil {
		signatureTime = 0
	}
	auxTemplate.SetNTimeMask(NTimeMask(signatureTime))
	// Height is encoded in the script sig for non kawpow chains
	switch ap.powID {
	case Kawpow:
		// For KAWPOW, set height from header
		auxTemplate.SetHeight(ap.header.Height())
	default:
		height, err := ExtractHeightFromCoinbase(scriptSig)
		if err != nil {
			height = 0
		}
		auxTemplate.SetHeight(height)
	}
	auxTemplate.SetCoinbaseOut(ExtractCoinbaseOutFromCoinbaseTx(ap.transaction))
	auxTemplate.SetMerkleBranch(ap.merkleBranch)
	auxTemplate.SetSigs(ap.signature)
	return auxTemplate
}

func (ap *AuxPow) PowID() PowID { return ap.powID }

func (ap *AuxPow) Header() *AuxPowHeader { return ap.header }

func (ap *AuxPow) Signature() []byte { return ap.signature }

func (ap *AuxPow) AuxPow2() []byte { return ap.auxPow2 }

func (ap *AuxPow) MerkleBranch() [][]byte { return ap.merkleBranch }

func (ap *AuxPow) Transaction() []byte { return ap.transaction }

func (ap *AuxPow) SetPowID(id PowID) { ap.powID = id }

func (ap *AuxPow) SetAuxPow2(auxPow2 []byte) { ap.auxPow2 = auxPow2 }

func (ap *AuxPow) SetHeader(header *AuxPowHeader) { ap.header = header }

func (ap *AuxPow) SetSignature(sig []byte) { ap.signature = sig }

func (ap *AuxPow) SetMerkleBranch(branch [][]byte) { ap.merkleBranch = branch }

func (ap *AuxPow) SetTransaction(tx []byte) { ap.transaction = tx }

func CopyAuxPow(ap *AuxPow) *AuxPow {
	if ap == nil {
		return nil
	}

	// Deep copy merkle branch
	merkleBranch := make([][]byte, len(ap.merkleBranch))
	for i, hash := range ap.merkleBranch {
		merkleBranch[i] = make([]byte, len(hash))
		copy(merkleBranch[i], hash)
	}

	// Deep copy signature
	signature := make([]byte, len(ap.signature))
	copy(signature, ap.signature)

	// Deep copy transaction
	transaction := make([]byte, len(ap.transaction))
	copy(transaction, ap.transaction)

	var header *AuxPowHeader
	if ap.header != nil {
		header = ap.header.Copy()
	}
	auxpow2 := make([]byte, len(ap.auxPow2))
	copy(auxpow2, ap.auxPow2)

	return &AuxPow{
		powID:        ap.powID,
		auxPow2:      auxpow2,
		header:       header,
		signature:    signature,
		merkleBranch: merkleBranch,
		transaction:  transaction,
	}
}

// RPCMarshal converts AuxPow to a map for RPC serialization
func (ap *AuxPow) RPCMarshal() map[string]interface{} {
	if ap == nil {
		return nil
	}

	// Convert merkle branch to hex strings
	merkleBranch := make([]hexutil.Bytes, len(ap.merkleBranch))
	for i, hash := range ap.merkleBranch {
		merkleBranch[i] = hexutil.Bytes(hash)
	}

	return map[string]interface{}{
		"powId":        hexutil.Uint64(ap.powID),
		"header":       hexutil.Bytes(ap.header.Bytes()),
		"auxpow2":      hexutil.Bytes(ap.auxPow2),
		"signature":    hexutil.Bytes(ap.signature),
		"merkleBranch": merkleBranch,
		"transaction":  hexutil.Bytes(ap.transaction),
	}
}

// UnmarshalJSON implements json.Unmarshaler for AuxPow
func (ap *AuxPow) UnmarshalJSON(data []byte) error {
	var dec struct {
		PowID        *hexutil.Uint64 `json:"powId"`
		Header       *hexutil.Bytes  `json:"header"`
		Auxpow2      *hexutil.Bytes  `json:"auxpow2"`
		Signature    *hexutil.Bytes  `json:"signature"`
		MerkleBranch []hexutil.Bytes `json:"merkleBranch"`
		Transaction  *hexutil.Bytes  `json:"transaction"`
	}

	if err := json.Unmarshal(data, &dec); err != nil {
		return err
	}

	if dec.PowID == nil {
		return errors.New("missing required fields 'powId' in AuxPow")
	}

	if dec.Header == nil {
		return errors.New("missing required fields 'header' in AuxPow")
	}

	if dec.Auxpow2 == nil {
		return errors.New("missing required fields 'auxpow2' in AuxPow")
	}

	if dec.Signature == nil {
		return errors.New("missing required fields 'signature' in AuxPow")
	}

	if dec.MerkleBranch == nil {
		return errors.New("missing required fields 'merkleBranch' in AuxPow")
	}

	ap.powID = PowID(*dec.PowID)

	switch ap.powID {
	case Kawpow:
		header := &RavencoinBlockHeader{}
		if err := header.Deserialize(bytes.NewReader(*dec.Header)); err != nil {
			return err
		}
		ap.header = NewAuxPowHeader(header)
	case SHA_BTC:
		header := &BitcoinHeaderWrapper{}
		if err := header.Deserialize(bytes.NewReader(*dec.Header)); err != nil {
			return err
		}
		ap.header = NewAuxPowHeader(header)
	case SHA_BCH:
		header := &BitcoinCashHeaderWrapper{}
		if err := header.Deserialize(bytes.NewReader(*dec.Header)); err != nil {
			return err
		}
		ap.header = NewAuxPowHeader(header)
	case Scrypt:
		header := &LitecoinHeaderWrapper{}
		if err := header.Deserialize(bytes.NewReader(*dec.Header)); err != nil {
			return err
		}
		ap.header = NewAuxPowHeader(header)
	}

	// Decode auxpow2
	ap.auxPow2 = *dec.Auxpow2
	// Decode signature
	ap.signature = *dec.Signature
	// Decode merkle branch
	merkleBranch := make([][]byte, len(dec.MerkleBranch))
	for i, hash := range dec.MerkleBranch {
		merkleBranch[i] = hash
	}
	ap.merkleBranch = merkleBranch

	ap.transaction = *dec.Transaction

	return nil
}

// ProtoEncode converts AuxPow to its protobuf representation
func (ap *AuxPow) ProtoEncode() *ProtoAuxPow {
	if ap == nil {
		return nil
	}

	powID := uint32(ap.PowID())

	// Convert merkle branch
	merkleBranch := make([][]byte, len(ap.MerkleBranch()))
	copy(merkleBranch, ap.MerkleBranch())

	return &ProtoAuxPow{
		ChainId:      &powID,
		Auxpow2:      ap.auxPow2,
		Header:       ap.Header().Bytes(),
		Signature:    ap.Signature(),
		MerkleBranch: merkleBranch,
		Transaction:  ap.Transaction(),
	}
}

// ProtoDecode populates AuxPow from its protobuf representation
func (ap *AuxPow) ProtoDecode(data *ProtoAuxPow) error {
	if data == nil {
		return nil
	}

	ap.SetPowID(PowID(data.GetChainId()))

	switch ap.PowID() {
	case Kawpow:
		header := &RavencoinBlockHeader{}
		if err := header.Deserialize(bytes.NewReader(data.GetHeader())); err != nil {
			return err
		}
		ap.SetHeader(NewAuxPowHeader(header))
	case SHA_BTC:
		header := &BitcoinHeaderWrapper{}
		if err := header.Deserialize(bytes.NewReader(data.GetHeader())); err != nil {
			return err
		}
		ap.SetHeader(NewAuxPowHeader(header))
	case SHA_BCH:
		header := &BitcoinCashHeaderWrapper{}
		if err := header.Deserialize(bytes.NewReader(data.GetHeader())); err != nil {
			return err
		}
		ap.SetHeader(NewAuxPowHeader(header))
	case Scrypt:
		header := &LitecoinHeaderWrapper{}
		if err := header.Deserialize(bytes.NewReader(data.GetHeader())); err != nil {
			return err
		}
		ap.SetHeader(NewAuxPowHeader(header))
	default:
		return errors.New("unsupported powId for AuxPow header")
	}
	ap.SetSignature(data.GetSignature())

	// Decode merkle branch
	ap.merkleBranch = make([][]byte, len(data.GetMerkleBranch()))
	for i, hash := range data.GetMerkleBranch() {
		ap.merkleBranch[i] = make([]byte, len(hash))
		copy(ap.merkleBranch[i], hash)
	}

	ap.transaction = data.GetTransaction()
	ap.auxPow2 = data.GetAuxpow2()

	return nil
}

// NewAuxPowTxFromBytes constructs an AuxPowTx for the given powId by deserializing raw bytes
// into the appropriate chain-specific transaction wrapper.
func NewAuxPowTxFromBytes(powId PowID, raw []byte, witness bool) (*AuxPowTx, error) {
	switch powId {
	case SHA_BTC:
		tx := &BitcoinTxWrapper{btcdwire.NewMsgTx(1)}
		if witness {
			if err := tx.Deserialize(bytes.NewReader(raw)); err != nil {
				return nil, err
			}
		} else {
			if err := tx.DeserializeNoWitness(bytes.NewReader(raw)); err != nil {
				return nil, err
			}
		}
		return &AuxPowTx{inner: tx}, nil
	case SHA_BCH:
		tx := &BitcoinCashTxWrapper{bchdwire.NewMsgTx(2)}
		if witness {
			if err := tx.Deserialize(bytes.NewReader(raw)); err != nil {
				return nil, err
			}
		} else {
			if err := tx.DeserializeNoWitness(bytes.NewReader(raw)); err != nil {
				return nil, err
			}
		}
		return &AuxPowTx{inner: tx}, nil
	case Scrypt:
		tx := &LitecoinTxWrapper{ltcdwire.NewMsgTx(1)}
		if witness {
			if err := tx.Deserialize(bytes.NewReader(raw)); err != nil {
				return nil, err
			}
		} else {
			if err := tx.DeserializeNoWitness(bytes.NewReader(raw)); err != nil {
				return nil, err
			}
		}
		return &AuxPowTx{inner: tx}, nil
	case Kawpow:
		tx := &RavencoinTx{btcdwire.NewMsgTx(2)}
		if witness {
			if err := tx.Deserialize(bytes.NewReader(raw)); err != nil {
				return nil, err
			}
		} else {
			if err := tx.DeserializeNoWitness(bytes.NewReader(raw)); err != nil {
				return nil, err
			}
		}
		return &AuxPowTx{inner: tx}, nil
	default:
		return nil, fmt.Errorf("unsupported powId for AuxPowTx")
	}
}

func AuxPowTxHash(PowID PowID, tx []byte) common.Hash {
	switch PowID {
	case SHA_BTC, Kawpow:
		return common.Hash(btcchainhash.DoubleHashH(tx))
	case SHA_BCH:
		return common.Hash(bchchainhash.DoubleHashH(tx))
	case Scrypt:
		return common.Hash(ltcchainhash.DoubleHashH(tx))
	}
	return common.Hash{}
}

func reverseBytesCopy(b []byte) []byte {
	out := make([]byte, len(b))
	for i := range b {
		out[i] = b[len(b)-1-i]
	}
	return out
}
