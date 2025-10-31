package types

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	btcblockchain "github.com/btcsuite/btcd/blockchain"
	btcutil "github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/dominant-strategies/go-quai/common"
	ltcblockchain "github.com/dominant-strategies/ltcd/blockchain"
	ltcchainhash "github.com/dominant-strategies/ltcd/chaincfg/chainhash"
	ltcutil "github.com/dominant-strategies/ltcd/ltcutil"
	bchblockchain "github.com/gcash/bchd/blockchain"
	bchchainhash "github.com/gcash/bchd/chaincfg/chainhash"
	bchutil "github.com/gcash/bchutil"
)

// ExtractSealHashFromCoinbase extracts the seal hash from the coinbase scriptSig format.
// Format:
//
//	OP_PUSH<n> <height(variable bytes)> ← BIP34 height (minimal encoding, 0-5 bytes)
//	OP_PUSH4   <fabe6d6d(4 bytes)>      ← Magic marker
//	OP_PUSH32  <AuxPowHash(32 bytes)>   ← Seal hash (this is what we extract)
//	OP_PUSH4   <merkle_size(4 bytes)>
//	OP_PUSH4   <merkle_nonce(4 bytes)>
//	OP_PUSH44  <extraNonce1(4 bytes) + extraNonce2(8 bytes) + extraData(32 bytes)> ← Combined extranonces (Bitcoin standard) + extraData (32 bytes)
//  OP_PUSH4   <signature_time>

func ExtractSealHashFromCoinbase(scriptSig []byte) (common.Hash, error) {
	if len(scriptSig) == 0 {
		return common.Hash{}, errors.New("coinbase scriptSig empty")
	}

	cursor := 0

	// 1. Parse and skip height (variable length - BIP34 minimal encoding)
	heightData, consumed, err := parseScriptPush(scriptSig[cursor:])
	if err != nil {
		return common.Hash{}, fmt.Errorf("decode coinbase height: %w", err)
	}
	// Height can be 0-5 bytes (BIP34 allows minimal encoding)
	if len(heightData) > 5 {
		return common.Hash{}, fmt.Errorf("invalid height length: expected 0-5 bytes, got %d", len(heightData))
	}
	cursor += consumed

	// 2. Parse and verify magic marker (should be "fabe6d6d")
	magicData, consumed, err := parseScriptPush(scriptSig[cursor:])
	if err != nil {
		return common.Hash{}, fmt.Errorf("decode magic marker: %w", err)
	}
	if len(magicData) != 4 {
		return common.Hash{}, fmt.Errorf("invalid magic marker length: expected 4, got %d", len(magicData))
	}
	expectedMagic := []byte{0xfa, 0xbe, 0x6d, 0x6d}
	if !bytes.Equal(magicData, expectedMagic) {
		return common.Hash{}, fmt.Errorf("invalid magic marker: expected %x, got %x", expectedMagic, magicData)
	}
	cursor += consumed

	// 3. Parse seal hash (32 bytes) - this is what we're looking for!
	sealHashData, _, err := parseScriptPush(scriptSig[cursor:])
	if err != nil {
		return common.Hash{}, fmt.Errorf("decode seal hash: %w", err)
	}
	if len(sealHashData) != common.HashLength {
		return common.Hash{}, fmt.Errorf("invalid seal hash length: expected %d, got %d", common.HashLength, len(sealHashData))
	}

	return common.BytesToHash(sealHashData), nil
}

// ExtractSignatureTimeFromCoinbase extracts the signature time from the coinbase scriptSig format.
// Format:
//
//	OP_PUSH<n> <height(variable bytes)> ← BIP34 height (minimal encoding, 0-5 bytes)
//	OP_PUSH4   <fabe6d6d(4 bytes)>      ← Magic marker
//	OP_PUSH32  <AuxPowHash(32 bytes)>   ← Seal hash (this is what we extract)
//	OP_PUSH4   <merkle_size(4 bytes)>
//	OP_PUSH4   <merkle_nonce(4 bytes)>
//	OP_PUSH42  <extraNonce1(4 bytes) + extraNonce2(8 bytes) + extraData(30 bytes)> ← Combined extranonces (Bitcoin standard) + extraData (30 bytes)
//  OP_PUSH4   <signature_time>

func ExtractSignatureTimeFromCoinbase(scriptSig []byte) (uint32, error) {
	if len(scriptSig) == 0 {
		return 0, errors.New("coinbase scriptSig empty")
	}

	cursor := 0

	// 1. Parse and skip height (variable length - BIP34 minimal encoding)
	heightData, consumed, err := parseScriptPush(scriptSig[cursor:])
	if err != nil {
		return 0, fmt.Errorf("decode coinbase height: %w", err)
	}
	// Height can be 0-5 bytes (BIP34 allows minimal encoding)
	if len(heightData) > 5 {
		return 0, fmt.Errorf("invalid height length: expected 0-5 bytes, got %d", len(heightData))
	}
	cursor += consumed

	// 2. Parse and verify magic marker (should be "fabe6d6d")
	magicData, consumed, err := parseScriptPush(scriptSig[cursor:])
	if err != nil {
		return 0, fmt.Errorf("decode magic marker: %w", err)
	}
	if len(magicData) != 4 {
		return 0, fmt.Errorf("invalid magic marker length: expected 4, got %d", len(magicData))
	}
	expectedMagic := []byte{0xfa, 0xbe, 0x6d, 0x6d}
	if !bytes.Equal(magicData, expectedMagic) {
		return 0, fmt.Errorf("invalid magic marker: expected %x, got %x", expectedMagic, magicData)
	}
	cursor += consumed

	// Add 86 bytes to skip: which covers the seal hash (32 bytes), merkle size (4 bytes), merkle nonce (4 bytes), and combined extra nonces + extraData (44 bytes)
	cursor += 86

	if cursor >= len(scriptSig) {
		return 0, errors.New("scriptSig too short to contain signature time")
	}

	// 3. Parse signature time (4 bytes)
	signatureTimeData, _, err := parseScriptPush(scriptSig[cursor:])
	if err != nil {
		return 0, fmt.Errorf("decode signature time: %w", err)
	}
	if len(signatureTimeData) != 4 {
		return 0, fmt.Errorf("invalid signature time length: expected 4, got %d", len(signatureTimeData))
	}

	return binary.LittleEndian.Uint32(signatureTimeData), nil
}

func parseScriptPush(script []byte) ([]byte, int, error) {
	if len(script) == 0 {
		return nil, 0, errors.New("empty script segment")
	}

	opcode := script[0]
	read := 1
	var dataLen int

	switch {
	case opcode <= 75:
		dataLen = int(opcode)
	case opcode == 0x4c: // OP_PUSHDATA1
		if len(script) < 2 {
			return nil, 0, errors.New("short OP_PUSHDATA1")
		}
		dataLen = int(script[1])
		read++
	case opcode == 0x4d: // OP_PUSHDATA2
		if len(script) < 3 {
			return nil, 0, errors.New("short OP_PUSHDATA2")
		}
		dataLen = int(binary.LittleEndian.Uint16(script[1:3]))
		read += 2
	default:
		return nil, 0, fmt.Errorf("unsupported opcode 0x%x in coinbase script", opcode)
	}

	if len(script) < read+dataLen {
		return nil, 0, errors.New("coinbase push exceeds script bounds")
	}

	return script[read : read+dataLen], read + dataLen, nil
}

// BuildCoinbaseScriptSigWithNonce creates a scriptSig for AuxPow coinbase with the Bitcoin standard format
// Format:
//
//		OP_PUSH<n> <height(variable bytes)> ← BIP34 height (MINIMAL encoding)
//		OP_PUSH4   <fabe6d6d(4 bytes)>      ← Magic marker
//		OP_PUSH32  <AuxMerkleRoot(32 bytes)>     ← Quai seal hash or aux merkle root
//		OP_PUSH4   <merkle_size(4 bytes)>   ← 1
//		OP_PUSH4   <merkle_nonce(4 bytes)>  ← 0
//		OP_PUSH42  <extraNonce1(4 bytes) + extraNonce2(8 bytes) + extraData(30 bytes)> ← Combined extranonces (Bitcoin standard) + extraData (30 bytes)
//	    OP_PUSH4   <signature_time> ← time from the aux template
func BuildCoinbaseScriptSigWithNonce(blockHeight uint32, extraNonce1 uint32, extraNonce2 uint64, auxMerkleRoot common.Hash, merkleSize uint32, signatureTime uint32) []byte {
	var buf bytes.Buffer

	// 1. BIP34: Block height (minimal encoding - variable length)
	// Must use minimal/compact encoding for BIP34 compliance
	heightBytes := encodeHeightForBIP34(blockHeight)
	if len(heightBytes) <= 75 {
		buf.WriteByte(byte(len(heightBytes))) // Direct push for <= 75 bytes
	} else if len(heightBytes) <= 255 {
		buf.WriteByte(0x4c) // OP_PUSHDATA1
		buf.WriteByte(byte(len(heightBytes)))
	}
	buf.Write(heightBytes)

	// 2. Magic marker "fabe6d6d" (4 bytes)
	// This marks the start of the AuxPow-specific data
	buf.WriteByte(0x04) // OP_PUSH4
	buf.WriteByte(0xfa)
	buf.WriteByte(0xbe)
	buf.WriteByte(0x6d)
	buf.WriteByte(0x6d)

	// 3. Seal hash (32 bytes)
	// Use provided seal hash, or zeros if not provided
	buf.WriteByte(0x20) // OP_PUSH32 (32 decimal = 0x20 hex)
	buf.Write(auxMerkleRoot[:])

	// 4. Merkle size (4 bytes, little-endian) - always 1 for single coinbase
	buf.WriteByte(0x04) // OP_PUSH4
	binary.Write(&buf, binary.LittleEndian, merkleSize)

	// 5. Merkle nonce (4 bytes, little-endian) - always 0
	buf.WriteByte(0x04) // OP_PUSH4
	binary.Write(&buf, binary.LittleEndian, uint32(0))

	// 6. Combined extra nonces and extraData (42 bytes total, little-endian)
	// Bitcoin standard: extraNonce1 (4 bytes) + extraNonce2 (8 bytes) + extraData (30 bytes) in a single push
	buf.WriteByte(0x2a) // OP_PUSH42 (42 decimal = 0x2a hex)
	binary.Write(&buf, binary.LittleEndian, extraNonce1)
	binary.Write(&buf, binary.LittleEndian, extraNonce2)
	// extraData: 30 bytes of zeros for now (can be used for additional miner data)
	buf.Write(make([]byte, 30))

	// 7. Signature time (4 bytes, little-endian)
	buf.WriteByte(0x04)
	binary.Write(&buf, binary.LittleEndian, signatureTime)

	return buf.Bytes()
}

// VerifyMerkleProof verifies a merkle proof for a transaction at index 0 (coinbase)
// merkleBranch contains the sibling hashes from leaf to root
func CalculateMerkleRoot(powId PowID, coinbaseTx []byte, merkleBranch [][]byte) [common.HashLength]byte {

	switch powId {
	case Kawpow, SHA_BTC:
		// Start with the transaction hash
		currentHash := chainhash.Hash(AuxPowTxHash(powId, coinbaseTx))

		// For coinbase (index 0), we always take the right branch
		// and our hash goes on the left
		for _, siblingBytes := range merkleBranch {
			var sibling chainhash.Hash
			copy(sibling[:], siblingBytes)

			// Since we're at index 0 (coinbase), we're always the left child
			currentHash = btcblockchain.HashMerkleBranches(&currentHash, &sibling)
		}
		return currentHash
	case Scrypt:
		// Start with the transaction hash
		currentHash := ltcchainhash.Hash(AuxPowTxHash(powId, coinbaseTx))

		// For coinbase (index 0), we always take the right branch
		// and our hash goes on the left
		for _, siblingBytes := range merkleBranch {
			var sibling ltcchainhash.Hash
			copy(sibling[:], siblingBytes)

			// Since we're at index 0 (coinbase), we're always the left child
			currentHash = ltcblockchain.HashMerkleBranches(&currentHash, &sibling)
		}
		return currentHash
	case SHA_BCH:
		// Start with the transaction hash
		currentHash := bchchainhash.Hash(AuxPowTxHash(powId, coinbaseTx))

		// For coinbase (index 0), we always take the right branch
		// and our hash goes on the left
		for _, siblingBytes := range merkleBranch {
			var sibling bchchainhash.Hash
			copy(sibling[:], siblingBytes)

			// Since we're at index 0 (coinbase), we're always the left child
			currentHash = *bchblockchain.HashMerkleBranches(&currentHash, &sibling)
		}
		return currentHash
	default:
		return [common.HashLength]byte{}
	}
}

func BuildMerkleTreeStore(powID PowID, txs []*AuxPowTx, witness bool) []*chainhash.Hash {
	switch powID {
	case Kawpow:
		transactions := make([]*btcutil.Tx, len(txs))
		for i, tx := range txs {
			ravenTx, ok := tx.inner.(*RavencoinTx)
			if !ok || ravenTx == nil || ravenTx.MsgTx == nil {
				return nil
			}
			transactions[i] = btcutil.NewTx(ravenTx.MsgTx)
		}
		return btcblockchain.BuildMerkleTreeStore(transactions, witness)
	case Scrypt:
		transactions := make([]*ltcutil.Tx, len(txs))
		for i, tx := range txs {
			litecoinTx, ok := tx.inner.(*LitecoinTxWrapper)
			if !ok || litecoinTx == nil || litecoinTx.MsgTx == nil {
				return nil
			}
			transactions[i] = ltcutil.NewTx(litecoinTx.MsgTx)
		}
		ltcTree := ltcblockchain.BuildMerkleTreeStore(transactions, witness)
		return convertLTCChainhashSlice(ltcTree)
	case SHA_BTC:
		transactions := make([]*btcutil.Tx, len(txs))
		for i, tx := range txs {
			bitcoinTx, ok := tx.inner.(*BitcoinTxWrapper)
			if !ok || bitcoinTx == nil || bitcoinTx.MsgTx == nil {
				return nil
			}
			transactions[i] = btcutil.NewTx(bitcoinTx.MsgTx)
		}
		return btcblockchain.BuildMerkleTreeStore(transactions, witness)
	case SHA_BCH:
		transactions := make([]*bchutil.Tx, len(txs))
		for i, tx := range txs {
			bitcoinCashTx, ok := tx.inner.(*BitcoinCashTxWrapper)
			if !ok || bitcoinCashTx == nil || bitcoinCashTx.MsgTx == nil {
				return nil
			}
			transactions[i] = bchutil.NewTx(bitcoinCashTx.MsgTx)
		}
		bchTree := bchblockchain.BuildMerkleTreeStore(transactions)
		return convertBCHChainhashSlice(bchTree)
	}
	return nil
}

func convertLTCChainhashSlice(input []*ltcchainhash.Hash) []*chainhash.Hash {
	if input == nil {
		return nil
	}
	out := make([]*chainhash.Hash, len(input))
	for i, h := range input {
		if h == nil {
			continue
		}
		converted := new(chainhash.Hash)
		copy(converted[:], h[:])
		out[i] = converted
	}
	return out
}

func convertBCHChainhashSlice(input []*bchchainhash.Hash) []*chainhash.Hash {
	if input == nil {
		return nil
	}
	out := make([]*chainhash.Hash, len(input))
	for i, h := range input {
		if h == nil {
			continue
		}
		converted := new(chainhash.Hash)
		copy(converted[:], h[:])
		out[i] = converted
	}
	return out
}

// ExtractMerkleBranch extracts the merkle branch for the coinbase (index 0)
// from a complete merkle tree
func ExtractMerkleBranch(merkleTree []*chainhash.Hash, txCount int) [][]byte {
	if len(merkleTree) == 0 || txCount == 0 {
		return nil
	}

	var branch [][]byte

	// blockchain.BuildMerkleTreeStore lays out the tree level-by-level using a
	// power-of-two leaf width. Determine that width so we can walk the levels.
	width := 1
	for width < txCount {
		width <<= 1
	}

	index := 0
	levelOffset := 0
	levelWidth := width

	for levelWidth > 1 {
		siblingIndex := index ^ 1
		siblingPos := levelOffset + siblingIndex
		if siblingIndex >= levelWidth || siblingPos >= len(merkleTree) || merkleTree[siblingPos] == nil {
			siblingPos = levelOffset + index
		}
		branch = append(branch, merkleTree[siblingPos][:])

		levelOffset += levelWidth
		index >>= 1
		levelWidth >>= 1
	}

	return branch
}

// encodeHeightForBIP34 encodes block height in minimal little-endian format
// This matches Bitcoin's CScriptNum serialization used for BIP34 compliance.
// The height must be encoded with the minimum number of bytes required.
func encodeHeightForBIP34(height uint32) []byte {
	if height == 0 {
		return []byte{}
	}

	// Convert to little-endian bytes, removing leading zeros
	result := make([]byte, 0, 4)
	for height > 0 {
		result = append(result, byte(height&0xff))
		height >>= 8
	}

	// If the most significant bit is set, add a zero byte to indicate positive number
	// This is part of Bitcoin's CScriptNum format to distinguish positive/negative
	if len(result) > 0 && (result[len(result)-1]&0x80) != 0 {
		result = append(result, 0x00)
	}

	return result
}

// TODO: Replace with a method from btcd/ltcd/bchd if available
// readVarInt decodes Bitcoin-style VarInts and returns the decoded value along with the number of bytes consumed.
func readVarInt(buf *bytes.Reader) (uint64, int, error) {
	b, err := buf.ReadByte()
	if err != nil {
		return 0, 0, err
	}

	switch b {
	case 0xfd:
		var v uint16
		if err := binary.Read(buf, binary.LittleEndian, &v); err != nil {
			return 0, 0, err
		}
		return uint64(v), 3, nil
	case 0xfe:
		var v uint32
		if err := binary.Read(buf, binary.LittleEndian, &v); err != nil {
			return 0, 0, err
		}
		return uint64(v), 5, nil
	case 0xff:
		var v uint64
		if err := binary.Read(buf, binary.LittleEndian, &v); err != nil {
			return 0, 0, err
		}
		return v, 9, nil
	default:
		return uint64(b), 1, nil
	}
}

// ExtractScriptSigFromCoinbaseTx extracts scriptSig from the first input.
func ExtractScriptSigFromCoinbaseTx(coinbaseTx []byte) []byte {
	r := bytes.NewReader(coinbaseTx)

	// Skip version (4 bytes)
	if _, err := r.Seek(4, io.SeekStart); err != nil {
		return nil
	}

	// Read input count (value unused, only advance reader)
	if _, _, err := readVarInt(r); err != nil {
		return nil
	}

	// Skip prev_txid (32) + prev_vout (4)
	if _, err := r.Seek(36, io.SeekCurrent); err != nil {
		return nil
	}

	// Read scriptSig length
	scriptLen, _, err := readVarInt(r)
	if err != nil {
		return nil
	}

	if scriptLen == 0 {
		return []byte{}
	}

	if scriptLen > uint64(r.Len()) {
		return nil
	}

	// Read scriptSig
	script := make([]byte, scriptLen)
	if _, err := io.ReadFull(r, script); err != nil {
		return nil
	}
	return script
}

// ExtractCoinbaseOutFromCoinbaseTx extracts all the outputs including the outputs length (varint + serialized outputs).
func ExtractCoinbaseOutFromCoinbaseTx(coinbaseTx []byte) []byte {
	r := bytes.NewReader(coinbaseTx)

	// Skip version
	if _, err := r.Seek(4, io.SeekStart); err != nil {
		return nil
	}

	// Skip input count + first input (we can reuse above but inline for simplicity)
	if _, _, err := readVarInt(r); err != nil {
		return nil
	}
	if _, err := r.Seek(36, io.SeekCurrent); err != nil { // prev_txid + vout
		return nil
	}

	scriptLen, _, err := readVarInt(r)
	if err != nil {
		return nil
	}
	if int64(scriptLen) < 0 || scriptLen > uint64(r.Len()) {
		return nil
	}
	if _, err := r.Seek(int64(scriptLen), io.SeekCurrent); err != nil { // skip script
		return nil
	}
	if _, err := r.Seek(4, io.SeekCurrent); err != nil { // skip sequence
		return nil
	}

	// Record the start of the outputs (includes the outputs count varint)
	outputsStart := int(r.Size()) - r.Len()

	return coinbaseTx[outputsStart:]
}

// ExtractHeightFromCoinbase extracts the block height from the coinbase scriptSig.
// The height is encoded at the beginning of the scriptSig using BIP34 minimal encoding.
// Format:
//
//	OP_PUSH<n> <height(variable bytes)> ← BIP34 height (minimal encoding, 0-5 bytes)
//	... (rest of scriptSig)
//
// Returns the decoded height and an error if the scriptSig is invalid.
func ExtractHeightFromCoinbase(scriptSig []byte) (uint32, error) {
	if len(scriptSig) == 0 {
		return 0, errors.New("coinbase scriptSig empty")
	}

	// Parse the height push operation
	heightData, _, err := parseScriptPush(scriptSig)
	if err != nil {
		return 0, fmt.Errorf("failed to parse height from scriptSig: %w", err)
	}

	// Height can be 0-5 bytes (BIP34 allows minimal encoding)
	if len(heightData) > 5 {
		return 0, fmt.Errorf("invalid height length: expected 0-5 bytes, got %d", len(heightData))
	}

	// Empty height data means height 0
	if len(heightData) == 0 {
		return 0, nil
	}

	// Decode the height from minimal little-endian format
	var height uint32
	for i := 0; i < len(heightData); i++ {
		height |= uint32(heightData[i]) << (8 * uint(i))
	}

	// Handle negative flag (last byte with high bit set followed by 0x00)
	// In BIP34, heights are always positive, but we need to handle the encoding
	if len(heightData) > 0 && heightData[len(heightData)-1] == 0x00 && len(heightData) > 1 {
		// Remove the sign byte and recalculate
		height = 0
		for i := 0; i < len(heightData)-1; i++ {
			height |= uint32(heightData[i]) << (8 * uint(i))
		}
	}

	return height, nil
}

// CreateAuxMerkleRoot creates an aux work merkle root for merged mining with multiple chains.
// According to the Bitcoin merged mining specification:
// - Each chain has a chain_id that determines its slot in the merkle tree
// - The merkle tree must have a power-of-two size (merkle_size)
// - A merkle_nonce is used to resolve slot collisions (though the algorithm is broken)
// - Block hashes are inserted in reversed byte order
// - The final merkle root is reversed before insertion into the coinbase
//
// For Dogecoin + Quai merged mining:
// - Dogecoin chain_id = 98
// - Quai chain_id = 9
// - merkle_size = smallest power of 2 that fits both chains without collision
// - merkle_nonce = 0
//
// Parameters:
//   - dogeHash: Dogecoin block hash (32 bytes)
//   - quaiSealHash: Quai seal hash (32 bytes)
//
// Returns:
//   - auxMerkleRoot: The merkle root to insert into the Litecoin coinbase (32 bytes, byte-reversed)
func CreateAuxMerkleRoot(dogeHash common.Hash, quaiSealHash common.Hash) common.Hash {
	// Chain IDs for merged mining
	const (
		dogeChainID uint32 = 98 // Dogecoin's chain ID
		quaiChainID uint32 = 9  // Quai's chain ID
	)

	// For merkle_size=2, the slot calculation simplifies to: slot ≡ (merkle_nonce + chain_id) mod 2
	// Since Dogecoin (98) is even and Quai (9) is odd, they have different parity
	// and will never collide at size=2 regardless of merkle_nonce.
	merkleNonce := uint32(0)
	merkleSize := uint32(2)

	// Calculate slot positions using the merged mining algorithm
	// Both chains use the SAME merkle_nonce (as per the spec - there's only one nonce in the coinbase)
	dogeSlot := CalculateMerkleSlot(dogeChainID, merkleNonce, merkleSize)
	quaiSlot := CalculateMerkleSlot(quaiChainID, merkleNonce, merkleSize)

	// Create the leaf level of the merkle tree
	// Fill with zeros and insert the chain hashes in reversed order
	leaves := make([][]byte, merkleSize)
	for i := range leaves {
		leaves[i] = make([]byte, 32) // Fill with zeros
	}

	// Reverse the bytes of each chain's block hash before inserting
	// (This is required by the merged mining spec)
	dogeHashReversed := reverseBytesCopy(dogeHash[:])
	quaiHashReversed := reverseBytesCopy(quaiSealHash[:])

	leaves[dogeSlot] = dogeHashReversed
	leaves[quaiSlot] = quaiHashReversed

	// Build the merkle tree by hashing pairs up to the root
	currentLevel := leaves
	for len(currentLevel) > 1 {
		nextLevel := make([][]byte, len(currentLevel)/2)
		for i := 0; i < len(currentLevel); i += 2 {
			left := currentLevel[i]
			right := currentLevel[i+1]

			// Double SHA256 of concatenated hashes
			combined := append(left, right...)
			hash1 := doubleSHA256(combined)
			nextLevel[i/2] = hash1[:]
		}
		currentLevel = nextLevel
	}

	// The root is the last remaining hash
	merkleRoot := currentLevel[0]

	// Reverse the bytes of the merkle root before returning
	// (Required by the merged mining spec for coinbase insertion)
	merkleRootReversed := reverseBytesCopy(merkleRoot)

	return common.BytesToHash(merkleRootReversed)
}

// calculateMerkleSlot calculates the slot position for a chain in the aux merkle tree
// using the algorithm from the Bitcoin merged mining specification.
func CalculateMerkleSlot(chainID uint32, merkleNonce uint32, merkleSize uint32) uint32 {
	// This is the exact algorithm from the merged mining spec
	rand := merkleNonce
	rand = rand*1103515245 + 12345
	rand += chainID
	rand = rand*1103515245 + 12345
	return rand % merkleSize
}

// doubleSHA256 performs double SHA256 hashing
func doubleSHA256(data []byte) [32]byte {
	first := chainhash.DoubleHashB(data)
	var result [32]byte
	copy(result[:], first)
	return result
}
