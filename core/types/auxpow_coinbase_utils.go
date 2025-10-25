package types

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"

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
	sealHashData, consumed, err := parseScriptPush(scriptSig[cursor:])
	if err != nil {
		return common.Hash{}, fmt.Errorf("decode seal hash: %w", err)
	}
	if len(sealHashData) != common.HashLength {
		return common.Hash{}, fmt.Errorf("invalid seal hash length: expected %d, got %d", common.HashLength, len(sealHashData))
	}

	return common.BytesToHash(sealHashData), nil
}

// SetSealHashInCoinbase updates the seal hash in an existing coinbase scriptSig.
// This is used by miners to insert the actual seal hash into the placeholder.
// Returns the modified scriptSig or an error if the format is invalid.
func SetSealHashInCoinbase(scriptSig []byte, sealHash common.Hash) ([]byte, error) {
	if len(scriptSig) == 0 {
		return nil, errors.New("coinbase scriptSig empty")
	}

	cursor := 0

	// 1. Skip height (variable length - BIP34 minimal encoding)
	heightData, consumed, err := parseScriptPush(scriptSig[cursor:])
	if err != nil {
		return nil, fmt.Errorf("decode coinbase height: %w", err)
	}
	// Height can be 0-5 bytes (BIP34 allows minimal encoding)
	if len(heightData) > 5 {
		return nil, fmt.Errorf("invalid height length: expected 0-5 bytes, got %d", len(heightData))
	}
	cursor += consumed

	// 2. Skip magic marker (4 bytes)
	magicData, consumed, err := parseScriptPush(scriptSig[cursor:])
	if err != nil {
		return nil, fmt.Errorf("decode magic marker: %w", err)
	}
	if len(magicData) != 4 {
		return nil, fmt.Errorf("invalid magic marker length: expected 4, got %d", len(magicData))
	}
	cursor += consumed

	// 3. Find the seal hash position (should be OP_PUSH32 followed by 32 bytes)
	if cursor >= len(scriptSig) {
		return nil, errors.New("scriptSig too short to contain seal hash")
	}
	if scriptSig[cursor] != 0x20 { // OP_PUSH32
		return nil, fmt.Errorf("expected OP_PUSH32 (0x20) at seal hash position, got 0x%x", scriptSig[cursor])
	}

	// Calculate the position where the seal hash data starts (after the OP_PUSH32 opcode)
	sealHashStart := cursor + 1
	sealHashEnd := sealHashStart + 32

	if sealHashEnd > len(scriptSig) {
		return nil, errors.New("scriptSig too short to contain 32-byte seal hash")
	}

	// Create a copy of the scriptSig and update the seal hash
	result := make([]byte, len(scriptSig))
	copy(result, scriptSig)
	copy(result[sealHashStart:sealHashEnd], sealHash[:])

	return result, nil
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

// VerifyMerkleProof verifies a merkle proof for a transaction at index 0 (coinbase)
// merkleBranch contains the sibling hashes from leaf to root
func CalculateMerkleRoot(coinbaseTx *AuxPowTx, merkleBranch [][]byte) [common.HashLength]byte {

	switch coinbaseTx.inner.(type) {
	case *RavencoinTx, *BitcoinTxWrapper:
		// Start with the transaction hash
		currentHash := chainhash.Hash(coinbaseTx.TxHash())

		// For coinbase (index 0), we always take the right branch
		// and our hash goes on the left
		for _, siblingBytes := range merkleBranch {
			var sibling chainhash.Hash
			copy(sibling[:], siblingBytes)

			// Since we're at index 0 (coinbase), we're always the left child
			currentHash = btcblockchain.HashMerkleBranches(&currentHash, &sibling)
		}
		return currentHash
	case *LitecoinTxWrapper:
		// Start with the transaction hash
		currentHash := ltcchainhash.Hash(coinbaseTx.TxHash())

		// For coinbase (index 0), we always take the right branch
		// and our hash goes on the left
		for _, siblingBytes := range merkleBranch {
			var sibling ltcchainhash.Hash
			copy(sibling[:], siblingBytes)

			// Since we're at index 0 (coinbase), we're always the left child
			currentHash = ltcblockchain.HashMerkleBranches(&currentHash, &sibling)
		}
		return currentHash
	case *BitcoinCashTxWrapper:
		// Start with the transaction hash
		currentHash := bchchainhash.Hash(coinbaseTx.TxHash())

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

// BuildCoinbaseScriptSigWithNonce creates a scriptSig for AuxPow coinbase with the Bitcoin standard format
// Format:
//
//	OP_PUSH<n> <height(variable bytes)> ← BIP34 height (MINIMAL encoding)
//	OP_PUSH4   <fabe6d6d(4 bytes)>      ← Magic marker
//	OP_PUSH32  <SealHash(32 bytes)>     ← Actual seal hash
//	OP_PUSH4   <merkle_size(4 bytes)>   ← 1
//	OP_PUSH4   <merkle_nonce(4 bytes)>  ← 0
//	OP_PUSH44  <extraNonce1(4 bytes) + extraNonce2(8 bytes) + extraData(32 bytes)> ← Combined extranonces (Bitcoin standard) + extraData (32 bytes)
func BuildCoinbaseScriptSigWithNonce(blockHeight uint32, extraNonce1 uint32, extraNonce2 uint64, sealHash common.Hash) []byte {
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
	buf.Write(sealHash[:])

	// 4. Merkle size (4 bytes, little-endian) - always 1 for single coinbase
	buf.WriteByte(0x04) // OP_PUSH4
	binary.Write(&buf, binary.LittleEndian, uint32(1))

	// 5. Merkle nonce (4 bytes, little-endian) - always 0
	buf.WriteByte(0x04) // OP_PUSH4
	binary.Write(&buf, binary.LittleEndian, uint32(0))

	// 6. Combined extra nonces and extraData (44 bytes total, little-endian)
	// Bitcoin standard: extraNonce1 (4 bytes) + extraNonce2 (8 bytes) + extraData (32 bytes) in a single push
	buf.WriteByte(0x2c) // OP_PUSH44 (44 decimal = 0x2c hex)
	binary.Write(&buf, binary.LittleEndian, extraNonce1)
	binary.Write(&buf, binary.LittleEndian, extraNonce2)
	// extraData: 32 bytes of zeros for now (can be used for additional miner data)
	buf.Write(make([]byte, 32))

	return buf.Bytes()
}

// CalculateMerkleRootFromTxs calculates merkle root from wire.MsgTx transactions
func CalculateMerkleRootFromTxs(powId PowID, txs []*AuxPowTx) common.Hash {
	if len(txs) == 0 {
		return common.Hash{}
	}

	switch powId {
	case Kawpow:
		transactions := make([]*btcutil.Tx, len(txs))
		for i, tx := range txs {
			ravenTx, ok := tx.inner.(*RavencoinTx)
			if !ok || ravenTx == nil || ravenTx.MsgTx == nil {
				return common.Hash{}
			}
			transactions[i] = btcutil.NewTx(ravenTx.MsgTx)
		}
		root := btcblockchain.CalcMerkleRoot(transactions, false) // false = not witness
		return common.BytesToHash(root[:])
	case SHA_BTC:
		transactions := make([]*btcutil.Tx, len(txs))
		for i, tx := range txs {
			bitcoinTx, ok := tx.inner.(*BitcoinTxWrapper)
			if !ok || bitcoinTx == nil || bitcoinTx.MsgTx == nil {
				return common.Hash{}
			}
			transactions[i] = btcutil.NewTx(bitcoinTx.MsgTx)
		}
		root := btcblockchain.CalcMerkleRoot(transactions, false) // false = not witness
		return common.BytesToHash(root[:])
	case SHA_BCH:
		transactions := make([]*bchutil.Tx, len(txs))
		for i, tx := range txs {
			bitcoinCashTx, ok := tx.inner.(*BitcoinCashTxWrapper)
			if !ok || bitcoinCashTx == nil || bitcoinCashTx.MsgTx == nil {
				return common.Hash{}
			}
			transactions[i] = bchutil.NewTx(bitcoinCashTx.MsgTx)
		}
		// Bitcoin Cash uses BuildMerkleTreeStore (no CalcMerkleRoot in bchd)
		// The last element of the tree is the merkle root
		tree := bchblockchain.BuildMerkleTreeStore(transactions)
		if len(tree) == 0 {
			return common.Hash{}
		}
		root := tree[len(tree)-1]
		return common.BytesToHash(root[:])

	case Scrypt:
		Transactions := make([]*ltcutil.Tx, len(txs))
		for i, tx := range txs {
			litecoinTx, ok := tx.inner.(*LitecoinTxWrapper)
			if !ok || litecoinTx == nil || litecoinTx.MsgTx == nil {
				return common.Hash{}
			}
			Transactions[i] = ltcutil.NewTx(litecoinTx.MsgTx)
		}
		root := ltcblockchain.CalcMerkleRoot(Transactions, false) // false = not witness
		return common.BytesToHash(root[:])
	}
	return common.Hash{}
}

// VerifyMerkleProof verifies a merkle proof for a transaction at index 0 (coinbase)
// merkleBranch contains the sibling hashes from leaf to root
func VerifyMerkleProof(txHash chainhash.Hash, merkleBranch [][]byte, merkleRoot common.Hash) bool {
	// Start with the transaction hash
	currentHash := txHash

	// For coinbase (index 0), we always take the right branch
	// and our hash goes on the left
	for _, siblingBytes := range merkleBranch {
		var sibling chainhash.Hash
		copy(sibling[:], siblingBytes)

		// Since we're at index 0 (coinbase), we're always the left child
		currentHash = btcblockchain.HashMerkleBranches(&currentHash, &sibling)
	}

	// Compare with expected merkle root
	return bytes.Equal(currentHash[:], merkleRoot[:])
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
