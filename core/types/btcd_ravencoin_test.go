package types

import (
	"encoding/hex"
	"testing"

	"github.com/dominant-strategies/go-quai/common"
	"github.com/stretchr/testify/require"
)

func TestBuildCoinbaseScriptSigRavencoinFormat(t *testing.T) {
	tests := []struct {
		name        string
		blockHeight uint32
		extraData   []byte
		wantPrefix  string // Expected hex prefix for height encoding
	}{
		{
			name:        "Block 680000 with small extra data",
			blockHeight: 680000,
			extraData:   []byte("Quai"),
			wantPrefix:  "0440600a00", // 0x04 (OP_PUSH4) + 0x40600a00 (680000 in little-endian)
		},
		{
			name:        "Block 1000000 with no extra data",
			blockHeight: 1000000,
			extraData:   nil,
			wantPrefix:  "0440420f00", // 0x04 (OP_PUSH4) + 0x40420f00 (1000000 in little-endian)
		},
		{
			name:        "Block 1 with message",
			blockHeight: 1,
			extraData:   []byte("Genesis"),
			wantPrefix:  "0401000000", // 0x04 (OP_PUSH4) + 0x01000000 (1 in little-endian)
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Convert extraData to Hash for testing purposes
			var sealHash common.Hash
			if len(tt.extraData) >= 32 {
				copy(sealHash[:], tt.extraData[:32])
			}
			scriptSig := BuildCoinbaseScriptSigWithNonce(tt.blockHeight, 0, 0, sealHash)

			// Check the height encoding prefix
			hexStr := hex.EncodeToString(scriptSig)
			require.True(t, len(hexStr) >= len(tt.wantPrefix),
				"ScriptSig too short: %s", hexStr)
			require.Equal(t, tt.wantPrefix, hexStr[:len(tt.wantPrefix)],
				"Height encoding mismatch. Got: %s, Want prefix: %s",
				hexStr, tt.wantPrefix)

			// If extra data exists, verify it's included
			if len(tt.extraData) > 0 {
				// After the height (5 bytes), we should have length prefix + data
				expectedLen := 5 + 1 + len(tt.extraData) // height + length byte + data
				require.Equal(t, expectedLen, len(scriptSig),
					"ScriptSig length mismatch for extra data")

				// Check extra data is present
				dataStart := 6 // After height (5 bytes) and length prefix (1 byte)
				actualData := scriptSig[dataStart:]
				require.Equal(t, tt.extraData, actualData,
					"Extra data mismatch")
			}
		})
	}
}

func TestBuildCoinbaseScriptSigLargeData(t *testing.T) {
	blockHeight := uint32(700000)

	// Test with 100 bytes of data (uses OP_PUSHDATA1)
	largeData := make([]byte, 100)
	for i := range largeData {
		largeData[i] = byte(i % 256)
	}

	scriptSig := BuildCoinbaseScriptSigWithNonce(blockHeight, 0, 0, common.Hash{})

	// Should be: 5 (height) + 1 (OP_PUSHDATA1) + 1 (length) + 100 (data) = 107 bytes
	require.Equal(t, 107, len(scriptSig))

	// Check OP_PUSHDATA1 is used (0x4c at position 5)
	require.Equal(t, byte(0x4c), scriptSig[5], "Should use OP_PUSHDATA1 for 100 bytes")
	require.Equal(t, byte(100), scriptSig[6], "Length should be 100")

	// Test with 300 bytes of data (uses OP_PUSHDATA2)
	veryLargeData := make([]byte, 300)
	for i := range veryLargeData {
		veryLargeData[i] = byte(i % 256)
	}

	scriptSig2 := BuildCoinbaseScriptSigWithNonce(blockHeight, 0, 0, common.Hash{})

	// Should be: 5 (height) + 1 (OP_PUSHDATA2) + 2 (length) + 300 (data) = 308 bytes
	require.Equal(t, 308, len(scriptSig2))

	// Check OP_PUSHDATA2 is used (0x4d at position 5)
	require.Equal(t, byte(0x4d), scriptSig2[5], "Should use OP_PUSHDATA2 for 300 bytes")
	require.Equal(t, byte(44), scriptSig2[6], "Low byte of length (300 = 0x012c)")
	require.Equal(t, byte(1), scriptSig2[7], "High byte of length")
}

func TestBuildCoinbaseScriptSigWithNonce(t *testing.T) {
	blockHeight := uint32(680000)
	extraNonce1 := uint32(0x12345678)
	extraNonce2 := uint64(0x123456789abcdef0)

	scriptSig := BuildCoinbaseScriptSigWithNonce(blockHeight, extraNonce1, extraNonce2, common.Hash{})

	// Expected structure:
	// [0x04][height 4 bytes][0x04][nonce1 4 bytes][0x08][nonce2 8 bytes][0x06]["KAWPOW"]
	// Total: 1 + 4 + 1 + 4 + 1 + 8 + 1 + 6 = 26 bytes

	require.Equal(t, 26, len(scriptSig), "ScriptSig should be 26 bytes")

	// Check height section
	require.Equal(t, byte(0x04), scriptSig[0], "Height should use OP_PUSH4")
	require.Equal(t, []byte{0x40, 0x60, 0x0a, 0x00}, scriptSig[1:5], "Height 680000 in little-endian")

	// Check extra nonce 1 section
	require.Equal(t, byte(0x04), scriptSig[5], "ExtraNonce1 should use OP_PUSH4")
	require.Equal(t, []byte{0x78, 0x56, 0x34, 0x12}, scriptSig[6:10], "ExtraNonce1 in little-endian")

	// Check extra nonce 2 section
	require.Equal(t, byte(0x08), scriptSig[10], "ExtraNonce2 should use OP_PUSH8")
	require.Equal(t, []byte{0xf0, 0xde, 0xbc, 0x9a, 0x78, 0x56, 0x34, 0x12}, scriptSig[11:19], "ExtraNonce2 in little-endian")

	// Check extra data section
	require.Equal(t, byte(0x06), scriptSig[19], "Extra data should use OP_PUSH6")
	require.Equal(t, []byte("KAWPOW"), scriptSig[20:26], "Extra data should be 'KAWPOW'")
}

func TestBuildCoinbaseScriptSigWithPartialNonces(t *testing.T) {
	blockHeight := uint32(700000)
	extraNonce1 := uint32(0x11223344)
	extraNonce2 := uint64(0) // No second nonce

	scriptSig := BuildCoinbaseScriptSigWithNonce(blockHeight, extraNonce1, extraNonce2, common.Hash{})

	// Expected: height(5) + nonce1(5) + data(5) = 15 bytes
	require.Equal(t, 15, len(scriptSig))

	// Verify structure
	require.Equal(t, byte(0x04), scriptSig[0], "Height OP_PUSH4")
	require.Equal(t, byte(0x04), scriptSig[5], "ExtraNonce1 OP_PUSH4")
	require.Equal(t, byte(0x04), scriptSig[10], "Extra data length")
	require.Equal(t, []byte("Quai"), scriptSig[11:15], "Extra data")
}
