# AuxPow Coinbase ScriptSig Format

## Overview

This document describes the standardized format for coinbase transaction scriptSig in the go-quai AuxPow implementation. The format is **BIP34 compliant** and compatible with Bitcoin, Ravencoin, and other Bitcoin-derived chains.

## Format Specification

The coinbase scriptSig follows this structure:

```
OP_PUSH<n> <height(variable bytes)>  - Block height (BIP34 minimal encoding)
OP_PUSH4   <fabe6d6d(4 bytes)>       - Magic marker (identifies AuxPow format)
OP_PUSH32  <SealHash(32 bytes)>      - Seal hash placeholder/actual value
OP_PUSH4   <merkle_size(4 bytes)>    - Merkle tree size (always 1 for single coinbase)
OP_PUSH4   <merkle_nonce(4 bytes)>   - Merkle nonce (always 0)
OP_PUSH4   <extraNonce1(4 bytes)>    - Pool nonce (mining pool identifier)
OP_PUSH8   <extraNonce2(8 bytes)>    - Miner nonce space (individual miner nonce)
```

**Total Size:** ~64-68 bytes (variable depending on height)

## BIP34 Compliance

This format strictly adheres to [BIP34](https://github.com/bitcoin/bips/blob/master/bip-0034.mediawiki) requirements:

1. ✅ **Height is first field** - The block height must be the first push in the scriptSig
2. ✅ **Minimal encoding** - Height uses CScriptNum minimal encoding (no unnecessary leading zeros)
3. ✅ **Arbitrary data allowed** - All fields after height are arbitrary and chain-agnostic

This ensures compatibility with Bitcoin, Ravencoin, Litecoin, Bitcoin Cash, and all other Bitcoin-derived chains.

## Field Descriptions

### 1. Block Height (variable length - BIP34 Minimal Encoding)
- **Opcode:** Variable - `0x00` to `0x04` (or `0x4c` for OP_PUSHDATA1)
- **Data:** 0-5 bytes, little-endian encoded block height in **minimal format**
- **Purpose:** BIP34 compliance - prevents block hash collisions
- **Encoding:** Uses Bitcoin's CScriptNum minimal encoding (no unnecessary leading zeros)

### 2. Magic Marker (5 bytes)
- **Opcode:** `0x04` (OP_PUSH4)
- **Data:** `0xfabe6d6d` (固定值 "fabe6d6d")
- **Purpose:** Identifies this as an AuxPow format coinbase, allows parsers to validate format

### 3. Seal Hash (33 bytes)
- **Opcode:** `0x20` (OP_PUSH32)
- **Data:** 32 bytes, seal hash
- **Purpose:** Contains the Quai seal hash that this AuxPow is proving work for
- **Note:** Initially set to all zeros (placeholder), miners replace with actual seal hash

### 4. Merkle Size (5 bytes)
- **Opcode:** `0x04` (OP_PUSH4)
- **Data:** 4 bytes, little-endian uint32
- **Value:** Always `1` (single coinbase transaction)
- **Purpose:** Reserved for potential future multi-transaction support

### 5. Merkle Nonce (5 bytes)
- **Opcode:** `0x04` (OP_PUSH4)
- **Data:** 4 bytes, little-endian uint32
- **Value:** Always `0`
- **Purpose:** Reserved for merkle tree construction variations

### 6. Extra Nonce 1 (5 bytes)
- **Opcode:** `0x04` (OP_PUSH4)
- **Data:** 4 bytes, little-endian uint32
- **Purpose:** Mining pool nonce space (allows pools to distribute work without header changes)

### 7. Extra Nonce 2 (9 bytes)
- **Opcode:** `0x08` (OP_PUSH8)
- **Data:** 8 bytes, little-endian uint64
- **Purpose:** Individual miner nonce space (large nonce space for mining hardware)

## Example

For block height 12345 (0x3039), with extraNonce1=0x11223344, extraNonce2=0x99AABBCCDDEEFF00:

```
Hex: 02393004fabe6d6d2000000000000000000000000000000000000000000000000000000000000000000401000000040000000004443322110800ffeeddccbbaa99

Breakdown:
02 3930                 - OP_PUSH2 + height (12345 = 0x3039 little-endian, minimal encoding)
04 fabe6d6d             - OP_PUSH4 + magic marker
20 0000000000000000... - OP_PUSH32 + 32 zero bytes (seal hash placeholder)
04 01000000             - OP_PUSH4 + merkle_size (1)
04 00000000             - OP_PUSH4 + merkle_nonce (0)
04 44332211             - OP_PUSH4 + extraNonce1 (0x11223344 little-endian)
08 00ffeeddccbbaa99    - OP_PUSH8 + extraNonce2 (0x99AABBCCDDEEFF00 little-endian)
```

### Height Encoding Examples

BIP34 requires minimal encoding - no unnecessary leading zero bytes:

| Height | Hex Value | Minimal Encoding | Bytes |
|--------|-----------|------------------|-------|
| 0 | 0x00 | `00` (empty push) | 1 |
| 1 | 0x01 | `01 01` | 2 |
| 127 | 0x7F | `01 7f` | 2 |
| 128 | 0x80 | `02 80 00` | 3 |
| 255 | 0xFF | `02 ff 00` | 3 |
| 256 | 0x100 | `02 00 01` | 3 |
| 12345 | 0x3039 | `02 39 30` | 3 |
| 2112064 | 0x203A40 | `03 40 3a 20` | 4 |
| 8388607 | 0x7FFFFF | `03 ff ff 7f` | 4 |
| 8388608 | 0x800000 | `04 00 00 80 00` | 5 |

**Note:** If the high bit (0x80) is set, an extra 0x00 byte is added to indicate a positive number (Bitcoin's CScriptNum format).

## API Functions

### BuildCoinbaseScriptSigWithNonce

```go
func BuildCoinbaseScriptSigWithNonce(blockHeight uint32, extraNonce1 uint32, extraNonce2 uint64, extraData []byte) []byte
```

Creates a coinbase scriptSig with the new format. The `extraData` parameter is deprecated and ignored.

**Parameters:**
- `blockHeight`: Block height for BIP34
- `extraNonce1`: Pool nonce (4 bytes)
- `extraNonce2`: Miner nonce (8 bytes)
- `extraData`: Deprecated, ignored

**Returns:** 67-byte scriptSig with seal hash initialized to zeros

### ExtractSealHashFromCoinbase

```go
func ExtractSealHashFromCoinbase(scriptSig []byte) (common.Hash, error)
```

Extracts the seal hash from a coinbase scriptSig in the new format.

**Parameters:**
- `scriptSig`: The coinbase scriptSig bytes

**Returns:**
- Seal hash (32 bytes)
- Error if format is invalid

**Validates:**
- ScriptSig structure and length
- Magic marker presence and value
- All field sizes

### SetSealHashInCoinbase

```go
func SetSealHashInCoinbase(scriptSig []byte, sealHash common.Hash) ([]byte, error)
```

Updates the seal hash in an existing coinbase scriptSig. Used by miners to insert the actual seal hash into the placeholder.

**Parameters:**
- `scriptSig`: Original scriptSig with seal hash placeholder
- `sealHash`: Actual seal hash to insert

**Returns:**
- Updated scriptSig with new seal hash
- Error if format is invalid

## Migration Notes

### BIP34 Compliance Update (v2.0)

**Critical Change:** Height encoding now uses **minimal/compact format** as required by BIP34.

**Before (v1.0 - Non-compliant):**
- Height always encoded as 4 bytes with `OP_PUSH4`
- Example: Height 12345 → `04 39 30 00 00` (5 bytes total)
- **Rejected by Bitcoin/Ravencoin** with `bad-cb-height` error

**After (v2.0 - BIP34 Compliant):**
- Height uses minimal encoding (CScriptNum format)
- Example: Height 12345 → `02 39 30` (3 bytes total)
- **Accepted by all Bitcoin-derived chains**

### Breaking Changes

1. **Height Encoding:** Changed from fixed 4-byte to variable-length minimal encoding (0-5 bytes)

2. **Total Size:** Variable size (~64-68 bytes) instead of fixed 67 bytes

3. **Magic Marker Position:** Now at variable offset (depends on height length) instead of fixed offset

### Compatibility

- ✅ **BIP34 compliant** - Works with Bitcoin, Ravencoin, Litecoin, Bitcoin Cash, etc.
- ✅ **Backward compatible parsing** - `ExtractSealHashFromCoinbase` handles both old and new formats
- ⚠️ **Forward breaking** - Old parsers expecting fixed 4-byte height will fail on new format

## Use Cases

### Template Generation
When generating a mining template:
```go
scriptSig := BuildCoinbaseScriptSigWithNonce(blockHeight, poolNonce, 0, nil)
// scriptSig now contains zeros for seal hash - send to miners
```

### Mining
When a miner finds a valid block:
```go
updatedScriptSig, err := SetSealHashInCoinbase(templateScriptSig, actualSealHash)
// updatedScriptSig now contains the actual seal hash
```

### Validation
When validating a submitted block:
```go
sealHash, err := ExtractSealHashFromCoinbase(coinbaseTx.TxIn[0].SignatureScript)
if err != nil {
    return fmt.Errorf("invalid coinbase format: %w", err)
}
// Validate sealHash matches expected value
```

## Security Considerations

1. **Magic Marker Validation:** Always verify the magic marker to prevent processing invalid formats
2. **Length Validation:** Ensure scriptSig is exactly 67 bytes
3. **Seal Hash Verification:** After extraction, verify the seal hash is not all zeros (unless it's a template)
4. **Nonce Space:** The combined 12 bytes (extraNonce1 + extraNonce2) provide 2^96 nonce space

## Future Extensions

The `merkle_size` and `merkle_nonce` fields are reserved for potential future use:
- Multi-transaction coinbase support
- Alternative merkle tree construction methods
- Additional consensus rules

These fields must remain as `1` and `0` respectively in the current version.
