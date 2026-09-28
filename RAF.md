# RAF file format, version 1

RAF (Random-Access File) is libaegis's format for encrypted files that can be read and updated one chunk at a time.

This document describes the bytes stored on disk and the cryptographic operations needed to write a compatible implementation.
It covers version 1 as implemented in this repository, not an extensible container format.

A RAF file consists of a 64-byte header followed by fixed-size chunk records:

```text
header || record[0] || record[1] || ... || record[n - 1]
```

The header is authenticated but not encrypted.
Each record contains a public nonce, encrypted chunk data, and an authentication tag.

The master key is supplied separately and is never stored in the file.

There is no filename, password encoding, compression, index table, or end-of-file marker.

## Conventions and algorithms

All sizes and offsets below are in bytes.

All stored integers are unsigned and little-endian.
`LE32(x)` and `LE64(x)` mean the four-byte and eight-byte encodings of `x`.

`||` means byte concatenation; slices such as `header[0:48]` exclude the end offset.

Serialize fields explicitly rather than writing a native C structure.

The algorithm identifier selects both the chunk cipher and the standalone AEGIS-MAC used for the header:

| ID  | Algorithm   | Master key and each derived key | Record nonce |  Tag |
| --- | ----------- | ------------------------------: | -----------: | ---: |
| 1   | AEGIS-128L  |                              16 |           16 |   16 |
| 2   | AEGIS-128X2 |                              16 |           16 |   16 |
| 3   | AEGIS-128X4 |                              16 |           16 |   16 |
| 4   | AEGIS-256   |                              32 |           32 |   16 |
| 5   | AEGIS-256X2 |                              32 |           32 |   16 |
| 6   | AEGIS-256X4 |                              32 |           32 |   16 |

Unknown identifiers must be rejected.

RAF always uses 16-byte tags, even though the underlying primitives also support 32-byte tags.

Use the selected algorithm exactly; the X2 and X4 variants are distinct algorithms, not interchangeable acceleration options.

The AEGIS primitives, including AEGIS-MAC, are described in [RFC 10032](https://www.rfc-editor.org/rfc/rfc10032.html).
The RAF-specific key derivation is described below.

## Header

| Offset | Length | Field        | Encoding or value                                     |
| -----: | -----: | ------------ | ----------------------------------------------------- |
|      0 |      8 | Magic        | ASCII `AEGISRAF`, hex `41 45 47 49 53 52 41 46`       |
|      8 |      2 | Header size  | Little-endian `64`, hex `40 00`                       |
|     10 |      1 | Version      | `01`                                                  |
|     11 |      1 | Algorithm ID | One of the IDs above                                  |
|     12 |      4 | Chunk size   | Plaintext capacity of each chunk                      |
|     16 |      8 | File size    | Logical plaintext length, not physical storage length |
|     24 |     24 | File ID      | Random bytes generated when the file is created       |
|     48 |     16 | Header MAC   | Authentication of bytes 0 through 47                  |

The chunk size must be between 1,024 and 1,048,576 inclusive and divisible by 16.
It need not be a power of two.

Version 1 requires exactly this header size and has no reserved fields or stored flags.
The API's create/truncate flags and scratch-buffer alignment do not appear on disk.

Generate the file ID using a cryptographically secure random number generator.
Keep it unchanged throughout the file's lifetime, including truncation to zero and subsequent growth.

Creating a replacement file generates a new ID and therefore new per-file keys.
The ID is also used as a public input to key derivation and chunk authentication.

### Per-file keys

Let `K` be the key length selected by the algorithm.
Derive `2 * K` bytes from the master key and the file ID:

```text
label    = ASCII("aegis-raf-kdf-v1")
input    = label || master_key || file_id
material = RAF_KDF(input, 2 * K, K)
enc_key  = material[0:K]
hdr_key  = material[K:2*K]
```

**The label is exactly 16 bytes, without a terminating zero byte.**

Its hex encoding is `61 65 67 69 73 2d 72 61 66 2d 6b 64 66 2d 76 31`.
Do not append a zero or add any length fields to this derivation.

The algorithm ID is not a separate KDF input; algorithms with the same key length use the same derivation.

`RAF_KDF(input, output_length, K)` is a single-block sponge operation:

1. Choose a rate of 168 bytes for `K = 16`, or 136 bytes for `K = 32`.
2. Initialize a 200-byte state to zero.
3. XOR the input bytes into the beginning of the state.
4. XOR `0x1f` into the byte at offset `len(input)`.
5. XOR `0x80` into the byte at offset `rate - 1`.
   If the two padding positions coincide, both XORs apply to the same byte.
6. Apply **Keccak-p[1600, 12]** once: the last 12 rounds of Keccak-f[1600], using round constants 12 through 23 when numbered from zero.
7. Return the first `output_length` bytes of the state.

Keccak lanes use little-endian byte encoding and the usual lane order `x + 5*y`.

The input must be shorter than the rate, and the output must not exceed the rate.
All RAF derivations fit these limits, so no further absorption or squeezing is needed.

This is not ordinary SHAKE128/SHAKE256, which use 24 rounds, nor is it HKDF, KMAC, or KangarooTwelve.
A cryptographic library exposing the Keccak-p permutation or the matching reduced-round sponge can supply this primitive.

### Key-derivation test vectors

These public test inputs and expected outputs come from `src/test/kdf_test.zig`.

For both vectors, use file ID `000102030405060708090a0b0c0d0e0f1011121314151617` and the 16-byte label above.
The output shown is `enc_key || hdr_key`.

For a 16-byte master key `000102030405060708090a0b0c0d0e0f`:

```text
enc_key = 4cc4759d9f10cf1b391cfc220d9b329d
hdr_key = 07656537477b6965708f98f35e7807af
```

For a 32-byte master key `000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f`:

```text
enc_key = 1e051b0052c53b397417d5670a1595f892a365101bcc79128cef842498b4cf90
hdr_key = 732b8fc7cec6a07f83b0c3631e97487454db4961b5ca8a39f5b5e2c87cbd85ba
```

These vectors test key derivation, not header MACs or complete encrypted files.

### Header authentication

Use the standalone AEGIS-MAC corresponding to the algorithm ID, with `hdr_key`, an all-zero nonce of the algorithm's nonce length, and a 16-byte output:

```text
state = AEGIS_MAC_init(hdr_key, zero_nonce)
AEGIS_MAC_update(state, header[0:48])
header[48:64] = AEGIS_MAC_final(state, tag_length = 16)
```

This means the `*_mac_init`, `*_mac_update`, and `*_mac_final` operations in libaegis.

Do not substitute an AEAD call with an empty plaintext and the header as associated data; standalone AEGIS-MAC has its own finalization.
Do not compute a 32-byte MAC and truncate it.

Verify the MAC before trusting the logical file size or exposing authenticated metadata.
A wrong master key and a modified header both cause authentication failure.

When the logical file size changes, serialize the new header and recompute its MAC.

The all-zero MAC nonce is part of the standalone MAC construction, not a nonce to reuse for chunk encryption.

## Chunk records

Let `C` be the chunk size, `N` the nonce length, and `L` the logical file size.
Every record has the same length, including the final record:

```text
record_size = N + C + 16
chunk_count = 0                         if L == 0
              1 + floor((L - 1) / C)   otherwise
record_offset(i) = 64 + i * record_size
minimum_physical_size = 64 + chunk_count * record_size
```

A normally sized empty file is just its 64-byte header, with no chunk records.
There is no extra record when `L` is an exact multiple of `C`.

Within each record:

| Relative offset | Length | Contents          |
| --------------: | -----: | ----------------- |
|               0 |    `N` | Random nonce      |
|             `N` |    `C` | Ciphertext        |
|         `N + C` |     16 | Detached AEAD tag |

The chunk index `i` starts at zero.
It is implied by the record's position and is not stored in the record.

Construct exactly 36 bytes of associated data:

```text
aad = file_id || LE64(i) || LE32(C)
```

Encrypt using the selected AEGIS variant:

```text
nonce = secure_random(N)
(ciphertext, tag) = AEGIS_encrypt_detached(
    key = enc_key,
    nonce = nonce,
    plaintext = full_chunk_buffer,
    associated_data = aad,
    tag_length = 16
)
record = nonce || ciphertext || tag
```

The plaintext passed to AEAD is always exactly `C` bytes.

Generate a fresh random nonce for every record encryption, including overwrites of existing records and writes of all-zero plaintext.
Do not derive it from the chunk index, reuse the previous nonce, or reset a deterministic random stream when reopening a file.
Nonce reuse under the same encryption key is unsafe.

To read a record, reconstruct the same associated data and authenticate/decrypt all `C` ciphertext bytes.
Only release plaintext from a record after its tag verifies.
A single-byte read still requires authenticating the whole record.

### The final chunk and padding

For each existing chunk, the number of logically visible bytes is:

```text
valid_length(i) = min(C, L - i * C)
```

Writers zero-fill bytes beyond the valid length when encrypting a partial final chunk.
These zeros are encrypted and authenticated; they are not a shorter ciphertext or a separate padding field.
The length comes only from the authenticated header.

However, shrinking a RAF file does **not** re-encrypt its retained final chunk.
Bytes beyond the new logical end may therefore contain previously written plaintext inside the authenticated ciphertext.

A compatible reader must ignore these bytes, not reject the file because they are nonzero and never return them to the caller.

Later growth must explicitly zero the newly exposed range rather than reveal old tail data.

### Worked layout example

For AEGIS-128L, a chunk size of 4,096 and a logical length of 5,000 give:

```text
nonce length          = 16
record size           = 16 + 4096 + 16 = 4128
chunk count           = 2
minimum physical size = 64 + 2 * 4128 = 8320

header                = bytes [0, 64)
record 0 nonce        = bytes [64, 80)
record 0 ciphertext   = bytes [80, 4176)
record 0 tag          = bytes [4176, 4192)
record 1 nonce        = bytes [4192, 4208)
record 1 ciphertext   = bytes [4208, 8304)
record 1 tag          = bytes [8304, 8320)
```

The second chunk has 904 visible bytes and 3,192 bytes beyond logical EOF.
Its associated data is the 24-byte file ID followed by `01 00 00 00 00 00 00 00` and `00 10 00 00`.

## Opening and validating a file

A reader can follow this sequence:

1. Require at least 64 bytes and read the header into a private buffer.
2. Check the magic, header size, version, supported algorithm ID, and chunk-size constraints.
3. Derive the per-file keys using the file ID from that buffer.
4. Verify the header MAC against the same buffered header.
   Do not reread different header bytes between parsing and verification.
5. Compute the chunk count and required physical length using checked arithmetic.
   In particular, require `chunk_count <= floor((UINT64_MAX - 64) / record_size)` before multiplication.
   Also enforce the limits of the implementation's storage offsets and buffer sizes.
6. Reject a backing store shorter than the required length.
7. Authenticate records as they are read, or scan all records if whole-file verification is required.

The current libaegis reader accepts backing stores larger than the required length.
Trailing bytes are ignored and are not authenticated as part of the logical file.
Do not infer the logical size from the physical size or interpret trailing bytes as additional records.

`aegis_raf_probe()` performs structural checks but has no key and does not authenticate the header or check that all records exist.
Its results are untrusted hints for algorithm selection and bounded buffer allocation.

Opening a file authenticates its header, not every chunk; an unread corrupt chunk can remain undetected until accessed.

For a plaintext offset `p`, the chunk index is `floor(p / C)` and the offset inside that chunk is `p % C`.
Bound reads by `L` and split cross-chunk reads accordingly.

Check additions such as `offset + length` for overflow before doing I/O.

Treat short reads, incomplete writes, and authentication failures as errors, not as empty or zero-filled records.

## Updating, extending, and truncating

For a partial overwrite, authenticate and decrypt the existing chunk, modify the requested bytes, then encrypt the entire chunk with a fresh nonce.
Preserve valid bytes both before and after the changed range.

A complete chunk overwrite can replace the record without reading its old contents.

A write beyond EOF or a truncation that grows the file fills the gap with plaintext zeros.
Every newly required chunk must have a real nonce, ciphertext, and valid tag.
An absent record or a filesystem hole containing raw zeros is not an encrypted zero chunk.

The reference implementation uses this ordering:

- Growth: enlarge the backing store if more records are needed, write the affected records, then publish the larger logical size in a newly authenticated header.
- Shrink: publish the smaller logical size in a newly authenticated header, then shorten the backing store to `64 + chunk_count * record_size`.
  Retained chunk records are not rewritten.
- Overwrite without growth: replace the affected records; the header need not change.

These operations are **not transactions**.
There is no journal, redundant header, generation counter, or atomic multi-record commit in the format.

A torn header write can make the file unreadable; a failed multi-record write can leave some records changed and others unchanged.

Storage durability and crash recovery need an application-level design.

In libaegis, failures after a mutation begins make the context unusable until it is closed and reopened.
Reopening is not rollback or repair, and it may fail if the header is damaged.

A sync failure alone does not invalidate the context.

## Optional application context binding

Applications may use `aegis_raf_derive_master_key()` before the per-file derivation.
This does not change the wire format and is not indicated in the header.

Both writer and reader must agree on the application key and the exact context bytes outside the RAF file.

For an application key of `K` bytes:

```text
label = ASCII("aegis-raf-master-key-v1")
input = label || application_key || LE64(len(context)) || context
master_key = RAF_KDF(input, K, K)
```

Here the label is exactly 23 bytes, **without** a terminating zero byte.
As with the per-file label, use only the ASCII bytes shown.

The application key and output must both be 16 bytes or both be 32 bytes.

The context is arbitrary bytes, limited to 120 bytes for 16-byte keys or 72 bytes for 32-byte keys.

An empty context still derives a new key; it does not pass the application key through unchanged.
Use the result as `master_key` in the normal per-file derivation.

Neither RAF KDF is a password-hardening function.
If the application starts from a password, it must separately define a suitable password KDF and how its salt and parameters are stored.

## Optional Merkle tree

The libaegis Merkle tree is application-maintained state, not an on-disk RAF extension.
Enabling it adds no header flags, records, roots, or trailers to the file.
A reader does not need a Merkle implementation to decrypt RAF files.

Leaf hashes cover the valid plaintext bytes of each chunk, with the chunk index supplied to the callback.
They are not the record's AEAD tags, and they exclude bytes beyond logical EOF.

The application supplies the leaf, parent, empty-node, and commitment hash functions, so RAF does not prescribe a universal content digest.

The tree is initialized empty on open; rebuild it from authenticated chunk data before using it as a commitment to existing contents.

The commitment callback receives the structural root, logical file size, and this 32-byte context:

```text
version || algorithm_id || LE32(chunk_size) || file_id || 00 00
```

The application defines how to hash these inputs and how to preserve a trusted commitment separately.
A commitment recomputed only from the current file cannot establish that the file is the latest version.

