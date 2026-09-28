# RAF Merkle tree format

This guide describes the logical structure of an optional Merkle tree over a [RAF file](RAF.md), its hash inputs, and its file commitment.

**The tree is not stored in a RAF file.**

Its use adds no header field, trailer, or extra chunk record.
This specification defines no tree-storage, sidecar-file, or Merkle-proof serialization format.

## Parameters and notation

| Symbol           | Meaning                                              |
| ---------------- | ---------------------------------------------------- |
| `M`              | Tree capacity: maximum number of leaves              |
| `H`              | Length in bytes of every node digest and commitment  |
| `C`              | RAF plaintext chunk size                             |
| `L`              | Logical plaintext file size in bytes                 |
| `A`              | Number of chunks currently in the file               |
| `T[level,index]` | Digest of a node, indexed from zero within its level |

The capacity must satisfy `M > 0`.
The hash profile specifies `H` and its security properties.

The number of occupied leaves is:

```text
A = 0                         if L == 0
    1 + floor((L - 1) / C)    otherwise
```

Require `A <= M`.

The tree shape depends on **capacity `M`, not occupied count `A`**.
Growing or shrinking a file does not change the shape while `M` stays fixed.
Different capacities can yield different roots even when the file contents are unchanged.

## Tree shape

Level 0 contains exactly `M` leaves.
Each subsequent level contains half as many nodes, rounded up:

```text
count[0] = M
count[level + 1] = ceil(count[level] / 2)
```

The highest level is the first level containing exactly one node.
That node is the structural root; there are no further one-node levels.

The total node count is the sum of the level counts.
For power-of-two capacities it is `2*M - 1`.
That formula does not apply to arbitrary capacities, and `M` is not rounded up to a power of two.
For `M = 5`, there are 11 nodes, not 9 or 15.

| Capacity | Level counts     | Total nodes |
| -------: | ---------------- | ----------: |
|        1 | `1`              |           1 |
|        2 | `2, 1`           |           3 |
|        3 | `3, 2, 1`        |           6 |
|        4 | `4, 2, 1`        |           7 |
|        5 | `5, 3, 2, 1`     |          11 |
|        8 | `8, 4, 2, 1`     |          15 |
|       16 | `16, 8, 4, 2, 1` |          31 |

Missing right siblings at odd-sized levels are represented by the `Empty` hash defined below.
They are not nodes in the tree shape and are not included in these counts.

## Hash functions

The tree uses four hash functions: `Leaf`, `Parent`, `Empty`, and `Commitment`.
Each produces an `H`-byte digest.

The notation below describes logical inputs, not their byte encodings.

Apart from the commitment context defined below, this specification does not select the byte order, field widths, domain labels, or hash algorithm.
An interoperable hash profile must specify them explicitly.

### Occupied leaves

For `0 <= i < A`:

```text
valid_length = min(C, L - i*C)
T[0,i] = Leaf(plaintext_chunk[0:valid_length], valid_length, i)
```

Here, `plaintext_chunk` is chunk `i` of the RAF plaintext.

The leaf covers its entire logically visible plaintext, not ciphertext, record nonces, or AEAD tags.
For the final chunk, bytes beyond logical EOF are excluded, including authenticated tail bytes left behind by a previous truncation.

Leaf hashing must be deterministic and depend only on the chunk bytes, their length, and chunk index under the agreed hash profile.
It must not depend on mutable state, the current overall file size, or the write history.

A chunk full of plaintext zeros is still an occupied leaf hashed with `Leaf`.
It is not an empty node.

### Unoccupied leaves

For `A <= i < M`:

```text
T[0,i] = Empty(0, i)
```

These empty leaf digests are not implicitly zero bytes and are not the result of `Leaf` with zero-length input.

### Parents and missing siblings

Parent index `j` above child level `level` is defined by:

```text
left = T[level, 2*j]

if 2*j + 1 < count[level]:
    right = T[level, 2*j + 1]
else:
    right = Empty(level, 2*j + 1)

T[level + 1, j] = Parent(left, right, level, j)
```

**The coordinates supplied to `Parent` are the children's level and the parent's index.**

For example, `T[1,2]` uses `level = 0` and `j = 2`.
The root of a five-leaf tree, `T[3,0]`, uses `level = 2` and `j = 0`.

Each child digest is exactly `H` bytes.
Left and right are ordered inputs; they are not sorted.

When a right sibling is missing, its digest is `Empty` with that missing node's level and index.
It is not a duplicate of the left child or an all-zero digest, and the left child is not promoted unchanged.

An internal node that exists in the tree shape always uses `Parent`, even if all leaves below it are unoccupied.
Such a subtree is not replaced with `Empty` at the internal node's coordinates.

### Five-leaf example

Suppose `M = 5` but only three chunks are occupied:

```text
T[0,0] = Leaf(chunk0, valid_length0, 0)
T[0,1] = Leaf(chunk1, valid_length1, 1)
T[0,2] = Leaf(chunk2, valid_length2, 2)
T[0,3] = Empty(0, 3)
T[0,4] = Empty(0, 4)

T[1,0] = Parent(T[0,0], T[0,1], 0, 0)
T[1,1] = Parent(T[0,2], T[0,3], 0, 1)
T[1,2] = Parent(T[0,4], Empty(0, 5), 0, 2)

T[2,0] = Parent(T[1,0], T[1,1], 1, 0)
T[2,1] = Parent(T[1,2], Empty(1, 3), 1, 1)

T[3,0] = Parent(T[2,0], T[2,1], 2, 0)
```

The `T` values are the 11 nodes of this tree.

`Empty(0,5)` and `Empty(1,3)` represent absent right siblings, not additional nodes.

### Single-leaf and empty-file cases

With `M = 1`, there is only level 0.
Its single digest is also the structural root, with no `Parent` hash.

For an empty file, all `M` leaves use `Empty(0,i)` and all existing parents follow the usual `Parent` rule.
With `M = 1`, the empty-file root is simply `Empty(0,0)`.
Zero capacity is not an alternate representation for an empty file; it is invalid.

## Structural root versus file commitment

The structural root is the sole node at the highest level.
The file commitment binds it to the RAF file's identity, parameters, and logical length.
It is distinct from the structural root and is not an additional tree node.

The commitment context is exactly 32 bytes:

| Offset | Length | Contents                           |
| -----: | -----: | ---------------------------------- |
|      0 |      1 | RAF format version                 |
|      1 |      1 | RAF algorithm ID                   |
|      2 |      4 | Chunk size, unsigned little-endian |
|      6 |     24 | File ID from the RAF header        |
|     30 |      2 | Zero bytes                         |

In byte-concatenation notation:

```text
context = version || algorithm_id || LE32(C) || file_id || 00 00
commitment = Commitment(structural_root, context, L)
```

`L` is an unsigned 64-bit integer, separate from the context.
The hash profile must define its encoding and incorporate the whole context, all `H` root bytes, and `L` into the commitment hash.

Capacity, digest length, and hash-profile identifiers are not encoded in the 32-byte context.
They must be agreed on separately and bound in the surrounding protocol where needed.
