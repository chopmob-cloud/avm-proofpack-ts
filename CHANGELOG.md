# Changelog

All notable changes to this project are documented here. This project adheres
to [Semantic Versioning](https://semver.org/).

## [0.2.0] — 2026-10-29

### Fixed (security)

- **`verifyMerkleProof` was unsound for non-power-of-two trees.** It derived the
  hash-combine direction from the raw bits of `index` with no knowledge of the
  tree shape, so it rejected valid inclusion proofs for every promoted odd-node
  position — the common case for real Algorand/Voi blocks, which rarely hold a
  power-of-two number of transactions. The verifier now walks the tree the way
  `merkleRoot` builds it, tracking each level's width.
- **Merkle `index` was unauthenticated (malleable).** Only the low
  `proof.length` bits of `index` were read, so a proof valid for index *i* also
  validated *i + k·2^proof.length*. `index` is now bound to the tree and
  out-of-range or stray-element inputs are rejected.
- **`decode` could overflow the call stack.** A crafted blob of nested
  array/map headers is now capped at 128 levels and throws `MsgpackError`
  instead of a `RangeError`.

### Changed

- **BREAKING:** `verifyMerkleProof(leaf, index, proof, root)` →
  `verifyMerkleProof(leaf, index, proof, root, leafCount)`. The function cannot
  verify promotions or authenticate `index` without the tree size, so
  `leafCount` is a required argument rather than optional.
- `verifyMerkleProof` now requires a 32-byte `leaf` and compares the computed
  root in constant time.

### Unchanged

- `merkleRoot` and `merkleProof` are byte-for-byte unchanged (the prover was
  already correct), and both Algorand (round 63605124) and Voi (round 181248)
  mainnet conformance vectors still pass.

## [0.1.0]

- Initial release: canonical MessagePack, AVM hashing (`txnId`, `stibHash`,
  `txnMerkleLeaf`) and Merkle inclusion-proof primitives.
