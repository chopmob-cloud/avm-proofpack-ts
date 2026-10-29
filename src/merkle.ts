/**
 * Merkle inclusion proofs over a binary tree, as used by the AVM transaction
 * commitment. Odd nodes are promoted unchanged to the next level.
 */
import { sha256 } from "./msgpack.ts";

export class MerkleError extends Error {}

function concat(a: Uint8Array, b: Uint8Array): Uint8Array {
  const out = new Uint8Array(a.byteLength + b.byteLength);
  out.set(a, 0);
  out.set(b, a.byteLength);
  return out;
}

export function merkleRoot(leaves: Uint8Array[]): Uint8Array {
  if (leaves.length === 0) throw new MerkleError("empty tree has no root");
  let level = leaves.slice();
  while (level.length > 1) {
    const next: Uint8Array[] = [];
    for (let i = 0; i < level.length; i += 2) {
      next.push(i + 1 < level.length ? sha256(concat(level[i], level[i + 1])) : level[i]);
    }
    level = next;
  }
  return level[0];
}

export function merkleProof(leaves: Uint8Array[], index: number): Uint8Array[] {
  if (index < 0 || index >= leaves.length) throw new MerkleError("index out of range");
  const proof: Uint8Array[] = [];
  let level = leaves.slice();
  let position = index;
  while (level.length > 1) {
    const sibling = position % 2 === 0 ? position + 1 : position - 1;
    if (sibling < level.length) proof.push(level[sibling]);
    const next: Uint8Array[] = [];
    for (let i = 0; i < level.length; i += 2) {
      next.push(i + 1 < level.length ? sha256(concat(level[i], level[i + 1])) : level[i]);
    }
    level = next;
    position = Math.floor(position / 2);
  }
  return proof;
}

/**
 * Verify that `leaf` sits at `index` in a tree of `leafCount` leaves whose root
 * is `root`.
 *
 * The verifier walks the tree the same way `merkleRoot` builds it, so it must
 * know how wide each level is: a promoted odd node consumes no proof element,
 * and the combine direction at each level comes from the node's position within
 * that level. Deriving direction from the raw `index` bits alone (without the
 * level widths) desyncs on any tree whose leaf count is not a power of two, and
 * leaves `index` unauthenticated — both are consensus-soundness bugs, so
 * `leafCount` is required and `index` is bound to it.
 */
export function verifyMerkleProof(
  leaf: Uint8Array,
  index: number,
  proof: Uint8Array[],
  root: Uint8Array,
  leafCount: number,
): boolean {
  if (!Number.isInteger(leafCount) || leafCount <= 0) return false;
  if (!Number.isInteger(index) || index < 0 || index >= leafCount) return false;
  if (root.byteLength !== 32 || leaf.byteLength !== 32) return false;

  let node = leaf;
  let position = index;
  let width = leafCount;
  let consumed = 0;
  while (width > 1) {
    // An odd-width level promotes its last node unchanged: no sibling, no proof
    // element. Every other node combines with the sibling at position ^ 1.
    const promoted = position === width - 1 && width % 2 === 1;
    if (!promoted) {
      if (consumed >= proof.length) return false;
      const sibling = proof[consumed++];
      if (sibling.byteLength !== 32) return false;
      node = position % 2 === 0 ? sha256(concat(node, sibling)) : sha256(concat(sibling, node));
    }
    position = Math.floor(position / 2);
    width = Math.ceil(width / 2);
  }
  // Reject proofs carrying stray elements the walk never used.
  if (consumed !== proof.length) return false;

  // Constant-time compare (both operands are public, but it costs nothing).
  if (node.byteLength !== root.byteLength) return false;
  let diff = 0;
  for (let i = 0; i < node.byteLength; i++) diff |= node[i] ^ root[i];
  return diff === 0;
}
