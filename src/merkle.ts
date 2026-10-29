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

export function verifyMerkleProof(
  leaf: Uint8Array,
  index: number,
  proof: Uint8Array[],
  root: Uint8Array,
): boolean {
  if (index < 0 || !Number.isInteger(index)) return false;
  if (root.byteLength !== 32) return false;
  let node = leaf;
  let position = index;
  for (const sibling of proof) {
    if (sibling.byteLength !== 32) return false;
    node = position % 2 === 0 ? sha256(concat(node, sibling)) : sha256(concat(sibling, node));
    position = Math.floor(position / 2);
  }
  if (node.byteLength !== root.byteLength) return false;
  for (let i = 0; i < node.byteLength; i++) if (node[i] !== root[i]) return false;
  return true;
}
