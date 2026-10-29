/**
 * AVM consensus hashing, matching `avm-proofpack` and go-algorand.
 *
 * - transaction id   = sha256("TX"   ‖ canonical(txn))
 * - STIB hash        = sha256("STIB" ‖ stib bytes)
 * - Merkle leaf (TL) = sha256("TL"   ‖ txid ‖ stib hash)
 */
import { encode, sha256, type MpValue } from "./msgpack.ts";

const utf8 = (text: string): Uint8Array => new TextEncoder().encode(text);

export const DOMAIN_TRANSACTION = utf8("TX");
export const DOMAIN_SIGNED_TXN_IN_BLOCK = utf8("STIB");
export const DOMAIN_TXN_MERKLE_LEAF = utf8("TL");

export function txnId(txn: MpValue): Uint8Array {
  return sha256(DOMAIN_TRANSACTION, encode(txn));
}

export function stibHash(stibBytes: Uint8Array): Uint8Array {
  return sha256(DOMAIN_SIGNED_TXN_IN_BLOCK, stibBytes);
}

export function txnMerkleLeaf(id: Uint8Array, stib: Uint8Array): Uint8Array {
  if (id.byteLength !== 32 || stib.byteLength !== 32) {
    throw new Error("txn id and stib hash must be 32 bytes");
  }
  return sha256(DOMAIN_TXN_MERKLE_LEAF, id, stib);
}
