"""Public child-key derivation below a vault xpub, exactly as the Vaultody server derives addresses.

The server derives every address at ``m/{account}/{change}/{index}`` below the vault's stored xpub, with no
hardened steps, so the public key alone is enough:

- secp256k1 (ECDSA chains) uses standard BIP 32 public derivation, through the ``hdkey`` JavaScript library.
  When a child is invalid (the HMAC's left half is at least the curve order, or the sum is the point at
  infinity), hdkey quietly moves on to the next index, as BIP 32 suggests, while the server still records
  the index it asked for. That is mirrored here: the address stored for index i may be child i + 1. The
  chance of meeting this is about 2^-127 per step.
- ed25519 (Solana) uses Vaultody's own scheme, since BIP 32 has no ed25519 public derivation:

  - the xpub layout is BIP 32's, with the key field holding ``0x00`` and the 32-byte encoded point;
  - the child point is the parent point times the integer HMAC-SHA256(chainCode, 0x02 || key || index),
    the index as 4 bytes little-endian and the digest read big-endian;
  - the child chain code is HMAC-SHA256(chainCode, 0x03 || key || index), the same index bytes.

The version, depth, parent fingerprint and child number in an xpub are ignored. The server rewrites the
version to the mainnet xpub one before deriving, and xpubs from older vaults sit at depth 1 with a parent
fingerprint, none of which changes what derives below them.
"""

import hashlib
import hmac
from collections import namedtuple

from .crypto import ed25519, secp256k1
from .crypto.base58 import b58check_decode

ECDSA = "ECDSA"
EDDSA = "EDDSA"

# Indexes at or above this are hardened, which needs the private key.
HARDENED = 0x80000000

_XPUB_LENGTH = 78

# ``key`` is the 33-byte compressed key for ECDSA and the 32-byte encoded point for EdDSA.
Node = namedtuple("Node", ["algorithm", "chain_code", "key", "point"])


class Underivable(Exception):
    """The server itself could not derive this child (it would need a hardened step)."""


def _hmac_sha512(key, data):
    return hmac.new(key, data, hashlib.sha512).digest()


def _hmac_sha256(key, data):
    return hmac.new(key, data, hashlib.sha256).digest()


def parse_xpub(xpub, algorithm):
    """The root node of a vault xpub. Raises ValueError if it is not a usable extended public key."""
    if not isinstance(xpub, str):
        raise TypeError("an xpub must be str")
    data = b58check_decode(xpub)
    if len(data) != _XPUB_LENGTH:
        raise ValueError("an extended public key is 78 bytes, this one is {}".format(len(data)))
    chain_code = data[13:45]
    key = data[45:]
    if algorithm == ECDSA:
        if key[0] not in (2, 3):
            raise ValueError("an ECDSA xpub must hold a compressed public key (02 or 03)")
        return Node(ECDSA, chain_code, key, secp256k1.decompress(key))
    if algorithm == EDDSA:
        if key[0] != 0:
            raise ValueError("an EdDSA xpub must hold 0x00 followed by the 32-byte public key")
        return Node(EDDSA, chain_code, key[1:], ed25519.decode(key[1:]))
    raise ValueError("unknown algorithm {!r}".format(algorithm))


def _ecdsa_child(node, index):
    while True:
        if index >= HARDENED:
            # hdkey's next try would be a hardened index, which fails without the private key.
            raise Underivable("no valid non-hardened child at or after this index")
        digest = _hmac_sha512(node.chain_code, node.key + index.to_bytes(4, "big"))
        tweak = int.from_bytes(digest[:32], "big")
        if tweak < secp256k1.N:
            point = secp256k1.add(secp256k1.multiply(tweak), node.point)
            if point is not None:
                return Node(ECDSA, digest[32:], secp256k1.compress(point), point)
        index += 1


def _eddsa_child(node, index):
    if index >= HARDENED:
        raise Underivable("hardened derivation is not supported")
    index_bytes = index.to_bytes(4, "little")
    tweak = int.from_bytes(_hmac_sha256(node.chain_code, b"\x02" + node.key + index_bytes), "big")
    chain_code = _hmac_sha256(node.chain_code, b"\x03" + node.key + index_bytes)
    point = ed25519.multiply(tweak, node.point)
    return Node(EDDSA, chain_code, ed25519.encode(point), point)


def derive_child(node, index):
    """The non-hardened child ``index`` of a node, as the server derives it."""
    if not 0 <= index < HARDENED:
        raise ValueError("a non-hardened index is 0 to 2^31 - 1")
    if node.algorithm == ECDSA:
        return _ecdsa_child(node, index)
    return _eddsa_child(node, index)


def derive_path(node, indexes):
    for index in indexes:
        node = derive_child(node, index)
    return node
