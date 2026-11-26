"""CashAddr, the Bitcoin Cash address format.

Written for this package from the specification, ``spec/cashaddr.md`` in github.com/bitcoincashorg/
bitcoincash.org (commit a86ce75cbdce8b14fa90b2315ebc7f0d78e6c9cb): the version byte, the 40-bit BCH-code
checksum (``PolyMod`` and its five generator constants) and the base32 alphabet are taken from there. The
result keeps its ``prefix:`` because the server returns Bitcoin Cash addresses with it.
"""

from .bech32 import CHARSET, convertbits

P2PKH = 0
P2SH = 1

_GENERATORS = (0x98F2BC8E61, 0x79B76D99E2, 0xF33E5FB3C4, 0xAE2EABE2A8, 0x1E4F43E470)

# The low three bits of the version byte give the hash size.
_SIZE_CODES = {20: 0, 24: 1, 28: 2, 32: 3, 40: 4, 48: 5, 56: 6, 64: 7}


def polymod(values):
    """The specification's PolyMod: 0 for a valid address."""
    checksum = 1
    for value in values:
        top = checksum >> 35
        checksum = ((checksum & 0x07FFFFFFFF) << 5) ^ value
        for bit, generator in enumerate(_GENERATORS):
            if (top >> bit) & 1:
                checksum ^= generator
    return checksum ^ 1


def prefix_values(prefix):
    """The lower five bits of each prefix character, then a zero for the ':' separator."""
    return [ord(character) & 0x1F for character in prefix] + [0]


def encode(prefix, address_type, hash_bytes):
    """``prefix:payload`` for a hash of the given type (P2PKH = 0, P2SH = 1)."""
    hash_bytes = bytes(hash_bytes)
    if len(hash_bytes) not in _SIZE_CODES or not 0 <= address_type < 16:
        raise ValueError("unsupported CashAddr type or hash size")
    payload = convertbits([(address_type << 3) | _SIZE_CODES[len(hash_bytes)]] + list(hash_bytes), 8, 5)
    checksum = polymod(prefix_values(prefix) + payload + [0] * 8)
    payload += [(checksum >> 5 * (7 - index)) & 0x1F for index in range(8)]
    return prefix + ":" + "".join(CHARSET[value] for value in payload)
