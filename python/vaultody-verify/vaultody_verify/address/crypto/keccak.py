"""Keccak-256 as Ethereum and Tron use it, in pure Python.

``hashlib.sha3_256`` is not this hash. FIPS 202 (SHA-3) runs the same Keccak-f[1600] permutation but pads
the message with the bits 0x06, while the original Keccak submission, which Ethereum adopted before SHA-3
was final, pads with 0x01. The digests differ completely, so Keccak-256 has to be vendored.

Written for this package from the Keccak reference (keccak.team, "The Keccak reference" 3.0) and FIPS 202
section 3.2: the 24 round constants and the rotation offsets below are the published ones. The tests check
the permutation against ``hashlib.sha3_256`` (same permutation, SHA-3 padding) for many message lengths,
and Keccak-256 against the Keccak team's known answers.
"""

_MASK = (1 << 64) - 1

_ROUND_CONSTANTS = (
    0x0000000000000001, 0x0000000000008082, 0x800000000000808A, 0x8000000080008000,
    0x000000000000808B, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
    0x000000000000008A, 0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
    0x000000008000808B, 0x800000000000008B, 0x8000000000008089, 0x8000000000008003,
    0x8000000000008002, 0x8000000000000080, 0x000000000000800A, 0x800000008000000A,
    0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
)

# Rotation offset of lane (x, y), stored at index x + 5 * y.
_ROTATIONS = (
    0, 1, 62, 28, 27,
    36, 44, 6, 55, 20,
    3, 10, 43, 25, 39,
    41, 45, 15, 21, 8,
    18, 2, 61, 56, 14,
)

# Rho and pi together: lane (x, y) moves to lane (y, 2x + 3y).
_PI = tuple(y + 5 * ((2 * x + 3 * y) % 5) for y in range(5) for x in range(5))
_SOURCE = tuple(x + 5 * y for y in range(5) for x in range(5))


def _rotate(lane, offset):
    return ((lane << offset) | (lane >> (64 - offset))) & _MASK if offset else lane


def keccak_f1600(lanes):
    """The Keccak-f[1600] permutation over 25 64-bit lanes (lane (x, y) at index x + 5 * y), in place."""
    for round_constant in _ROUND_CONSTANTS:
        # theta
        columns = [lanes[x] ^ lanes[x + 5] ^ lanes[x + 10] ^ lanes[x + 15] ^ lanes[x + 20] for x in range(5)]
        for x in range(5):
            mix = columns[(x - 1) % 5] ^ _rotate(columns[(x + 1) % 5], 1)
            for y in range(0, 25, 5):
                lanes[x + y] ^= mix
        # rho and pi
        moved = [0] * 25
        for source, target in zip(_SOURCE, _PI):
            moved[target] = _rotate(lanes[source], _ROTATIONS[source])
        # chi
        for y in range(0, 25, 5):
            row = moved[y:y + 5]
            for x in range(5):
                lanes[x + y] = row[x] ^ ((~row[(x + 1) % 5]) & row[(x + 2) % 5])
        # iota
        lanes[0] ^= round_constant


def _sponge(data, rate_bytes, padding_byte, output_bytes):
    data = bytes(data)
    padded = bytearray(data)
    padded.append(padding_byte)
    padded.extend(b"\x00" * (-len(padded) % rate_bytes))
    padded[-1] |= 0x80
    lanes = [0] * 25
    for offset in range(0, len(padded), rate_bytes):
        block = padded[offset:offset + rate_bytes]
        for index in range(rate_bytes // 8):
            lanes[index] ^= int.from_bytes(block[8 * index:8 * index + 8], "little")
        keccak_f1600(lanes)
    output = b"".join(lane.to_bytes(8, "little") for lane in lanes[:rate_bytes // 8])
    return output[:output_bytes]


def keccak256(data):
    """Keccak-256 with the original 0x01 padding (rate 1088 bits), as Ethereum and Tron use it."""
    return _sponge(data, 136, 0x01, 32)


def _sha3_256(data):
    """SHA3-256 (the same sponge with FIPS 202 padding). Only for testing the permutation against hashlib."""
    return _sponge(data, 136, 0x06, 32)
