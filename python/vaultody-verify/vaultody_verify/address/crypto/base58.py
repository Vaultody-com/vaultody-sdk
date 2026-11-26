"""Base58 and Base58Check, with the Bitcoin and the XRP Ledger alphabets.

Written for this package after Bitcoin Core's ``src/base58.cpp``: each leading zero byte becomes the
alphabet's first character, the rest is the big-endian number in base 58, and Base58Check appends the first
four bytes of a double SHA-256. XRP uses the same scheme with its own alphabet. Every byte string has
exactly one encoding, so decoding needs no canonical-form check.
"""

import hashlib

BITCOIN_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
RIPPLE_ALPHABET = "rpshnaf39wBUDNEGHJKLM4PQRST7VWXYZ2bcdeCg65jkm8oFqi1tuvAxyz"

_INDEXES = {alphabet: {character: index for index, character in enumerate(alphabet)}
            for alphabet in (BITCOIN_ALPHABET, RIPPLE_ALPHABET)}


def b58encode(data, alphabet=BITCOIN_ALPHABET):
    data = bytes(data)
    stripped = data.lstrip(b"\x00")
    number = int.from_bytes(stripped, "big")
    digits = []
    while number:
        number, remainder = divmod(number, 58)
        digits.append(alphabet[remainder])
    return alphabet[0] * (len(data) - len(stripped)) + "".join(reversed(digits))


def b58decode(text, alphabet=BITCOIN_ALPHABET):
    """The bytes of a Base58 string. Raises ValueError for a character outside the alphabet."""
    if not isinstance(text, str):
        raise TypeError("base58 text must be str")
    indexes = _INDEXES[alphabet]
    stripped = text.lstrip(alphabet[0])
    number = 0
    for character in stripped:
        index = indexes.get(character)
        if index is None:
            raise ValueError("not a base58 character: {!r}".format(character))
        number = number * 58 + index
    body = number.to_bytes((number.bit_length() + 7) // 8, "big")
    return b"\x00" * (len(text) - len(stripped)) + body


def _checksum(payload):
    return hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]


def b58check_encode(payload, alphabet=BITCOIN_ALPHABET):
    payload = bytes(payload)
    return b58encode(payload + _checksum(payload), alphabet)


def b58check_decode(text, alphabet=BITCOIN_ALPHABET):
    """The payload of a Base58Check string. Raises ValueError when the checksum is wrong."""
    data = b58decode(text, alphabet)
    if len(data) < 4 or _checksum(data[:-4]) != data[-4:]:
        raise ValueError("base58check checksum mismatch")
    return data[:-4]
