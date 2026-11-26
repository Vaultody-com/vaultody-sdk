"""Known-answer tests for the vendored crypto behind address checking, each against its published source."""

import hashlib
import os

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from vaultody_verify.address.crypto import base58, bech32, cashaddr, ed25519, keccak, secp256k1
from vaultody_verify.address.crypto.ripemd160 import ripemd160

# --- RIPEMD-160 ------------------------------------------------------------------------------------------
# The RIPEMD-160 authors' test vectors (homes.esat.kuleuven.be/~bosselae/ripemd160.html), the same list
# Bitcoin Core's ripemd160.py tests itself with.
RIPEMD160_VECTORS = [
    (b"", "9c1185a5c5e9fc54612808977ee8f548b2258d31"),
    (b"a", "0bdc9d2d256b3ee9daae347be6f4dc835a467ffe"),
    (b"abc", "8eb208f7e05d987a9b044a8e98c6b087f15a0bfc"),
    (b"message digest", "5d0689ef49d2fae572b881b123a85ffa21595f36"),
    (b"abcdefghijklmnopqrstuvwxyz", "f71c27109c692c1b56bbdceb5b9d2865b3708dbc"),
    (b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", "12a053384a9c0c88e405a06c27dcf49ada62eb2b"),
    (b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", "b0e20b6e3116640286ed3a87a5713079b21f5189"),
    (b"1234567890" * 8, "9b752e45573d4b39f4dbd3323cab82bf63326bfb"),
    (b"a" * 1000000, "52783243c1697bdbe16d37f97f68f08325dc1528"),
]


@pytest.mark.parametrize("message, digest", RIPEMD160_VECTORS, ids=range(len(RIPEMD160_VECTORS)))
def test_ripemd160_known_answers(message, digest):
    assert ripemd160(message).hex() == digest


def test_ripemd160_matches_hashlib_where_available():
    try:
        hashlib.new("ripemd160")
    except ValueError:
        pytest.skip("this Python's OpenSSL has no RIPEMD-160, which is why it is vendored")
    for length in list(range(0, 200)) + [1000, 4096]:
        message = os.urandom(length)
        assert ripemd160(message) == hashlib.new("ripemd160", message).digest()


# --- Keccak-256 ------------------------------------------------------------------------------------------
# From the Keccak team's ShortMsgKAT_256.txt (the original Keccak submission, as Ethereum uses it).
KECCAK256_VECTORS = [
    ("", "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"),
    ("cc", "eead6dbfc7340a56caedc044696a168870549a6a7f6f56961e84a54bd9970b8a"),
    ("41fb", "a8eaceda4d47b3281a795ad9e1ea2122b407baf9aabcb9e18b5717b7873537d2"),
    ("1f877c", "627d7bc1491b2ab127282827b8de2d276b13d7d70fb4c5957fdf20655bc7ac30"),
]


@pytest.mark.parametrize("message, digest", KECCAK256_VECTORS)
def test_keccak256_known_answers(message, digest):
    assert keccak.keccak256(bytes.fromhex(message)).hex() == digest


def test_keccak256_of_abc():
    # The value Ethereum tooling (web3, ethers) gives for keccak256("abc").
    assert keccak.keccak256(b"abc").hex() == "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45"


def test_keccak_permutation_matches_hashlib_sha3():
    """SHA3-256 is the same sponge with other padding, so it checks the permutation and the absorbing,
    including every length around the 136-byte block boundary."""
    for length in list(range(0, 420)) + [1000, 5000]:
        message = os.urandom(length)
        assert keccak._sha3_256(message) == hashlib.sha3_256(message).digest()


def test_keccak256_is_not_nist_sha3():
    assert keccak.keccak256(b"") != hashlib.sha3_256(b"").digest()


# --- secp256k1 -------------------------------------------------------------------------------------------


def test_secp256k1_small_multiples_of_the_generator():
    # x coordinates of 2G and 3G, as listed for example in Bitcoin's secp256k1 test data.
    assert secp256k1.multiply(2)[0] == 0xC6047F9441ED7D6D3045406E95C07CD85C778E4B8CEF3CA7ABAC09B95C709EE5
    assert secp256k1.multiply(3)[0] == 0xF9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9
    assert secp256k1.add(secp256k1.G, secp256k1.G) == secp256k1.multiply(2)
    assert secp256k1.add(secp256k1.multiply(2), secp256k1.G) == secp256k1.multiply(3)


def test_secp256k1_infinity():
    assert secp256k1.multiply(secp256k1.N) is None
    assert secp256k1.multiply(0) is None
    assert secp256k1.add(secp256k1.G, secp256k1.multiply(secp256k1.N - 1)) is None
    assert secp256k1.add(None, secp256k1.G) == secp256k1.G


def test_secp256k1_compress_round_trip():
    for scalar in (1, 2, 7, 2 ** 128 + 5, secp256k1.N - 1):
        point = secp256k1.multiply(scalar)
        assert secp256k1.decompress(secp256k1.compress(point)) == point


@pytest.mark.parametrize(
    "encoded",
    [
        "04" + "00" * 32,  # wrong prefix
        "02" + "ff" * 32,  # x above the field prime
        "02" + "00" * 31 + "05",  # x = 5 is not on the curve (5^3 + 7 is not a square)
        "02" + "00" * 31,  # too short
    ],
)
def test_secp256k1_decompress_rejects(encoded):
    with pytest.raises(ValueError):
        secp256k1.decompress(bytes.fromhex(encoded))


# --- ed25519 ---------------------------------------------------------------------------------------------
_BASE_Y = 4 * pow(5, ed25519.P - 2, ed25519.P) % ed25519.P
BASE = ed25519.decode(_BASE_Y.to_bytes(32, "little"))

# Public keys from RFC 8032 section 7.1, tests 1 to 3.
RFC8032_PUBLIC_KEYS = [
    "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
    "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
    "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
]


@pytest.mark.parametrize("public_key", RFC8032_PUBLIC_KEYS)
def test_ed25519_decode_encode_round_trip(public_key):
    assert ed25519.encode(ed25519.decode(bytes.fromhex(public_key))).hex() == public_key


def test_ed25519_scalar_multiplication_matches_cryptography():
    """RFC 8032 5.1.5: the public key is the clamped SHA-512 of the seed times the base point."""
    for _ in range(16):
        seed = os.urandom(32)
        public = Ed25519PrivateKey.from_private_bytes(seed).public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
        scalar = bytearray(hashlib.sha512(seed).digest()[:32])
        scalar[0] &= 248
        scalar[31] = (scalar[31] & 127) | 64
        assert ed25519.encode(ed25519.multiply(int.from_bytes(scalar, "little"), BASE)) == public


def test_ed25519_group_order():
    assert ed25519.encode(ed25519.multiply(ed25519.L, BASE)) == ed25519.encode(ed25519.NEUTRAL)
    assert ed25519.encode(ed25519.multiply(ed25519.L + 1, BASE)) == ed25519.encode(BASE)


def test_ed25519_decode_reduces_a_y_above_p_like_the_server_library():
    # elliptic's pointFromY reduces y modulo p; y = p + 1 decodes as y = 1, the neutral element.
    encoded = (ed25519.P + 1).to_bytes(32, "little")
    assert ed25519.encode(ed25519.decode(encoded)) == ed25519.encode(ed25519.NEUTRAL)


@pytest.mark.parametrize(
    "encoded",
    [
        "01" + "00" * 30 + "80",  # y = 1 gives x = 0, which can't carry the odd sign bit
        "02" + "00" * 31,  # y = 2 is not on the curve
        "00" * 31,  # 31 bytes
    ],
)
def test_ed25519_decode_rejects(encoded):
    with pytest.raises(ValueError):
        ed25519.decode(bytes.fromhex(encoded))


# --- Base58 ----------------------------------------------------------------------------------------------
# Bitcoin Core src/test/data/base58_encode_decode.json.
BASE58_VECTORS = [
    ("", ""),
    ("61", "2g"),
    ("626262", "a3gV"),
    ("636363", "aPEr"),
    ("73696d706c792061206c6f6e6720737472696e67", "2cFupjhnEsSn59qHXstmK2ffpLv2"),
    ("00eb15231dfceb60925886b67d065299925915aeb172c06647", "1NS17iag9jJgTHD1VXjvLCEnZuQ3rJDE9L"),
    ("516b6fcd0f", "ABnLTmg"),
    ("bf4f89001e670274dd", "3SEo3LWLoPntC"),
    ("572e4794", "3EFU7m"),
    ("ecac89cad93923c02321", "EJDM8drfXA6uyA"),
    ("10c8511e", "Rt5zm"),
    ("00000000000000000000", "1111111111"),
    ("00" * 40, "1" * 40),
    ("00" * 39 + "01", "1" * 39 + "2"),
    (
        "00" * 86 + "ec39d04c37e71e5d591881f6",
        "1" * 86 + "5TYzLYH1udmLdzCLM",
    ),
    (
        "000111d38e5fc9071ffcd20b4a763cc9ae4f252bb4e48fd66a835e252ada93ff480d6dd43dc62a641155a5",
        "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz",
    ),
    (
        bytes(range(256)).hex(),
        "1cWB5HCBdLjAuqGGReWE3R3CguuwSjw6RHn39s2yuDRTS5NsBgNiFpWgAnEx6VQi8csexkgYw3mdYrMHr8x9i7aEwP8kZ7vccXWqKDvG"
        "v3u1GxFKPuAkn8JCPPGDMf3vMMnbzm6Nh9zh1gcNsMvH3ZNLmP5fSG6DGbbi2tuwMWPthr4boWwCxf7ewSgNQeacyozhKDDQQ1qL5fQFUW"
        "52QKUZDZ5fw3KXNQJMcNTcaB723LchjeKun7MuGW5qyCBZYzA1KjofN1gYBV3NqyhQJ3Ns746GNuf9N2pQPmHz4xpnSrrfCvy6TVVz5d4P"
        "drjeshsWQwpZsZGzvbdAdN8MKV5QsBDY",
    ),
    ("271F359E", "zzzzy"),
    ("271F359F", "zzzzz"),
    ("271F35A0", "211111"),
    ("271F35A1", "211112"),
]


@pytest.mark.parametrize("data, text", BASE58_VECTORS, ids=range(len(BASE58_VECTORS)))
def test_base58_known_answers(data, text):
    assert base58.b58encode(bytes.fromhex(data)) == text
    assert base58.b58decode(text) == bytes.fromhex(data)


def test_base58_rejects_characters_outside_the_alphabet():
    for text in ("0", "O", "I", "l", "3SEo3LWLoPntC ", "a+b"):
        with pytest.raises(ValueError):
            base58.b58decode(text)


def test_base58check():
    # Bitcoin's genesis coinbase address: version 0x00 and the HASH160 in the Base58 vectors above.
    assert base58.b58check_decode("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa").hex() == "0062e907b15cbf27d5425399ebf6f0fb50ebb88f18"
    with pytest.raises(ValueError):
        base58.b58check_decode("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNb")
    with pytest.raises(ValueError):
        base58.b58check_decode("1")


def test_base58check_ripple_alphabet():
    # ACCOUNT_ZERO and ACCOUNT_ONE, the special addresses in the XRP Ledger documentation.
    assert base58.b58check_encode(b"\x00" * 21, base58.RIPPLE_ALPHABET) == "rrrrrrrrrrrrrrrrrrrrrhoLvTp"
    assert base58.b58check_encode(b"\x00" * 20 + b"\x01", base58.RIPPLE_ALPHABET) == "rrrrrrrrrrrrrrrrrrrrBZbvji"


# --- Bech32 ----------------------------------------------------------------------------------------------
# BIP 173 "Test vectors": valid Bech32 strings, and valid version 0 segwit addresses with their scriptPubKey.
BECH32_VALID = [
    "A12UEL5L",
    "a12uel5l",
    "an83characterlonghumanreadablepartthatcontainsthenumber1andtheexcludedcharactersbio1tt5tgs",
    "abcdef1qpzry9x8gf2tvdw0s3jn54khce6mua7lmqqqxw",
    "11" + "q" * 82 + "c8247j",
    "split1checkupstagehandshakeupstreamerranterredcaperred2y9e3w",
]
SEGWIT_V0_VECTORS = [
    ("BC1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KV8F3T4", "0014751e76e8199196d454941c45d1b3a323f1433bd6"),
    (
        "tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sl5k7",
        "00201863143c14c5166804bd19203356da136c985678cd4d27a1b8c6329604903262",
    ),
    (
        "tb1qqqqqp399et2xygdj5xreqhjjvcmzhxw4aywxecjdzew6hylgvsesrxh6hy",
        "0020000000c4a5cad46221b2a187905e5266362b99d5e91c6ce24d165dab93e86433",
    ),
]


@pytest.mark.parametrize("text", BECH32_VALID)
def test_bech32_checksums(text):
    lowered = text.lower()
    hrp, data = lowered[:lowered.rfind("1")], lowered[lowered.rfind("1") + 1:]
    values = [bech32.CHARSET.index(character) for character in data]
    assert bech32.bech32_encode(hrp, values[:-6]) == lowered


@pytest.mark.parametrize("address, script", SEGWIT_V0_VECTORS)
def test_segwit_v0_addresses(address, script):
    hrp = address.lower()[:2]
    assert bech32.encode_segwit_v0(hrp, bytes.fromhex(script)[2:]) == address.lower()


def test_segwit_v0_refuses_other_program_lengths():
    with pytest.raises(ValueError):
        bech32.encode_segwit_v0("bc", b"\x00" * 21)


# --- CashAddr --------------------------------------------------------------------------------------------
# spec/cashaddr.md in bitcoincashorg/bitcoincash.org: checksum vectors, "Examples of address translation"
# (legacy hashes from the Base58 vectors above) and "Larger Test Vectors".
CASHADDR_CHECKSUM_VECTORS = [
    "prefix:x64nx6hz",
    "p:gpf8m4h7",
    "bitcoincash:qpzry9x8gf2tvdw0s3jn54khce6mua7lcw20ayyn",
    "bchtest:testnetaddress4d6njnut",
    "bchreg:555555555555555555555555555555555555555555555udxmlmrz",
]
CASHADDR_TRANSLATIONS = [
    ("1BpEi6DfDAUFd7GtittLSdBeYJvcoaVggu", "bitcoincash:qpm2qsznhks23z7629mms6s4cwef74vcwvy22gdx6a"),
    ("1KXrWXciRDZUpQwQmuM1DbwsKDLYAYsVLR", "bitcoincash:qr95sy3j9xwd2ap32xkykttr4cvcu7as4y0qverfuy"),
    ("16w1D5WRVKJuZUsSRzdLp9w3YGcgoxDXb", "bitcoincash:qqq3728yw0y47sqn6l2na30mcw6zm78dzqre909m2r"),
    ("3CWFddi6m4ndiGyKqzYvsFYagqDLPVMTzC", "bitcoincash:ppm2qsznhks23z7629mms6s4cwef74vcwvn0h829pq"),
    ("3LDsS579y7sruadqu11beEJoTjdFiFCdX4", "bitcoincash:pr95sy3j9xwd2ap32xkykttr4cvcu7as4yc93ky28e"),
    ("31nwvkZwyPdgzjBJZXfDmSWsC4ZLKpYyUw", "bitcoincash:pqq3728yw0y47sqn6l2na30mcw6zm78dzq5ucqzc37"),
]
CASHADDR_LARGER = [
    (0, "bitcoincash:qr6m7j9njldwwzlg9v7v53unlr4jkmx6eylep8ekg2", "F5BF48B397DAE70BE82B3CCA4793F8EB2B6CDAC9"),
    (1, "bchtest:pr6m7j9njldwwzlg9v7v53unlr4jkmx6eyvwc0uz5t", "F5BF48B397DAE70BE82B3CCA4793F8EB2B6CDAC9"),
    (1, "pref:pr6m7j9njldwwzlg9v7v53unlr4jkmx6ey65nvtks5", "F5BF48B397DAE70BE82B3CCA4793F8EB2B6CDAC9"),
    (15, "prefix:0r6m7j9njldwwzlg9v7v53unlr4jkmx6ey3qnjwsrf", "F5BF48B397DAE70BE82B3CCA4793F8EB2B6CDAC9"),
    (0, "bitcoincash:q9adhakpwzztepkpwp5z0dq62m6u5v5xtyj7j3h2ws4mr9g0", "7ADBF6C17084BC86C1706827B41A56F5CA32865925E946EA"),
    (1, "bchtest:p9adhakpwzztepkpwp5z0dq62m6u5v5xtyj7j3h2u94tsynr", "7ADBF6C17084BC86C1706827B41A56F5CA32865925E946EA"),
    (
        0,
        "bitcoincash:qvch8mmxy0rtfrlarg7ucrxxfzds5pamg73h7370aa87d80gyhqxq5nlegake",
        "3173EF6623C6B48FFD1A3DCC0CC6489B0A07BB47A37F47CFEF4FE69DE825C060",
    ),
    (
        15,
        "prefix:0lg0x333p4238k0qrc5ej7rzfw5g8e4a4r6vvzyrcy8j3s5k0en7calvclhw46hudk5flttj6ydvjc0pv3nchp52amk97tqa5zygg96ms92w6845",
        "D0F346310D5513D9E01E299978624BA883E6BDA8F4C60883C10F28C2967E67EC77ECC7EEEAEAFC6DA89FAD72D11AC961E164678B868AEEEC5F2C1DA08884175B",
    ),
]


@pytest.mark.parametrize("address", CASHADDR_CHECKSUM_VECTORS)
def test_cashaddr_checksum_vectors(address):
    prefix, payload = address.split(":")
    values = cashaddr.prefix_values(prefix) + [bech32.CHARSET.index(character) for character in payload]
    assert cashaddr.polymod(values) == 0


@pytest.mark.parametrize("legacy, address", CASHADDR_TRANSLATIONS)
def test_cashaddr_translations(legacy, address):
    payload = base58.b58check_decode(legacy)
    address_type = cashaddr.P2PKH if payload[0] == 0x00 else cashaddr.P2SH
    assert cashaddr.encode("bitcoincash", address_type, payload[1:]) == address


@pytest.mark.parametrize("address_type, address, payload", CASHADDR_LARGER)
def test_cashaddr_larger_vectors(address_type, address, payload):
    assert cashaddr.encode(address.split(":")[0], address_type, bytes.fromhex(payload)) == address
