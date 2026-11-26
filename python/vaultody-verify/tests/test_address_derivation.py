"""Public child derivation below a vault xpub: BIP 32 for ECDSA, Vaultody's own scheme for EdDSA."""

import hashlib
import hmac

import pytest

from vaultody_verify.address import derivation
from vaultody_verify.address.crypto import ed25519, secp256k1
from vaultody_verify.address.crypto.base58 import b58check_decode, b58check_encode
from vaultody_verify.address.derivation import ECDSA, EDDSA, HARDENED, Node, Underivable, derive_child, derive_path, parse_xpub

# BIP 32 (github.com/bitcoin/bips, bip-0032.mediawiki), test vectors 1 and 2: the extended public keys of the
# chains whose last step is not hardened, so public derivation can reach them from their parent.
TV1_M = "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8"
TV1_M_0H = "xpub68Gmy5EdvgibQVfPdqkBBCHxA5htiqg55crXYuXoQRKfDBFA1WEjWgP6LHhwBZeNK1VTsfTFUHCdrfp1bgwQ9xv5ski8PX9rL2dZXvgGDnw"
TV1_M_0H_1 = "xpub6ASuArnXKPbfEwhqN6e3mwBcDTgzisQN1wXN9BJcM47sSikHjJf3UFHKkNAWbWMiGj7Wf5uMash7SyYq527Hqck2AxYysAA7xmALppuCkwQ"
TV1_M_0H_1_2H = "xpub6D4BDPcP2GT577Vvch3R8wDkScZWzQzMMUm3PWbmWvVJrZwQY4VUNgqFJPMM3No2dFDFGTsxxpG5uJh7n7epu4trkrX7x7DogT5Uv6fcLW5"
TV1_M_0H_1_2H_2 = "xpub6FHa3pjLCk84BayeJxFW2SP4XRrFd1JYnxeLeU8EqN3vDfZmbqBqaGJAyiLjTAwm6ZLRQUMv1ZACTj37sR62cfN7fe5JnJ7dh8zL4fiyLHV"
TV1_M_0H_1_2H_2_1000000000 = "xpub6H1LXWLaKsWFhvm6RVpEL9P4KfRZSW7abD2ttkWP3SSQvnyA8FSVqNTEcYFgJS2UaFcxupHiYkro49S8yGasTvXEYBVPamhGW6cFJodrTHy"
TV2_M = "xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB"
TV2_M_0 = "xpub69H7F5d8KSRgmmdJg2KhpAK8SR3DjMwAdkxj3ZuxV27CprR9LgpeyGmXUbC6wb7ERfvrnKZjXoUmmDznezpbZb7ap6r1D3tgFxHmwMkQTPH"
TV2_M_0_2147483647H = "xpub6ASAVgeehLbnwdqV6UKMHVzgqAG8Gr6riv3Fxxpj8ksbH9ebxaEyBLZ85ySDhKiLDBrQSARLq1uNRts8RuJiHjaDMBU4Zn9h8LZNnBC5y4a"
TV2_M_0_2147483647H_1 = "xpub6DF8uhdarytz3FWdA8TvFSvvAh8dP3283MY7p2V4SeE2wyWmG5mg5EwVvmdMVCQcoNJxGoWaU9DCWh89LojfZ537wTfunKau47EL2dhHKon"
TV2_M_0_2147483647H_1_2147483646H = "xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL"
TV2_M_0_2147483647H_1_2147483646H_2 = "xpub6FnCn6nSzZAw5Tw7cgR9bi15UV96gLZhjDstkXXxvCLsUXBGXPdSnLFbdpq8p9HmGsApME5hQTZ3emM2rnY5agb9rXpVGyy3bdW6EEgAtqt"

BIP32_PUBLIC_STEPS = [
    (TV1_M_0H, [1], TV1_M_0H_1),
    (TV1_M_0H_1_2H, [2], TV1_M_0H_1_2H_2),
    (TV1_M_0H_1_2H, [2, 1000000000], TV1_M_0H_1_2H_2_1000000000),
    (TV2_M, [0], TV2_M_0),
    (TV2_M_0_2147483647H, [1], TV2_M_0_2147483647H_1),
    (TV2_M_0_2147483647H_1_2147483646H, [2], TV2_M_0_2147483647H_1_2147483646H_2),
]


def same_node(node, xpub):
    expected = parse_xpub(xpub, node.algorithm)
    return (node.chain_code, node.key, node.point) == (expected.chain_code, expected.key, expected.point)


def with_header(xpub, version=None, depth=None, fingerprint=None, child_number=None):
    """The same key and chain code with other version, depth, fingerprint or child number bytes."""
    data = bytearray(b58check_decode(xpub))
    if version is not None:
        data[0:4] = bytes.fromhex(version)
    if depth is not None:
        data[4] = depth
    if fingerprint is not None:
        data[5:9] = bytes.fromhex(fingerprint)
    if child_number is not None:
        data[9:13] = child_number.to_bytes(4, "big")
    return b58check_encode(bytes(data))


@pytest.mark.parametrize("parent, path, child", BIP32_PUBLIC_STEPS, ids=range(len(BIP32_PUBLIC_STEPS)))
def test_bip32_public_derivation(parent, path, child):
    assert same_node(derive_path(parse_xpub(parent, ECDSA), path), child)


def test_depth_one_xpub_derives_like_any_other():
    # m/0H of test vector 1 sits at depth 1 with a parent fingerprint and a hardened child number, like the
    # xpubs of vaults made by the earlier MPC provider.
    node = parse_xpub(TV1_M_0H, ECDSA)
    assert b58check_decode(TV1_M_0H)[4] == 1
    assert same_node(derive_child(node, 1), TV1_M_0H_1)


@pytest.mark.parametrize(
    "header",
    [
        {"version": "043587cf"},  # tpub
        {"version": "04b24746"},  # zpub
        {"version": "019da462"},  # Ltub
        {"version": "00000000", "depth": 9, "fingerprint": "deadbeef", "child_number": 7},
    ],
)
def test_xpub_header_is_ignored(header):
    tpub = with_header(TV1_M_0H, **header)
    assert tpub != TV1_M_0H
    assert same_node(derive_child(parse_xpub(tpub, ECDSA), 1), TV1_M_0H_1)


def test_tpub_spelling():
    tpub = with_header(TV1_M, version="043587cf")
    assert tpub.startswith("tpub")
    assert derive_path(parse_xpub(tpub, ECDSA), (0, 1, 5)) == derive_path(parse_xpub(TV1_M, ECDSA), (0, 1, 5))


@pytest.mark.parametrize(
    "xpub, algorithm",
    [
        (TV1_M[:-1] + ("9" if TV1_M[-1] != "9" else "8"), ECDSA),  # checksum broken
        (b58check_encode(b58check_decode(TV1_M)[:-1]), ECDSA),  # 77 bytes
        (b58check_encode(b58check_decode(TV1_M) + b"\x00"), ECDSA),  # 79 bytes
        (b58check_encode(b58check_decode(TV1_M)[:45] + b"\x00" + bytes(32)), ECDSA),  # private-key marker
        (b58check_encode(b58check_decode(TV1_M)[:45] + b"\x02" + (5).to_bytes(32, "big")), ECDSA),  # x off the curve
        (TV1_M, EDDSA),  # an ECDSA key where an EdDSA one belongs
        ("xpub with spaces", ECDSA),
    ],
)
def test_parse_xpub_rejects(xpub, algorithm):
    with pytest.raises(ValueError):
        parse_xpub(xpub, algorithm)


def test_indexes_must_be_non_hardened():
    node = parse_xpub(TV1_M, ECDSA)
    for index in (-1, HARDENED, 2 ** 32):
        with pytest.raises(ValueError):
            derive_child(node, index)


# --- hdkey's handling of an invalid child -------------------------------------------------------------


def _patched_hmac(monkeypatch, replacements):
    """Makes the BIP 32 HMAC return ``replacements[index]`` (a left-half integer) for the given indexes."""
    real = derivation._hmac_sha512

    def fake(key, data):
        digest = real(key, data)
        index = int.from_bytes(data[-4:], "big")
        if index in replacements:
            return replacements[index].to_bytes(32, "big") + digest[32:]
        return digest

    monkeypatch.setattr(derivation, "_hmac_sha512", fake)


def test_tweak_at_or_above_the_order_moves_to_the_next_index(monkeypatch):
    node = parse_xpub(TV1_M, ECDSA)
    expected = derive_child(node, 6)
    _patched_hmac(monkeypatch, {5: secp256k1.N})
    assert derive_child(node, 5) == expected


def test_child_at_infinity_moves_to_the_next_index(monkeypatch):
    private = 0x1234567890ABCDEF
    point = secp256k1.multiply(private)
    node = Node(ECDSA, bytes(32), secp256k1.compress(point), point)
    expected = derive_child(node, 4)
    _patched_hmac(monkeypatch, {3: secp256k1.N - private})  # IL * G + K = (n - k + k) * G = infinity
    assert derive_child(node, 3) == expected


def test_invalid_last_index_cannot_be_derived(monkeypatch):
    _patched_hmac(monkeypatch, {HARDENED - 1: secp256k1.N})
    with pytest.raises(Underivable):
        derive_child(parse_xpub(TV1_M, ECDSA), HARDENED - 1)


def test_skip_applies_at_every_level(monkeypatch):
    root = parse_xpub(TV1_M, ECDSA)
    _patched_hmac(monkeypatch, {0: secp256k1.N + 1})
    # Index 0 is invalid at every level now, so m/0/0/0 comes out as m/1/1/1.
    assert derive_path(root, (0, 0, 0)) == derive_path(root, (1, 1, 1))


# --- Vaultody's EdDSA scheme ------------------------------------------------------------------------------
# An EdDSA xpub made for these tests: RFC 8032 test 1's public key and the chain code sha256 of a fixed label.
ED_KEY = bytes.fromhex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
ED_CHAIN_CODE = hashlib.sha256(b"vaultody eddsa test chain code").digest()
ED_XPUB = b58check_encode(bytes.fromhex("0488b21e") + bytes(9) + ED_CHAIN_CODE + b"\x00" + ED_KEY)
ED_XPUB_DEPTH_1 = with_header(ED_XPUB, depth=1, fingerprint="deadbeef", child_number=3)

# Solana addresses the server library (the xpub utilities at the version the vault service pins) derives
# from ED_XPUB and ED_XPUB_DEPTH_1.
ED_SERVER_ADDRESSES = [
    ((1, 0, 5), "5hymX2nJS4EdcgjKS49BqqpQxTXuNGTw78Sn8zX5Hcr3"),
    ((7, 1, 2147483647), "9FpxBCxASkeNaYBFZSD5bMPw5y8rFvLXN7DgRiKe58YA"),
]


def spelled_out_eddsa_child(chain_code, key, index):
    """The scheme written out step by step, independently of derivation.py."""
    index_le = index.to_bytes(4, "little")
    tweak = int.from_bytes(hmac.new(chain_code, b"\x02" + key + index_le, hashlib.sha256).digest(), "big")
    child_chain_code = hmac.new(chain_code, b"\x03" + key + index_le, hashlib.sha256).digest()
    return child_chain_code, ed25519.encode(ed25519.multiply(tweak, ed25519.decode(key)))


def test_eddsa_xpub_layout():
    node = parse_xpub(ED_XPUB, EDDSA)
    assert (node.chain_code, node.key) == (ED_CHAIN_CODE, ED_KEY)


def test_eddsa_child_matches_the_scheme():
    node = parse_xpub(ED_XPUB, EDDSA)
    chain_code, key = ED_CHAIN_CODE, ED_KEY
    for index in (7, 1, 2147483647):
        node = derive_child(node, index)
        chain_code, key = spelled_out_eddsa_child(chain_code, key, index)
        assert (node.chain_code, node.key) == (chain_code, key)


@pytest.mark.parametrize("xpub", [ED_XPUB, ED_XPUB_DEPTH_1], ids=["depth0", "depth1"])
@pytest.mark.parametrize("path, address", ED_SERVER_ADDRESSES)
def test_eddsa_matches_the_server_library(xpub, path, address):
    from vaultody_verify.address.crypto.base58 import b58encode

    assert b58encode(derive_path(parse_xpub(xpub, EDDSA), path).key) == address


def test_eddsa_has_no_skip_rule_and_refuses_hardened():
    node = parse_xpub(ED_XPUB, EDDSA)
    with pytest.raises(ValueError):
        derive_child(node, HARDENED)
