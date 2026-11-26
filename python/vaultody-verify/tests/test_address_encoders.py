"""Every address encoder, for every chain, network and format the server derives."""

import hashlib

import pytest

from vaultody_verify.address.chains import CHAINS
from vaultody_verify.address.crypto import secp256k1
from vaultody_verify.address.crypto.base58 import b58check_encode
from vaultody_verify.address.derivation import ECDSA, Node, derive_path, parse_xpub

TV1_M = "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8"
# An EdDSA xpub at depth 0: RFC 8032 test 1's public key and the chain code sha256 of a fixed label.
ED_XPUB = b58check_encode(
    bytes.fromhex("0488b21e") + bytes(9) + hashlib.sha256(b"vaultody eddsa test chain code").digest() + b"\x00"
    + bytes.fromhex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
)

# What the server library (the xpub utilities at the version the vault service pins) returns for m/0/0/0
# below BIP 32 test vector 1's master xpub (ED_XPUB for Solana), for each chain, network and format.
SERVER_ADDRESSES_AT_M_0_0_0 = [
    ("bitcoin", "mainnet", "p2pkh", "1CL9viDipACKL6YM1pyWRVDX7UyCN9pk2j"),
    ("bitcoin", "mainnet", "p2sh", "3LMLep6QxjutMpcupcZJ8nspstgfo3qMV6"),
    ("bitcoin", "mainnet", "p2wpkh", "bc1q03ytemrlfyx7tpv5hp793745kaqr0x0vq2eusq"),
    ("bitcoin", "testnet", "p2pkh", "mrr7DmJhdBda7D1xjPwtFQRqyUZuH8aC5F"),
    ("bitcoin", "testnet", "p2sh", "2NBuYiZ2SaCREZcFTVkBAkjs66EtqaL8S95"),
    ("bitcoin", "testnet", "p2wpkh", "tb1q03ytemrlfyx7tpv5hp793745kaqr0x0v2vz0tn"),
    ("litecoin", "mainnet", "p2pkh", "LWZ7BvXYtpSNauEWBxxohWHHKhLUZbKwWM"),
    ("litecoin", "mainnet", "p2sh", "MSZUxhWNurmKAKtovVYdxS8ECbH7nUMEk5"),
    ("litecoin", "mainnet", "p2wpkh", "ltc1q03ytemrlfyx7tpv5hp793745kaqr0x0vykrcgs"),
    ("litecoin", "testnet", "p2pkh", "mrr7DmJhdBda7D1xjPwtFQRqyUZuH8aC5F"),
    ("litecoin", "testnet", "p2sh", "2NBuYiZ2SaCREZcFTVkBAkjs66EtqaL8S95"),
    ("litecoin", "testnet", "p2wpkh", "tltc1q03ytemrlfyx7tpv5hp793745kaqr0x0vnyq3m6"),
    ("dogecoin", "mainnet", "p2pkh", "DGUFTyAN7a6bs6iwkQy4yFP7zchVioR74A"),
    ("dogecoin", "mainnet", "p2sh", "AB6bPfAK2onnGBzPEkDiNvWCaU4hrJSq9n"),
    ("dogecoin", "testnet", "p2pkh", "nfXKByuH3YZKk5J8nEcXDeyREV5nnSPeJi"),
    ("dogecoin", "testnet", "p2sh", "2NBuYiZ2SaCREZcFTVkBAkjs66EtqaL8S95"),
    ("dash", "mainnet", "p2pkh", "Xn1zkxscmsQuV38vsiHjH1uJwpYtUmzxDi"),
    ("dash", "mainnet", "p2sh", "7m4yV1Namj1XMb9s6EDoUAsUoSX3gDP54U"),
    ("dash", "testnet", "p2pkh", "yXebmux4DR4ypn4USZc8K3KfE73FuDxD9i"),
    ("dash", "testnet", "p2sh", "8y5nSLGSuGQ9ota8AVDkvYgqgxHsnRfLB3"),
    ("bitcoin-cash", "mainnet", "p2pkh", "1CL9viDipACKL6YM1pyWRVDX7UyCN9pk2j"),
    ("bitcoin-cash", "mainnet", "p2sh", "3LMLep6QxjutMpcupcZJ8nspstgfo3qMV6"),
    ("bitcoin-cash", "mainnet", "p2pkh-cash", "bitcoincash:qp7y308v0aysmev9jju8ck86kjm5qdueasd4qfcnpc"),
    ("bitcoin-cash", "mainnet", "p2sh-cash", "bitcoincash:prxtrdryqgptfq4ue9nhnwychs8dcanjfqemrtmp9k"),
    ("bitcoin-cash", "testnet", "p2pkh", "mrr7DmJhdBda7D1xjPwtFQRqyUZuH8aC5F"),
    ("bitcoin-cash", "testnet", "p2sh", "2NBuYiZ2SaCREZcFTVkBAkjs66EtqaL8S95"),
    ("bitcoin-cash", "testnet", "p2pkh-cash", "bchtest:qp7y308v0aysmev9jju8ck86kjm5qdueasf8yw6yxy"),
    ("bitcoin-cash", "testnet", "p2sh-cash", "bchtest:prxtrdryqgptfq4ue9nhnwychs8dcanjfqaf8vekz2"),
    ("zcash", "mainnet", "p2pkh", "t1VCkw3drnUyuvjbExFndZJKSN9AHBwsmMK"),
    ("zcash", "testnet", "p2pkh", "tmM3WFt8GB9VR4yngcz6NQxzBy8F6hSCTr7"),
    ("xrp", "mainnet", "classic", "rUL9v5D5FwUKLaYMrFyWRVDXf7yU49Fkpj"),
    ("xrp", "testnet", "classic", "rUL9v5D5FwUKLaYMrFyWRVDXf7yU49Fkpj"),
    ("tron", "mainnet", "base58", "TLaRKwrzmxLHuVvtCoDMgdEdRPP6sw3Af5"),
    ("tron", "nile", "base58", "TLaRKwrzmxLHuVvtCoDMgdEdRPP6sw3Af5"),
    ("solana", "mainnet", "base58", "3eQqyLdYmnK1Qz2mfFgJENUm7UShBuWDctNV22sTJCN8"),
    ("solana", "devnet", "base58", "3eQqyLdYmnK1Qz2mfFgJENUm7UShBuWDctNV22sTJCN8"),
] + [
    (chain, network, "standard", "0x745a1afdcafdb0954feb14f7e73053bc15939e7e")
    for chain, testnet in (
        ("ethereum", "sepolia"),
        ("ethereum-classic", "mordor"),
        ("binance-smart-chain", "testnet"),
        ("polygon", "amoy"),
        ("arbitrum", "sepolia"),
        ("optimism", "sepolia"),
        ("base", "sepolia"),
        ("avalanche", "fuji"),
    )
    for network in ("mainnet", testnet)
]


def test_the_table_covers_every_chain_network_and_format():
    covered = {(chain, network, fmt) for chain, network, fmt, _ in SERVER_ADDRESSES_AT_M_0_0_0}
    expected = {
        (chain.name, network, fmt) for chain in CHAINS.values() for network in chain.networks for fmt in chain.formats
    }
    assert covered == expected
    assert len(CHAINS) == 17


@pytest.mark.parametrize(
    "blockchain, network, address_format, address",
    SERVER_ADDRESSES_AT_M_0_0_0,
    ids=["/".join(row[:3]) for row in SERVER_ADDRESSES_AT_M_0_0_0],
)
def test_server_addresses(blockchain, network, address_format, address):
    chain = CHAINS[blockchain]
    xpub = ED_XPUB if chain.algorithm != ECDSA else TV1_M
    node = derive_path(parse_xpub(xpub, chain.algorithm), (0, 0, 0))
    assert chain.address(address_format, network, node) == address


# Independent references: the key 1 * G (private key 1) in well-known addresses, and the XRP Ledger's
# genesis account from its documentation.
GENERATOR = Node(ECDSA, bytes(32), secp256k1.compress(secp256k1.G), secp256k1.G)
GENESIS_KEY = bytes.fromhex("0330E7FC9D56BB25D6893BA3F317AE5BCF33B3291BD63DB32654A313222F7FD020")
GENESIS = Node(ECDSA, bytes(32), GENESIS_KEY, secp256k1.decompress(GENESIS_KEY))
WELL_KNOWN = [
    ("bitcoin", "p2pkh", GENERATOR, "1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH"),
    ("bitcoin", "p2sh", GENERATOR, "3JvL6Ymt8MVWiCNHC7oWU6nLeHNJKLZGLN"),
    ("bitcoin", "p2wpkh", GENERATOR, "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"),  # BIP 173's example
    ("ethereum", "standard", GENERATOR, "0x7e5f4552091a69125d5dfcb7b8c2659029395bdf"),
    ("tron", "base58", GENERATOR, "TMVQGm1qAQYVdetCeGRRkTWYYrLXuHK2HC"),
    ("xrp", "classic", GENESIS, "rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh"),
]


@pytest.mark.parametrize("blockchain, address_format, node, address", WELL_KNOWN, ids=[row[0] + "/" + row[1] for row in WELL_KNOWN])
def test_well_known_addresses(blockchain, address_format, node, address):
    assert CHAINS[blockchain].address(address_format, "mainnet", node) == address
