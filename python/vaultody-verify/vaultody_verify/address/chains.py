"""Every blockchain, network and address format the Vaultody server derives from a vault xpub.

The names, version bytes and prefixes are those of the server's xpub utilities library, and each encoder
does what the server's encoder for that chain does:

- ``p2pkh``: Base58Check of the network's public-key-hash version and HASH160 of the compressed key. Zcash
  uses a two-byte version.
- ``p2sh``: on every chain, including Bitcoin Cash, a P2SH-wrapped P2WPKH: Base58Check of the script-hash
  version and HASH160 of the redeem script ``0x00 0x14 <HASH160(key)>``.
- ``p2wpkh``: a version 0 segwit Bech32 address of HASH160 of the key.
- ``p2pkh-cash`` / ``p2sh-cash``: the same hashes as ``p2pkh`` / ``p2sh`` in CashAddr, with its prefix.
- ``classic`` (XRP): Base58Check in the XRP alphabet of 0x00 and HASH160 of the key; the same on testnet.
- ``base58`` (Tron): Base58Check of 0x41 and the last 20 bytes of Keccak-256 of the uncompressed key (x || y);
  Nile uses the same prefix.
- ``base58`` (Solana): Base58 of the 32-byte ed25519 child key.
- ``standard`` (EVM): ``0x`` and the last 20 bytes of Keccak-256 of x || y, in lowercase hex. EVM addresses
  are compared ignoring letter case, every other chain's exactly.

Format names are lowercase here; callers' formats are matched case-insensitively.
"""

import hashlib
from types import MappingProxyType

from .crypto import cashaddr, secp256k1
from .crypto.base58 import RIPPLE_ALPHABET, b58check_encode, b58encode
from .crypto.bech32 import encode_segwit_v0
from .crypto.keccak import keccak256
from .crypto.ripemd160 import ripemd160
from .derivation import ECDSA, EDDSA

MAINNET = "mainnet"


def _hash160(data):
    return ripemd160(hashlib.sha256(data).digest())


def _p2wpkh_redeem_script(node):
    return b"\x00\x14" + _hash160(node.key)


def _p2pkh(params, node):
    return b58check_encode(params["p2pkh"] + _hash160(node.key))


def _p2sh_p2wpkh(params, node):
    return b58check_encode(params["p2sh"] + _hash160(_p2wpkh_redeem_script(node)))


def _p2wpkh(params, node):
    return encode_segwit_v0(params["bech32"], _hash160(node.key))


def _p2pkh_cash(params, node):
    return cashaddr.encode(params["cashaddr"], cashaddr.P2PKH, _hash160(node.key))


def _p2sh_cash(params, node):
    return cashaddr.encode(params["cashaddr"], cashaddr.P2SH, _hash160(_p2wpkh_redeem_script(node)))


def _xrp_classic(params, node):
    return b58check_encode(b"\x00" + _hash160(node.key), RIPPLE_ALPHABET)


def _keccak_account(node):
    return keccak256(secp256k1.encode_xy(node.point))[12:]


def _tron_base58(params, node):
    return b58check_encode(b"\x41" + _keccak_account(node))


def _evm_standard(params, node):
    return "0x" + _keccak_account(node).hex()


def _solana_base58(params, node):
    return b58encode(node.key)


class Chain:
    """One blockchain: its signing algorithm, its networks (with their prefixes) and its address formats."""

    __slots__ = ("name", "algorithm", "networks", "formats", "case_insensitive", "_encoders")

    def __init__(self, name, algorithm, networks, encoders, case_insensitive=False):
        self.name = name
        self.case_insensitive = case_insensitive
        self.algorithm = algorithm
        self.networks = MappingProxyType({network: MappingProxyType(params) for network, params in networks.items()})
        self.formats = tuple(encoders)
        self._encoders = dict(encoders)

    def address(self, address_format, network, node):
        """The address of a derived child node in one format on one network."""
        return self._encoders[address_format](self.networks[network], node)


def _utxo(name, mainnet, testnet, formats):
    encoders = {
        "p2pkh": _p2pkh,
        "p2sh": _p2sh_p2wpkh,
        "p2wpkh": _p2wpkh,
        "p2pkh-cash": _p2pkh_cash,
        "p2sh-cash": _p2sh_cash,
    }
    return Chain(name, ECDSA, {MAINNET: mainnet, "testnet": testnet}, {fmt: encoders[fmt] for fmt in formats})


def _evm(name, testnet):
    return Chain(name, ECDSA, {MAINNET: {}, testnet: {}}, {"standard": _evm_standard}, case_insensitive=True)


_CHAIN_LIST = (
    _utxo(
        "bitcoin",
        {"p2pkh": b"\x00", "p2sh": b"\x05", "bech32": "bc"},
        {"p2pkh": b"\x6f", "p2sh": b"\xc4", "bech32": "tb"},
        ("p2pkh", "p2sh", "p2wpkh"),
    ),
    _utxo(
        "litecoin",
        {"p2pkh": b"\x30", "p2sh": b"\x32", "bech32": "ltc"},
        {"p2pkh": b"\x6f", "p2sh": b"\xc4", "bech32": "tltc"},
        ("p2pkh", "p2sh", "p2wpkh"),
    ),
    _utxo("dogecoin", {"p2pkh": b"\x1e", "p2sh": b"\x16"}, {"p2pkh": b"\x71", "p2sh": b"\xc4"}, ("p2pkh", "p2sh")),
    _utxo("dash", {"p2pkh": b"\x4c", "p2sh": b"\x10"}, {"p2pkh": b"\x8c", "p2sh": b"\x13"}, ("p2pkh", "p2sh")),
    _utxo(
        "bitcoin-cash",
        {"p2pkh": b"\x00", "p2sh": b"\x05", "cashaddr": "bitcoincash"},
        {"p2pkh": b"\x6f", "p2sh": b"\xc4", "cashaddr": "bchtest"},
        ("p2pkh", "p2sh", "p2pkh-cash", "p2sh-cash"),
    ),
    _utxo("zcash", {"p2pkh": b"\x1c\xb8"}, {"p2pkh": b"\x1d\x25"}, ("p2pkh",)),
    Chain("xrp", ECDSA, {MAINNET: {}, "testnet": {}}, {"classic": _xrp_classic}),
    Chain("tron", ECDSA, {MAINNET: {}, "nile": {}}, {"base58": _tron_base58}),
    Chain("solana", EDDSA, {MAINNET: {}, "devnet": {}}, {"base58": _solana_base58}),
    _evm("ethereum", "sepolia"),
    _evm("ethereum-classic", "mordor"),
    _evm("binance-smart-chain", "testnet"),
    _evm("polygon", "amoy"),
    _evm("arbitrum", "sepolia"),
    _evm("optimism", "sepolia"),
    _evm("base", "sepolia"),
    _evm("avalanche", "fuji"),
)

# Formats this helper refuses, per chain. Bitcoin Cash, Dogecoin and Dash have no SegWit, but the server library
# once derived their ``p2sh`` (and Bitcoin Cash's ``p2sh-cash``) as P2SH-wrapped P2WPKH. Anyone can spend coins
# sent to such an address, so it must never be reported as genuine. The server no longer derives these and none
# exist in production.
REFUSED_FORMATS = MappingProxyType(
    {
        "bitcoin-cash": frozenset({"p2sh", "p2sh-cash"}),
        "dogecoin": frozenset({"p2sh"}),
        "dash": frozenset({"p2sh"}),
    }
)


def is_refused_format(blockchain, address_format):
    return address_format in REFUSED_FORMATS.get(blockchain, ())


CHAINS = MappingProxyType({chain.name: chain for chain in _CHAIN_LIST})
