"""Checks that an address the Vaultody API returned derives from its vault's extended public key (xpub).

Every vault address is derived from the vault's xpub with public math only, at
``m/{account_index}/{1 if is_change else 0}/{address_index}``. Given the xpub, a client derives the address
itself and compares, so a changed address fails however it was changed: in a proxy, a CDN or anywhere else.

This module is pure: it derives and compares. Where the xpub comes from is the caller's trust decision. The SDK
takes it only from ``GET /vaults/{main|test}`` and pins it on first sight (an xpub never changes), so an xpub
swapped later is an alarm instead of a new truth.

``check_address`` runs its checks in a fixed order, shared with the other language helpers. The order decides
which reason a caller sees:

0. argument types and ranges, else ``TypeError`` or ``ValueError``;
1. the chain and network are known, else ``unsupported``;
2. ``"mainnet"`` goes with a main vault and any other network with a test vault, else ``network_mismatch``;
3. ``account_index``, ``is_change`` and ``address_index`` are all present, else ``not_verifiable`` (returned
   instead of raised with ``allow_unverifiable``);
4. ``address_format``, when given, is a format of the chain and not a refused one (``p2sh`` on bitcoin-cash,
   dogecoin and dash, ``p2sh-cash`` on bitcoin-cash), else ``unsupported``;
5. the vault has a readable key for the chain's algorithm, else ``missing_key``;
6. the address derived at the path, in the given format or in any format of the chain when none is given
   (refused formats are skipped), equals the address (EVM chains: ignoring letter case), else ``mismatch``.
"""

import re
from dataclasses import dataclass
from typing import Optional

from .chains import CHAINS, MAINNET, is_refused_format
from .derivation import ECDSA, EDDSA, HARDENED, Underivable, derive_child, parse_xpub
from .errors import AddressVerificationError

_VAULT_TYPES = ("main", "test")
# Canonical decimal, as the API writes an index it returns as a string: no sign, no leading zero.
_DECIMAL = re.compile(r"(?:0|[1-9][0-9]*)")
_MAX_INDEX_DIGITS = len(str(HARDENED - 1))

# Parsed keys and account/change nodes, so a page of addresses costs one derivation step each. Bounded, because
# the xpubs and indexes come from API responses. Public data only: never logged.
_CACHE_LIMIT = 1024
_cache = {}


def _cached(key, make):
    if key in _cache:
        return _cache[key]
    value = make()
    if len(_cache) >= _CACHE_LIMIT:
        del _cache[next(iter(_cache))]
    _cache[key] = value
    return value


@dataclass(frozen=True)
class AddressCheckResult:
    """The outcome of a ``check_address`` call that didn't raise.

    ``verified`` is True when the address is exactly the one the vault xpub gives; ``algorithm`` (``"ECDSA"`` or
    ``"EDDSA"``), ``path`` (``"m/account/change/index"``), ``address`` and ``address_format`` (the lowercase
    format that matched) say how. It is False only with ``allow_unverifiable=True`` for an address without a
    derivation path; ``reason`` is then ``"not_verifiable"`` and the rest is None.
    """

    verified: bool
    reason: Optional[str] = None
    algorithm: Optional[str] = None
    path: Optional[str] = None
    address: Optional[str] = None
    address_format: Optional[str] = None


def _index(value, name):
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, (int, str)):
        raise TypeError("{} must be an int or a decimal string".format(name))
    if isinstance(value, str):
        if len(value) > _MAX_INDEX_DIGITS or not _DECIMAL.fullmatch(value):
            raise ValueError("{} is not a canonical decimal: {!r}".format(name, value))
        value = int(value)
    if not 0 <= value < HARDENED:
        raise ValueError("{} must be 0 to 2^31 - 1, not {}".format(name, value))
    return value


def _change(value):
    if value is None:
        return None
    if isinstance(value, bool):
        return int(value)
    if not isinstance(value, int):
        raise TypeError("is_change must be True, False, 0 or 1")
    if value not in (0, 1):
        raise ValueError("is_change must be True, False, 0 or 1, not {}".format(value))
    return value


def _string(value, name):
    if not isinstance(value, str) or value == "":
        raise TypeError("{} must be a non-empty str".format(name))
    return value


def _read_vault(vault):
    try:
        vault_type = vault["type"]
        keys = vault["keys"]
    except (TypeError, KeyError, IndexError):
        vault_type = keys = None
    if vault_type not in _VAULT_TYPES or not hasattr(keys, "get"):
        raise TypeError('vault must be {"type": "main"|"test", "keys": {"ECDSA": xpub|None, "EDDSA": xpub|None}}')
    for algorithm in (ECDSA, EDDSA):
        xpub = keys.get(algorithm)
        if xpub is not None and not isinstance(xpub, str):
            raise TypeError("vault keys {} must be an xpub str or None".format(algorithm))
    return vault_type, keys


def check_address(
    vault,
    *,
    blockchain,
    network,
    address,
    account_index=None,
    is_change=None,
    address_index=None,
    address_format=None,
    allow_unverifiable=False,
):
    """Checks that ``address`` is the one the vault's key derives at ``m/account_index/is_change/address_index``.

    :param vault: ``{"type": "main"|"test", "keys": {"ECDSA": xpub|None, "EDDSA": xpub|None}}``, the vault's
        type and its xpub per MPC algorithm, as pinned.
    :param blockchain, network: as in API paths, e.g. ``"bitcoin"``, ``"mainnet"``, ``"sepolia"``.
    :param address: the address exactly as the API returned it.
    :param account_index, is_change, address_index: the API's ``accountIndex``, ``isChange`` and
        ``addressIndex``. Indexes are ints or decimal strings; ``is_change`` is True, False, 0 or 1.
    :param address_format: any case; when absent every format of the chain is tried (refused ones skipped).
    :param allow_unverifiable: return ``AddressCheckResult(verified=False, reason="not_verifiable")`` for an
        address without a derivation path instead of raising.
    :returns: AddressCheckResult
    :raises AddressVerificationError: the address is not verified; ``.reason`` is one of ``unsupported``,
        ``network_mismatch``, ``not_verifiable``, ``missing_key`` or ``mismatch``, checked in that order.
    :raises TypeError, ValueError: an argument of the wrong type, or an index out of range.
    """
    vault_type, keys = _read_vault(vault)
    if not isinstance(allow_unverifiable, bool):
        raise TypeError("allow_unverifiable must be True or False")
    if address_format is not None and not isinstance(address_format, str):
        raise TypeError("address_format must be a str, or None")
    _string(blockchain, "blockchain")
    _string(network, "network")
    _string(address, "address")
    account = _index(account_index, "account_index")
    change = _change(is_change)
    index = _index(address_index, "address_index")

    chain = CHAINS.get(blockchain)
    if chain is None or network not in chain.networks:
        raise AddressVerificationError(
            "unsupported", "{} on {} is not a chain and network this helper knows".format(blockchain, network)
        )
    if (vault_type == "main") != (network == MAINNET):
        raise AddressVerificationError(
            "network_mismatch", "{} does not belong with a {} vault".format(network, vault_type)
        )

    if account is None or change is None or index is None:
        if allow_unverifiable:
            return AddressCheckResult(verified=False, reason="not_verifiable")
        raise AddressVerificationError(
            "not_verifiable",
            "the address has no derivation path (account_index, is_change and address_index), "
            "so it cannot be checked against the vault key",
        )

    if address_format is None:
        formats = tuple(name for name in chain.formats if not is_refused_format(chain.name, name))
    else:
        fmt = address_format.lower()
        if fmt not in chain.formats:
            raise AddressVerificationError(
                "unsupported", "{} is not an address format of {}".format(address_format, blockchain)
            )
        if is_refused_format(chain.name, fmt):
            raise AddressVerificationError(
                "unsupported",
                "{} on {} is refused: it is P2SH-wrapped SegWit on a chain without SegWit, "
                "which anyone can spend".format(address_format, blockchain),
            )
        formats = (fmt,)

    xpub = keys.get(chain.algorithm)
    if not isinstance(xpub, str) or xpub == "":
        raise AddressVerificationError("missing_key", "the vault has no {} key".format(chain.algorithm))
    try:
        root = _cached(("key", chain.algorithm, xpub), lambda: parse_xpub(xpub, chain.algorithm))
    except (ValueError, TypeError) as error:
        raise AddressVerificationError(
            "missing_key", "the vault's {} key could not be read: {}".format(chain.algorithm, error)
        ) from None

    path = "m/{}/{}/{}".format(account, change, index)
    try:
        parent = _cached(
            ("node", chain.algorithm, xpub, account, change),
            lambda: derive_child(derive_child(root, account), change),
        )
        node = derive_child(parent, index)
    except Underivable as error:
        # Only possible past the last non-hardened index; the server cannot derive such an address either.
        raise AddressVerificationError(
            "mismatch", "the vault key derives no address at {}: {}".format(path, error)
        ) from None

    for candidate in formats:
        derived = chain.address(candidate, network, node)
        # EVM addresses are hex, so an EIP-55 checksummed spelling is the same address.
        if (derived.lower() == address.lower()) if chain.case_insensitive else (derived == address):
            return AddressCheckResult(
                verified=True, algorithm=chain.algorithm, path=path, address=address, address_format=candidate
            )
    raise AddressVerificationError(
        "mismatch", "the address is not the {} address of the vault at {}".format(" or ".join(formats), path)
    )


def network_of_vault(blockchain, vault_type):
    """The network an address of a vault is on when the response does not say.

    ``"mainnet"`` for a main vault, the chain's one test network for a test vault; ``None`` for a chain this
    helper does not know.
    """
    chain = CHAINS.get(blockchain) if isinstance(blockchain, str) else None
    if chain is None or vault_type not in _VAULT_TYPES:
        return None
    networks = [name for name in chain.networks if (name == MAINNET) == (vault_type == "main")]
    return networks[0] if len(networks) == 1 else None
