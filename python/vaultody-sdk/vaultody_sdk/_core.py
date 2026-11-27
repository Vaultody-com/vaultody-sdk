"""The transport core: everything a call does, without doing any I/O.

Each step that needs I/O is a small effect object the core yields: wait for the rate limiter, sleep, call
the signer, send the request, call the vault key store. ``Vaultody`` performs them with httpx.Client and
``time.sleep``, ``AsyncVaultody`` with httpx.AsyncClient and ``asyncio``; everything else, every decision
included, is this one code path, so the two clients can't drift apart.

One call:

1. build the request target (path and query exactly as sent and signed) and the JSON body;
2. take a token from the rate limiter;
3. sign: HMAC v2 with a nonce, and the key-pair signature when a signer is configured. A call gets a fresh
   nonce; a write keeps it on every retry (re-signed with a fresh timestamp, or resent as it was), a read
   gets a new one when re-signed (retry.py);
4. send;
5. verify the response signature before anything reads the body. A signed response (any of the four
   x-api-response-* headers) is always checked, and latches its origin before anything is raised, whether
   it verifies or not (the strict latch, kept in the vault key store); an unsigned one passes only while
   the mode in force is ``when-present`` and the origin is not latched. A client with response-signing
   roots is always ``required``, and before its first write it makes one signed read, so a write is never
   sent to an origin whose answers can't be checked. A failure is never retried;
6. decide (retry.py): return, retry re-signed, resend the same signed request, fail, or outcome unknown;
7. on success: unwrap the envelope, compare every vault list with the pins, check returned addresses
   against their vault's pinned xpub.

test-vectors/response-mode-v1.json pins the mode and the latch, the same in every language.
"""

import collections
import json
import logging
import os
import platform
import random as _random
import re
import sys
import time
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any, Callable, Generic, List, Optional, Tuple, TypeVar
from urllib.parse import unquote, urlsplit

from vaultody_verify import ConfigurationError as _VerifyConfigurationError
from vaultody_verify import ResponseSignatureError, UsageError, read_signing_keys_response, sign_hmac_v2_request, verify_response
from vaultody_verify import AddressVerificationError as _DerivationError
from vaultody_verify import check_address, network_of_vault
from vaultody_verify.address.chains import CHAINS
from vaultody_verify.keys import API_HEADERS, NONCE_PATTERN, UnexpectedResponseError, decode_api_secret, keypair_request_message
from vaultody_verify.response import DEFAULT_MAX_CLOCK_SKEW_SECONDS, HEADER_CERT, HEADER_SIGN, HEADER_TIMESTAMP, HEADER_VERSION
from vaultody_verify.roots import embedded_fingerprints, parse_roots

from ._defaults import ADDRESS_PATHS_PUBLIC, DEFAULT_RESPONSE_SIGNATURE
from ._version import API_VERSION, __version__
from .errors import (
    AddressVerificationError,
    ApiError,
    ConfigurationError,
    PaginationError,
    ParameterError,
    RequestOutcomeUnknownError,
    ResponseVerificationError,
    TransportError,
    VaultKeyChangedError,
    VaultKeyStoreError,
    read_envelope,
)
from .request_target import build_request_target
from .retry import decide_retry
from .security_events import security_event
from .signers import SignerInfo, normalise_signature
from .stores import default_vault_key_store
from .transport_errors import classify_transport_error
from .vault_keys import (
    ADDRESS_CHECK_STATUS,
    OUTCOMES,
    PIN_STATUS,
    address_check_status,
    address_path_required,
    configured_pins,
    observe_vaults,
    read_vault_list,
)

_LOG = logging.getLogger("vaultody_sdk")

DEFAULT_BASE_URL = "https://rest.vaultody.com"
#: A request body is refused above this; the gateway reads at most this much to bind a response to it.
MAX_REQUEST_BODY_BYTES = 1024 * 1024
#: A response body (after Content-Encoding) above this is not read.
MAX_RESPONSE_BODY_BYTES = 10 * 1024 * 1024
DEFAULT_MAX_REQUESTS_PER_SECOND = 5
DEFAULT_TIMEOUT_SECONDS = 30.0

RESPONSE_SIGNATURE_MODES = ("when-present", "required")
ENV_RESPONSE_SIGNATURE = "VAULTODY_RESPONSE_SIGNATURE"
#: Logged once when a client is made with response-signing roots and a "when-present" given explicitly.
WHEN_PRESENT_IGNORED = (
    'response_signature "when-present" is ignored: response-signing roots are configured, so every response must be signed'
)
# The four headers of a response signature; an answer with any of them (a value that is not empty) is signed.
_RESPONSE_SIGNATURE_HEADERS = frozenset((HEADER_SIGN, HEADER_TIMESTAMP, HEADER_VERSION, HEADER_CERT))
# A stable release in its PEP 440 form: X.Y.Z exactly (a release candidate is X.Y.ZrcN).
_STABLE_VERSION = re.compile(r"[0-9]+\.[0-9]+\.[0-9]+")

SIGNING_KEYS_PATH = "/api-keys/current/signing-keys"
#: How long a confirmation that the key pair is active counts, before it is checked again.
KEY_CHECK_TTL_SECONDS = 600
VAULT_LIST_PATH = "/vaults/{networkType}"
VAULT_LIST_PAGE_LIMIT = 50
#: Looking for one vault reads at most this many pages of a vault list.
MAX_VAULT_LIST_PAGES = 200

_METHODS = ("GET", "POST", "PUT")
_LOOPBACK_HOSTS = ("127.0.0.1", "::1", "localhost")
_API_VERSION_SHAPE = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}")
_HEADER_TEXT = re.compile(r"[\x20-\x7e]+")
_RETRY_AFTER = re.compile(r"[0-9]{1,6}")

# The routes whose answers carry what the SDK checks; matched on the path as sent, so a call made through
# the clients' internal _request() is checked exactly like one made through an API method.
_VAULT_LIST = re.compile(r"/vaults/(main|test)", re.IGNORECASE)
_ADDRESS_ROUTES = (
    ("POST", re.compile(r"/vaults/([^/]+)/([^/]+)/([^/]+)/addresses"), "generateDepositAddress"),
    ("GET", re.compile(r"/vaults/([^/]+)/vault-accounts/([^/]+)/list-addresses"), "listAddressesByVaultAccountId"),
    ("PUT", re.compile(r"/vaults/([^/]+)/vault-accounts/([^/]+)/add-asset"), "addAssetToVaultAccount"),
)

T = TypeVar("T")


# ---------------------------------------------------------------------------------------------------
# Effects: what the core asks the client to do
# ---------------------------------------------------------------------------------------------------


@dataclass(frozen=True)
class Sleep:
    seconds: float


@dataclass(frozen=True)
class Acquire:
    """Wait for a token of the client's rate limiter."""


@dataclass(frozen=True, repr=False)
class Sign:
    signer: SignerInfo
    data: bytes  # the key-pair string, which holds the passphrase (or its SHA-256)

    def __repr__(self):
        return "Sign({})".format(self.signer.fingerprint)


@dataclass(frozen=True, repr=False)
class Send:
    method: str
    url: str
    headers: Tuple[Tuple[str, str], ...]  # the API key and passphrase among them
    body: Optional[bytes]

    def __repr__(self):
        return "Send({} {})".format(self.method, self.url)


@dataclass(frozen=True)
class StoreOp:
    name: str
    args: tuple


@dataclass(frozen=True)
class RawResponse:
    """What came back: the status, every header as sent (names lowercased) and the body bytes."""

    status: int
    headers: "Headers"
    body: bytes


@dataclass(frozen=True)
class SendFailure:
    """The request failed on the network (``error``), or the response was larger than the cap."""

    error: BaseException
    too_large: bool = False


class Headers:
    """Response headers as received: every value of a repeated header is kept, so a verifier sees both."""

    __slots__ = ("_pairs",)

    def __init__(self, pairs):
        self._pairs = tuple((str(name).lower(), str(value)) for name, value in pairs)

    def items(self):
        return list(self._pairs)

    def get(self, name, default=None):
        name = name.lower()
        return next((value for key, value in self._pairs if key == name), default)

    def __repr__(self):
        return "Headers({!r})".format(self._pairs)


# ---------------------------------------------------------------------------------------------------
# Results
# ---------------------------------------------------------------------------------------------------


@dataclass(frozen=True)
class ResponseMeta:
    """What the SDK knows about the answer besides its data.

    ``signature`` is ``"verified"`` or ``"absent"`` (an unsigned answer, accepted only by a client in
    ``when-present`` mode, until this origin has sent a signed one). ``address_checks`` holds one
    ``{"vaultId", "address", "status"}`` per address the answer returned, ``status`` being ``verified``,
    ``unverified`` (checked against a pin that only an unsigned vault list showed) or ``not_verifiable`` (no
    derivation path: SMART vaults, older rows).
    ``vault_keys`` is set on an answer of GET /vaults/{main|test}: one ``{"vaultId", "status", "outcome"}``
    per vault, in the order of the answer. ``status`` is the vault's pin after this answer (``verified``,
    ``unverified``) or ``not_verifiable`` (no MPC keys); ``outcome`` is what the answer did to the pin
    (``pinned``, ``unchanged``, ``upgraded``, ``not_verifiable``). An alarm returns nothing: it raises
    VaultKeyChangedError.
    """

    status: int
    request_id: Optional[str]
    api_version: Optional[str]
    context: Optional[str]
    replayed: bool
    signature: str
    signature_root_id: Optional[str] = None
    signature_timestamp: Optional[int] = None
    address_checks: Tuple[dict, ...] = ()
    vault_keys: Tuple[dict, ...] = ()


@dataclass(frozen=True)
class Item(Generic[T]):
    """A single item: ``data.item`` of the answer, as sent (unknown fields kept, amounts as strings)."""

    item: T
    meta: ResponseMeta


@dataclass(frozen=True)
class Page(Generic[T]):
    """One page of a list. Cursor paging: ``has_more`` and ``starting_after``; offset paging: ``offset``
    and ``total``."""

    items: List[T]
    meta: ResponseMeta
    paging: str = "cursor"
    limit: Optional[int] = None
    has_more: bool = False
    starting_after: Optional[str] = None
    offset: Optional[int] = None
    total: Optional[int] = None


@dataclass
class Exchange:
    """One answered request, before it becomes a result."""

    target: str
    status: int
    headers: Headers
    body: bytes
    signature: str
    root_id: Optional[str] = None
    signature_timestamp: Optional[int] = None
    envelope: Optional[dict] = None
    address_checks: list = field(default_factory=list)
    vault_keys: list = field(default_factory=list)
    request_id: Optional[str] = None

    def result(self):
        envelope = self.envelope
        meta = ResponseMeta(
            status=self.status,
            request_id=envelope["request_id"],
            api_version=envelope["api_version"],
            context=envelope["context"],
            replayed=envelope["replayed"],
            signature=self.signature,
            signature_root_id=self.root_id,
            signature_timestamp=self.signature_timestamp,
            address_checks=tuple(self.address_checks),
            vault_keys=tuple(self.vault_keys),
        )
        if envelope["kind"] == "item":
            return Item(item=envelope["item"], meta=meta)
        if envelope["paging"] == "offset":
            return Page(items=envelope["items"], meta=meta, paging="offset", limit=envelope["limit"], offset=envelope["offset"], total=envelope["total"])
        return Page(
            items=envelope["items"], meta=meta, paging="cursor", limit=envelope["limit"],
            has_more=envelope["has_more"], starting_after=envelope["starting_after"],
        )


# ---------------------------------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------------------------------


@dataclass
class Hooks:
    """Test hooks, deliberately unsupported (the parameter is ``_hooks``): a fixed clock, nonce and
    timestamp make the shared vectors reproducible; nothing else should set them.

    ``embedded_roots`` and ``sdk_version`` let a test play a build: roots in the form ``roots`` takes that act
    as the roots this build embeds (they count for "roots configured" in a stable version, and check a
    signature when ``roots`` is not given), and the version the client takes itself for (PEP 440, such as
    ``1.0.0`` or ``1.0.0rc1``). None: the real embedded roots.
    """

    clock: Callable[[], float] = time.time
    sleep: Optional[Callable[[float], Any]] = None
    random: Callable[[], float] = _random.random
    nonce: Callable[[], str] = field(default=lambda: os.urandom(16).hex())
    timestamp: Optional[Callable[[], str]] = None
    api_version: str = API_VERSION
    embedded_roots: Optional[Any] = None
    sdk_version: str = __version__


class RateLimiter:
    """The client-side rate limit: at most ``rate`` calls in any one-second window (for a rate below one,
    one call per ``1 / rate`` seconds).

    The gateway counts calls per wall-clock second, so a window that slides keeps every such second at or
    under the limit whatever the two clocks' alignment; a token bucket with a burst would let up to twice
    the rate into one second. No I/O: the client holds the lock and does the waiting.
    """

    def __init__(self, rate):
        if isinstance(rate, bool) or not isinstance(rate, (int, float)) or not rate > 0 or rate == float("inf"):
            raise ConfigurationError("max_requests_per_second must be a positive number", "invalid_rate")
        self.count = max(1, int(rate))
        self.window = self.count / float(rate)
        self.slots = collections.deque()

    def reserve(self, now):
        """Takes a slot; returns how many seconds to wait before using it."""
        slots = self.slots
        while slots and slots[0] <= now - self.window:
            slots.popleft()
        if len(slots) < self.count:
            slots.append(now)
            return 0.0
        # The earliest slot leaves the window at oldest + window; this call takes its place then.
        start = slots.popleft() + self.window
        slots.append(start)
        return max(0.0, start - now)


class _Credentials:
    """The API key, secret and passphrase; never shown by repr or str."""

    __slots__ = ("_api_key", "_api_secret", "_passphrase")

    def __init__(self, api_key, api_secret, passphrase):
        for name, value in (("api_key", api_key), ("passphrase", passphrase)):
            if not isinstance(value, str) or not _HEADER_TEXT.fullmatch(value):
                raise ConfigurationError("the {} must be non-empty printable ASCII text".format(name), "invalid_" + name)
        try:
            decode_api_secret(api_secret)
        except UsageError:
            raise ConfigurationError("the API secret must be the base64 text the dashboard shows", "invalid_api_secret") from None
        self._api_key = api_key
        self._api_secret = api_secret
        self._passphrase = passphrase

    def mapping(self):
        return {"apiKey": self._api_key, "apiSecret": self._api_secret, "passphrase": self._passphrase}

    def __repr__(self):
        return "<credentials redacted>"

    __str__ = __repr__

    def __reduce__(self):
        raise TypeError("credentials can't be pickled")


def _parse_base_url(base_url):
    if not isinstance(base_url, str):
        raise ConfigurationError("base_url must be a URL string", "invalid_base_url")
    try:
        parts = urlsplit(base_url)
        host = (parts.hostname or "").lower()
        port = parts.port
    except ValueError:
        raise ConfigurationError("base_url is not a valid URL", "invalid_base_url") from None
    if parts.scheme not in ("https", "http") or not host:
        raise ConfigurationError("base_url must be an https:// URL", "invalid_base_url")
    if parts.scheme == "http" and host not in _LOOPBACK_HOSTS:
        raise ConfigurationError("plain http is allowed only to this machine (127.0.0.1, ::1, localhost)", "insecure_base_url")
    if parts.username or parts.password or parts.query or parts.fragment:
        raise ConfigurationError("base_url can't hold credentials, a query or a fragment", "invalid_base_url")
    prefix = parts.path.rstrip("/")
    if prefix and (not re.fullmatch(r"(/[A-Za-z0-9._~-]+)+", prefix) or set(prefix.split("/")[1:]) & {".", ".."}):
        raise ConfigurationError("base_url's path must be plain segments, such as /v2", "invalid_base_url")
    netloc = "[{}]".format(host) if ":" in host else host
    # The origin as a URL (and every other SDK) writes it: the scheme's default port left out.
    if port is not None and port != {"https": 443, "http": 80}[parts.scheme]:
        netloc += ":{}".format(port)
    return "{}://{}".format(parts.scheme, netloc), prefix


def _response_signature_option(value):
    """The response_signature option, else ``$VAULTODY_RESPONSE_SIGNATURE`` (empty: not set); None when
    neither is given."""
    if value is None:
        value = os.environ.get(ENV_RESPONSE_SIGNATURE) or None
    if value is not None and (not isinstance(value, str) or value not in RESPONSE_SIGNATURE_MODES):
        raise ConfigurationError('response_signature must be "when-present" or "required"', "invalid_response_signature")
    return value


def response_signature_config(option, *, roots_option, embedded_roots, version, build_default):
    """The response-signature mode in force (test-vectors/response-mode-v1.json, ``config``).

    Response-signing roots are configured when the ``roots`` option is given, or when this is a stable
    release (``X.Y.Z``) whose build embeds a root. Such a client is ``required``, whatever was asked: a
    signature stripped from its very first answer is refused. A release candidate that embeds the root is not
    strict for that alone; it turns strict through the latch once the API signs.

    :param option: the response_signature option, else ``$VAULTODY_RESPONSE_SIGNATURE``; None when neither
        is given
    :param roots_option: whether the ``roots`` option is given
    :param embedded_roots: whether the build embeds at least one response-signing root
    :param version: the SDK version, PEP 440 (``1.0.0``, or ``1.0.0rc1`` for a release candidate)
    :param build_default: DEFAULT_RESPONSE_SIGNATURE (_defaults.py)
    :returns: ``(mode, warn)``: warn is True when a "when-present" given explicitly is ignored (the client
        logs WHEN_PRESENT_IGNORED once)
    """
    if _roots_configured(roots_option, embedded_roots, version):
        return "required", option == "when-present"
    return (build_default if option is None else option), False


def _roots_configured(roots_option, embedded_roots, version):
    stable = isinstance(version, str) and _STABLE_VERSION.fullmatch(version) is not None
    return bool(roots_option) or (bool(embedded_roots) and stable)


def carries_signature(headers):
    """Whether an answer carries a response signature: any of the four x-api-response-* headers with a value
    that is not empty (names in any case). Such an answer latches its origin, whether it verifies or not."""
    if headers is None:
        return False
    return any(
        isinstance(name, str) and name.lower() in _RESPONSE_SIGNATURE_HEADERS and value is not None and value != ""
        for name, value in headers.items()
    )


def user_agent():
    return "vaultody-sdk-python/{} (python/{}; {})".format(__version__, platform.python_version(), sys.platform)


@dataclass(repr=False)
class _Signed:
    """One signed request: sent as is on a resend. Its headers hold the API key and passphrase."""

    headers: Tuple[Tuple[str, str], ...]
    url_target: str
    timestamp: str
    nonce: str
    api_sign: str
    keypair_sign: Optional[str]
    signed_at_ms: int

    def __repr__(self):
        return "<signed request {} nonce {}>".format(self.url_target.partition("?")[0], self.nonce)


@dataclass(frozen=True)
class Call:
    """One API call: an operation path (a template such as ``/vaults/{vaultId}/utxos``), its parameters, and
    for POST and PUT the item sent as ``data.item``."""

    method: str
    path: str
    path_params: Mapping = field(default_factory=dict)
    query: tuple = ()
    item: Any = None
    has_item: bool = False
    context: Optional[str] = None
    retry: Optional[str] = None
    operation_id: Optional[str] = None


class Core:
    """The shared logic of Vaultody and AsyncVaultody. Its generator methods yield effects and return results."""

    def __init__(
        self,
        api_key,
        api_secret,
        passphrase,
        *,
        base_url=DEFAULT_BASE_URL,
        signer=None,
        response_signature=None,
        roots=None,
        vault_key_store=None,
        pinned_vault_keys=None,
        require_address_paths=ADDRESS_PATHS_PUBLIC,
        on_security_event=None,
        max_requests_per_second=DEFAULT_MAX_REQUESTS_PER_SECOND,
        verify_signatures_locally=True,
        max_clock_skew_seconds=DEFAULT_MAX_CLOCK_SKEW_SECONDS,
        allow_async_signer=False,
        hooks=None,
    ):
        self._credentials = _Credentials(api_key, api_secret, passphrase)
        self.origin, self._prefix = _parse_base_url(base_url)
        self._signer = None if signer is None else SignerInfo(signer, allow_async=allow_async_signer)
        self.hooks = hooks if hooks is not None else Hooks()
        option = _response_signature_option(response_signature)
        # The roots a signature is checked with: the option, else the build's embedded ones (None: those of
        # vaultody_verify, unless a test plays a build that embeds others).
        if roots is not None:
            self._roots = self._read_roots(roots)
            embedded = False
        elif self.hooks.embedded_roots is not None:
            self._roots = self._read_roots(self.hooks.embedded_roots)
            embedded = len(self._roots) > 0
        else:
            self._roots = None
            embedded = len(embedded_fingerprints()) > 0
        self.response_signature, ignored = response_signature_config(
            option, roots_option=roots is not None, embedded_roots=embedded, version=self.hooks.sdk_version,
            build_default=DEFAULT_RESPONSE_SIGNATURE,
        )
        # Such a client also makes one signed read before its first write (exchange).
        self._roots_configured = _roots_configured(roots is not None, embedded, self.hooks.sdk_version)
        if not isinstance(require_address_paths, bool):
            raise ConfigurationError("require_address_paths must be True or False", "invalid_require_address_paths")
        self._require_address_paths = require_address_paths
        self.vault_key_store = default_vault_key_store() if vault_key_store is None else vault_key_store
        for name in ("get", "list", "pin_if_absent", "upgrade_trust", "get_strict_latch", "set_strict_latch"):
            if not callable(getattr(self.vault_key_store, name, None)):
                raise ConfigurationError("vault_key_store needs a {}() method (see VaultKeyStore)".format(name), "invalid_store")
        # Pins given in configuration, for this origin: verified, never stored, and in place of the stored pin
        # of the same vault.
        self._configured = configured_pins(pinned_vault_keys)
        if on_security_event is not None and not callable(on_security_event):
            raise ConfigurationError("on_security_event must be a function", "invalid_hook")
        self._on_security_event = on_security_event
        self.limiter = RateLimiter(max_requests_per_second)
        self._verify_locally = bool(verify_signatures_locally)
        if isinstance(max_clock_skew_seconds, bool) or not isinstance(max_clock_skew_seconds, (int, float)) or max_clock_skew_seconds < 0:
            raise ConfigurationError("max_clock_skew_seconds must be a non-negative number", "invalid_skew")
        self._max_skew = max_clock_skew_seconds
        if not isinstance(self.hooks.api_version, str) or not _API_VERSION_SHAPE.fullmatch(self.hooks.api_version):
            raise ConfigurationError("the API version must be YYYY-MM-DD", "invalid_api_version")
        self._user_agent = user_agent()
        self._latch_loaded = False
        self._latched = False
        self._unsigned_reported = False
        self._key_check = None
        self._keyless = set()
        self._reconfirmed = set()
        if ignored:
            # Once, when the client is made.
            _LOG.warning(WHEN_PRESENT_IGNORED)

    def __repr__(self):
        return "<vaultody_sdk core {}{}>".format(self.origin, self._prefix)

    @staticmethod
    def _read_roots(roots):
        try:
            return [root.public_key for root in parse_roots(roots)]
        except _VerifyConfigurationError as error:
            raise ConfigurationError(str(error), "invalid_roots") from None

    # -- small helpers ------------------------------------------------------------------------------

    @property
    def signer_fingerprint(self):
        return None if self._signer is None else self._signer.fingerprint

    @property
    def strict(self):
        """Whether an unsigned response is refused: ``required`` mode, or the latch."""
        return self.response_signature == "required" or self._latched

    def now(self):
        return self.hooks.clock()

    def now_ms(self):
        return int(self.hooks.clock() * 1000)

    def url(self, url_target):
        return self.origin + url_target

    def emit(self, data):
        """Calls the security event hook with exactly the event's catalogued fields (security_events.py). With
        no hook, the event is logged once as a warning, its JSON (it never holds a secret, an xpub or an
        address), as in Node and PHP. A hook that raises is logged and never allowed to hide the event."""
        event = security_event(data)
        if self._on_security_event is None:
            _LOG.warning("Vaultody security event: %s", json.dumps(event, ensure_ascii=False, separators=(",", ":")))
            return
        try:
            self._on_security_event(dict(event))
        except Exception:  # noqa: BLE001 - the hook is the caller's code
            _LOG.warning("the security event hook raised on %s; the call still fails or continues as it would", event["type"])

    # -- building and signing -----------------------------------------------------------------------

    def _target(self, call):
        method = call.method.upper() if isinstance(call.method, str) else call.method
        if method not in _METHODS:
            raise ParameterError("invalid_method", "the method must be one of {}".format(", ".join(_METHODS)))
        query = list(call.query or ())
        if call.context is not None:
            if not isinstance(call.context, str):
                raise ParameterError("invalid_context", "context must be a string")
            if method == "GET":
                query.append(("context", call.context))
        if not isinstance(call.path, str) or not call.path.startswith("/") or "?" in call.path or "#" in call.path:
            raise ParameterError("invalid_path", "path must be the operation path, such as /vaults/{vaultId}/utxos")
        return method, build_request_target(call.path, call.path_params or {}, query)

    @staticmethod
    def _body(method, call):
        if not call.has_item:
            return None
        if method == "GET":
            raise ParameterError("invalid_body", "a GET request has no body")
        envelope = {}
        if call.context is not None:
            envelope["context"] = call.context
        envelope["data"] = {"item": call.item}
        try:
            body = json.dumps(envelope, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode("utf-8")
        except (TypeError, ValueError, UnicodeEncodeError) as error:
            raise ParameterError("invalid_body", "the item can't be sent as JSON: {}".format(error)) from None
        if len(body) > MAX_REQUEST_BODY_BYTES:
            raise ParameterError("request_too_large", "the request body is over 1 MiB")
        return body

    def _sign(self, method, target, body, nonce=None):
        """Signs one attempt: a fresh timestamp, and ``nonce`` (the call's, when a write is re-signed) or a
        fresh one."""
        url_target = self._prefix + target
        path, _, query = url_target.partition("?")
        hooks = self.hooks
        timestamp = hooks.timestamp() if hooks.timestamp is not None else str(int(hooks.clock()))
        if nonce is None:
            nonce = hooks.nonce()
        if not isinstance(nonce, str) or not NONCE_PATTERN.fullmatch(nonce):
            raise ConfigurationError("a nonce must be 1 to 128 printable ASCII characters without spaces", "invalid_nonce")
        fields = {
            "timestamp": timestamp,
            "method": method,
            "path": path,
            "apiVersion": hooks.api_version,
            "nonce": nonce,
            "query": query,
            "body": body.decode("utf-8") if body else "",
        }
        signed = sign_hmac_v2_request(self._credentials.mapping(), fields)
        keypair_sign = None
        if self._signer is not None:
            # Over the x-api-key it is sent with too: a request signed for one API key is refused under another.
            message = keypair_request_message(
                dict(fields, apiKey=signed[API_HEADERS["api_key"]], passphrase=signed[API_HEADERS["passphrase"]])
            )
            signature = yield Sign(self._signer, self._signer.input_for(message))
            keypair_sign = normalise_signature(self._signer, message, signature, verify_locally=self._verify_locally)
            signed[API_HEADERS["keypair_sign"]] = keypair_sign
            signed[API_HEADERS["keypair_id"]] = self._signer.fingerprint
        headers = list(signed.items())
        headers.append(("user-agent", self._user_agent))
        headers.append(("accept", "application/json"))
        if body is not None:
            headers.append(("content-type", "application/json"))
        return _Signed(
            headers=tuple(headers),
            url_target=url_target,
            timestamp=timestamp,
            nonce=nonce,
            api_sign=signed[API_HEADERS["sign"]],
            keypair_sign=keypair_sign,
            signed_at_ms=int(timestamp) * 1000,
        )

    # -- the strict latch ---------------------------------------------------------------------------

    def _load_latch(self):
        # Read in every mode, required too: a strict client latches as well (so a release candidate sharing its
        # store is strict from then on), and an origin latched before is never latched again.
        if self._latch_loaded:
            return
        latch = yield StoreOp("get_strict_latch", (self.origin,))
        if latch is not None:
            self._latched = True
        self._latch_loaded = True

    def _set_latch(self, root_id):
        """Latches the origin once: ``root_id`` is the root that verified the answer, or None when it did not
        verify (refused, or no root to check it with)."""
        if self._latched:
            return
        latched_at = int(self.now())
        stored = yield StoreOp("set_strict_latch", (self.origin, {"latchedAt": latched_at, "rootId": root_id}))
        self._latched = True
        if isinstance(stored, Mapping):
            root_id, latched_at = stored.get("rootId", root_id), stored.get("latchedAt", latched_at)
        self.emit({"type": "response_signature_latched", "origin": self.origin, "rootId": root_id, "latchedAt": latched_at})

    # -- one attempt's outcome ----------------------------------------------------------------------

    def _outcome(self, method, signed, body, result, operation_id=None):
        """The outcome of one attempt for decide_retry, and what it carries: an Exchange or an error."""
        if isinstance(result, SendFailure):
            sent = classify_transport_error(result.error)["sent"]
            error = TransportError("the request failed on the network: {}".format(type(result.error).__name__), sent=sent)
            error.__cause__ = result.error
            return {"type": "not_sent" if sent is False else "sent_unknown"}, None, error

        status = result.status
        # An answer with any part of a signature latches the origin, verified or not, before anything is raised:
        # whoever strips the signature once the API signs can't keep this client lenient.
        signed_answer = carries_signature(result.headers)
        try:
            verification = verify_response(
                {"method": method, "url": signed.url_target, "body": body, "api_sign": signed.api_sign, "keypair_sign": signed.keypair_sign},
                {"status": status, "headers": result.headers, "body": result.body},
                require_response_signature=self.strict,
                roots=self._roots,
                now=self.now(),
                max_clock_skew_seconds=self._max_skew,
            )
        except ResponseSignatureError as failure:
            if signed_answer:
                yield from self._set_latch(None)
            self.emit({
                "type": "response_verification_failed", "origin": self.origin, "operationId": operation_id,
                "status": status, "reason": failure.reason,
            })
            error = ResponseVerificationError(failure.reason, "the response failed its signature check: {}".format(failure), status)
            return {"type": "verification_failed"}, None, error
        except _VerifyConfigurationError as failure:
            # A signed response and no root to check it with: fail closed. A setup error, not a refused answer, so
            # no response_verification_failed; the origin signs all the same, so it latches.
            if signed_answer:
                yield from self._set_latch(None)
            raise ConfigurationError(str(failure), "no_root_keys") from None

        if verification.verified:
            yield from self._set_latch(verification.root_id)
        elif not self._unsigned_reported:
            # Once per client: the security event, then one warning.
            self._unsigned_reported = True
            self.emit({"type": "unsigned_response_accepted", "origin": self.origin, "operationId": operation_id})
            _LOG.warning(
                "Vaultody API responses from %s are not signed: accepted unverified until the first signed one, after which "
                "this client refuses unsigned responses from this origin (response_signature=\"required\" refuses them now)",
                self.origin,
            )

        exchange = Exchange(
            target=signed.url_target,
            status=status,
            headers=result.headers,
            body=result.body,
            signature="verified" if verification.verified else "absent",
            root_id=verification.root_id,
            signature_timestamp=verification.timestamp,
        )
        code, exchange.request_id = _error_fields(result.body)
        retry_after = result.headers.get("retry-after")
        outcome = {
            "type": "response",
            "status": status,
            "code": code if not 200 <= status <= 299 else None,
            "replayed": result.headers.get("x-api-replayed") == "true",
            "retryAfterSeconds": int(retry_after) if retry_after and _RETRY_AFTER.fullmatch(retry_after) else None,
        }
        return outcome, exchange, None

    # -- one call, with its retries -----------------------------------------------------------------

    def exchange(self, method, target, body, operation, operation_id=None):
        """Sends one call until decide_retry says stop. Returns the Exchange of an answer to return (any
        status); raises for a failure, a verification failure and an unknown outcome."""
        yield from self._load_latch()
        key_mode = "legacy"
        if operation == "write":
            if self._signer is not None:
                # The key-pair check is a signed read: before the first write it is also the read below.
                key_mode = yield from self._key_mode()
            else:
                yield from self._read_before_write()
        started_ms = self.now_ms()
        attempt = 0
        may_have_run = False
        conflict_retried = False
        signed = None
        # Kept from the first signing on every retry of a write; None: a new one (the first, or a read re-signed).
        keep_nonce = None
        resends = 0
        first_send_ms = None
        while True:
            if signed is None:
                signed = yield from self._sign(method, target, body, keep_nonce)
                resends = 0
                first_send_ms = None
            yield Acquire()
            if first_send_ms is None:
                first_send_ms = self.now_ms()
            result = yield Send(method, self.url(signed.url_target), signed.headers, body)
            attempt += 1
            if isinstance(result, SendFailure) and result.too_large:
                if operation == "write":
                    raise RequestOutcomeUnknownError(False, signed.nonce, signed.timestamp, None)
                raise TransportError("the response is larger than 10 MiB", sent="unknown")
            outcome, exchange, error = yield from self._outcome(method, signed, body, result, operation_id)
            now_ms = self.now_ms()
            decision = decide_retry({
                "operation": operation,
                "keyMode": key_mode,
                "attempt": attempt,
                "elapsedMs": now_ms - started_ms,
                "signedAgeMs": now_ms - signed.signed_at_ms,
                "sinceFirstSendMs": now_ms - first_send_ms,
                "resends": resends,
                "mayHaveRun": may_have_run,
                "conflictRetried": conflict_retried,
                "random": self.hooks.random(),
                "outcome": outcome,
            })
            action = decision["action"]
            if action == "return":
                return exchange
            if action == "fail":
                raise error
            if action == "outcome_unknown":
                request_id = exchange.request_id if exchange is not None else None
                raise RequestOutcomeUnknownError(decision["inProgress"], signed.nonce, signed.timestamp, request_id)
            # retry
            if outcome["type"] == "response" and outcome["code"] in ("address_derivation_conflict", "vault_accounts_creation_failed"):
                conflict_retried = True
            may_have_run = may_have_run or outcome["type"] == "sent_unknown" or (
                outcome["type"] == "response" and 500 <= outcome["status"] <= 599
            )
            if decision["delayMs"] > 0:
                yield Sleep(decision["delayMs"] / 1000.0)
            if decision["mode"] == "resign":
                keep_nonce = signed.nonce if decision["nonce"] == "same" else None
                signed = None
            else:
                resends += 1

    def request(self, call):
        """One call through the whole pipeline. Returns the Exchange of a success, with its envelope read
        and its addresses checked; raises the typed error of anything else."""
        method, target = self._target(call)
        body = self._body(method, call)
        operation = call.retry or ("read" if method == "GET" else "write")
        if operation not in ("read", "write"):
            raise ParameterError("invalid_retry", 'retry must be "read" or "write"')
        exchange = yield from self.exchange(method, target, body, operation, call.operation_id)
        exchange.envelope = read_envelope(exchange.status, exchange.headers, exchange.body)
        path = target.partition("?")[0]
        if method == "GET" and _VAULT_LIST.fullmatch(path):
            exchange.vault_keys = yield from self._observe_vault_list(path.rsplit("/", 1)[1].lower(), exchange)
        for route_method, pattern, operation_id in _ADDRESS_ROUTES:
            match = pattern.fullmatch(path) if method == route_method else None
            if match is not None:
                exchange.address_checks = yield from self._check_addresses(operation_id, match, call, exchange)
        return exchange

    # -- the key pair -------------------------------------------------------------------------------

    def signing_key_status(self):
        """Whether the signer's key is registered and active on this API key (GET /api-keys/current/signing-keys).

        :returns: ``{"fingerprint", "outcome": active | inactive | not_listed | refused, "signature":
            verified | absent, "code", "request_id", "keys"}``
        """
        if self._signer is None:
            raise ConfigurationError("no signer is configured", "no_signer")
        exchange = yield from self.exchange("GET", SIGNING_KEYS_PATH, None, "read", "listApiKeySigningKeys")
        try:
            status = read_signing_keys_response(exchange.status, exchange.body, self._signer.fingerprint)
        except UnexpectedResponseError:
            read_envelope(exchange.status, exchange.headers, exchange.body)  # raises the typed error
            raise ApiError(exchange.status, None, "the signing-keys answer is not a list of keys")
        return {
            "fingerprint": self._signer.fingerprint,
            "outcome": status["outcome"],
            "signature": exchange.signature,
            "code": (status["error"] or {}).get("code"),
            "request_id": status["request_id"],
            "keys": status["keys"],
        }

    def _read_before_write(self):
        """One signed read (GET /api-keys/current/signing-keys) before the first write of a client with
        response-signing roots, while its origin is not latched.

        Against an origin that does not sign, or a signature stripped from the start, the read is refused
        (ResponseVerificationError, or ConfigurationError) and the write is never sent, instead of running and
        coming back as an answer that can't be trusted. Any answer that passes its check is verified (such a
        client is required), so it latches the origin and settles it for good. A network failure leaves it
        open: the write goes ahead with its own answer checked as always, and the next write reads again.
        """
        if not self._roots_configured or self._latched:
            return
        try:
            yield from self.exchange("GET", SIGNING_KEYS_PATH, None, "read", "listApiKeySigningKeys")
        except TransportError:
            pass

    def _key_mode(self):
        """``keypair`` only while a signed answer confirmed the key pair active within the last 10 minutes.

        With response-signing roots it is checked again before each write until the origin is latched: it is
        the signed read before the first write (_read_before_write)."""
        now = self.now()
        settled = self._latched or not self._roots_configured
        if self._key_check is not None and self._key_check[1] > now and settled:
            return self._key_check[0]
        mode = "legacy"
        try:
            status = yield from self.signing_key_status()
            if status["signature"] == "verified" and status["outcome"] == "active":
                mode = "keypair"
        except (ApiError, TransportError):
            mode = "legacy"  # not confirmed: a write is then never resent once it may have run
        self._key_check = (mode, now + KEY_CHECK_TTL_SECONDS)
        return mode

    # -- vault xpub pins ----------------------------------------------------------------------------

    def _observe_vault_list(self, route_type, exchange):
        envelope = exchange.envelope
        if envelope["kind"] != "page":
            raise ApiError(exchange.status, None, "the vault list answer has no list of vaults", envelope["request_id"])
        try:
            vaults = read_vault_list(envelope["items"])
        except TypeError as error:
            raise ApiError(exchange.status, None, "the vault list is malformed: {}".format(error), envelope["request_id"]) from None
        for vault in vaults:
            if not isinstance(vault["type"], str) or vault["type"].lower() != route_type:
                raise ApiError(
                    exchange.status, None,
                    "vault {} is listed as {!r} in GET /vaults/{}".format(vault["vaultId"], vault["type"], route_type),
                    envelope["request_id"],
                )
            # Pinned as the route names it (main, test), whatever the case of the answer.
            vault["type"] = route_type
        stored = yield StoreOp("list", (self.origin,))
        pins = {pin["vaultId"]: pin for pin in stored}
        # A configured pin is compared like a stored one; it is verified, so it is never among the changes.
        pins.update(self._configured)
        evidence = {"now": int(self.now()), "signed": exchange.signature == "verified"}
        if evidence["signed"]:
            evidence.update(rootId=exchange.root_id, timestamp=exchange.signature_timestamp)
        outcomes, changes = self._observe(pins, vaults, evidence)
        by_id = {vault["vaultId"]: vault for vault in vaults}
        after = dict(pins)
        for change in changes:
            after[change["vaultId"]] = yield from self._write_pin(pins.get(change["vaultId"]), change, by_id[change["vaultId"]], evidence)
        results = []
        for outcome in outcomes:
            vault_id = outcome["vaultId"]
            if outcome["outcome"] == OUTCOMES["NOT_VERIFIABLE"]:
                self._keyless.add(vault_id)
                status = ADDRESS_CHECK_STATUS["NOT_VERIFIABLE"]
            else:
                self._keyless.discard(vault_id)
                status = after[vault_id]["status"]
            results.append({"vaultId": vault_id, "status": status, "outcome": outcome["outcome"]})
        return results

    def _observe(self, pins, vaults, evidence):
        try:
            return observe_vaults(pins, vaults, evidence)
        except VaultKeyChangedError as alarm:
            self.emit({"type": "vault_key_changed", "origin": self.origin, "alarms": [dict(item) for item in alarm.alarms]})
            raise

    def _write_pin(self, before, change, vault, evidence):
        """Stores a new or upgraded pin; returns the pin stored."""
        vault_id = change["vaultId"]
        if before is None:
            stored = yield StoreOp("pin_if_absent", (self.origin, change))
        else:
            stored = yield StoreOp("upgrade_trust", (self.origin, vault_id, before, change))
        conflict = "the pin of vault {} changed in the store while this client wrote it; call again".format(vault_id)
        if stored is None:
            # Another writer removed the pin between the read and the write.
            raise VaultKeyStoreError(conflict, "store_conflict")
        if stored != change:
            # Another client wrote this vault meanwhile: what it stored is compared like any pin.
            _, again = self._observe({vault_id: stored}, [vault], evidence)
            if again:
                change, before = again[0], stored
                stored = yield StoreOp("upgrade_trust", (self.origin, vault_id, before, change))
                if stored != change:
                    raise VaultKeyStoreError(conflict, "store_conflict")
            else:
                return stored
        self.emit({
            "type": "vault_key_pinned" if before is None else "vault_key_verified",
            "origin": self.origin, "vaultId": vault_id, "status": change["status"],
        })
        return stored

    def _discover(self, vault_id, vault_type):
        """Reads GET /vaults/{type} page by page until the vault shows up; every page is observed. The list
        the address suggests comes first, then the other."""
        for network_type in (["test", "main"] if vault_type == "test" else ["main", "test"]):
            starting_after = None
            used = set()
            for _ in range(MAX_VAULT_LIST_PAGES):
                query = [("limit", VAULT_LIST_PAGE_LIMIT)]
                if starting_after is not None:
                    query.append(("startingAfter", starting_after))
                exchange = yield from self.request(Call("GET", VAULT_LIST_PATH, {"networkType": network_type}, tuple(query), operation_id="listVaults"))
                items = exchange.envelope["items"]
                if any(isinstance(item, Mapping) and item.get("id") == vault_id for item in items):
                    return
                if not exchange.envelope.get("has_more") or not items:
                    break
                cursor = items[-1].get("id") if isinstance(items[-1], Mapping) else None
                if not isinstance(cursor, str) or not cursor or cursor in used:
                    raise PaginationError("pagination_loop", "the vault list does not advance; stopping instead of looping")
                used.add(cursor)
                starting_after = cursor

    def _pin_for(self, vault_id, vault_type):
        """The vault's pin, read from the vault lists first if needed; None for a vault without MPC keys. A
        configured pin comes first: no listing, and no store."""
        if vault_id in self._configured:
            return self._configured[vault_id]
        pin = yield StoreOp("get", (self.origin, vault_id))
        if pin is not None:
            if pin["status"] == PIN_STATUS["UNVERIFIED"] and self.strict and vault_id not in self._reconfirmed:
                # Signing is on now: a signed vault list confirms the pin, or raises the alarm.
                self._reconfirmed.add(vault_id)
                kind = pin["type"].lower() if isinstance(pin.get("type"), str) else None
                yield from self._discover(vault_id, kind if kind in ("main", "test") else None)
                pin = yield StoreOp("get", (self.origin, vault_id))
            return pin
        if vault_id in self._keyless:
            return None
        yield from self._discover(vault_id, vault_type)
        pin = yield StoreOp("get", (self.origin, vault_id))
        if pin is None and vault_id not in self._keyless:
            raise AddressVerificationError(
                "unknown_vault", "vault {} is in neither GET /vaults/main nor GET /vaults/test".format(vault_id), vault_id=vault_id
            )
        return pin

    # -- address checks -----------------------------------------------------------------------------

    def _check_addresses(self, operation_id, match, call, exchange):
        try:
            return (yield from self._address_statuses(operation_id, match, call, exchange))
        except AddressVerificationError as error:
            self.emit({
                "type": "address_verification_failed", "origin": self.origin, "operationId": operation_id,
                "vaultId": error.vault_id, "code": error.code,
            })
            raise

    def _address_statuses(self, operation_id, match, call, exchange):
        envelope = exchange.envelope
        vault_id = unquote(match.group(1))
        if operation_id == "listAddressesByVaultAccountId":
            if envelope["kind"] != "page":
                raise AddressVerificationError("invalid", "the address list answer has no list", vault_id=vault_id)
            items = envelope["items"]
        else:
            if envelope["kind"] != "item":
                raise AddressVerificationError("invalid", "the address answer has no item", vault_id=vault_id)
            items = [envelope["item"]]

        # What the call asked for: an item that names another chain or network is refused (as in Node and PHP).
        requested_blockchain = requested_network = None
        if operation_id == "generateDepositAddress":
            requested_blockchain, requested_network = unquote(match.group(2)), unquote(match.group(3))
        elif operation_id == "listAddressesByVaultAccountId":
            requested_blockchain = next((value for name, value in call.query if name == "blockchain" and isinstance(value, str)), None)

        entries = []
        for item in items:
            if not isinstance(item, Mapping) or not isinstance(item.get("address"), str) or not item["address"]:
                raise AddressVerificationError("invalid", "an answer item has no address", vault_id=vault_id)
            address = item["address"]
            sent = None
            if operation_id == "addAssetToVaultAccount":
                # With an address, the asset is added to that address: the answer must name it, byte for
                # byte. With a label instead, the answer is a newly derived address, checked like any other.
                sent = call.item.get("address") if isinstance(call.item, Mapping) else None
                if sent is not None and address != sent:
                    raise AddressVerificationError(
                        "mismatch", "the address returned is not the address sent", vault_id=vault_id, address=address
                    )
            blockchain = item.get("blockchain") if item.get("blockchain") is not None else requested_blockchain
            network = item.get("network") if item.get("network") is not None else requested_network
            path = (item.get("accountIndex"), item.get("isChange"), item.get("addressIndex"))
            derivable = all(part is not None for part in path)
            # A new address that comes without its path, on a chain the SDK can derive: refused (path_missing)
            # with require_address_paths, once the vault turns out to have MPC keys.
            path_required = not derivable and address_path_required(
                self._require_address_paths, operation_id, isinstance(blockchain, str) and blockchain in CHAINS
            )
            if derivable and not isinstance(blockchain, str):
                if sent is not None:
                    derivable = False  # the chain is not known: only the byte-equal check above applies
                else:
                    raise AddressVerificationError(
                        "unsupported", "an address carries its derivation path but the answer does not say which chain it is on",
                        vault_id=vault_id, address=address,
                    )
            if network is not None and not isinstance(network, str):
                raise AddressVerificationError("invalid", "an address has a malformed network", vault_id=vault_id, address=address)
            entries.append((item, address, blockchain, network, path, derivable, path_required))

        pin = None
        if any(entry[5] or entry[6] for entry in entries):
            # The vault's pin, read from the vault lists if needed; None for a vault without MPC keys.
            hint = None
            if requested_network is not None:
                hint = "main" if requested_network.lower() == "mainnet" else "test"
            pin = yield from self._pin_for(vault_id, hint)

        checks = []
        for item, address, blockchain, network, path, derivable, path_required in entries:
            if not derivable:
                # No derivation path (SMART vaults, older rows): not verifiable, or path_missing when one is required
                # and the vault has MPC keys.
                try:
                    status = address_check_status(pin, pin is not None, False, None, path_required=path_required)
                except AddressVerificationError as error:
                    raise AddressVerificationError(error.code, str(error), vault_id=vault_id, address=address) from None
            elif pin is None:
                # A vault without MPC keys.
                status = ADDRESS_CHECK_STATUS["NOT_VERIFIABLE"]
            else:
                if requested_blockchain is not None and item.get("blockchain") is not None and item["blockchain"] != requested_blockchain:
                    raise AddressVerificationError(
                        "mismatch", "an address is on {}, but {} was asked for".format(item["blockchain"], requested_blockchain),
                        vault_id=vault_id, address=address,
                    )
                if requested_network is not None and item.get("network") is not None and item["network"] != requested_network:
                    raise AddressVerificationError(
                        "network_mismatch", "an address is on {}, but {} was asked for".format(item["network"], requested_network),
                        vault_id=vault_id, address=address,
                    )
                derivation = self._derive(pin, vault_id, item, address, blockchain, network, path)
                try:
                    status = address_check_status(pin, True, True, derivation)
                except AddressVerificationError as error:
                    raise AddressVerificationError(error.code, str(error), vault_id=vault_id, address=address) from None
            checks.append({"vaultId": vault_id, "address": address, "status": status})
        return checks

    @staticmethod
    def _derive(pin, vault_id, item, address, blockchain, network, path):
        vault_type = pin["type"].lower() if isinstance(pin.get("type"), str) else None
        if vault_type not in ("main", "test"):
            raise AddressVerificationError("invalid", "vault {} has the type {!r}".format(vault_id, pin.get("type")), vault_id=vault_id, address=address)
        if network is None:
            network = network_of_vault(blockchain, vault_type)
            if network is None:
                raise AddressVerificationError(
                    "unsupported", "{} is not a blockchain the SDK can derive addresses for".format(blockchain), vault_id=vault_id, address=address
                )
        try:
            address_format = item.get("addressFormat")
            check_address(
                {"type": vault_type, "keys": pin["keys"]},
                blockchain=blockchain,
                network=network,
                address=address,
                account_index=path[0],
                is_change=path[1],
                address_index=path[2],
                address_format=address_format if isinstance(address_format, str) else None,
            )
        except _DerivationError as error:
            if error.reason == "mismatch":
                return "mismatch"
            raise AddressVerificationError(error.reason, str(error), vault_id=vault_id, address=address) from None
        except (TypeError, ValueError) as error:
            raise AddressVerificationError("invalid", "malformed derivation fields: {}".format(error), vault_id=vault_id, address=address) from None
        return "match"


def _error_fields(body):
    """``(error.code, requestId)`` of a body, read leniently for the retry decision; (None, None) otherwise."""
    try:
        parsed = json.loads(bytes(body).decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        return None, None
    if not isinstance(parsed, dict):
        return None, None
    error = parsed.get("error")
    code = error.get("code") if isinstance(error, dict) and isinstance(error.get("code"), str) else None
    request_id = parsed.get("requestId") if isinstance(parsed.get("requestId"), str) else None
    return code, request_id


def run_sync(generator, perform):
    """Drives a core generator, performing each effect with ``perform``; the sync client's loop."""
    value, error = None, None
    while True:
        try:
            effect = generator.throw(error) if error is not None else generator.send(value)
        except StopIteration as stop:
            return stop.value
        value, error = None, None
        try:
            value = perform(effect)
        except Exception as raised:  # noqa: BLE001 - handed to the core, which decides
            error = raised
        except BaseException:
            generator.close()
            raise


async def run_async(generator, perform):
    """The same for the async client: ``perform`` is a coroutine function."""
    value, error = None, None
    while True:
        try:
            effect = generator.throw(error) if error is not None else generator.send(value)
        except StopIteration as stop:
            return stop.value
        value, error = None, None
        try:
            value = await perform(effect)
        except Exception as raised:  # noqa: BLE001
            error = raised
        except BaseException:
            generator.close()
            raise


def paging_query(query, request):
    """The query of one page: the caller's pairs, then ``limit``, then ``startingAfter`` or ``offset``."""
    pairs = [pair for pair in (query or ()) if pair[0] not in ("limit", "startingAfter", "offset")]
    pairs.append(("limit", request["limit"]))
    if "offset" in request:
        pairs.append(("offset", request["offset"]))
    elif request.get("startingAfter") is not None:
        pairs.append(("startingAfter", request["startingAfter"]))
    return tuple(pairs)


def page_for_pager(result):
    """What the pager reads of a page; ``page`` is the Page itself, for ``Pages.pages()``."""
    if not isinstance(result, Page):
        raise PaginationError("not_a_list", "the operation did not answer with a list")
    return {"items": result.items, "hasMore": result.has_more, "total": result.total, "page": result}


__all__ = [
    "DEFAULT_BASE_URL",
    "MAX_REQUEST_BODY_BYTES",
    "MAX_RESPONSE_BODY_BYTES",
    "RESPONSE_SIGNATURE_MODES",
    "Call",
    "Core",
    "Hooks",
    "Item",
    "Page",
    "ResponseMeta",
]
