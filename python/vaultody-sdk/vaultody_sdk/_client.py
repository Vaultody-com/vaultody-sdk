"""Vaultody: the synchronous transport, httpx.Client over the shared core (_core.py)."""

import ssl
import threading
import time
from collections.abc import Mapping
from typing import Any, Callable, Dict, Iterable, Mapping as _Mapping, Optional, Sequence, Union

import httpx

from ._core import (
    DEFAULT_BASE_URL,
    DEFAULT_MAX_REQUESTS_PER_SECOND,
    DEFAULT_TIMEOUT_SECONDS,
    MAX_RESPONSE_BODY_BYTES,
    Acquire,
    Call,
    Core,
    Headers,
    RawResponse,
    Send,
    SendFailure,
    Sign,
    Sleep,
    StoreOp,
    page_for_pager,
    paging_query,
    run_sync,
)
from ._defaults import ADDRESS_PATHS_PUBLIC
from ._operations import OPERATION_BY_ID, check_context, check_params, operation_call, page_call, paging_options, single_item
from ._resources import ApiKeys, AssetsAddresses, Transactions, VaultAccounts, Vaults
from .errors import ConfigurationError, ParameterError
from .pagination import Pages
from .signers import Signer
from .stores import VaultKeyStore
from .webhooks import Webhooks

_NO_ITEM = object()


def http_options(timeout, verify, proxy, transport, transport_class):
    """The httpx client options: TLS verification always on (a custom CA is fine), no redirects."""
    if isinstance(timeout, bool) or not isinstance(timeout, (int, float)) or not timeout > 0:
        raise ConfigurationError("timeout must be a positive number of seconds", "invalid_timeout")
    options = {"timeout": httpx.Timeout(float(timeout)), "follow_redirects": False}
    if verify is None or verify is True:
        pass
    elif isinstance(verify, ssl.SSLContext):
        if verify.verify_mode != ssl.CERT_REQUIRED or not verify.check_hostname:
            raise ConfigurationError("the SSL context must verify certificates and host names", "insecure_tls")
        options["verify"] = verify
    elif isinstance(verify, str) and verify:
        try:
            options["verify"] = ssl.create_default_context(cafile=verify)
        except (OSError, ssl.SSLError) as error:
            raise ConfigurationError("cannot read the CA bundle {!r}: {}".format(verify, error), "invalid_ca_bundle") from None
    else:
        # There is deliberately no way to switch certificate checks off.
        raise ConfigurationError("verify must be a CA bundle path or an ssl.SSLContext; TLS checks can't be turned off", "insecure_tls")
    if proxy is not None:
        options["proxy"] = proxy
    if transport is not None:
        if not isinstance(transport, transport_class):
            raise ConfigurationError("transport must be an {}".format(transport_class.__name__), "invalid_transport")
        options["transport"] = transport
    return options


def query_pairs(query):
    if query is None:
        return ()
    if isinstance(query, Mapping):
        return tuple(query.items())
    if isinstance(query, (str, bytes)):
        raise ParameterError("invalid_query_param", "query must be a mapping or (name, value) pairs")
    pairs = tuple(tuple(pair) for pair in query)
    if any(len(pair) != 2 for pair in pairs):
        raise ParameterError("invalid_query_param", "query must be a mapping or (name, value) pairs")
    return pairs


def make_call(method, path, path_params, query, item, context, retry):
    return Call(
        method=method,
        path=path,
        path_params=dict(path_params or {}),
        query=query_pairs(query),
        item=None if item is _NO_ITEM else item,
        has_item=item is not _NO_ITEM,
        context=context,
        retry=retry,
    )


class Vaultody:
    """The Vaultody API client, synchronous. Safe to share between threads.

    One method per documented operation, grouped as the docs group them: ``vaults``, ``vault_accounts``,
    ``assets_addresses``, ``transactions`` and ``api_keys`` (see _resources.py and the README), such as
    ``client.transactions.create_single_transfer(vaultId=..., ...)``.

    :param api_key, api_secret, passphrase: the API key's credentials, as the dashboard shows them. Kept in
        memory (HMAC needs them), never shown by repr, errors or logs.
    :param base_url: ``https://rest.vaultody.com`` by default; plain http only to this machine.
    :param signer: a request signer (signers.py) when the API key has a key pair of its own.
    :param response_signature: ``"when-present"`` or ``"required"``; not given: ``$VAULTODY_RESPONSE_SIGNATURE``,
        else the build default (``"when-present"`` for release candidates). ``"when-present"``: an unsigned
        response passes until this origin has sent one signed response, after which unsigned responses are
        refused, also after a restart; a signed response is always checked. ``"required"``: every response
        must be signed. With response-signing roots (``roots``, or those a stable release embeds) the client
        is always ``"required"``; a ``"when-present"`` given then is ignored, with one warning.
    :param roots: response-signing roots to trust instead of the embedded ones (test environments only). Given,
        they make the client strict from its first response, and before its first write it makes one signed
        read (GET /api-keys/current/signing-keys, the key-pair check when a signer is set), so a write is never
        sent to an origin that does not sign.
    :param vault_key_store: where vault xpub pins and the strict latch are kept; the default is a file
        (stores.py).
    :param pinned_vault_keys: vault xpubs you give yourself, for this client's origin: a list of
        ``{"vaultId": ..., "type": "main" | "test", "keys": {"ECDSA": xpub or None, "EDDSA": xpub or None}}``.
        Such a pin counts as verified, is compared with every vault list like any pin (any difference is
        the alarm), is never written to the store, and takes the place of the stored pin of that vault.
    :param require_address_paths: refuse (AddressVerificationError ``path_missing``) an address that
        generate_deposit_address answers without its derivation path, for a vault with MPC keys on a chain the
        SDK can derive. Default: on once the API returns the paths (``ADDRESS_PATHS_PUBLIC``), off before.
    :param on_security_event: ``f(event: dict)``, called before a security error is raised and when a
        vault is pinned: ``response_verification_failed``, ``vault_key_changed``,
        ``address_verification_failed``, ``vault_key_pinned``, ``vault_key_verified``,
        ``response_signature_latched``. Never given a secret or an xpub.
    :param max_requests_per_second: the client-side rate limit (default 5).
    :param timeout: seconds per attempt.
    :param verify_signatures_locally: check each key-pair signature against the signer's public key
        before sending it (default True).
    :param verify: a CA bundle path or an ``ssl.SSLContext`` for a private CA; certificate checks can't be
        switched off.
    :param proxy: an HTTP(S) proxy URL.
    :param transport: an httpx transport, for tests and special networks.
    """

    # The API methods, one namespace per docs group (declared here for type checkers).
    vaults: Vaults
    vault_accounts: VaultAccounts
    assets_addresses: AssetsAddresses
    transactions: Transactions
    api_keys: ApiKeys

    def __init__(
        self,
        api_key: str,
        api_secret: str,
        passphrase: str,
        *,
        base_url: str = DEFAULT_BASE_URL,
        signer: Optional[Signer] = None,
        response_signature: Optional[str] = None,
        roots: Optional[Iterable[Any]] = None,
        vault_key_store: Optional[VaultKeyStore] = None,
        pinned_vault_keys: Optional[Sequence[_Mapping[str, Any]]] = None,
        require_address_paths: bool = ADDRESS_PATHS_PUBLIC,
        on_security_event: Optional[Callable[[Dict[str, Any]], object]] = None,
        max_requests_per_second: float = DEFAULT_MAX_REQUESTS_PER_SECOND,
        timeout: float = DEFAULT_TIMEOUT_SECONDS,
        verify_signatures_locally: bool = True,
        max_clock_skew_seconds: float = 300,
        verify: Union[str, ssl.SSLContext, None] = None,
        proxy: Union[str, httpx.URL, httpx.Proxy, None] = None,
        transport: Optional[httpx.BaseTransport] = None,
        _hooks: Any = None,
    ) -> None:
        self._core = Core(
            api_key,
            api_secret,
            passphrase,
            base_url=base_url,
            signer=signer,
            response_signature=response_signature,
            roots=roots,
            vault_key_store=vault_key_store,
            pinned_vault_keys=pinned_vault_keys,
            require_address_paths=require_address_paths,
            on_security_event=on_security_event,
            max_requests_per_second=max_requests_per_second,
            verify_signatures_locally=verify_signatures_locally,
            max_clock_skew_seconds=max_clock_skew_seconds,
            allow_async_signer=False,
            hooks=_hooks,
        )
        self._http = httpx.Client(**http_options(timeout, verify, proxy, transport, httpx.BaseTransport))
        self._limiter_lock = threading.Lock()
        self.webhooks = Webhooks()
        self.vaults = Vaults(self)
        self.vault_accounts = VaultAccounts(self)
        self.assets_addresses = AssetsAddresses(self)
        self.transactions = Transactions(self)
        self.api_keys = ApiKeys(self)

    def __repr__(self):
        return "<vaultody_sdk.Vaultody {} response_signature={}>".format(self._core.origin, self._core.response_signature)

    def __enter__(self) -> "Vaultody":
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.close()

    def close(self) -> None:
        self._http.close()

    @property
    def origin(self) -> str:
        return self._core.origin

    @property
    def vault_key_store(self) -> VaultKeyStore:
        return self._core.vault_key_store

    @property
    def response_signature(self) -> str:
        """The response-signature mode in force: ``"when-present"`` or ``"required"``; ``"required"`` whenever
        response-signing roots are configured, whatever was asked."""
        return self._core.response_signature

    @property
    def strict(self) -> bool:
        """Whether unsigned responses are refused now (``required``, or latched)."""
        return self._core.strict

    def _request(self, method, path, *, path_params=None, query=None, item=_NO_ITEM, context=None, retry=None):
        """One call of any path through the whole pipeline, without the operation table's argument checks.

        Internal: the tests and the vector runners use it. Callers use the API methods, which check their
        arguments against the documented operation first.

        :param method: ``GET``, ``POST`` or ``PUT``
        :param path: the operation path as documented, such as ``"/vaults/{vaultId}/utxos"``
        :param path_params: a value for each ``{name}`` in the path
        :param query: a mapping or ``(name, value)`` pairs, sent in that order; None values are left out
        :param item: for POST and PUT, sent as ``data.item``
        :param context: your own reference, echoed back (query for GET, body for POST and PUT)
        :param retry: ``"read"`` for a POST that changes nothing (retried like a GET); writes by default
        :returns: Item or Page
        """
        call = make_call(method, path, path_params, query, item, context, retry)
        return run_sync(self._core.request(call), self._perform).result()

    def _paginate(self, method, path, *, path_params=None, query=None, cursor_field=None, paging="cursor", limit=None, max_limit=50, max_items=None, context=None, retry=None):
        """Every item of a list of any path, page by page; each page is a call like any other (signed,
        verified, checked). Internal, like _request.

        :param cursor_field: the field of the last item sent as startingAfter (``id``, ``addressId`` ...)
        :param paging: ``"cursor"`` or ``"offset"``
        :param limit: the page size; the operation's largest (``max_limit``) by default
        :param max_items: stop after this many items
        :returns: pagination.Pages; iterate it. ``.stop`` says why it ended.
        """
        base_query = query_pairs(query)

        def fetch_page(page_request):
            return page_for_pager(self._request(method, path, path_params=path_params, query=paging_query(base_query, page_request), context=context, retry=retry))

        return Pages(fetch_page, paging=paging, cursor_field=cursor_field, limit=limit, max_limit=max_limit, max_items=max_items)

    def check_signing_key(self) -> Dict[str, Any]:
        """Whether the signer's key is registered and active on this API key: ``{"fingerprint", "outcome",
        "signature", "code", "request_id", "keys"}``, ``outcome`` being ``active``, ``inactive``,
        ``not_listed`` or ``refused``. Trust ``active`` only with ``signature == "verified"``."""
        return run_sync(self._core.signing_key_status(), self._perform)

    # -- the API methods (_resources.py) ------------------------------------------------------------

    def _item(self, operation_id, params, context):
        """One call of an operation that answers with one item."""
        operation = OPERATION_BY_ID[operation_id]
        call = operation_call(operation, check_params(operation, params), check_context(context))
        return single_item(run_sync(self._core.request(call), self._perform).result(), operation)

    def _list(self, operation_id, params, context, max_items):
        """The items of a list operation, fetched page by page as the caller iterates. The arguments are
        checked now; nothing is sent before the first item is asked for."""
        operation = OPERATION_BY_ID[operation_id]
        checked = check_params(operation, params)
        check_context(context)
        options = paging_options(operation, checked, max_items)

        def fetch_page(page_request):
            call = page_call(operation, checked, context, page_request)
            return page_for_pager(run_sync(self._core.request(call), self._perform).result())

        return Pages(fetch_page, **options)

    # -- effects ------------------------------------------------------------------------------------

    def _sleep(self, seconds):
        hook = self._core.hooks.sleep
        if hook is not None:
            hook(seconds)
        elif seconds > 0:
            time.sleep(seconds)

    def _perform(self, effect):
        if isinstance(effect, Send):
            return self._send(effect)
        if isinstance(effect, StoreOp):
            return getattr(self._core.vault_key_store, effect.name)(*effect.args)
        if isinstance(effect, Acquire):
            with self._limiter_lock:
                wait = self._core.limiter.reserve(self._core.now())
            if wait > 0:
                self._sleep(wait)
            return None
        if isinstance(effect, Sign):
            return effect.signer.signer.sign(effect.data)
        if isinstance(effect, Sleep):
            self._sleep(effect.seconds)
            return None
        raise TypeError("unknown effect {!r}".format(effect))

    def _send(self, effect):
        request = self._http.build_request(effect.method, effect.url, headers=list(effect.headers), content=effect.body)
        try:
            response = self._http.send(request, stream=True)
        except httpx.RequestError as error:
            return SendFailure(error)
        try:
            chunks = []
            size = 0
            for chunk in response.iter_bytes():
                size += len(chunk)
                if size > MAX_RESPONSE_BODY_BYTES:
                    return SendFailure(ValueError("the response is larger than 10 MiB"), too_large=True)
                chunks.append(chunk)
        except httpx.RequestError as error:
            return SendFailure(error)
        finally:
            response.close()
        return RawResponse(response.status_code, Headers(response.headers.multi_items()), b"".join(chunks))


__all__ = ["Vaultody"]
