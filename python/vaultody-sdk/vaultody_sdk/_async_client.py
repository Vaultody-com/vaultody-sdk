"""AsyncVaultody: the asynchronous transport, httpx.AsyncClient over the same core as Vaultody."""

import asyncio
import inspect
import ssl
import threading
from typing import Any, Callable, Dict, Iterable, Mapping as _Mapping, Optional, Sequence, Union

import httpx

from ._client import _NO_ITEM, http_options, make_call, query_pairs
from ._core import (
    DEFAULT_BASE_URL,
    DEFAULT_MAX_REQUESTS_PER_SECOND,
    DEFAULT_TIMEOUT_SECONDS,
    MAX_RESPONSE_BODY_BYTES,
    Acquire,
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
    run_async,
)
from ._defaults import ADDRESS_PATHS_PUBLIC
from ._operations import OPERATION_BY_ID, check_context, check_params, operation_call, page_call, paging_options, single_item
from ._resources import AsyncApiKeys, AsyncAssetsAddresses, AsyncTransactions, AsyncVaultAccounts, AsyncVaults
from .pagination import AsyncPages
from .signers import AsyncSigner, Signer
from .stores import VaultKeyStore
from .webhooks import Webhooks


class AsyncVaultody:
    """The Vaultody API client for asyncio. The parameters and behaviour are those of Vaultody.

    It takes a sync signer (run in a thread, such as boto3's KMS client) or an async one. The vault key
    store is called in a thread.

    The API methods are those of Vaultody: a single item is awaited
    (``await client.transactions.create_single_transfer(...)``), a list is an async iterator
    (``async for vault in client.vaults.list_vaults(networkType="main")``).
    """

    # The API methods, one namespace per docs group (declared here for type checkers).
    vaults: AsyncVaults
    vault_accounts: AsyncVaultAccounts
    assets_addresses: AsyncAssetsAddresses
    transactions: AsyncTransactions
    api_keys: AsyncApiKeys

    def __init__(
        self,
        api_key: str,
        api_secret: str,
        passphrase: str,
        *,
        base_url: str = DEFAULT_BASE_URL,
        signer: Union[Signer, AsyncSigner, None] = None,
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
        transport: Optional[httpx.AsyncBaseTransport] = None,
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
            allow_async_signer=True,
            hooks=_hooks,
        )
        self._http = httpx.AsyncClient(**http_options(timeout, verify, proxy, transport, httpx.AsyncBaseTransport))
        # Held only around the token arithmetic, never across an await.
        self._limiter_lock = threading.Lock()
        self.webhooks = Webhooks()
        self.vaults = AsyncVaults(self)
        self.vault_accounts = AsyncVaultAccounts(self)
        self.assets_addresses = AsyncAssetsAddresses(self)
        self.transactions = AsyncTransactions(self)
        self.api_keys = AsyncApiKeys(self)

    def __repr__(self):
        return "<vaultody_sdk.AsyncVaultody {} response_signature={}>".format(self._core.origin, self._core.response_signature)

    async def __aenter__(self) -> "AsyncVaultody":
        return self

    async def __aexit__(self, *exc_info: object) -> None:
        await self.aclose()

    async def aclose(self) -> None:
        await self._http.aclose()

    @property
    def origin(self) -> str:
        return self._core.origin

    @property
    def vault_key_store(self) -> VaultKeyStore:
        return self._core.vault_key_store

    @property
    def response_signature(self) -> str:
        """See Vaultody.response_signature."""
        return self._core.response_signature

    @property
    def strict(self) -> bool:
        return self._core.strict

    async def _request(self, method, path, *, path_params=None, query=None, item=_NO_ITEM, context=None, retry=None):
        """Internal; see Vaultody._request."""
        call = make_call(method, path, path_params, query, item, context, retry)
        return (await run_async(self._core.request(call), self._perform)).result()

    def _paginate(self, method, path, *, path_params=None, query=None, cursor_field=None, paging="cursor", limit=None, max_limit=50, max_items=None, context=None, retry=None):
        """Internal; ``async for`` over the result. See Vaultody._paginate."""
        base_query = query_pairs(query)

        async def fetch_page(page_request):
            result = await self._request(method, path, path_params=path_params, query=paging_query(base_query, page_request), context=context, retry=retry)
            return page_for_pager(result)

        return AsyncPages(fetch_page, paging=paging, cursor_field=cursor_field, limit=limit, max_limit=max_limit, max_items=max_items)

    async def check_signing_key(self) -> Dict[str, Any]:
        """See Vaultody.check_signing_key."""
        return await run_async(self._core.signing_key_status(), self._perform)

    # -- the API methods (_resources.py) ------------------------------------------------------------

    async def _item(self, operation_id, params, context):
        """See Vaultody._item."""
        operation = OPERATION_BY_ID[operation_id]
        call = operation_call(operation, check_params(operation, params), check_context(context))
        return single_item((await run_async(self._core.request(call), self._perform)).result(), operation)

    def _list(self, operation_id, params, context, max_items):
        """See Vaultody._list; an async iterator."""
        operation = OPERATION_BY_ID[operation_id]
        checked = check_params(operation, params)
        check_context(context)
        options = paging_options(operation, checked, max_items)

        async def fetch_page(page_request):
            call = page_call(operation, checked, context, page_request)
            return page_for_pager((await run_async(self._core.request(call), self._perform)).result())

        return AsyncPages(fetch_page, **options)

    # -- effects ------------------------------------------------------------------------------------

    async def _sleep(self, seconds):
        hook = self._core.hooks.sleep
        if hook is not None:
            hook(seconds)
            await asyncio.sleep(0)
        elif seconds > 0:
            await asyncio.sleep(seconds)

    async def _perform(self, effect):
        if isinstance(effect, Send):
            return await self._send(effect)
        if isinstance(effect, StoreOp):
            return await asyncio.to_thread(getattr(self._core.vault_key_store, effect.name), *effect.args)
        if isinstance(effect, Acquire):
            with self._limiter_lock:
                wait = self._core.limiter.reserve(self._core.now())
            if wait > 0:
                await self._sleep(wait)
            return None
        if isinstance(effect, Sign):
            info = effect.signer
            if info.is_async:
                return await info.signer.sign(effect.data)
            result = await asyncio.to_thread(info.signer.sign, effect.data)
            return (await result) if inspect.isawaitable(result) else result
        if isinstance(effect, Sleep):
            await self._sleep(effect.seconds)
            return None
        raise TypeError("unknown effect {!r}".format(effect))

    async def _send(self, effect):
        request = self._http.build_request(effect.method, effect.url, headers=list(effect.headers), content=effect.body)
        try:
            response = await self._http.send(request, stream=True)
        except httpx.RequestError as error:
            return SendFailure(error)
        try:
            chunks = []
            size = 0
            async for chunk in response.aiter_bytes():
                size += len(chunk)
                if size > MAX_RESPONSE_BODY_BYTES:
                    return SendFailure(ValueError("the response is larger than 10 MiB"), too_large=True)
                chunks.append(chunk)
        except httpx.RequestError as error:
            return SendFailure(error)
        finally:
            await response.aclose()
        return RawResponse(response.status_code, Headers(response.headers.multi_items()), b"".join(chunks))


__all__ = ["AsyncVaultody"]
