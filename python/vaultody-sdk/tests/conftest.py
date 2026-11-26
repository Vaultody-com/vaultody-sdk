"""Fixtures that run one scenario through both clients.

A scenario is written once, as ``async def scenario(api)``; ``api`` calls the sync Vaultody directly or
awaits AsyncVaultody, so every client test runs the same steps on both.
"""

import asyncio

import pytest

from vaultody_sdk import AsyncVaultody, MemoryVaultKeyStore, Vaultody
from vaultody_sdk._core import Hooks

from mock_gateway import API_KEY, API_SECRET, ORIGIN, PASSPHRASE, PINNED_ROOTS, FakeClock, MockGateway, Nonces


class Api:
    """One client behind awaitable methods, whichever kind it is."""

    def __init__(self, client):
        self.client = client
        self.is_async = isinstance(client, AsyncVaultody)

    async def _call(self, name, *args, **kwargs):
        result = getattr(self.client, name)(*args, **kwargs)
        return (await result) if self.is_async else result

    async def request(self, *args, **kwargs):
        """The client's internal _request(): any path, without the operation table's checks."""
        return await self._call("_request", *args, **kwargs)

    async def check_signing_key(self):
        return await self._call("check_signing_key")

    async def collect(self, pages):
        if self.is_async:
            return [item async for item in pages]
        return list(pages)

    async def close(self):
        if self.is_async:
            await self.client.aclose()
        else:
            self.client.close()


def make_client(kind, gateway=None, *, clock=None, store=None, hooks=None, credentials=None, **options):
    """A Vaultody or AsyncVaultody talking to ``gateway`` with a fake clock and memory pins."""
    clock = clock or (gateway.clock if gateway is not None else FakeClock())
    if hooks is None:
        hooks = Hooks(clock=clock, sleep=clock.sleep, random=lambda: 0.5, nonce=Nonces())
    options.setdefault("roots", PINNED_ROOTS)
    options.setdefault("base_url", ORIGIN)
    options.setdefault("max_requests_per_second", 1000)
    if gateway is not None:
        options.setdefault("transport", gateway.transport())
    cls = Vaultody if kind == "sync" else AsyncVaultody
    api_key, api_secret, passphrase = credentials or (API_KEY, API_SECRET, PASSPHRASE)
    return cls(api_key, api_secret, passphrase, vault_key_store=store if store is not None else MemoryVaultKeyStore(), _hooks=hooks, **options)


def run(kind, client, scenario):
    """Runs ``scenario(api)`` on the client and closes it."""

    async def main():
        api = Api(client)
        try:
            return await scenario(api)
        finally:
            await api.close()

    return asyncio.run(main())


@pytest.fixture(params=["sync", "async"])
def kind(request):
    return request.param


@pytest.fixture
def clock():
    return FakeClock()


@pytest.fixture
def gateway(clock):
    return MockGateway(clock)
