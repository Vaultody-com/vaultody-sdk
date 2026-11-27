"""The surface scripts/coverage.mjs reads, and the pinned API version."""

import asyncio
import json
import re
import subprocess
import sys

import vaultody_sdk
import vaultody_verify
from vaultody_sdk._surface import client_methods, describe_surface, surface_clients

from sdk_vectors import ROOT


def test_pins_the_api_version_of_the_published_contract():
    contract = json.loads((ROOT / "contract" / "openapi.json").read_text(encoding="utf-8"))
    assert vaultody_sdk.API_VERSION == contract["info"]["version"] == "2026-03-20"


def test_carries_the_one_version_number_of_the_repository():
    # Python carries the PEP 440 form of VERSION: 0.9.0-rc.1 is 0.9.0rc1 (scripts/version.mjs).
    version = re.sub(r"-rc\.(\d+)$", r"rc\1", (ROOT / "VERSION").read_text(encoding="utf-8").strip())
    assert vaultody_sdk.__version__ == version
    assert vaultody_verify.__version__ == version


def test_describes_a_client_by_walking_it():
    class Vaults:
        def list_vaults(self, params=None):
            return params

        list_vaults.__vaultody_operation__ = "listVaults"

        def helper(self):
            return None

    class Transactions:
        async def create_single_transfer(self, params=None):
            return params

        create_single_transfer.__vaultody_operation__ = "createSingleTransfer"

    class Client:
        version = "1"

        def __init__(self):
            self.vaults = Vaults()
            self.transactions = Transactions()

    assert client_methods(Client()) == [
        {"namespace": "transactions", "method": "create_single_transfer", "operationId": "createSingleTransfer"},
        {"namespace": "vaults", "method": "list_vaults", "operationId": "listVaults"},
    ]


def test_both_clients_have_every_operation_of_the_table():
    sync_client, async_client = surface_clients()
    try:
        surface = describe_surface(sync_client, async_client)
    finally:
        sync_client.close()
        asyncio.run(async_client.aclose())
    assert surface["language"] == "python"
    table = sorted(entry["operationId"] for entry in surface["operations"])
    assert len(table) == 32
    for target in ("python-sync", "python-async"):
        assert sorted(method["operationId"] for method in surface["clients"][target]) == table
    entry = next(entry for entry in surface["operations"] if entry["operationId"] == "createSingleTransfer")
    assert entry["method"] == "POST" and entry["path"] == "/vaults/{vaultId}/transaction-requests/single-transfer"
    assert {"name": "vaultId", "in": "path", "required": True} in entry["params"]
    assert {"name": "feeInput", "in": "body", "required": False} in entry["params"]


def test_the_module_prints_the_surface():
    out = subprocess.run([sys.executable, "-I", "-m", "vaultody_sdk._surface"], check=True, capture_output=True, text=True).stdout
    sync_client, async_client = surface_clients()
    try:
        assert json.loads(out) == describe_surface(sync_client, async_client)
    finally:
        sync_client.close()
        asyncio.run(async_client.aclose())


def test_no_public_call_bypasses_the_operation_checks():
    """Only the API methods send requests: the low-level calls of any path are internal."""
    sync_client, async_client = surface_clients()
    try:
        for client in (sync_client, async_client):
            assert not hasattr(client, "request") and not hasattr(client, "paginate")
            assert callable(client._request) and callable(client._paginate)
    finally:
        sync_client.close()
        asyncio.run(async_client.aclose())
    assert "request" not in vaultody_sdk.__all__
