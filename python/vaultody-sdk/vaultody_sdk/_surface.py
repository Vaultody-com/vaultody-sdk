"""What this SDK really exposes, for scripts/coverage.mjs.

The methods of the sync and the async client, found by walking real client instances, and the operation
table. A method counts only when it is bound to an operation, through its ``__vaultody_operation__``
attribute.

    python -I -m vaultody_sdk._surface

prints the surface as JSON. The clients are built with throwaway credentials and an in-memory pin store;
nothing is sent.
"""

import asyncio
import json
import sys

from ._operations import OPERATIONS
from ._version import API_VERSION, __version__


def client_methods(client):
    """``[{"namespace", "method", "operationId"}]`` for every bound API method of a client, sorted.

    :param client: a client instance whose attributes are the namespaces holding the API methods, or None
    """
    if client is None:
        return []
    methods = []
    for namespace in sorted(name for name in dir(client) if not name.startswith("_")):
        group = getattr(client, namespace)
        if group is None or isinstance(group, (str, bytes, int, float, bool)) or callable(group):
            continue
        for method in sorted(name for name in dir(group) if not name.startswith("_")):
            function = getattr(group, method)
            operation_id = getattr(function, "__vaultody_operation__", None)
            if callable(function) and isinstance(operation_id, str):
                methods.append({"namespace": namespace, "method": method, "operationId": operation_id})
    return methods


def operation_table():
    """The operation table as scripts/coverage.mjs reads it."""
    return [
        {
            "operationId": op.operation_id,
            "method": op.method,
            "path": op.path,
            "params": [{"name": param["name"], "in": param["in"], "required": param["required"]} for param in op.params],
        }
        for op in OPERATIONS
    ]


def describe_surface(sync_client=None, async_client=None):
    """The surface dump scripts/coverage.mjs reads."""
    return {
        "language": "python",
        "sdkVersion": __version__,
        "apiVersion": API_VERSION,
        "clients": {
            "python-sync": client_methods(sync_client),
            "python-async": client_methods(async_client),
        },
        "operations": operation_table(),
    }


def surface_clients():
    """A Vaultody and an AsyncVaultody to walk: throwaway credentials, memory pins, never used to send."""
    from . import AsyncVaultody, MemoryVaultKeyStore, Vaultody

    credentials = ("surface", "c3VyZmFjZQ==", "surface")
    return (
        Vaultody(*credentials, vault_key_store=MemoryVaultKeyStore()),
        AsyncVaultody(*credentials, vault_key_store=MemoryVaultKeyStore()),
    )


def main():
    sync_client, async_client = surface_clients()
    try:
        surface = describe_surface(sync_client, async_client)
    finally:
        sync_client.close()
        asyncio.run(async_client.aclose())
    json.dump(surface, sys.stdout, indent=2)
    sys.stdout.write("\n")


if __name__ == "__main__":
    main()
