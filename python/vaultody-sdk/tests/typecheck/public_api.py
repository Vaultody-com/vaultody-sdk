"""The public API as an application calls it, checked with ``mypy --strict`` in CI (the ``python-types`` job).

Not a pytest module and never run: it only has to type-check against the installed package. Each
``assert_type`` pins what a call returns; each ``# type: ignore[...]`` marks a call mypy must refuse, and
``--strict`` (``--warn-unused-ignores``) fails when it no longer does.
"""

from typing import Any, Dict, List

from typing_extensions import assert_type

from vaultody_sdk import (
    AsyncPages,
    AsyncVaultody,
    FileSigner,
    Item,
    MemoryVaultKeyStore,
    Page,
    Pages,
    ParameterError,
    ResponseMeta,
    Vaultody,
    models,
)


def sync_client() -> None:
    with Vaultody(
        "key", "secret", "passphrase", signer=FileSigner("private.pem"), vault_key_store=MemoryVaultKeyStore(),
        pinned_vault_keys=({"vaultId": "v1", "type": "main", "keys": {"ECDSA": "xpub...", "EDDSA": None}},),
        require_address_paths=True,
    ) as vaultody:
        assert_type(vaultody.response_signature, str)
        vaults = vaultody.vaults.list_vaults(networkType="main", limit=10)
        assert_type(vaults, Pages[models.ListVaultsItem])
        for vault in vaults:
            assert_type(vault, models.ListVaultsItem)
        for page in vaults.pages():
            assert_type(page, Page[models.ListVaultsItem])
            assert_type(page.items, List[models.ListVaultsItem])
            for result in page.meta.vault_keys:
                status: str = result["status"]
                outcome: str = result["outcome"]

        address = vaultody.assets_addresses.generate_deposit_address(
            vaultId="v", blockchain="bitcoin", network="mainnet", label="Alice", vaultAccountId="a", context="order-1",
        )
        assert_type(address, Item[models.GenerateDepositAddressResult])
        assert_type(address.meta, ResponseMeta)
        created: str = address.item["address"]

        transfer = vaultody.transactions.create_single_transfer(
            vaultId="v", vaultAccountId="a", assetId="asset", fromAddress=created, toAddress="to", amount="0.001",
            note="Payout 1", feePriority="standard",
        )
        assert_type(transfer.item.get("transactionRequestId"), str | None)

        vaultody.transactions.create_multiple_transfer(
            vaultId="v", vaultAccountId="a", assetId="asset", feePriority="fast", note="n",
            prepareStrategy="minimize-dust", recipients=[{"address": "to", "amount": "1"}],
        )
        vaultody.transactions.estimate_transaction_fee_by_asset_id(
            vaultId="v", vaultAccountId="a", transactionType="single", prepareStrategy="minimize_dust",
        )

        keys = vaultody.api_keys.list_api_key_signing_keys()
        assert_type(keys, Pages[models.ApiKeySigningKey])

        # What mypy must refuse: a value outside the documented list, an undocumented argument, a
        # missing required one, an amount that is not a string, and a parameter on the signing-keys list.
        vaultody.vaults.list_vaults(networkType="MAIN")  # type: ignore[arg-type]
        vaultody.vaults.list_vaults(networkType="main", offset=0)  # type: ignore[call-arg]
        vaultody.vaults.list_vaults()  # type: ignore[call-arg]
        vaultody.transactions.create_multiple_transfer(
            vaultId="v", vaultAccountId="a", assetId="asset", feePriority="fast", note="n",
            prepareStrategy="minimize_dust", recipients=[],  # type: ignore[arg-type]
        )
        vaultody.transactions.create_single_transfer(
            vaultId="v", vaultAccountId="a", assetId="asset", fromAddress="f", toAddress="t", note="n",
            amount=0.001,  # type: ignore[arg-type]
        )
        vaultody.api_keys.list_api_key_signing_keys(limit=2)  # type: ignore[call-arg]
    Vaultody("key", "secret", "passphrase", require_address_paths="yes")  # type: ignore[arg-type]


async def async_client() -> None:
    pinned = [{"vaultId": "v1", "type": "main", "keys": {"ECDSA": "xpub...", "EDDSA": None}}]
    async with AsyncVaultody("key", "secret", "passphrase", pinned_vault_keys=pinned, require_address_paths=False) as vaultody:
        assert_type(vaultody.response_signature, str)
        vaults = vaultody.vaults.list_vaults(networkType="test")
        assert_type(vaults, AsyncPages[models.ListVaultsItem])
        async for vault in vaults:
            assert_type(vault, models.ListVaultsItem)

        account = await vaultody.vault_accounts.get_vault_account_by_id(vaultId="v", vaultAccountId="a")
        assert_type(account, Item[models.GetVaultAccountByIdResult])

        try:
            request = await vaultody.transactions.get_transaction_request_details(transactionRequestId="t")
            assert_type(request, Item[models.GetTransactionRequestDetailsResult])
        except ParameterError:
            pass

        key_check = await vaultody.check_signing_key()
        assert_type(key_check, Dict[str, Any])
