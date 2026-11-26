"""The API methods: one per documented operation, grouped as the docs group them.

``client.vaults``, ``client.vault_accounts``, ``client.assets_addresses``, ``client.transactions`` and
``client.api_keys``; each method is the docs operationId in snake_case (``createSingleTransfer`` →
``client.transactions.create_single_transfer``). Every method is a one-liner into the operation table
(_operations.py), the single definition of each operation both clients use; the sync and the async classes
differ only in ``async``/``await``.

Arguments are keyword arguments with the API's own field names, path, query and body fields together
(``vaultId=...``, ``feePriority=...``): the table places each one. They are checked against the request
model (models.py) before anything is sent. Two keyword arguments are not API fields: ``context``, your own
value echoed back in the answer, and, for lists, ``max_items``.

A single item comes back as ``Item`` (``.item``, ``.meta``). A list comes back as ``Pages`` (sync) or
``AsyncPages`` (``async for``): iterating it fetches page after page, each one signed, verified and
checked like any call; ``.pages()`` gives the pages themselves, with their ``meta``.
"""

from __future__ import annotations

import sys
from typing import TYPE_CHECKING, Any, Callable, Optional, TypeVar

from . import models as m
from ._core import Item
from .pagination import AsyncPages, Pages

if sys.version_info >= (3, 11):
    from typing import Unpack
elif TYPE_CHECKING:  # pragma: no cover - read by type checkers only, never imported at run time
    from typing_extensions import Unpack

if TYPE_CHECKING:
    from ._async_client import AsyncVaultody
    from ._client import Vaultody

_F = TypeVar("_F", bound=Callable[..., Any])


def _binds(operation_id: str) -> Callable[[_F], _F]:
    """Marks a method as the one for ``operation_id``; scripts/coverage.mjs finds methods by this mark."""

    def mark(function: _F) -> _F:
        function.__vaultody_operation__ = operation_id  # type: ignore[attr-defined]
        return function

    return mark


class _Namespace:
    __slots__ = ("_client",)

    def __init__(self, client: Any) -> None:
        self._client = client

    def __repr__(self) -> str:
        return "<vaultody_sdk {} of {!r}>".format(type(self).__name__, self._client)


# ===================================================================================================
# Vaultody (sync)
# ===================================================================================================


class Vaults(_Namespace):
    """The Vaults docs group."""

    _client: Vaultody

    @_binds("listVaults")
    def list_vaults(self, *, context: Optional[str] = None, max_items: Optional[int] = None, **params: Unpack[m.ListVaultsParams]) -> Pages[m.ListVaultsItem]:
        """List Vaults: your main or test Vaults (``GET /vaults/{networkType}``). Every page is compared with
        the pinned vault xpubs."""
        return self._client._list("listVaults", params, context, max_items)

    @_binds("listVaultsByAssetId")
    def list_vaults_by_asset_id(self, *, context: Optional[str] = None, **params: Unpack[m.ListVaultsByAssetIdParams]) -> Item[m.ListVaultsByAssetIdResult]:
        """List Vaults by Asset ID: how much of one asset each Vault holds
        (``GET /assets/{assetId}/{blockchain}/vaults/{networkType}``)."""
        return self._client._item("listVaultsByAssetId", params, context)

    @_binds("listAssetsByVault")
    def list_assets_by_vault(self, *, context: Optional[str] = None, **params: Unpack[m.ListAssetsByVaultParams]) -> Item[m.ListAssetsByVaultResult]:
        """List Assets by Vault (``GET /vaults/{vaultId}/assets``)."""
        return self._client._item("listAssetsByVault", params, context)

    @_binds("listTransactionsByVault")
    def list_transactions_by_vault(self, *, context: Optional[str] = None, max_items: Optional[int] = None, **params: Unpack[m.ListTransactionsByVaultParams]) -> Pages[m.ListTransactionsByVaultItem]:
        """List Transactions by Vault (``GET /vaults/{vaultId}/transactions``)."""
        return self._client._list("listTransactionsByVault", params, context, max_items)


class VaultAccounts(_Namespace):
    """The Vault Accounts docs group."""

    _client: Vaultody

    @_binds("createVaultAccount")
    def create_vault_account(self, *, context: Optional[str] = None, **params: Unpack[m.CreateVaultAccountParams]) -> Item[m.CreateVaultAccountResult]:
        """Create Vault Account (``POST /vaults/{vaultId}/vault-account``). A write: never sent twice."""
        return self._client._item("createVaultAccount", params, context)

    @_binds("listVaultAccounts")
    def list_vault_accounts(self, *, context: Optional[str] = None, max_items: Optional[int] = None, **params: Unpack[m.ListVaultAccountsParams]) -> Pages[m.ListVaultAccountsItem]:
        """List Vault Accounts (``GET /vaults/{vaultId}/vault-accounts/details``)."""
        return self._client._list("listVaultAccounts", params, context, max_items)

    @_binds("getVaultAccountById")
    def get_vault_account_by_id(self, *, context: Optional[str] = None, **params: Unpack[m.GetVaultAccountByIdParams]) -> Item[m.GetVaultAccountByIdResult]:
        """Get Vault Account by ID (``GET /vaults/{vaultId}/vault-accounts/{vaultAccountId}/details``)."""
        return self._client._item("getVaultAccountById", params, context)

    @_binds("updateVaultAccount")
    def update_vault_account(self, *, context: Optional[str] = None, **params: Unpack[m.UpdateVaultAccountParams]) -> Item[m.UpdateVaultAccountResult]:
        """Update Vault Account (``PUT /vaults/{vaultId}/vault-accounts/{vaultAccountId}/edit``)."""
        return self._client._item("updateVaultAccount", params, context)

    @_binds("addAssetToVaultAccount")
    def add_asset_to_vault_account(self, *, context: Optional[str] = None, **params: Unpack[m.AddAssetToVaultAccountParams]) -> Item[m.AddAssetToVaultAccountResult]:
        """Add Asset to Vault Account (``PUT /vaults/{vaultId}/vault-accounts/{vaultAccountId}/add-asset``).
        With ``address``, the answer must name that address; with ``label``, the new address is checked
        against the vault's pinned xpub (``meta.address_checks``)."""
        return self._client._item("addAssetToVaultAccount", params, context)

    @_binds("listAssetsByVaultAccountId")
    def list_assets_by_vault_account_id(self, *, context: Optional[str] = None, max_items: Optional[int] = None, **params: Unpack[m.ListAssetsByVaultAccountIdParams]) -> Pages[m.ListAssetsByVaultAccountIdItem]:
        """List Assets by Vault Account ID (``GET /vaults/{vaultId}/vault-accounts/{vaultAccountId}/list-assets``)."""
        return self._client._list("listAssetsByVaultAccountId", params, context, max_items)

    @_binds("listTransactionsByVaultAccount")
    def list_transactions_by_vault_account(self, *, context: Optional[str] = None, max_items: Optional[int] = None, **params: Unpack[m.ListTransactionsByVaultAccountParams]) -> Pages[m.ListTransactionsByVaultAccountItem]:
        """List Transactions by Vault Account (``GET /vaults/{vaultId}/vault-accounts/{vaultAccountId}/transactions``)."""
        return self._client._list("listTransactionsByVaultAccount", params, context, max_items)


class AssetsAddresses(_Namespace):
    """The Assets & Addresses docs group."""

    _client: Vaultody

    @_binds("generateDepositAddress")
    def generate_deposit_address(self, *, context: Optional[str] = None, **params: Unpack[m.GenerateDepositAddressParams]) -> Item[m.GenerateDepositAddressResult]:
        """Generate Deposit Address (``POST /vaults/{vaultId}/{blockchain}/{network}/addresses``). The address
        is checked against the vault's pinned xpub (``meta.address_checks``); a mismatch raises."""
        return self._client._item("generateDepositAddress", params, context)

    @_binds("getAddressBalance")
    def get_address_balance(self, *, context: Optional[str] = None, max_items: Optional[int] = None, **params: Unpack[m.GetAddressBalanceParams]) -> Pages[m.GetAddressBalanceItem]:
        """Get Address Balance (``GET /vaults/{vaultId}/addresses/{address}/balance``). Its cursor field is not
        documented, so it is not paged past one page: PaginationError ``cursor_unknown`` when there is more."""
        return self._client._list("getAddressBalance", params, context, max_items)

    @_binds("listAddressesByVaultAccountId")
    def list_addresses_by_vault_account_id(self, *, context: Optional[str] = None, max_items: Optional[int] = None, **params: Unpack[m.ListAddressesByVaultAccountIdParams]) -> Pages[m.ListAddressesByVaultAccountIdItem]:
        """List Addresses by Vault Account ID (``GET /vaults/{vaultId}/vault-accounts/{vaultAccountId}/list-addresses``).
        Every address of every page is checked against the vault's pinned xpub (``.pages()`` → ``meta.address_checks``)."""
        return self._client._list("listAddressesByVaultAccountId", params, context, max_items)

    @_binds("listSupportedAssets")
    def list_supported_assets(self, *, context: Optional[str] = None, max_items: Optional[int] = None, **params: Unpack[m.ListSupportedAssetsParams]) -> Pages[m.ListSupportedAssetsItem]:
        """List Supported Assets (``GET /supported-assets``)."""
        return self._client._list("listSupportedAssets", params, context, max_items)

    @_binds("validateAddress")
    def validate_address(self, *, context: Optional[str] = None, **params: Unpack[m.ValidateAddressParams]) -> Item[m.ValidateAddressResult]:
        """Validate Address (``POST /info/{blockchain}/{network}/addresses/validate``). Changes nothing, so it
        is retried like a read."""
        return self._client._item("validateAddress", params, context)

    @_binds("encodeXrpAddress")
    def encode_xrp_address(self, *, context: Optional[str] = None, **params: Unpack[m.EncodeXrpAddressParams]) -> Item[m.EncodeXrpAddressResult]:
        """Encode XRP Address (``GET /utils/xrp/{network}/addresses/encode/{classicAddress}/{addressTag}``)."""
        return self._client._item("encodeXrpAddress", params, context)

    @_binds("decodeXrpAddress")
    def decode_xrp_address(self, *, context: Optional[str] = None, **params: Unpack[m.DecodeXrpAddressParams]) -> Item[m.DecodeXrpAddressResult]:
        """Decode XRP Address (``GET /utils/xrp/{network}/addresses/decode/{xAddress}``)."""
        return self._client._item("decodeXrpAddress", params, context)

    @_binds("tronResourceOverview")
    def tron_resource_overview(self, *, context: Optional[str] = None, **params: Unpack[m.TronResourceOverviewParams]) -> Item[m.TronResourceOverviewResult]:
        """Tron Resource Overview (``GET /vaults/{vaultId}/{blockchain}/{network}/{address}/overview``)."""
        return self._client._item("tronResourceOverview", params, context)

    @_binds("tronResourceManagement")
    def tron_resource_management(self, *, context: Optional[str] = None, **params: Unpack[m.TronResourceManagementParams]) -> Item[m.TronResourceManagementResult]:
        """Tron Resource Management
        (``POST /vaults/{vaultId}/{blockchain}/{network}/addresses/{fromAddress}/manage-resource``). A write."""
        return self._client._item("tronResourceManagement", params, context)


class Transactions(_Namespace):
    """The Transactions docs group."""

    _client: Vaultody

    @_binds("createSingleTransfer")
    def create_single_transfer(self, *, context: Optional[str] = None, **params: Unpack[m.CreateSingleTransferParams]) -> Item[m.CreateSingleTransferResult]:
        """Create Single Transfer (``POST /vaults/{vaultId}/transaction-requests/single-transfer``). A write:
        never signed twice; RequestOutcomeUnknownError when its outcome can't be learned."""
        return self._client._item("createSingleTransfer", params, context)

    @_binds("createMultipleTransfer")
    def create_multiple_transfer(self, *, context: Optional[str] = None, **params: Unpack[m.CreateMultipleTransferParams]) -> Item[m.CreateMultipleTransferResult]:
        """Create Multiple Transfer (``POST /vaults/{vaultId}/transaction-requests/multiple-transfer``). A write."""
        return self._client._item("createMultipleTransfer", params, context)

    @_binds("createUtxoTransfer")
    def create_utxo_transfer(self, *, context: Optional[str] = None, **params: Unpack[m.CreateUtxoTransferParams]) -> Item[m.CreateUtxoTransferResult]:
        """Create UTXO Transfer (``POST /vaults/{vaultId}/transaction-requests/utxo-transfer``). A write."""
        return self._client._item("createUtxoTransfer", params, context)

    @_binds("validateUtxoTransfer")
    def validate_utxo_transfer(self, *, context: Optional[str] = None, **params: Unpack[m.ValidateUtxoTransferParams]) -> Item[m.ValidateUtxoTransferResult]:
        """Validate UTXO Transfer (``POST /vaults/{vaultId}/transaction-requests/utxo-transfer/validate``): a dry
        run that creates nothing, retried like a read."""
        return self._client._item("validateUtxoTransfer", params, context)

    @_binds("createBatchTransactionRequest")
    def create_batch_transaction_request(self, *, context: Optional[str] = None, **params: Unpack[m.CreateBatchTransactionRequestParams]) -> Item[m.CreateBatchTransactionRequestResult]:
        """Create Batch Transaction Request (``POST /vaults/{vaultId}/transaction-requests/batch``). A write."""
        return self._client._item("createBatchTransactionRequest", params, context)

    @_binds("gasSponsorshipTransfer")
    def gas_sponsorship_transfer(self, *, context: Optional[str] = None, **params: Unpack[m.GasSponsorshipTransferParams]) -> Item[m.GasSponsorshipTransferResult]:
        """Gas Sponsorship Transfer (``POST /vaults/{vaultId}/transaction-requests/gas-sponsorship-transfer``). A write."""
        return self._client._item("gasSponsorshipTransfer", params, context)

    @_binds("createTronContractInteractionRequest")
    def create_tron_contract_interaction_request(self, *, context: Optional[str] = None, **params: Unpack[m.CreateTronContractInteractionRequestParams]) -> Item[m.CreateTronContractInteractionRequestResult]:
        """Create Tron Contract Interaction Request (``POST /vaults/{vaultId}/transaction-requests/contract-interaction``). A write."""
        return self._client._item("createTronContractInteractionRequest", params, context)

    @_binds("estimateTransactionFeeByAssetId")
    def estimate_transaction_fee_by_asset_id(self, *, context: Optional[str] = None, **params: Unpack[m.EstimateTransactionFeeByAssetIdParams]) -> Item[m.EstimateTransactionFeeByAssetIdResult]:
        """Estimate Transaction Fee by Asset ID (``POST /vaults/{vaultId}/approximate-fee``). Changes nothing,
        so it is retried like a read."""
        return self._client._item("estimateTransactionFeeByAssetId", params, context)

    @_binds("getTransactionDetails")
    def get_transaction_details(self, *, context: Optional[str] = None, **params: Unpack[m.GetTransactionDetailsParams]) -> Item[m.GetTransactionDetailsResult]:
        """Get Transaction Details (``GET /vaults/{vaultId}/{blockchain}/transactions/{transactionId}``)."""
        return self._client._item("getTransactionDetails", params, context)

    @_binds("getTransactionRequestDetails")
    def get_transaction_request_details(self, *, context: Optional[str] = None, **params: Unpack[m.GetTransactionRequestDetailsParams]) -> Item[m.GetTransactionRequestDetailsResult]:
        """Get Transaction Request Details (``GET /transaction-requests/{transactionRequestId}``)."""
        return self._client._item("getTransactionRequestDetails", params, context)

    @_binds("listUtxos")
    def list_utxos(self, *, context: Optional[str] = None, max_items: Optional[int] = None, **params: Unpack[m.ListUtxosParams]) -> Pages[m.ListUtxosItem]:
        """List UTXOs (``GET /vaults/{vaultId}/utxos``)."""
        return self._client._list("listUtxos", params, context, max_items)


class ApiKeys(_Namespace):
    """The API Keys docs group (documented, not on production yet)."""

    _client: Vaultody

    @_binds("listApiKeySigningKeys")
    def list_api_key_signing_keys(self, *, context: Optional[str] = None, max_items: Optional[int] = None, **params: Unpack[m.ListApiKeySigningKeysParams]) -> Pages[m.ApiKeySigningKey]:
        """List API Key Signing Keys (``GET /api-keys/current/signing-keys``): the public keys registered for
        request signing on the calling API key. Takes no parameter. Compare each fingerprint with your own
        only when the answer's signature verified; ``check_signing_key()`` does both."""
        return self._client._list("listApiKeySigningKeys", params, context, max_items)


# ===================================================================================================
# AsyncVaultody: the same methods; the single-item ones are coroutines, the lists are async iterators
# ===================================================================================================


class AsyncVaults(_Namespace):
    """The Vaults docs group."""

    _client: AsyncVaultody

    @_binds("listVaults")
    def list_vaults(self, *, context: Optional[str] = None, max_items: Optional[int] = None, **params: Unpack[m.ListVaultsParams]) -> AsyncPages[m.ListVaultsItem]:
        """See Vaults.list_vaults; ``async for`` over the result."""
        return self._client._list("listVaults", params, context, max_items)

    @_binds("listVaultsByAssetId")
    async def list_vaults_by_asset_id(self, *, context: Optional[str] = None, **params: Unpack[m.ListVaultsByAssetIdParams]) -> Item[m.ListVaultsByAssetIdResult]:
        """See Vaults.list_vaults_by_asset_id."""
        return await self._client._item("listVaultsByAssetId", params, context)

    @_binds("listAssetsByVault")
    async def list_assets_by_vault(self, *, context: Optional[str] = None, **params: Unpack[m.ListAssetsByVaultParams]) -> Item[m.ListAssetsByVaultResult]:
        """See Vaults.list_assets_by_vault."""
        return await self._client._item("listAssetsByVault", params, context)

    @_binds("listTransactionsByVault")
    def list_transactions_by_vault(self, *, context: Optional[str] = None, max_items: Optional[int] = None, **params: Unpack[m.ListTransactionsByVaultParams]) -> AsyncPages[m.ListTransactionsByVaultItem]:
        """See Vaults.list_transactions_by_vault."""
        return self._client._list("listTransactionsByVault", params, context, max_items)


class AsyncVaultAccounts(_Namespace):
    """The Vault Accounts docs group."""

    _client: AsyncVaultody

    @_binds("createVaultAccount")
    async def create_vault_account(self, *, context: Optional[str] = None, **params: Unpack[m.CreateVaultAccountParams]) -> Item[m.CreateVaultAccountResult]:
        """See VaultAccounts.create_vault_account."""
        return await self._client._item("createVaultAccount", params, context)

    @_binds("listVaultAccounts")
    def list_vault_accounts(self, *, context: Optional[str] = None, max_items: Optional[int] = None, **params: Unpack[m.ListVaultAccountsParams]) -> AsyncPages[m.ListVaultAccountsItem]:
        """See VaultAccounts.list_vault_accounts."""
        return self._client._list("listVaultAccounts", params, context, max_items)

    @_binds("getVaultAccountById")
    async def get_vault_account_by_id(self, *, context: Optional[str] = None, **params: Unpack[m.GetVaultAccountByIdParams]) -> Item[m.GetVaultAccountByIdResult]:
        """See VaultAccounts.get_vault_account_by_id."""
        return await self._client._item("getVaultAccountById", params, context)

    @_binds("updateVaultAccount")
    async def update_vault_account(self, *, context: Optional[str] = None, **params: Unpack[m.UpdateVaultAccountParams]) -> Item[m.UpdateVaultAccountResult]:
        """See VaultAccounts.update_vault_account."""
        return await self._client._item("updateVaultAccount", params, context)

    @_binds("addAssetToVaultAccount")
    async def add_asset_to_vault_account(self, *, context: Optional[str] = None, **params: Unpack[m.AddAssetToVaultAccountParams]) -> Item[m.AddAssetToVaultAccountResult]:
        """See VaultAccounts.add_asset_to_vault_account."""
        return await self._client._item("addAssetToVaultAccount", params, context)

    @_binds("listAssetsByVaultAccountId")
    def list_assets_by_vault_account_id(self, *, context: Optional[str] = None, max_items: Optional[int] = None, **params: Unpack[m.ListAssetsByVaultAccountIdParams]) -> AsyncPages[m.ListAssetsByVaultAccountIdItem]:
        """See VaultAccounts.list_assets_by_vault_account_id."""
        return self._client._list("listAssetsByVaultAccountId", params, context, max_items)

    @_binds("listTransactionsByVaultAccount")
    def list_transactions_by_vault_account(self, *, context: Optional[str] = None, max_items: Optional[int] = None, **params: Unpack[m.ListTransactionsByVaultAccountParams]) -> AsyncPages[m.ListTransactionsByVaultAccountItem]:
        """See VaultAccounts.list_transactions_by_vault_account."""
        return self._client._list("listTransactionsByVaultAccount", params, context, max_items)


class AsyncAssetsAddresses(_Namespace):
    """The Assets & Addresses docs group."""

    _client: AsyncVaultody

    @_binds("generateDepositAddress")
    async def generate_deposit_address(self, *, context: Optional[str] = None, **params: Unpack[m.GenerateDepositAddressParams]) -> Item[m.GenerateDepositAddressResult]:
        """See AssetsAddresses.generate_deposit_address."""
        return await self._client._item("generateDepositAddress", params, context)

    @_binds("getAddressBalance")
    def get_address_balance(self, *, context: Optional[str] = None, max_items: Optional[int] = None, **params: Unpack[m.GetAddressBalanceParams]) -> AsyncPages[m.GetAddressBalanceItem]:
        """See AssetsAddresses.get_address_balance."""
        return self._client._list("getAddressBalance", params, context, max_items)

    @_binds("listAddressesByVaultAccountId")
    def list_addresses_by_vault_account_id(self, *, context: Optional[str] = None, max_items: Optional[int] = None, **params: Unpack[m.ListAddressesByVaultAccountIdParams]) -> AsyncPages[m.ListAddressesByVaultAccountIdItem]:
        """See AssetsAddresses.list_addresses_by_vault_account_id."""
        return self._client._list("listAddressesByVaultAccountId", params, context, max_items)

    @_binds("listSupportedAssets")
    def list_supported_assets(self, *, context: Optional[str] = None, max_items: Optional[int] = None, **params: Unpack[m.ListSupportedAssetsParams]) -> AsyncPages[m.ListSupportedAssetsItem]:
        """See AssetsAddresses.list_supported_assets."""
        return self._client._list("listSupportedAssets", params, context, max_items)

    @_binds("validateAddress")
    async def validate_address(self, *, context: Optional[str] = None, **params: Unpack[m.ValidateAddressParams]) -> Item[m.ValidateAddressResult]:
        """See AssetsAddresses.validate_address."""
        return await self._client._item("validateAddress", params, context)

    @_binds("encodeXrpAddress")
    async def encode_xrp_address(self, *, context: Optional[str] = None, **params: Unpack[m.EncodeXrpAddressParams]) -> Item[m.EncodeXrpAddressResult]:
        """See AssetsAddresses.encode_xrp_address."""
        return await self._client._item("encodeXrpAddress", params, context)

    @_binds("decodeXrpAddress")
    async def decode_xrp_address(self, *, context: Optional[str] = None, **params: Unpack[m.DecodeXrpAddressParams]) -> Item[m.DecodeXrpAddressResult]:
        """See AssetsAddresses.decode_xrp_address."""
        return await self._client._item("decodeXrpAddress", params, context)

    @_binds("tronResourceOverview")
    async def tron_resource_overview(self, *, context: Optional[str] = None, **params: Unpack[m.TronResourceOverviewParams]) -> Item[m.TronResourceOverviewResult]:
        """See AssetsAddresses.tron_resource_overview."""
        return await self._client._item("tronResourceOverview", params, context)

    @_binds("tronResourceManagement")
    async def tron_resource_management(self, *, context: Optional[str] = None, **params: Unpack[m.TronResourceManagementParams]) -> Item[m.TronResourceManagementResult]:
        """See AssetsAddresses.tron_resource_management."""
        return await self._client._item("tronResourceManagement", params, context)


class AsyncTransactions(_Namespace):
    """The Transactions docs group."""

    _client: AsyncVaultody

    @_binds("createSingleTransfer")
    async def create_single_transfer(self, *, context: Optional[str] = None, **params: Unpack[m.CreateSingleTransferParams]) -> Item[m.CreateSingleTransferResult]:
        """See Transactions.create_single_transfer."""
        return await self._client._item("createSingleTransfer", params, context)

    @_binds("createMultipleTransfer")
    async def create_multiple_transfer(self, *, context: Optional[str] = None, **params: Unpack[m.CreateMultipleTransferParams]) -> Item[m.CreateMultipleTransferResult]:
        """See Transactions.create_multiple_transfer."""
        return await self._client._item("createMultipleTransfer", params, context)

    @_binds("createUtxoTransfer")
    async def create_utxo_transfer(self, *, context: Optional[str] = None, **params: Unpack[m.CreateUtxoTransferParams]) -> Item[m.CreateUtxoTransferResult]:
        """See Transactions.create_utxo_transfer."""
        return await self._client._item("createUtxoTransfer", params, context)

    @_binds("validateUtxoTransfer")
    async def validate_utxo_transfer(self, *, context: Optional[str] = None, **params: Unpack[m.ValidateUtxoTransferParams]) -> Item[m.ValidateUtxoTransferResult]:
        """See Transactions.validate_utxo_transfer."""
        return await self._client._item("validateUtxoTransfer", params, context)

    @_binds("createBatchTransactionRequest")
    async def create_batch_transaction_request(self, *, context: Optional[str] = None, **params: Unpack[m.CreateBatchTransactionRequestParams]) -> Item[m.CreateBatchTransactionRequestResult]:
        """See Transactions.create_batch_transaction_request."""
        return await self._client._item("createBatchTransactionRequest", params, context)

    @_binds("gasSponsorshipTransfer")
    async def gas_sponsorship_transfer(self, *, context: Optional[str] = None, **params: Unpack[m.GasSponsorshipTransferParams]) -> Item[m.GasSponsorshipTransferResult]:
        """See Transactions.gas_sponsorship_transfer."""
        return await self._client._item("gasSponsorshipTransfer", params, context)

    @_binds("createTronContractInteractionRequest")
    async def create_tron_contract_interaction_request(self, *, context: Optional[str] = None, **params: Unpack[m.CreateTronContractInteractionRequestParams]) -> Item[m.CreateTronContractInteractionRequestResult]:
        """See Transactions.create_tron_contract_interaction_request."""
        return await self._client._item("createTronContractInteractionRequest", params, context)

    @_binds("estimateTransactionFeeByAssetId")
    async def estimate_transaction_fee_by_asset_id(self, *, context: Optional[str] = None, **params: Unpack[m.EstimateTransactionFeeByAssetIdParams]) -> Item[m.EstimateTransactionFeeByAssetIdResult]:
        """See Transactions.estimate_transaction_fee_by_asset_id."""
        return await self._client._item("estimateTransactionFeeByAssetId", params, context)

    @_binds("getTransactionDetails")
    async def get_transaction_details(self, *, context: Optional[str] = None, **params: Unpack[m.GetTransactionDetailsParams]) -> Item[m.GetTransactionDetailsResult]:
        """See Transactions.get_transaction_details."""
        return await self._client._item("getTransactionDetails", params, context)

    @_binds("getTransactionRequestDetails")
    async def get_transaction_request_details(self, *, context: Optional[str] = None, **params: Unpack[m.GetTransactionRequestDetailsParams]) -> Item[m.GetTransactionRequestDetailsResult]:
        """See Transactions.get_transaction_request_details."""
        return await self._client._item("getTransactionRequestDetails", params, context)

    @_binds("listUtxos")
    def list_utxos(self, *, context: Optional[str] = None, max_items: Optional[int] = None, **params: Unpack[m.ListUtxosParams]) -> AsyncPages[m.ListUtxosItem]:
        """See Transactions.list_utxos."""
        return self._client._list("listUtxos", params, context, max_items)


class AsyncApiKeys(_Namespace):
    """The API Keys docs group (documented, not on production yet)."""

    _client: AsyncVaultody

    @_binds("listApiKeySigningKeys")
    def list_api_key_signing_keys(self, *, context: Optional[str] = None, max_items: Optional[int] = None, **params: Unpack[m.ListApiKeySigningKeysParams]) -> AsyncPages[m.ApiKeySigningKey]:
        """See ApiKeys.list_api_key_signing_keys."""
        return self._client._list("listApiKeySigningKeys", params, context, max_items)


__all__ = [
    "ApiKeys",
    "AssetsAddresses",
    "AsyncApiKeys",
    "AsyncAssetsAddresses",
    "AsyncTransactions",
    "AsyncVaultAccounts",
    "AsyncVaults",
    "Transactions",
    "VaultAccounts",
    "Vaults",
]
