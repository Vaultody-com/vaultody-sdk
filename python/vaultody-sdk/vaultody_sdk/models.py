"""The request and response models of every API method: ``TypedDict``s with the API's own field names.

Written by hand from the published OpenAPI document (contract/openapi.json, and contract/pending/ for
listApiKeySigningKeys); tests/test_models.py compares every model, field by field and type by type, with
that document, so a model can't drift from it unnoticed.

- ``<Operation>Params``: the flat keyword arguments of a method, path, query and body fields together.
  The keys a method requires are required here; the others may be left out (or passed as None).
- ``<Operation>Result``: ``data.item`` of an answer. ``<Operation>Item``: one item of a list.
- Every response field is optional, as in the document, and an answer keeps fields it does not list: the
  API adds fields without a new version. Amounts are strings. Answers are read leniently: a value outside
  a documented list of values is passed through, never refused.

A request model is also what a method checks its arguments against before anything is sent (unknown,
missing or mistyped fields are refused), so a model lists exactly the fields the document allows. Where
the document lists the values a request field takes, the model's ``Literal`` holds that operation's list
and any other value is refused, case included (``networkType="MAIN"``): the SDK pins the API version, so
the values it accepts are known.
"""

from typing import List, Literal, TypedDict

# ---------------------------------------------------------------------------------------------------
# The documented values of request fields. Each operation's own list is compared with these in
# tests/test_models.py; an operation whose list differs gets a type of its own (prepareStrategy).
# ---------------------------------------------------------------------------------------------------

Blockchain = Literal[
    "arbitrum", "avalanche", "base", "binance-smart-chain", "bitcoin", "bitcoin-cash", "dash", "dogecoin", "ethereum",
    "ethereum-classic", "litecoin", "optimism", "polygon", "solana", "tron", "xrp", "zcash",
]
Network = Literal["mainnet", "testnet", "devnet", "mordor", "nile", "fuji", "sepolia", "amoy"]
NetworkType = Literal["main", "test"]
FeePriority = Literal["slow", "standard", "fast"]
XrpNetwork = Literal["mainnet", "testnet"]
TronBlockchain = Literal["tron"]
TronNetwork = Literal["mainnet", "nile"]
TronResource = Literal["bandwidth", "energy"]
TronResourceAction = Literal["freeze", "unfreeze", "withdraw-resource", "delegate", "undelegate"]
ContractMethod = Literal["approve", "transfer-from"]
#: createMultipleTransfer's spelling
MultipleTransferPrepareStrategy = Literal["minimize-dust", "optimize-size"]
#: estimateTransactionFeeByAssetId's spelling, which differs from createMultipleTransfer's in the document
FeeEstimatePrepareStrategy = Literal["minimize_dust", "optimize_size"]

# ---------------------------------------------------------------------------------------------------
# Shared
# ---------------------------------------------------------------------------------------------------


class AssetData(TypedDict, total=False):
    """The amounts of one asset: total, available and allocated (held for pending transactions)."""

    allocatedAmount: str
    availableAmount: str
    contractAddress: str
    standard: str
    totalAmount: str


class TransactionFee(TypedDict, total=False):
    amount: str
    amountUnit: str


class AddressRef(TypedDict, total=False):
    address: str


class FeeInput(TypedDict, total=False):
    """Fee values that replace the ones ``feePriority`` would choose; which apply depends on the blockchain."""

    acknowledgeHighFee: bool
    computeUnitPrice: str
    fee: str
    feeLimit: str
    feeRate: str
    gasPrice: str
    maxFeePerGas: str
    maxPriorityFeePerGas: str
    total: str


# ---------------------------------------------------------------------------------------------------
# vaults
# ---------------------------------------------------------------------------------------------------


class _ListVaultsRequired(TypedDict):
    networkType: NetworkType


class ListVaultsParams(_ListVaultsRequired, total=False):
    limit: int
    startingAfter: str


class ListVaultsItem(TypedDict, total=False):
    backuped: bool
    changeAddressesCount: int
    color: str
    createdTimestamp: int
    depositAddressesCount: int
    id: str
    name: str
    type: str


class ListVaultsByAssetIdParams(TypedDict):
    assetId: str
    blockchain: Blockchain
    networkType: NetworkType


class VaultWithAsset(TypedDict, total=False):
    allocatedAmount: str
    availableAmount: str
    totalAmount: str
    vaultColor: str
    vaultId: str
    vaultName: str
    vaultType: str


class ListVaultsByAssetIdResult(TypedDict, total=False):
    exchangeRateUnit: str
    vaults: List[VaultWithAsset]


class ListAssetsByVaultParams(TypedDict):
    vaultId: str


class VaultAsset(TypedDict, total=False):
    assetData: AssetData
    assetId: str
    assetUnit: str
    blockchain: str
    exchangeRateUnit: str
    network: str
    type: str


class ListAssetsByVaultResult(TypedDict, total=False):
    assets: List[VaultAsset]


class _ListTransactionsByVaultRequired(TypedDict):
    vaultId: str


class ListTransactionsByVaultParams(_ListTransactionsByVaultRequired, total=False):
    limit: int
    startingAfter: str


class TransactionParty(TypedDict, total=False):
    """A sender or recipient of a transaction. ``isVaultAddress`` is ``"true"`` or ``"false"`` here."""

    address: str
    addressType: str
    amount: str
    amountUnit: str
    isVaultAddress: str
    label: str


class ListTransactionsByVaultItem(TypedDict, total=False):
    blockchain: str
    createdTimestamp: int
    direction: str
    hasTokenTransfer: bool
    id: str
    isInternal: bool
    minedInBlockHeight: str
    network: str
    recipients: List[TransactionParty]
    senders: List[TransactionParty]
    status: str
    transactionFee: TransactionFee
    transactionId: str


# ---------------------------------------------------------------------------------------------------
# vault-accounts
# ---------------------------------------------------------------------------------------------------


class CreateVaultAccountParams(TypedDict):
    vaultId: str
    color: str
    isHiddenInDashboard: bool
    name: str


class VaultAccountBalance(TypedDict, total=False):
    assetId: str
    assetName: str
    assetUnit: str
    blockchain: str
    exchangeRateUnit: str
    latestExchangeRateToUSD: str
    totalAmount: str


class CreateVaultAccountResult(TypedDict, total=False):
    addressesCount: str
    balances: List[VaultAccountBalance]
    createdAt: int
    index: str
    isHiddenInDashboard: bool
    vaultAccountColour: str
    vaultAccountId: str
    vaultAccountName: str
    vaultId: str


class _ListVaultAccountsRequired(TypedDict):
    vaultId: str


class ListVaultAccountsParams(_ListVaultAccountsRequired, total=False):
    isHidden: bool
    isHideEmpty: bool
    limit: int
    startingAfter: str


class ListVaultAccountsItem(TypedDict, total=False):
    addressesCount: str
    balances: List[VaultAccountBalance]
    createdAt: int
    index: int
    isFavoriteInDashboard: bool
    isHiddenInDashboard: bool
    vaultAccountColour: str
    vaultAccountId: str
    vaultAccountName: str
    vaultId: str


class GetVaultAccountByIdParams(TypedDict):
    vaultId: str
    vaultAccountId: str


class GetVaultAccountByIdResult(TypedDict, total=False):
    addressesCount: str
    balances: List[VaultAccountBalance]
    createdAt: int
    index: str
    isFavoriteInDashboard: bool
    isHiddenInDashboard: bool
    vaultAccountColour: str
    vaultAccountId: str
    vaultAccountName: str
    vaultId: str


class _UpdateVaultAccountRequired(TypedDict):
    vaultId: str
    vaultAccountId: str


class UpdateVaultAccountParams(_UpdateVaultAccountRequired, total=False):
    color: str
    isFavoriteInDashboard: bool
    isHiddenInDashboard: bool
    name: str


class UpdateVaultAccountResult(TypedDict, total=False):
    addressesCount: str
    createdAt: int
    index: str
    isHiddenInDashboard: bool
    vaultAccountColour: str
    vaultAccountId: str
    vaultAccountName: str
    vaultId: str


class _AddAssetToVaultAccountRequired(TypedDict):
    vaultId: str
    vaultAccountId: str
    assetId: str


class AddAssetToVaultAccountParams(_AddAssetToVaultAccountRequired, total=False):
    """``address`` adds the asset to an address the Vault Account holds; ``label`` derives a new one."""

    address: str
    label: str


class AddAssetToVaultAccountResult(TypedDict, total=False):
    address: str
    assetUnit: str
    balance: str
    contractAddress: str
    decimals: str


class _ListAssetsByVaultAccountIdRequired(TypedDict):
    vaultId: str
    vaultAccountId: str


class ListAssetsByVaultAccountIdParams(_ListAssetsByVaultAccountIdRequired, total=False):
    assetUnit: str
    limit: int
    startingAfter: str


class ListAssetsByVaultAccountIdItem(TypedDict, total=False):
    assetId: str
    assetUnit: str
    availableAmount: str
    blockchain: str
    exchangeRateToUsd: str


class _ListTransactionsByVaultAccountRequired(TypedDict):
    vaultId: str
    vaultAccountId: str


class ListTransactionsByVaultAccountParams(_ListTransactionsByVaultAccountRequired, total=False):
    limit: int
    startingAfter: str


class VaultAccountTransactionRecipient(TypedDict, total=False):
    address: str
    addressType: str
    amount: str
    amountUnit: str
    isVaultAddress: bool
    label: str


class VaultAccountTransactionSender(TypedDict, total=False):
    address: str
    amount: str
    amountUnit: str
    isVaultAddress: bool
    label: str


class ListTransactionsByVaultAccountItem(TypedDict, total=False):
    blockchain: str
    createdTimestamp: int
    direction: str
    hasTokenTransfer: bool
    id: str
    isInternal: bool
    minedInBlockHeight: str
    network: str
    recipients: List[VaultAccountTransactionRecipient]
    senders: List[VaultAccountTransactionSender]
    status: str
    transactionFee: TransactionFee
    transactionId: str


# ---------------------------------------------------------------------------------------------------
# assets-addresses
# ---------------------------------------------------------------------------------------------------


class GenerateDepositAddressParams(TypedDict):
    vaultId: str
    blockchain: Blockchain
    network: Network
    label: str
    vaultAccountId: str


class GenerateDepositAddressResult(TypedDict, total=False):
    address: str
    createdTimestamp: int
    label: str


class _GetAddressBalanceRequired(TypedDict):
    vaultId: str
    address: str


class GetAddressBalanceParams(_GetAddressBalanceRequired, total=False):
    assetUnit: str
    blockchain: Blockchain
    limit: int
    startingAfter: str


class GetAddressBalanceItem(TypedDict, total=False):
    assetData: AssetData
    assetId: str
    assetUnit: str
    blockchain: str
    exchangeRateUnit: str
    type: str


class _ListAddressesByVaultAccountIdRequired(TypedDict):
    vaultId: str
    vaultAccountId: str


class ListAddressesByVaultAccountIdParams(_ListAddressesByVaultAccountIdRequired, total=False):
    assetId: str
    blockchain: Blockchain
    limit: int
    startingAfter: str


class AddressAssetBalance(TypedDict, total=False):
    amount: str
    assetId: str
    assetUnit: str


class ListAddressesByVaultAccountIdItem(TypedDict, total=False):
    address: str
    addressId: str
    addressIndex: str
    balances: List[AddressAssetBalance]
    blockchain: str
    createdTimestamp: int
    label: str


class ListSupportedAssetsParams(TypedDict, total=False):
    assetUnit: str
    blockchain: Blockchain
    limit: int
    networkType: NetworkType
    startingAfter: str


class AssetPrice(TypedDict, total=False):
    amount: str
    calculationTimestamp: int
    unit: str


class ListSupportedAssetsItem(TypedDict, total=False):
    active: str
    assetId: str
    assetName: str
    assetType: str
    assetUnit: str
    blockchain: str
    contractAddress: str
    contractType: str
    decimals: str
    network: str
    price: AssetPrice


class ValidateAddressParams(TypedDict):
    blockchain: Blockchain
    network: Network
    address: str


class ValidateAddressResult(TypedDict, total=False):
    address: str
    isValid: bool


class EncodeXrpAddressParams(TypedDict):
    network: XrpNetwork
    classicAddress: str
    addressTag: str  # a whole number, as text


class EncodeXrpAddressResult(TypedDict, total=False):
    xAddress: str


class DecodeXrpAddressParams(TypedDict):
    network: XrpNetwork
    xAddress: str


class DecodeXrpAddressResult(TypedDict, total=False):
    classicAddress: str
    tag: str


class TronResourceOverviewParams(TypedDict):
    vaultId: str
    blockchain: TronBlockchain
    network: TronNetwork
    address: str


class TronBalance(TypedDict, total=False):
    available: str
    availableFrozen: str
    delegated: str
    total: str
    unit: str
    withdrawableAmount: str


class TronFrozenResources(TypedDict, total=False):
    bandwidth: str
    energy: str
    tronPower: str


class TronBandwidth(TypedDict, total=False):
    acquiredDelegated: str
    available: int
    delegated: str
    freeLimit: int
    freeUsed: int
    limit: int
    used: int


class TronEnergy(TypedDict, total=False):
    acquiredDelegated: str
    available: int
    delegated: str
    limit: int
    used: int


class TronResources(TypedDict, total=False):
    bandwidth: TronBandwidth
    energy: TronEnergy


class TronResourceOverviewResult(TypedDict, total=False):
    address: str
    balance: TronBalance
    frozenResources: TronFrozenResources
    network: str
    resources: TronResources


class _TronResourceManagementRequired(TypedDict):
    vaultId: str
    blockchain: TronBlockchain
    network: TronNetwork
    fromAddress: str
    resource: TronResource
    type: TronResourceAction


class TronResourceManagementParams(_TronResourceManagementRequired, total=False):
    amount: str
    lock: str
    lockPeriod: str
    note: str
    toAddress: str


class TronResourceDestination(TypedDict, total=False):
    address: str
    amount: str
    amountUnit: str


class TronResourceManagementResult(TypedDict, total=False):
    blockchain: str
    destination: List[TronResourceDestination]
    id: str
    network: str
    resource: str
    source: AddressRef
    status: str
    type: str
    vaultId: str


# ---------------------------------------------------------------------------------------------------
# transactions
# ---------------------------------------------------------------------------------------------------


class Recipient(TypedDict):
    """A recipient of a transfer: the address and the amount it receives."""

    address: str
    amount: str


class TransferResultRecipient(TypedDict, total=False):
    address: str
    addressTag: int
    amount: str
    amountUnit: str
    classicAddress: str
    convertedAmountToUSD: str


class TransferResultSender(TypedDict, total=False):
    address: str
    addressTag: int
    classicAddress: str


class _CreateSingleTransferRequired(TypedDict):
    vaultId: str
    amount: str
    assetId: str
    fromAddress: str
    note: str
    toAddress: str
    vaultAccountId: str


class CreateSingleTransferParams(_CreateSingleTransferRequired, total=False):
    feeInput: FeeInput
    feeOptimization: bool
    feePriority: FeePriority
    gross: bool
    maxFee: str


class CreateSingleTransferResult(TypedDict, total=False):
    amountUnit: str
    feePriority: str
    gross: bool
    maxFee: str
    note: str
    recipients: List[TransferResultRecipient]
    senders: TransferResultSender
    totalTransactionAmount: str
    transactionRequestId: str
    transactionRequestStatus: str


class _CreateMultipleTransferRequired(TypedDict):
    vaultId: str
    assetId: str
    feePriority: FeePriority
    note: str
    prepareStrategy: MultipleTransferPrepareStrategy
    recipients: List[Recipient]
    vaultAccountId: str


class CreateMultipleTransferParams(_CreateMultipleTransferRequired, total=False):
    feeInput: FeeInput
    gross: bool
    maxFee: str


class TransferAmountRecipient(TypedDict, total=False):
    address: str
    amount: str
    amountUnit: str
    convertedAmountToUSD: str


class CreateMultipleTransferResult(TypedDict, total=False):
    amountUnit: str
    feePriority: str
    gross: bool
    maxFee: str
    note: str
    prepareStrategy: str
    recipients: List[TransferAmountRecipient]
    totalTransactionAmount: str
    transactionRequestId: str
    transactionRequestStatus: str


class UtxoChangeData(TypedDict, total=False):
    """Where the change goes: an address, or a Vault Account to derive one in."""

    address: str
    vaultAccountId: str


class UtxoSender(TypedDict):
    utxoId: str


class _CreateUtxoTransferRequired(TypedDict):
    vaultId: str
    assetId: str
    feePriority: str
    note: str
    recipients: List[Recipient]
    senders: List[UtxoSender]


class CreateUtxoTransferParams(_CreateUtxoTransferRequired, total=False):
    changeData: UtxoChangeData
    feeInput: FeeInput
    feePayer: str
    gross: bool
    maxFee: str


class UtxoTransferResultRecipient(TypedDict, total=False):
    address: str
    amount: str
    amountUnit: str
    assetId: str


class UtxoTransferResultSender(TypedDict, total=False):
    address: str
    addressLabel: str
    amount: str
    amountUnit: str
    assetId: str
    utxoId: str
    vaultAccountId: str


class CreateUtxoTransferResult(TypedDict, total=False):
    amountUnit: str
    feePriority: str
    note: str
    recipients: List[UtxoTransferResultRecipient]
    senders: List[UtxoTransferResultSender]
    totalTransactionAmount: str
    transactionRequestId: str
    transactionRequestStatus: str
    transactionType: str


class _ValidateUtxoTransferRequired(TypedDict):
    vaultId: str
    assetId: str
    feePriority: str
    recipients: List[Recipient]
    senders: List[UtxoSender]


class ValidateUtxoTransferParams(_ValidateUtxoTransferRequired, total=False):
    changeData: UtxoChangeData
    feePayer: str
    gross: bool
    maxFee: str
    note: str


class UtxoValidationRecipient(TypedDict, total=False):
    address: str
    amount: str


class UtxoValidationSender(TypedDict, total=False):
    address: str
    addressLabel: str
    amount: str
    utxoId: str
    vaultAccountId: str


class ValidateUtxoTransferResult(TypedDict, total=False):
    error: str
    feeInNative: str
    inputAmount: str
    inputSize: str
    outputAmount: str
    outputSize: str
    recipients: List[UtxoValidationRecipient]
    recipientsValid: bool
    senders: List[UtxoValidationSender]
    sendersValid: bool
    size: str


class BatchFeePayer(TypedDict):
    """The address that pays the fee of the batch, and the asset it pays in."""

    address: str
    assetId: str


class BatchRecipient(TypedDict):
    address: str
    amount: str
    assetId: str


class _CreateBatchTransactionRequestRequired(TypedDict):
    vaultId: str
    feePayer: BatchFeePayer
    fromAddress: str
    note: str
    recipients: List[BatchRecipient]


class CreateBatchTransactionRequestParams(_CreateBatchTransactionRequestRequired, total=False):
    feePriority: FeePriority
    vaultAccountId: str


class BatchResultRecipient(TypedDict, total=False):
    address: str
    amount: str
    amountUnit: str
    assetId: str
    convertedAmountToUSD: str


class CreateBatchTransactionRequestResult(TypedDict, total=False):
    amountUnit: str
    feePayer: str
    feePriority: str
    note: str
    recipients: List[BatchResultRecipient]
    senders: AddressRef
    totalTransactionAmountInUsd: str
    transactionRequestId: str
    transactionRequestStatus: str


class _GasSponsorshipTransferRequired(TypedDict):
    vaultId: str
    amount: str
    assetId: str
    feePayer: str
    fromAddress: str
    note: str
    toAddress: str
    vaultAccountId: str


class GasSponsorshipTransferParams(_GasSponsorshipTransferRequired, total=False):
    feeInput: FeeInput
    feePriority: FeePriority
    maxFee: str


class GasSponsorshipTransferResult(TypedDict, total=False):
    amountUnit: str
    feePayer: str
    feePriority: str
    maxFee: str
    note: str
    recipients: List[TransferResultRecipient]
    senders: TransferResultSender
    totalTransactionAmount: str
    transactionRequestId: str
    transactionRequestStatus: str


class _CreateTronContractInteractionRequestRequired(TypedDict):
    vaultId: str
    assetId: str
    feePayer: str
    fromAddress: str
    method: ContractMethod
    note: str
    vaultAccountId: str


class CreateTronContractInteractionRequestParams(_CreateTronContractInteractionRequestRequired, total=False):
    amount: str
    feeInput: FeeInput
    feeOptimization: bool
    maxFee: str
    toAddress: str


class ContractInteractionData(TypedDict, total=False):
    contractAddress: str


class CreateTronContractInteractionRequestResult(TypedDict, total=False):
    amountUnit: str
    assetId: str
    contractInteractionData: ContractInteractionData
    feePayer: str
    maxFee: str
    method: str
    note: str
    recipients: List[TransferAmountRecipient]
    senders: AddressRef
    totalTransactionAmount: str
    transactionRequestId: str
    transactionRequestStatus: str


class FeeEstimateRecipient(TypedDict, total=False):
    address: str
    amount: str
    assetId: str


class _EstimateTransactionFeeByAssetIdRequired(TypedDict):
    vaultId: str
    transactionType: str
    vaultAccountId: str


class EstimateTransactionFeeByAssetIdParams(_EstimateTransactionFeeByAssetIdRequired, total=False):
    amount: str
    assetId: str
    feeOptimization: bool
    feePayer: str
    feePayerAssetId: str
    feePriority: FeePriority
    fromAddress: str
    method: ContractMethod
    prepareStrategy: FeeEstimatePrepareStrategy
    recipients: List[FeeEstimateRecipient]
    toAddress: str


class EstimateTransactionFeeByAssetIdResult(TypedDict, total=False):
    errorMessage: str
    feeInNative: str
    insufficientBalance: bool
    maxAmount: str


class GetTransactionDetailsParams(TypedDict):
    vaultId: str
    blockchain: Blockchain
    transactionId: str


class InternalTransfer(TypedDict, total=False):
    fromAddress: str
    operationId: str
    operationType: str
    previousTxHash: str
    timestamp: int
    toAddress: str


class TokenTransfer(TypedDict, total=False):
    amount: str
    amountUnit: str
    contractAddress: str
    decimals: int
    fromAddress: str
    toAddress: str
    tokenName: str
    type: str


class GetTransactionDetailsResult(TypedDict, total=False):
    dateTime: int
    direction: str
    internalTransfers: List[InternalTransfer]
    minedInBlockHeight: str
    network: str
    recipients: List[TransactionParty]
    senders: List[TransactionParty]
    status: str
    tokensTransfers: List[TokenTransfer]
    transactionFee: TransactionFee


class GetTransactionRequestDetailsParams(TypedDict):
    transactionRequestId: str


class TransactionRequestRecipient(TypedDict, total=False):
    address: str
    addressTag: int
    amount: str
    amountUnit: str
    classicAddress: str


class GetTransactionRequestDetailsResult(TypedDict, total=False):
    amountUnit: str
    blockchain: str
    feePriority: str
    network: str
    note: str
    recipients: List[TransactionRequestRecipient]
    senders: TransferResultSender
    totalTransactionAmount: str
    transactionId: str
    transactionRequestStatus: str
    transactionType: str
    vaultAccountId: str
    vaultId: str


class _ListUtxosRequired(TypedDict):
    vaultId: str


class ListUtxosParams(_ListUtxosRequired, total=False):
    address: str
    assetId: str
    isSpent: bool
    limit: int
    startingAfter: str
    vaultAccountId: str


class UtxoValue(TypedDict, total=False):
    amount: str
    assetUnit: str


class ListUtxosItem(TypedDict, total=False):
    address: str
    assetId: str
    createdTimestamp: int
    index: str
    isSpent: bool
    transactionId: str
    utxoId: str
    value: UtxoValue
    vaultAccountId: str


# ---------------------------------------------------------------------------------------------------
# api-keys (contract/pending/: documented, not on production yet)
# ---------------------------------------------------------------------------------------------------


class ListApiKeySigningKeysParams(TypedDict):
    """None: the list covers the API key that makes the call."""


class ApiKeySigningKey(TypedDict, total=False):
    """A public key registered for request signing on the calling API key."""

    fingerprint: str
    algorithm: str  # ed25519 | p-256
    status: str
    createdTimestamp: int
    approvedTimestamp: int


ListApiKeySigningKeysItem = ApiKeySigningKey
