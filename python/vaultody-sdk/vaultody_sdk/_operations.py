"""The operation table: one entry per documented operation, the one definition both clients call through.

Each entry says where each parameter goes (path, query or body item), how a failed attempt may be retried
(``read``: re-signed freely; ``write``: never signed again once it may have reached the gateway, see
retry.py) and how a list is paged. Which parameters exist and which are required is the operation's
request model (models.py), so a method's arguments, the checks below and scripts/coverage.mjs all read
the same thing; tests/test_models.py compares the models with the published OpenAPI document and
scripts/coverage.mjs compares this table with it.

``OPERATIONS[i].params`` is ``({"name", "in", "required"}, ...)``, with ``in`` one of ``path``, ``query`` or
``body``.

Paging and retry classes come from contract/overlay.json. Two gaps in the docs are taken the safe way:
getAddressBalance pages by cursor, but its cursor field is not documented, so it is not paged past its
first page (PaginationError ``cursor_unknown``); listApiKeySigningKeys takes no parameter in the docs, so
none is sent, and an answer that says it holds more than one page raises PaginationError ``not_paged``.
"""

from collections.abc import Mapping
from dataclasses import dataclass
from types import MappingProxyType
from typing import Any, Dict, Literal, Optional, Tuple, get_args, get_origin, get_type_hints, is_typeddict

from . import models
from ._core import Call, Item
from .errors import ApiError, PaginationError, ParameterError

#: The client namespace of each docs group (an operation's first tag).
GROUP_NAMESPACES = MappingProxyType({
    "vaults": "vaults",
    "vault-accounts": "vault_accounts",
    "assets-addresses": "assets_addresses",
    "transactions": "transactions",
    "api-keys": "api_keys",
})


def snake_case(name):
    """``createSingleTransfer`` → ``create_single_transfer``, as scripts/coverage.mjs names Python methods."""
    return "".join("_" + letter.lower() if letter.isupper() else letter for letter in name)


@dataclass(frozen=True)
class Operation:
    """One documented operation.

    :ivar operation_id: the docs operationId; the method is ``client.<namespace>.<snake_case(operation_id)>``
    :ivar params: ``({"name", "in", "required"}, ...)`` in the order of path, query (the order sent), body
    :ivar model: the request model the arguments are checked against
    :ivar retry: ``read`` or ``write``
    :ivar paging: ``cursor``, ``offset`` or None (a single item)
    :ivar cursor_field: cursor paging: the item field sent as the next ``startingAfter``; None when the
        docs don't say (the list is then not paged past its first page)
    :ivar max_limit: the largest page, also the page size used when the call gives no ``limit``
    """

    operation_id: str
    group: str
    method: str
    path: str
    params: Tuple[Mapping, ...]
    model: Any
    retry: str
    paging: Optional[str] = None
    cursor_field: Optional[str] = None
    max_limit: Optional[int] = None

    @property
    def namespace(self):
        return GROUP_NAMESPACES[self.group]

    @property
    def method_name(self):
        return snake_case(self.operation_id)

    def names(self, location):
        return tuple(param["name"] for param in self.params if param["in"] == location)


def _op(operation_id, group, method, path, model, *, query=(), body=(), retry, paging=None, cursor_field=None, max_limit=None):
    path_names = tuple(sorted(part[1:-1] for part in path.split("/") if part.startswith("{")))
    declared = set(path_names) | set(query) | set(body)
    fields = set(model.__required_keys__) | set(model.__optional_keys__)
    if declared != fields or len(declared) != len(path_names) + len(query) + len(body):
        raise AssertionError("{}: the table places {}, the model has {}".format(operation_id, sorted(declared), sorted(fields)))
    required = model.__required_keys__
    params = tuple(
        MappingProxyType({"name": name, "in": location, "required": name in required})
        for location, names in (("path", path_names), ("query", tuple(query)), ("body", tuple(body)))
        for name in names
    )
    if paging is not None and "limit" in query and max_limit is None:
        raise AssertionError("{}: a paged list with a limit needs its max_limit".format(operation_id))
    return Operation(operation_id, group, method, path, params, model, retry, paging, cursor_field, max_limit)


OPERATIONS = (
    # -- vaults -------------------------------------------------------------------------------------
    _op("listVaults", "vaults", "GET", "/vaults/{networkType}", models.ListVaultsParams,
        query=("limit", "startingAfter"), retry="read", paging="cursor", cursor_field="id", max_limit=50),
    _op("listVaultsByAssetId", "vaults", "GET", "/assets/{assetId}/{blockchain}/vaults/{networkType}", models.ListVaultsByAssetIdParams,
        retry="read"),
    _op("listAssetsByVault", "vaults", "GET", "/vaults/{vaultId}/assets", models.ListAssetsByVaultParams,
        retry="read"),
    _op("listTransactionsByVault", "vaults", "GET", "/vaults/{vaultId}/transactions", models.ListTransactionsByVaultParams,
        query=("limit", "startingAfter"), retry="read", paging="cursor", cursor_field="id", max_limit=50),
    # -- vault-accounts -----------------------------------------------------------------------------
    _op("createVaultAccount", "vault-accounts", "POST", "/vaults/{vaultId}/vault-account", models.CreateVaultAccountParams,
        body=("color", "isHiddenInDashboard", "name"), retry="write"),
    _op("listVaultAccounts", "vault-accounts", "GET", "/vaults/{vaultId}/vault-accounts/details", models.ListVaultAccountsParams,
        query=("isHidden", "isHideEmpty", "limit", "startingAfter"), retry="read", paging="cursor", cursor_field="vaultAccountId", max_limit=50),
    _op("getVaultAccountById", "vault-accounts", "GET", "/vaults/{vaultId}/vault-accounts/{vaultAccountId}/details", models.GetVaultAccountByIdParams,
        retry="read"),
    _op("updateVaultAccount", "vault-accounts", "PUT", "/vaults/{vaultId}/vault-accounts/{vaultAccountId}/edit", models.UpdateVaultAccountParams,
        body=("color", "isFavoriteInDashboard", "isHiddenInDashboard", "name"), retry="write"),
    _op("addAssetToVaultAccount", "vault-accounts", "PUT", "/vaults/{vaultId}/vault-accounts/{vaultAccountId}/add-asset", models.AddAssetToVaultAccountParams,
        body=("address", "assetId", "label"), retry="write"),
    _op("listAssetsByVaultAccountId", "vault-accounts", "GET", "/vaults/{vaultId}/vault-accounts/{vaultAccountId}/list-assets", models.ListAssetsByVaultAccountIdParams,
        query=("assetUnit", "limit", "startingAfter"), retry="read", paging="cursor", cursor_field="assetId", max_limit=50),
    _op("listTransactionsByVaultAccount", "vault-accounts", "GET", "/vaults/{vaultId}/vault-accounts/{vaultAccountId}/transactions", models.ListTransactionsByVaultAccountParams,
        query=("limit", "startingAfter"), retry="read", paging="cursor", cursor_field="id", max_limit=50),
    # -- assets-addresses ---------------------------------------------------------------------------
    _op("generateDepositAddress", "assets-addresses", "POST", "/vaults/{vaultId}/{blockchain}/{network}/addresses", models.GenerateDepositAddressParams,
        body=("label", "vaultAccountId"), retry="write"),
    _op("getAddressBalance", "assets-addresses", "GET", "/vaults/{vaultId}/addresses/{address}/balance", models.GetAddressBalanceParams,
        query=("assetUnit", "blockchain", "limit", "startingAfter"), retry="read", paging="cursor", cursor_field=None, max_limit=50),
    _op("listAddressesByVaultAccountId", "assets-addresses", "GET", "/vaults/{vaultId}/vault-accounts/{vaultAccountId}/list-addresses", models.ListAddressesByVaultAccountIdParams,
        query=("assetId", "blockchain", "limit", "startingAfter"), retry="read", paging="cursor", cursor_field="addressId", max_limit=50),
    _op("listSupportedAssets", "assets-addresses", "GET", "/supported-assets", models.ListSupportedAssetsParams,
        query=("assetUnit", "blockchain", "limit", "networkType", "startingAfter"), retry="read", paging="cursor", cursor_field="assetId", max_limit=50),
    _op("validateAddress", "assets-addresses", "POST", "/info/{blockchain}/{network}/addresses/validate", models.ValidateAddressParams,
        body=("address",), retry="read"),
    _op("encodeXrpAddress", "assets-addresses", "GET", "/utils/xrp/{network}/addresses/encode/{classicAddress}/{addressTag}", models.EncodeXrpAddressParams,
        retry="read"),
    _op("decodeXrpAddress", "assets-addresses", "GET", "/utils/xrp/{network}/addresses/decode/{xAddress}", models.DecodeXrpAddressParams,
        retry="read"),
    _op("tronResourceOverview", "assets-addresses", "GET", "/vaults/{vaultId}/{blockchain}/{network}/{address}/overview", models.TronResourceOverviewParams,
        retry="read"),
    _op("tronResourceManagement", "assets-addresses", "POST", "/vaults/{vaultId}/{blockchain}/{network}/addresses/{fromAddress}/manage-resource", models.TronResourceManagementParams,
        body=("amount", "lock", "lockPeriod", "note", "resource", "toAddress", "type"), retry="write"),
    # -- transactions -------------------------------------------------------------------------------
    _op("createSingleTransfer", "transactions", "POST", "/vaults/{vaultId}/transaction-requests/single-transfer", models.CreateSingleTransferParams,
        body=("amount", "assetId", "feeInput", "feeOptimization", "feePriority", "fromAddress", "gross", "maxFee", "note", "toAddress", "vaultAccountId"), retry="write"),
    _op("createMultipleTransfer", "transactions", "POST", "/vaults/{vaultId}/transaction-requests/multiple-transfer", models.CreateMultipleTransferParams,
        body=("assetId", "feeInput", "feePriority", "gross", "maxFee", "note", "prepareStrategy", "recipients", "vaultAccountId"), retry="write"),
    _op("createUtxoTransfer", "transactions", "POST", "/vaults/{vaultId}/transaction-requests/utxo-transfer", models.CreateUtxoTransferParams,
        body=("assetId", "changeData", "feeInput", "feePayer", "feePriority", "gross", "maxFee", "note", "recipients", "senders"), retry="write"),
    _op("validateUtxoTransfer", "transactions", "POST", "/vaults/{vaultId}/transaction-requests/utxo-transfer/validate", models.ValidateUtxoTransferParams,
        body=("assetId", "changeData", "feePayer", "feePriority", "gross", "maxFee", "note", "recipients", "senders"), retry="read"),
    _op("createBatchTransactionRequest", "transactions", "POST", "/vaults/{vaultId}/transaction-requests/batch", models.CreateBatchTransactionRequestParams,
        body=("feePayer", "feePriority", "fromAddress", "note", "recipients", "vaultAccountId"), retry="write"),
    _op("gasSponsorshipTransfer", "transactions", "POST", "/vaults/{vaultId}/transaction-requests/gas-sponsorship-transfer", models.GasSponsorshipTransferParams,
        body=("amount", "assetId", "feeInput", "feePayer", "feePriority", "fromAddress", "maxFee", "note", "toAddress", "vaultAccountId"), retry="write"),
    _op("createTronContractInteractionRequest", "transactions", "POST", "/vaults/{vaultId}/transaction-requests/contract-interaction", models.CreateTronContractInteractionRequestParams,
        body=("amount", "assetId", "feeInput", "feeOptimization", "feePayer", "fromAddress", "maxFee", "method", "note", "toAddress", "vaultAccountId"), retry="write"),
    _op("estimateTransactionFeeByAssetId", "transactions", "POST", "/vaults/{vaultId}/approximate-fee", models.EstimateTransactionFeeByAssetIdParams,
        body=("amount", "assetId", "feeOptimization", "feePayer", "feePayerAssetId", "feePriority", "fromAddress", "method", "prepareStrategy", "recipients", "toAddress", "transactionType", "vaultAccountId"),
        retry="read"),
    _op("getTransactionDetails", "transactions", "GET", "/vaults/{vaultId}/{blockchain}/transactions/{transactionId}", models.GetTransactionDetailsParams,
        retry="read"),
    _op("getTransactionRequestDetails", "transactions", "GET", "/transaction-requests/{transactionRequestId}", models.GetTransactionRequestDetailsParams,
        retry="read"),
    _op("listUtxos", "transactions", "GET", "/vaults/{vaultId}/utxos", models.ListUtxosParams,
        query=("address", "assetId", "isSpent", "limit", "startingAfter", "vaultAccountId"), retry="read", paging="cursor", cursor_field="utxoId", max_limit=50),
    # -- api-keys (contract/pending/) ---------------------------------------------------------------
    # The docs name no parameter: the list covers the calling API key and holds at most two keys.
    _op("listApiKeySigningKeys", "api-keys", "GET", "/api-keys/current/signing-keys", models.ListApiKeySigningKeysParams,
        retry="read", paging="offset", max_limit=2),
)

OPERATION_BY_ID: Mapping = MappingProxyType({operation.operation_id: operation for operation in OPERATIONS})


# ---------------------------------------------------------------------------------------------------
# Checking the arguments against the request model
# ---------------------------------------------------------------------------------------------------

_HINTS: Dict[Any, Dict[str, Any]] = {}


def _hints(model):
    hints = _HINTS.get(model)
    if hints is None:
        hints = _HINTS[model] = get_type_hints(model)
    return hints


def _invalid(where, what):
    return ParameterError("invalid_param", "{} must be {}".format(where, what), param=where)


def _check(hint, value, where):
    """The value, checked against its model type; nested objects and lists are copied without None fields.
    The value itself never goes into an error."""
    if hint is str:
        if not isinstance(value, str):
            raise _invalid(where, "a string")
        return value
    if get_origin(hint) is Literal:
        # One of the values the document lists for this field of this operation, exactly (case included).
        allowed = get_args(hint)
        if not isinstance(value, str):
            raise _invalid(where, "a string")
        if value not in allowed:
            raise _invalid(where, "one of {}".format(", ".join(allowed)))
        return value
    if hint is bool:
        if not isinstance(value, bool):
            raise _invalid(where, "true or false")
        return value
    if hint is int:
        if isinstance(value, bool) or not isinstance(value, int):
            raise _invalid(where, "an integer")
        return value
    if get_origin(hint) is list:
        (element,) = get_args(hint)
        if not isinstance(value, (list, tuple)):
            raise _invalid(where, "a list")
        return [_check(element, entry, "{}[{}]".format(where, index)) for index, entry in enumerate(value)]
    if is_typeddict(hint):
        return _check_object(hint, value, where)
    raise TypeError("the model type {!r} of {} is not supported".format(hint, where))  # a bug in models.py


def _check_object(model, value, where):
    if not isinstance(value, Mapping):
        raise _invalid(where, "an object")
    hints = _hints(model)
    checked = {}
    for name, entry in value.items():
        at = "{}.{}".format(where, name)
        if not isinstance(name, str) or name not in hints:
            raise ParameterError("unknown_param", "{} is not a field the API documents here".format(at), param=at)
        if entry is None:
            continue  # left out
        checked[name] = _check(hints[name], entry, at)
    _require(model, checked, where + ".")
    return checked


def _require(model, checked, prefix):
    missing = sorted(name for name in model.__required_keys__ if name not in checked)
    if missing:
        at = prefix + missing[0]
        raise ParameterError("missing_param", "{} is required".format(at), param=at)


def check_params(operation, params):
    """The call's arguments, checked against the operation's request model.

    A parameter the operation does not document, a required one missing (None counts as missing), a value
    of the wrong type and a value outside the list the document gives for the field are refused before
    anything is sent; an optional one passed as None is left out. Nested objects are checked the same way.
    ``limit`` must be 1 to the operation's largest page. The error names the field (``param``), never
    the value.

    :returns: a copy, without the None values
    :raises ParameterError: ``unknown_param``, ``missing_param`` or ``invalid_param``
    """
    hints = _hints(operation.model)
    checked = {}
    for name, value in params.items():
        if name not in hints:
            raise ParameterError(
                "unknown_param", "{} is not a parameter of {}".format(name, operation.operation_id), param=name
            )
        if value is None:
            continue
        checked[name] = _check(hints[name], value, name)
    _require(operation.model, checked, "")
    limit = checked.get("limit")
    if limit is not None and not 1 <= limit <= operation.max_limit:
        raise _invalid("limit", "from 1 to {}".format(operation.max_limit))
    return checked


def check_context(context):
    if context is not None and not isinstance(context, str):
        raise ParameterError("invalid_context", "context must be a string")
    return context


def check_max_items(max_items):
    if max_items is not None and (isinstance(max_items, bool) or not isinstance(max_items, int) or max_items < 1):
        raise ParameterError("invalid_option", "max_items must be a positive integer")
    return max_items


# ---------------------------------------------------------------------------------------------------
# From checked arguments to a call
# ---------------------------------------------------------------------------------------------------


def operation_call(operation, checked, context):
    """The core's Call for checked arguments: each one placed in the path, the query or the body item."""
    method = operation.method
    body = None
    if method != "GET":
        body = {name: checked[name] for name in operation.names("body") if name in checked}
    return Call(
        method=method,
        path=operation.path,
        path_params={name: checked[name] for name in operation.names("path")},
        query=tuple((name, checked.get(name)) for name in operation.names("query")),
        item=body,
        has_item=body is not None,
        context=context,
        retry=operation.retry,
        operation_id=operation.operation_id,
    )


def single_item(result, operation):
    """The Item of an operation that answers with one item; a list instead is refused, not returned."""
    if not isinstance(result, Item):
        raise ApiError(
            result.meta.status, None, "{} answered with a list instead of one item".format(operation.operation_id), result.meta.request_id,
            result.meta.api_version, result.meta.replayed,
        )
    return result


def page_call(operation, checked, context, request):
    """The Call of one page of a list: the pager's ``limit`` and ``startingAfter`` (or ``offset``) placed
    where the operation takes them. A parameter the operation does not document is never sent."""
    query_names = operation.names("query")
    values = dict(checked)
    if "limit" in query_names:
        values["limit"] = request["limit"]
    if operation.paging == "cursor":
        values["startingAfter"] = request["startingAfter"]
    elif "offset" in query_names:
        values["offset"] = request["offset"]
    elif request["offset"] > 0:
        raise PaginationError(
            "not_paged", "{} takes no offset, so a second page can't be asked for".format(operation.operation_id)
        )
    return operation_call(operation, values, context)


def paging_options(operation, checked, max_items):
    """The Pages / AsyncPages options of a list call."""
    if operation.paging is None:
        raise PaginationError("not_paged", "{} does not answer with pages".format(operation.operation_id))
    return {
        "paging": operation.paging,
        "cursor_field": operation.cursor_field,
        "cursor_unknown": operation.paging == "cursor" and operation.cursor_field is None,
        "limit": checked.get("limit"),
        "max_limit": operation.max_limit,
        "max_items": check_max_items(max_items),
        "starting_after": checked.get("startingAfter"),
    }


__all__ = ["GROUP_NAMESPACES", "OPERATIONS", "OPERATION_BY_ID", "Operation", "check_params", "snake_case"]
