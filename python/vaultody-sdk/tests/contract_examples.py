"""The published OpenAPI document (contract/openapi.json) and the pending docs file, read for the tests.

The method tests call every operation with the docs' own examples and answer with the docs' own answers,
so what the SDK sends and returns is compared with the document, not with the SDK's own table.
"""

import copy
import json
import re
from urllib.parse import quote

from sdk_vectors import ROOT

CONTRACT = json.loads((ROOT / "contract" / "openapi.json").read_text(encoding="utf-8"))
PENDING = (ROOT / "contract" / "pending" / "api-keys" / "list-api-key-signing-keys.yaml").read_text(encoding="utf-8")
_SHARED_PARAMS = CONTRACT["components"]["parameters"]
_NOT_PARAMS = ("x-api-version", "context")


def _resolve(param):
    return _SHARED_PARAMS[param["$ref"].rsplit("/", 1)[1]] if "$ref" in param else param


def documented():
    """operationId → ``{"method", "path", "op"}`` for every operation of the document."""
    found = {}
    for path, item in CONTRACT["paths"].items():
        for method in ("get", "post", "put", "patch", "delete"):
            if method in item:
                found[item[method]["operationId"]] = {"method": method.upper(), "path": path, "op": item[method]}
    return found


DOCUMENTED = documented()


def params_of(operation_id):
    """The path and query parameters of an operation: ``[{"name", "in", "required", "schema"}]``."""
    entry = DOCUMENTED[operation_id]["op"]
    return [
        param for param in map(_resolve, entry.get("parameters", []))
        if param["in"] in ("path", "query") and param["name"] not in _NOT_PARAMS
    ]


def body_item_schema(operation_id):
    body = DOCUMENTED[operation_id]["op"].get("requestBody")
    if body is None:
        return None
    return body["content"]["application/json"]["schema"]["properties"]["data"]["properties"]["item"]


def request_example(operation_id):
    body = DOCUMENTED[operation_id]["op"].get("requestBody")
    return None if body is None else copy.deepcopy(body["content"]["application/json"]["example"])


def success(operation_id):
    """``(status, documented answer)`` of the operation's success."""
    responses = DOCUMENTED[operation_id]["op"]["responses"]
    status = next(code for code in responses if code.startswith("2"))
    content = responses[status]["content"]["application/json"]
    return int(status), copy.deepcopy(content["examples"]["success"]["value"])


def response_item_schema(operation_id):
    """The schema of ``data.item``, or of one of ``data.items``; and which of the two."""
    responses = DOCUMENTED[operation_id]["op"]["responses"]
    status = next(code for code in responses if code.startswith("2"))
    data = responses[status]["content"]["application/json"]["schema"]["properties"]["data"]["properties"]
    if "items" in data:
        return "items", data["items"]["items"]
    return "item", data["item"]


# Codes the client answers to by retrying on purpose; the error tests want a plain answer.
_RETRIED_CODES = ("address_derivation_conflict", "vault_accounts_creation_failed", "duplicate_api_request", "duplicate_api_request_in_progress")


def documented_error(operation_id):
    """``(status, documented error answer)``: the first documented 404, 400, 422, 409 or 403."""
    responses = DOCUMENTED[operation_id]["op"]["responses"]
    for status in ("404", "400", "422", "409", "403"):
        examples = responses.get(status, {}).get("content", {}).get("application/json", {}).get("examples", {})
        for example in examples.values():
            if example["value"].get("error", {}).get("code") not in _RETRIED_CODES:
                return int(status), copy.deepcopy(example["value"])
    raise LookupError(operation_id)


def example_call(operation_id):
    """The documented call of an operation.

    :returns: ``(params, path, query, body)``: the flat keyword arguments (every path and query parameter
        with its documented example, and the documented request item), the path they must produce, the
        query as a dict, and the documented request body (None for GET)
    """
    entry = DOCUMENTED[operation_id]
    params, query = {}, {}
    path = entry["path"]
    for param in params_of(operation_id):
        value = param["schema"]["example"]
        params[param["name"]] = value
        if param["in"] == "path":
            path = path.replace("{" + param["name"] + "}", quote(str(value), safe=""))
        else:
            query[param["name"]] = str(value).lower() if isinstance(value, bool) else str(value)
    body = request_example(operation_id)
    if body is not None:
        params.update(body["data"]["item"])
    return params, path, query, body


def pending_fields():
    """The response fields of the pending listApiKeySigningKeys: name → "string" or "integer"."""
    fields = {}
    in_fields = False
    for line in PENDING.splitlines():
        if line.startswith("fields:"):
            in_fields = True
            continue
        if in_fields and not line.startswith(" "):
            break
        match = re.match(r'\s+"(\w+)": \{.*example: (.+) \}$', line)
        if in_fields and match:
            fields[match.group(1)] = "string" if match.group(2).startswith('"') else "integer"
    return fields
