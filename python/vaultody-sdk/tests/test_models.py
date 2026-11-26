"""The hand-written models (models.py), the operation table (_operations.py) and the method namespaces
(_resources.py) against the published OpenAPI document: every field, its type, and whether it is required.

scripts/coverage.mjs checks the table and the methods too, from the Node side; these run with the Python
tests, and also reach into the models, which the coverage check does not read.
"""

import inspect
import typing

import pytest

from vaultody_sdk import AsyncVaultody, MemoryVaultKeyStore, Vaultody, models
from vaultody_sdk._operations import GROUP_NAMESPACES, OPERATION_BY_ID, OPERATIONS
from vaultody_sdk._surface import client_methods

from contract_examples import DOCUMENTED, body_item_schema, params_of, pending_fields, response_item_schema

PENDING = ("listApiKeySigningKeys",)
_SCALARS = {"string": str, "integer": int, "boolean": bool}


def model_name(operation_id, suffix):
    return operation_id[0].upper() + operation_id[1:] + suffix


def assert_matches(hint, schema, where):
    """The model type ``hint`` describes exactly ``schema``: the same fields, types and required ones."""
    kind = schema.get("type")
    if "enum" in schema:
        # This operation's own list of values, exactly: the SDK refuses any other value in a request.
        assert kind == "string" and typing.get_origin(hint) is typing.Literal, "{}: the document lists the values".format(where)
        args = typing.get_args(hint)
        assert len(args) == len(set(args)) and set(args) == set(schema["enum"]), "{}: values differ from the document's".format(where)
    elif kind in _SCALARS:
        assert hint is _SCALARS[kind], "{}: the model has {!r}, the document {}".format(where, hint, kind)
    elif kind == "array":
        assert typing.get_origin(hint) is list, "{}: the document has a list".format(where)
        assert_matches(typing.get_args(hint)[0], schema["items"], where + "[]")
    elif kind == "object":
        assert typing.is_typeddict(hint), "{}: the document has an object".format(where)
        hints = typing.get_type_hints(hint)
        properties = schema.get("properties", {})
        assert sorted(hints) == sorted(properties), "{}: fields differ".format(where)
        assert sorted(hint.__required_keys__) == sorted(schema.get("required", [])), "{}: required fields differ".format(where)
        for name, field_schema in properties.items():
            assert_matches(hints[name], field_schema, "{}.{}".format(where, name))
    else:
        raise AssertionError("{}: unexpected schema type {!r}".format(where, kind))


def contract_params(operation_id):
    """``[(name, in, required)]`` as the document places them: path and query parameters, body item fields."""
    found = [(param["name"], param["in"], param.get("required") is True) for param in params_of(operation_id)]
    item = body_item_schema(operation_id)
    if item is not None:
        required = set(item.get("required", []))
        found += [(name, "body", name in required) for name in item["properties"]]
    return sorted(found)


PUBLISHED = sorted(DOCUMENTED)


def test_the_table_has_every_documented_operation_and_no_other():
    assert sorted(OPERATION_BY_ID) == sorted(PUBLISHED + list(PENDING))
    assert len(OPERATIONS) == 32


@pytest.mark.parametrize("operation_id", PUBLISHED)
def test_table_entry_matches_the_document(operation_id):
    operation = OPERATION_BY_ID[operation_id]
    documented = DOCUMENTED[operation_id]
    assert (operation.method, operation.path) == (documented["method"], documented["path"])
    assert operation.group == documented["op"]["tags"][0]
    placed = sorted((param["name"], param["in"], param["required"]) for param in operation.params)
    assert placed == contract_params(operation_id)


@pytest.mark.parametrize("operation_id", PUBLISHED)
def test_request_model_matches_the_document(operation_id):
    model = getattr(models, model_name(operation_id, "Params"))
    assert OPERATION_BY_ID[operation_id].model is model
    hints = typing.get_type_hints(model)
    params = {param["name"]: param for param in params_of(operation_id)}
    item = body_item_schema(operation_id) or {"properties": {}, "required": []}
    assert sorted(hints) == sorted(list(params) + list(item["properties"]))
    for name, param in params.items():
        assert_matches(hints[name], param["schema"], "{}.{}".format(operation_id, name))
    for name, schema in item["properties"].items():
        assert_matches(hints[name], schema, "{}.{}".format(operation_id, name))
    required = sorted([name for name, param in params.items() if param.get("required")] + list(item.get("required", [])))
    assert sorted(model.__required_keys__) == required


@pytest.mark.parametrize("operation_id", PUBLISHED)
def test_response_model_matches_the_document(operation_id):
    kind, schema = response_item_schema(operation_id)
    suffix = "Item" if kind == "items" else "Result"
    model = getattr(models, model_name(operation_id, suffix))
    assert not model.__required_keys__, "every response field is optional, as in the document"
    assert_matches(model, schema, operation_id)
    paged = OPERATION_BY_ID[operation_id].paging is not None
    assert paged == (kind == "items"), "a list answer is paged, a single item is not"


def test_the_pending_operation_follows_its_docs_file():
    operation = OPERATION_BY_ID["listApiKeySigningKeys"]
    assert (operation.method, operation.path, operation.group) == ("GET", "/api-keys/current/signing-keys", "api-keys")
    assert operation.params == (), "the docs: the request takes no parameters"
    assert not typing.get_type_hints(models.ListApiKeySigningKeysParams)
    hints = typing.get_type_hints(models.ApiKeySigningKey)
    fields = pending_fields()
    assert sorted(hints) == sorted(fields)
    for name, kind in fields.items():
        assert hints[name] is _SCALARS[kind], name
    assert models.ListApiKeySigningKeysItem is models.ApiKeySigningKey


def test_retry_classes_and_paging_follow_the_overlay():
    import json

    from sdk_vectors import ROOT

    overlay = json.loads((ROOT / "contract" / "overlay.json").read_text(encoding="utf-8"))["operations"]
    for operation in OPERATIONS:
        entry = overlay[operation.operation_id]
        assert operation.retry == entry["retry"], operation.operation_id
        if "cursorField" in entry:
            assert (operation.paging, operation.cursor_field) == ("cursor", entry["cursorField"]), operation.operation_id
        elif entry.get("paging") == "offset":
            assert operation.paging == "offset"
        else:
            assert operation.paging is None, operation.operation_id
        if operation.method == "GET":
            assert operation.retry == "read"


@pytest.mark.parametrize("operation_id", [op.operation_id for op in OPERATIONS if op.paging is not None and op.names("query")])
def test_page_size_limit_is_the_documented_maximum(operation_id):
    limit = next(param for param in params_of(operation_id) if param["name"] == "limit")
    assert OPERATION_BY_ID[operation_id].max_limit == limit["schema"]["maximum"]


# -- the methods ---------------------------------------------------------------------------------------


@pytest.fixture(scope="module")
def clients():
    sync_client = Vaultody("TEST", "VEVTVA==", "TEST", vault_key_store=MemoryVaultKeyStore())
    async_client = AsyncVaultody("TEST", "VEVTVA==", "TEST", vault_key_store=MemoryVaultKeyStore())
    yield sync_client, async_client
    sync_client.close()


@pytest.mark.parametrize("operation_id", sorted(OPERATION_BY_ID))
def test_each_client_has_the_method_in_its_docs_group(clients, operation_id):
    operation = OPERATION_BY_ID[operation_id]
    assert operation.namespace == GROUP_NAMESPACES[operation.group]
    for client in clients:
        method = getattr(getattr(client, operation.namespace), operation.method_name)
        assert method.__vaultody_operation__ == operation_id
        is_async = isinstance(client, AsyncVaultody)
        assert inspect.iscoroutinefunction(method) == (is_async and operation.paging is None), "lists are iterators, not coroutines"
        signature = inspect.signature(method)
        keyword_only = [name for name, param in signature.parameters.items() if param.kind is param.KEYWORD_ONLY]
        assert keyword_only == (["context", "max_items"] if operation.paging else ["context"])
        assert [param.kind for param in signature.parameters.values()][-1] is inspect.Parameter.VAR_KEYWORD
        annotations = method.__annotations__
        assert annotations["params"] == "Unpack[m.{}]".format(operation.model.__name__)
        result = model_name(operation_id, "Item" if operation.paging else "Result")
        if operation_id == "listApiKeySigningKeys":
            result = "ApiKeySigningKey"
        container = ("AsyncPages" if is_async else "Pages") if operation.paging else "Item"
        assert annotations["return"] == "{}[m.{}]".format(container, result)


def test_the_two_clients_have_exactly_the_same_methods(clients):
    sync_methods, async_methods = (client_methods(client) for client in clients)
    assert sync_methods == async_methods
    assert len(sync_methods) == 32
