"""The request-signing vector sets through both clients: what each client puts on the wire.

- request-hmac-v2.json: x-api-sign for each request the SDK can send as written;
- request-full-v1.json: every authentication header, with and without a key pair;
- request-keypair-v1.json: the key-pair signature, the gateway's verdict reaching the caller as a typed
  error, and the fingerprint of every public key form;
- p1363-der-v1.json: a P-256 signer returning IEEE P1363 r || s, sent as DER.

The client gets the vector's clock, nonce and x-api-version through the unsupported test hooks; the
mock transport records what was sent.
"""

import base64
import json
import re
from urllib.parse import quote, unquote

import httpx
import pytest

from vaultody_sdk import CallbackSigner, ConfigurationError, PemSigner, RequestSigningError, SignerError
from vaultody_sdk._core import Hooks
from vaultody_verify import read_signing_key, verify_keypair_request
from vaultody_verify.keys import verify_message

from conftest import make_client, run
from mock_gateway import ORIGIN, FakeClock, envelope_error, envelope_item, envelope_page
from sdk_vectors import ids, load

HMAC = load("request-hmac-v2.json")
FULL = load("request-full-v1.json")
KEYPAIR = load("request-keypair-v1.json")
P1363 = load("p1363-der-v1.json")

# What the SDK never sends, so a client can't reproduce these cases (the verify package runs them on the
# signing functions): it always sends a nonce and x-api-version, encodes every query value itself (a raw
# "?" becomes %3F), and writes the JSON body itself (compact, no trailing newline).
NOT_SENDABLE = {
    "request-hmac-v2.json": {"get_empty_fields", "no_api_version", "no_nonce", "query_with_question_mark", "unicode_body", "body_trailing_newline"},
    "request-full-v1.json": {"legacy_without_api_version"},
    "request-keypair-v1.json": {
        "valid_ed25519_get_empty_fields", "valid_p256_get_empty_fields", "valid_ed25519_raw_query_as_sent", "valid_ed25519_raw_body_as_sent",
    },
}


class Recorder:
    """A transport that records requests and answers each with an unsigned item, so the clients that use it have
    no response-signing roots (a release candidate before the API signs) and accept that."""

    def __init__(self, answer=None):
        self.requests = []
        self.answer = answer or self.default

    @staticmethod
    def default(request):
        if re.fullmatch(r"(/v2)?/vaults/(main|test)", request.url.path):
            return httpx.Response(200, json=envelope_page([]))
        # An address without its derivation path: the deposit-address route reports it not verifiable.
        return httpx.Response(200, json=envelope_item({"ok": True, "address": "TEST-address"}))

    def __call__(self, request):
        self.requests.append(request)
        return self.answer(request)

    def transport(self):
        return httpx.MockTransport(self)


def as_call(fields):
    """The request() arguments that send exactly these request fields, or None when the SDK can't."""
    if not fields.get("nonce") or not fields.get("apiVersion"):
        return None
    pairs = []
    if fields["query"]:
        for part in fields["query"].split("&"):
            name, separator, value = part.partition("=")
            if not separator:
                return None
            pairs.append((unquote(name), unquote(value)))
        if "&".join("{}={}".format(quote(n, safe=""), quote(v, safe="")) for n, v in pairs) != fields["query"]:
            return None
    call = {"method": fields["method"], "path": fields["path"], "query": pairs}
    if fields["body"]:
        try:
            document = json.loads(fields["body"])
        except ValueError:
            return None
        if not isinstance(document, dict) or set(document) - {"context", "data"} or set(document.get("data", {})) != {"item"}:
            return None
        call["item"] = document["data"]["item"]
        if "context" in document:
            call["context"] = document["context"]
        written = json.dumps(document, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        if written != fields["body"].encode("utf-8") or list(document) != (["context", "data"] if "context" in document else ["data"]):
            return None
    elif fields["method"] != "GET":
        return None
    return call


def hooks_for(fields):
    clock = FakeClock(int(fields["timestamp"]) + 0.5)
    return Hooks(clock=clock, sleep=clock.sleep, random=lambda: 0.5, nonce=lambda: fields["nonce"], timestamp=lambda: fields["timestamp"], api_version=fields["apiVersion"])


def send(kind, call, *, credentials, fields, signer=None, recorder=None, **options):
    """Sends one call with the vector's clock and nonce; returns the recorded request."""
    recorder = recorder or Recorder()
    base_url = ORIGIN + ("/v2" if call["path"].startswith("/v2/") else "")
    path = call["path"][3:] if call["path"].startswith("/v2/") else call["path"]
    options.setdefault("roots", None)
    client = make_client(kind, None, hooks=hooks_for(fields), credentials=credentials, signer=signer, transport=recorder.transport(), base_url=base_url, **options)
    arguments = {key: value for key, value in call.items() if key in ("query", "item", "context")}

    async def scenario(api):
        return await api.request(call["method"], path, **arguments)

    run(kind, client, scenario)
    return recorder.requests[-1]


def sendable(vectors, name, cases, fields_of):
    unsendable = {case["name"] for case in cases if as_call(fields_of(case)) is None}
    assert unsendable == NOT_SENDABLE[name], "the cases a client can't send changed"
    return [case for case in cases if case["name"] not in unsendable]


# -- request-hmac-v2.json ---------------------------------------------------------------------------

HMAC_CASES = [case for case in HMAC["cases"] if "error" not in case["expected"]]
HMAC_SENDABLE = sendable(HMAC, "request-hmac-v2.json", HMAC_CASES, lambda case: case["request"])
HMAC_ERRORS = [case for case in HMAC["cases"] if "error" in case["expected"]]


@pytest.mark.parametrize("vector", HMAC_SENDABLE, ids=ids(HMAC_SENDABLE))
def test_hmac_v2_signature_on_the_wire(kind, vector):
    fields = vector["request"]
    sent = send(kind, as_call(fields), credentials=("TEST-key", vector["secret"], fields["passphrase"]), fields=fields)
    assert sent.headers["x-api-sign"] == vector["expected"]["signature"]
    assert sent.headers["x-api-sign-version"] == "2"
    assert sent.url.raw_path.decode("ascii") == fields["path"] + ("?" + fields["query"] if fields["query"] else "")
    assert sent.content == fields["body"].encode("utf-8")


@pytest.mark.parametrize("vector", HMAC_ERRORS, ids=ids(HMAC_ERRORS))
def test_an_unusable_secret_is_refused_before_anything_is_sent(kind, vector):
    with pytest.raises(ConfigurationError) as raised:
        make_client(kind, None, credentials=("TEST-key", vector["secret"], "TEST passphrase"))
    assert raised.value.code == vector["expected"]["error"]
    if vector["secret"]:
        assert vector["secret"] not in str(raised.value)


# -- request-full-v1.json ---------------------------------------------------------------------------

FULL_SENDABLE = sendable(FULL, "request-full-v1.json", FULL["cases"], lambda case: case["request"])
CREDENTIALS = (FULL["credentials"]["apiKey"], FULL["credentials"]["apiSecret"], FULL["credentials"]["passphrase"])


@pytest.mark.parametrize("vector", FULL_SENDABLE, ids=ids(FULL_SENDABLE))
def test_every_authentication_header(kind, vector):
    fields = vector["request"]
    signer = PemSigner(FULL["keys"][vector["key"]]["privateKeyPkcs8Pem"]) if vector["key"] else None
    sent = send(kind, as_call(fields), credentials=CREDENTIALS, fields=fields, signer=signer)
    expected = vector["expected"]["headers"]
    actual = {name: sent.headers.get(name) for name in expected}
    if vector["expected"].get("keypairSignature") == "verify":
        # P-256 signatures are randomised: the one sent must verify over the key-pair string.
        key = read_signing_key(FULL["keys"][vector["key"]]["publicKeySpkiPem"])
        message = base64.b64decode(vector["expected"]["keypairSignedStringBase64"])
        assert verify_message(key, message, actual.pop("x-api-keypair-sign"))
        expected = {name: value for name, value in expected.items() if name != "x-api-keypair-sign"}
    assert actual == expected
    # In the vector's order, and nothing else of that family.
    names = [name for name, _ in sent.headers.multi_items() if name.startswith("x-api-")]
    assert names == list(vector["expected"]["headers"])


def test_the_sdk_headers_besides_authentication(kind):
    fields = FULL["cases"][0]["request"]
    sent = send(kind, as_call(fields), credentials=CREDENTIALS, fields=fields)
    assert sent.headers["user-agent"].startswith("vaultody-sdk-python/")
    assert sent.headers["accept"] == "application/json"
    assert "content-type" not in sent.headers
    post = next(case for case in FULL["cases"] if case["name"] == "legacy_post_create_address")["request"]
    assert send(kind, as_call(post), credentials=CREDENTIALS, fields=post).headers["content-type"] == "application/json"


# -- request-keypair-v1.json ------------------------------------------------------------------------

VALID = [case for case in KEYPAIR["cases"] if case["category"] == "valid"]
VALID_SENDABLE = sendable(KEYPAIR, "request-keypair-v1.json", VALID, lambda case: case["signed"]["request"])
REFUSED = [case for case in KEYPAIR["cases"] if case["category"] != "valid"]


@pytest.mark.parametrize("vector", VALID_SENDABLE, ids=ids(VALID_SENDABLE))
def test_keypair_signature_the_gateway_accepts(kind, vector):
    fields = vector["signed"]["request"]
    key = KEYPAIR["keys"][vector["signed"]["key"]]
    registered = [read_signing_key(KEYPAIR["keys"][name]["publicKeySpkiPem"]) for name in vector["verify"]["registeredKeys"]]
    # Sent with the vector's API key: the key-pair string carries it.
    sent = send(kind, as_call(fields), credentials=(fields["apiKey"], "9PRj8ICIohJMpg==", fields["passphrase"]), fields=fields, signer=PemSigner(key["privateKeyPkcs8Pem"]))
    assert sent.headers["x-api-keypair-id"] == key["fingerprint"]
    if key["algorithm"] == "ed25519":
        assert sent.headers["x-api-keypair-sign"] == vector["signed"]["signature"]
    assert verify_keypair_request(registered, fields, sent.headers["x-api-keypair-id"], sent.headers["x-api-keypair-sign"]) == {"valid": True}


@pytest.mark.parametrize("vector", REFUSED, ids=ids(REFUSED))
def test_the_gateways_refusal_reaches_the_caller_typed(kind, vector):
    """The verdict on the vector's request as received comes back through the client as RequestSigningError."""
    verify = vector["verify"]
    registered = [read_signing_key(KEYPAIR["keys"][name]["publicKeySpkiPem"]) for name in verify["registeredKeys"]]
    verdict = verify_keypair_request(registered, verify["request"], verify["headers"]["x-api-keypair-id"], verify["headers"]["x-api-keypair-sign"])
    assert verdict == vector["expected"]
    recorder = Recorder(lambda request: httpx.Response(401, json=envelope_error(verdict["reason"])))
    client = make_client(kind, None, transport=recorder.transport(), roots=None)

    async def scenario(api):
        with pytest.raises(RequestSigningError) as raised:
            await api.request("POST", "/vaults/{vaultId}/transaction-requests/single-transfer", path_params={"vaultId": "v1"}, item={})
        return raised.value

    error = run(kind, client, scenario)
    assert (error.status, error.code) == (401, verdict["reason"])
    assert len(recorder.requests) == 1, "a refused write is never sent again"


@pytest.mark.parametrize("vector", KEYPAIR["publicKeys"], ids=ids(KEYPAIR["publicKeys"]))
def test_the_fingerprint_of_each_public_key_form(kind, vector):
    algorithm = vector["expected"].get("algorithm", "ed25519")
    private = next((key["privateKeyPkcs8Pem"] for key in KEYPAIR["keys"].values() if key.get("fingerprint") == vector["expected"].get("fingerprint")), None)
    signing = PemSigner(private) if private else None
    if "error" in vector["expected"]:
        with pytest.raises(ConfigurationError) as raised:
            CallbackSigner(algorithm, vector["publicKeyPem"], lambda message: b"")
        assert raised.value.code == vector["expected"]["error"]
        return
    signer = CallbackSigner(algorithm, vector["publicKeyPem"], signing.sign)
    assert signer.fingerprint == vector["expected"]["fingerprint"]
    fields = FULL["cases"][0]["request"]
    sent = send(kind, as_call(fields), credentials=CREDENTIALS, fields=fields, signer=signer)
    assert sent.headers["x-api-keypair-id"] == vector["expected"]["fingerprint"]


# -- p1363-der-v1.json ------------------------------------------------------------------------------

P1363_PEM = "-----BEGIN PUBLIC KEY-----\n{}\n-----END PUBLIC KEY-----\n".format(P1363["publicKeySpkiDerBase64"])


@pytest.mark.parametrize("vector", P1363["cases"], ids=ids(P1363["cases"]))
def test_a_p1363_signature_is_sent_as_der(kind, vector):
    signature = bytes.fromhex(vector["p1363Hex"])
    signer = CallbackSigner("p-256", P1363_PEM, lambda message: signature)
    fields = FULL["cases"][0]["request"]
    if vector["name"] == "der_given":
        # p1363_to_der refuses DER, but a signer may return DER (AWS and GCP KMS, Vault Transit with
        # asn1 do): the client sends it unchanged.
        sent = send(kind, as_call(fields), credentials=CREDENTIALS, fields=fields, signer=signer, verify_signatures_locally=False)
        assert base64.b64decode(sent.headers["x-api-keypair-sign"]) == signature
        return
    if "error" in vector["expected"]:
        with pytest.raises(SignerError) as raised:
            send(kind, as_call(fields), credentials=CREDENTIALS, fields=fields, signer=signer, verify_signatures_locally=False)
        assert raised.value.code == vector["expected"]["error"]
        return
    # The vector's signature is over its own message, not this request: sent unchecked here; the local
    # check is tested with real signers in test_signers.py.
    sent = send(kind, as_call(fields), credentials=CREDENTIALS, fields=fields, signer=signer, verify_signatures_locally=False)
    assert base64.b64decode(sent.headers["x-api-keypair-sign"]).hex() == vector["expected"]["derHex"]
