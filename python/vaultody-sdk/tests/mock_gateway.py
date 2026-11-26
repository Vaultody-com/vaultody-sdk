"""A mock Vaultody API gateway for the client tests, served through httpx.MockTransport (Vaultody and
AsyncVaultody alike).

It checks requests the way the gateway does (HMAC v2, the timestamp window, the key-pair signature, the
replay rules: the first answer replayed for 3 s, then duplicate_api_request; a 429 forgets the request),
signs responses with the TEST-ONLY roots and pod keys of test-vectors/v1.json, and can play a man in the
middle: strip or alter signature headers, swap an address, change an xpub, inject a 429 or a 5xx, drop a
response after the request was carried out.

TEST-ONLY KEYS AND SECRETS throughout; they are public in test-vectors/.
"""

import base64
import hashlib
import hmac
import itertools
import json
import re
from urllib.parse import parse_qsl, unquote

import httpx
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from vaultody_verify import hmac_v2_signature, read_signing_key, verify_keypair_request

from sdk_vectors import load

RESPONSE_VECTORS = load("v1.json")
FULL_VECTORS = load("request-full-v1.json")
KEYPAIR_VECTORS = load("request-keypair-v1.json")
ADDRESS_VECTORS = load("address-v1.json")

CREDENTIALS = FULL_VECTORS["credentials"]
API_KEY = CREDENTIALS["apiKey"]
API_SECRET = CREDENTIALS["apiSecret"]
PASSPHRASE = CREDENTIALS["passphrase"]
ORIGIN = "https://rest.example.test"

ROOTS = RESPONSE_VECTORS["keys"]["roots"]
PODS = RESPONSE_VECTORS["keys"]["podKeys"]
PINNED_ROOTS = [base64.b64decode(ROOTS[name]["publicKeySpkiDerBase64"]) for name in ("current", "next")]
CLIENT_KEYS = KEYPAIR_VECTORS["keys"]

T0 = 1794201000


def private_key(pem):
    return serialization.load_pem_private_key(pem.encode("ascii"), password=None)


class FakeClock:
    """The time both the client and the gateway see; sleeping advances it."""

    def __init__(self, now=T0 + 0.25):
        self.now = float(now)
        self.sleeps = []

    def __call__(self):
        return self.now

    def sleep(self, seconds):
        self.sleeps.append(seconds)
        self.now += seconds

    def advance(self, seconds):
        self.now += seconds


class Nonces:
    """Distinct nonces, readable in a test: n-1, n-2, ..."""

    def __init__(self):
        self._counter = itertools.count(1)

    def __call__(self):
        return "n-{}".format(next(self._counter))


def envelope_item(item, request_id="6630f1c2a9e4b5d7c8e9f001"):
    return {"apiVersion": "2026-03-20", "requestId": request_id, "data": {"item": item}}


def envelope_page(items, has_more=False, limit=50, starting_after=None, request_id="6630f1c2a9e4b5d7c8e9f002"):
    return {
        "apiVersion": "2026-03-20",
        "requestId": request_id,
        "data": {"limit": limit, "startingAfter": starting_after, "hasMore": has_more, "items": items},
    }


def envelope_error(code, message="TEST error", request_id="6630f1c2a9e4b5d7c8e9f003", details=None):
    error = {"code": code, "message": message}
    if details is not None:
        error["details"] = details
    return {"apiVersion": "2026-03-20", "requestId": request_id, "error": error}


class ResponseSigner:
    """Signs responses as the gateway does (vaultody-response-v1), with a TEST-ONLY root and pod key.

    The certificate is valid for an hour at most, as the gateway's are (a longer one is refused): by default from
    a minute before T0, which covers the clock range the tests run in.
    """

    def __init__(self, root="current", pod="pod1", not_before=T0 - 60, not_after=T0 + 3540):
        self.root_key = private_key(ROOTS[root]["privateKeyPkcs8Pem"])
        self.pod_key = private_key(PODS[pod]["privateKeyPkcs8Pem"])
        cert = "\n".join((
            "vaultody-response-key-v1",
            ROOTS[root]["rootId"],
            PODS[pod]["publicKeyBase64"],
            PODS[pod]["keyId"],
            str(not_before),
            str(not_after),
        )).encode("ascii")
        signature = self.root_key.sign(cert, ec.ECDSA(hashes.SHA256()))
        self.cert_header = base64.b64encode(cert).decode("ascii") + "." + base64.b64encode(signature).decode("ascii")

    def headers(self, request, request_body, status, body, ts, unread=False):
        path, _, query = request.url.raw_path.decode("ascii").partition("?")
        body_hash = "unread" if unread else hashlib.sha256(request_body).hexdigest()
        head = "\n".join((
            "vaultody-response-v1", str(ts), str(status), request.method, path, query, body_hash,
            request.headers.get("x-api-sign", ""), request.headers.get("x-api-keypair-sign", ""),
        ))
        signature = self.pod_key.sign(head.encode("ascii") + b"\n" + body)
        return {
            "x-api-response-sign": base64.b64encode(signature).decode("ascii"),
            "x-api-response-timestamp": str(ts),
            "x-api-response-sign-version": "1",
            "x-api-response-cert": self.cert_header,
        }


class Respond(Exception):
    """Raised by a route or a check to answer at once."""

    def __init__(self, status, payload, headers=None):
        super().__init__(status)
        self.status = status
        self.payload = payload
        self.headers = headers or {}


def vault_item(vault_id, vault_type="main", keys=None):
    item = {"id": vault_id, "name": "Vault " + vault_id[-2:], "type": vault_type, "backuped": True, "createdTimestamp": 1725458109}
    if keys is not None:
        item["mpcKeys"] = [{"algorithm": algorithm, "xpub": xpub} for algorithm, xpub in keys.items() if xpub]
    return item


class MockGateway:
    """The handler of an httpx.MockTransport.

    :param clock: the FakeClock shared with the client
    :param sign_responses: sign every answer (False: answer unsigned, as production does today)
    :param registered_keys: names of CLIENT_KEYS registered on the API key; their signatures are required
    """

    def __init__(self, clock, *, sign_responses=True, signer=None, registered_keys=(), replay_window_ms=3000):
        self.clock = clock
        self.sign_responses = sign_responses
        self.signer = signer or ResponseSigner()
        self.registered = [read_signing_key(CLIENT_KEYS[name]["publicKeySpkiPem"]) for name in registered_keys]
        self.replay_window_ms = replay_window_ms
        self.routes = []
        self.received = []
        self.replay = {}
        # Interventions, consumed one per request in order: see intervene().
        self.plan = []
        self.vaults = {"main": [], "test": []}
        self.addresses = {}
        self.transfers = []
        self._default_routes()

    # -- configuration ----------------------------------------------------------------------------

    def route(self, method, pattern, handler):
        """``handler(request, match, body_json) -> (status, payload)``; registered routes win over defaults."""
        self.routes.insert(0, (method, re.compile(pattern), handler))

    def intervene(self, *steps):
        """Queue what happens to the next requests, one step each (None: nothing):

        - ``"connect_error"``: the connection fails before anything is sent;
        - ``"read_timeout"``: the request arrives and is carried out, the answer is lost;
          ``("read_timeout", seconds)``: the same, noticed only after that many seconds;
        - ``"timeout_before"``: the request arrives, is not carried out, and times out;
        - ``("status", 429 | 5xx)``: answered with this error instead of the route (a 429 forgets the request);
        - ``("after", 5xx)``: carried out, then answered with this error;
        - ``"strip"``: the signature headers removed; ``("strip_one", name)``: one of them removed;
        - ``("tamper", f)``: the answer body replaced by ``f(body bytes)`` after signing;
        - ``("in_progress",)``: answered 409 duplicate_api_request_in_progress.
        """
        self.plan.extend(steps)

    def transport(self):
        return httpx.MockTransport(self)

    # -- the handler ------------------------------------------------------------------------------

    def __call__(self, request):
        body = request.content
        self.received.append(request)
        step = self.plan.pop(0) if self.plan else None
        if step == "connect_error":
            raise httpx.ConnectError("TEST connection refused", request=request)
        if step == "timeout_before":
            raise httpx.ReadTimeout("TEST timed out", request=request)
        status, payload, headers, unread = self._answer(request, body, step)
        raw = payload if isinstance(payload, bytes) else json.dumps(payload, separators=(",", ":")).encode("utf-8")
        if step == "read_timeout" or (isinstance(step, tuple) and step[0] == "read_timeout"):
            if isinstance(step, tuple):
                self.clock.advance(step[1])
            raise httpx.ReadTimeout("TEST timed out after the request was carried out", request=request)
        if self.sign_responses:
            headers.update(self.signer.headers(request, body, status, raw, int(self.clock()), unread=unread))
        if step == "strip":
            for name in ("x-api-response-sign", "x-api-response-timestamp", "x-api-response-sign-version", "x-api-response-cert"):
                headers.pop(name, None)
        if isinstance(step, tuple) and step[0] == "strip_one":
            headers.pop(step[1], None)
        if isinstance(step, tuple) and step[0] == "tamper":
            raw = step[1](raw)
        return httpx.Response(status, headers=headers, content=raw)

    def _answer(self, request, body, step):
        try:
            nonce = self._authenticate(request, body)
            if isinstance(step, tuple) and step[0] == "status":
                if step[1] == 429:
                    self.replay.pop(nonce, None)
                    raise Respond(429, envelope_error("request_limit_reached", "TEST too many requests"))
                raise Respond(step[1], envelope_error("unexpected_server_error"))
            if isinstance(step, tuple) and step[0] == "in_progress":
                raise Respond(409, envelope_error("duplicate_api_request_in_progress"))
            record = self.replay.get(nonce)
            now_ms = int(self.clock() * 1000)
            if record is not None:
                if now_ms - record["at"] <= self.replay_window_ms:
                    status, payload = record["answer"]
                    return status, payload, {"x-api-replayed": "true"}, False
                raise Respond(401, envelope_error("duplicate_api_request"))
            record = self.replay[nonce] = {"at": now_ms, "answer": None}
            status, payload = self._route(request, body)
            if isinstance(step, tuple) and step[0] == "after":
                status, payload = step[1], envelope_error("unexpected_server_error")
            record["answer"] = (status, payload)
            return status, payload, {}, False
        except Respond as answer:
            return answer.status, answer.payload, dict(answer.headers), False

    def _authenticate(self, request, body):
        headers = request.headers
        if headers.get("x-api-sign-version") != "2":
            raise Respond(401, envelope_error("invalid_api_sign"))
        if headers.get("x-api-key") != API_KEY or headers.get("x-api-passphrase") != PASSPHRASE:
            raise Respond(401, envelope_error("invalid_api_key"))
        timestamp = headers.get("x-api-timestamp", "")
        if not timestamp.isdigit() or abs(int(timestamp) - self.clock()) > 40:
            raise Respond(401, envelope_error("invalid_api_timestamp"))
        path, _, query = request.url.raw_path.decode("ascii").partition("?")
        fields = {
            "timestamp": timestamp,
            "method": request.method,
            "path": path,
            "apiVersion": headers.get("x-api-version", ""),
            "passphrase": headers.get("x-api-passphrase"),
            "nonce": headers.get("x-api-nonce", ""),
            "query": query,
            "body": body.decode("utf-8"),
        }
        expected = hmac_v2_signature(API_SECRET, fields)
        if not hmac.compare_digest(expected, headers.get("x-api-sign", "")):
            raise Respond(401, envelope_error("invalid_api_sign"))
        if self.registered and path != "/api-keys/current/signing-keys":
            if not headers.get("x-api-keypair-sign"):
                raise Respond(401, envelope_error("missing_api_keypair_sign"))
            # Checked over the x-api-key the request came with (the HMAC above does not cover it).
            received = dict(fields, apiKey=headers.get("x-api-key"))
            verdict = verify_keypair_request(self.registered, received, headers.get("x-api-keypair-id"), headers.get("x-api-keypair-sign"))
            if not verdict["valid"]:
                raise Respond(401, envelope_error(verdict["reason"]))
        return fields["nonce"]

    def _route(self, request, body):
        path, _, query = request.url.raw_path.decode("ascii").partition("?")
        parsed = json.loads(body) if body else None
        for method, pattern, handler in self.routes:
            match = pattern.fullmatch(path)
            if method == request.method and match is not None:
                request.query_pairs = parse_qsl(query, keep_blank_values=True)
                return handler(request, match, parsed)
        return 404, envelope_error("resource_not_found")

    # -- default routes ---------------------------------------------------------------------------

    def _default_routes(self):
        self.route("GET", r"/vaults/(main|test)", self._list_vaults)
        self.route("POST", r"/vaults/([^/]+)/([^/]+)/([^/]+)/addresses", self._new_address)
        self.route("GET", r"/vaults/([^/]+)/vault-accounts/([^/]+)/list-addresses", self._list_addresses)
        self.route("PUT", r"/vaults/([^/]+)/vault-accounts/([^/]+)/add-asset", self._add_asset)
        self.route("GET", r"/api-keys/current/signing-keys", self._signing_keys)
        self.route("POST", r"/vaults/([^/]+)/transaction-requests/single-transfer", self._transfer)
        self.route("GET", r"/ping", lambda request, match, body: (200, envelope_item({"pong": True})))

    def _list_vaults(self, request, match, body):
        query = dict(request.query_pairs)
        vaults = self.vaults[match.group(1).lower()]
        limit = int(query.get("limit", 50))
        start = 0
        if query.get("startingAfter"):
            start = next(i for i, vault in enumerate(vaults) if vault["id"] == query["startingAfter"]) + 1
        page = vaults[start:start + limit]
        return 200, envelope_page(page, has_more=start + limit < len(vaults), limit=limit, starting_after=query.get("startingAfter"))

    def _new_address(self, request, match, body):
        key = tuple(unquote(part) for part in match.groups())
        queue = self.addresses.get(key)
        if not queue:
            return 404, envelope_error("resource_not_found")
        item = dict(queue.pop(0))
        item.setdefault("createdTimestamp", 1759823400)
        if body and body.get("data", {}).get("item", {}).get("label"):
            item["label"] = body["data"]["item"]["label"]
        return 201, envelope_item(item)

    def _list_addresses(self, request, match, body):
        items = self.addresses.get(("list",) + tuple(unquote(part) for part in match.groups()), [])
        return 200, envelope_page(items)

    def _add_asset(self, request, match, body):
        sent = body["data"]["item"]
        return 200, envelope_item({"address": sent["address"], "assetUnit": "USDT", "balance": "0", "decimals": "6"})

    def _signing_keys(self, request, match, body):
        items = [
            {"fingerprint": key.fingerprint, "algorithm": key.algorithm, "status": "active", "createdTimestamp": 1795000000, "approvedTimestamp": 1795000300}
            for key in self.registered
        ]
        return 200, {"apiVersion": "2026-03-20", "requestId": "6630f1c2a9e4b5d7c8e9f0e1", "data": {"limit": 2, "offset": 0, "total": len(items), "items": items}}

    def _transfer(self, request, match, body):
        self.transfers.append(body)
        return 201, envelope_item({"transactionRequestId": "6630f1c2a9e4b5d7c8e9{:04d}".format(len(self.transfers)), "transactionRequestStatus": "created"})


# ---------------------------------------------------------------------------------------------------
# Vaults and addresses from test-vectors/address-v1.json
# ---------------------------------------------------------------------------------------------------

XPUBS = {entry["name"]: entry for entry in ADDRESS_VECTORS["xpubs"]}
ECDSA_XPUB = XPUBS["ecdsa-bip32-tv1-master"]["xpub"]
EDDSA_XPUB = next(entry["xpub"] for entry in ADDRESS_VECTORS["xpubs"] if entry["algorithm"] == "EDDSA")
OTHER_ECDSA_XPUB = next(entry["xpub"] for entry in ADDRESS_VECTORS["xpubs"] if entry["algorithm"] == "ECDSA" and entry["xpub"] != ECDSA_XPUB)

VAULT_MAIN = "6630f1c2a9e4b5d7c8e9f0a1"
VAULT_TEST = "6630f1c2a9e4b5d7c8e9f0b2"
VAULT_SMART = "6630f1c2a9e4b5d7c8e9f0d7"
ACCOUNT = "69ba58c529eb49000746b311"


def address_case(blockchain, network, address_format=None, xpub=ECDSA_XPUB, path=None):
    """An address case of the vectors for this chain, network and xpub (first one, or the given path)."""
    for case in ADDRESS_VECTORS["cases"]:
        if (case["blockchain"], case["network"], case["xpub"]) != (blockchain, network, xpub):
            continue
        if address_format is not None and case["addressFormatWire"] != address_format:
            continue
        if path is not None and case["path"] != path:
            continue
        return case
    raise LookupError((blockchain, network, address_format, path))


def address_item(case, *, with_path=True, with_network=False, with_format=True):
    item = {"address": case["address"], "addressId": "addr-" + case["path"].replace("/", "-"), "blockchain": case["blockchain"], "label": "TEST"}
    if with_path:
        item.update(accountIndex=case["accountIndex"], isChange=case["change"], addressIndex=str(case["addressIndex"]))
    if with_network:
        item["network"] = case["network"]
    if with_format:
        item["addressFormat"] = case["addressFormatWire"]
    return item


def standard_vaults(gateway):
    """A main vault and a test vault with the vector xpubs, and a SMART vault without MPC keys."""
    gateway.vaults["main"] = [
        vault_item(VAULT_MAIN, "main", {"ECDSA": ECDSA_XPUB, "EDDSA": EDDSA_XPUB}),
        vault_item(VAULT_SMART, "main", None),
    ]
    gateway.vaults["test"] = [vault_item(VAULT_TEST, "test", {"ECDSA": ECDSA_XPUB, "EDDSA": EDDSA_XPUB})]
