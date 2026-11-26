"""Retries in both clients, as timelines against the mock gateway: one scenario per row of the retry table.

test_retry_vectors.py runs test-vectors/retry-v1.json on decide_retry, which both clients call after every
attempt. Those inputs are single synthetic states (for example attempt 4 with 0 ms elapsed) that no real
timeline produces, so here each row is played out instead, and the gateway counts what actually ran.
"""

import httpx
import pytest

from vaultody_sdk import (
    ConflictError,
    PemSigner,
    RateLimitError,
    RequestOutcomeUnknownError,
    ServerError,
    TransportError,
)

from conftest import make_client, run
from mock_gateway import CLIENT_KEYS, MockGateway, envelope_error, envelope_item

TRANSFER = "/vaults/{vaultId}/transaction-requests/single-transfer"
# The clients have response-signing roots, so before their first write they make one signed read
# (GET /api-keys/current/signing-keys); nothing happens to it.
SIGNED_READ = None


def transfer(api):
    return api.request("POST", TRANSFER, path_params={"vaultId": "v1"}, item={"amount": "0.1"})


def ping(api):
    return api.request("GET", "/ping")


def keypair_gateway(clock, **options):
    return MockGateway(clock, registered_keys=["ed25519"], **options)


def keypair_client(kind, gateway, **options):
    return make_client(kind, gateway, signer=PemSigner(CLIENT_KEYS["ed25519"]["privateKeyPkcs8Pem"]), **options)


def posts(gateway):
    return [request for request in gateway.received if request.method == "POST"]


def expect(kind, client, call, error_class):
    async def scenario(api):
        with pytest.raises(error_class) as raised:
            await call(api)
        return raised.value

    return run(kind, client, scenario)


# -- reads --------------------------------------------------------------------------------------------


def test_read_5xx_is_retried_resigned_with_backoff(kind, gateway, clock):
    gateway.intervene(("status", 503), ("status", 502))
    result = run(kind, make_client(kind, gateway), ping)
    assert result.item == {"pong": True}
    assert len({request.headers["x-api-nonce"] for request in gateway.received}) == 3, "re-signed every time"
    assert clock.sleeps == [0.5, 1.0], "full jitter at random 0.5: 1 s, then 2 s ceilings"


def test_read_not_sent_and_sent_unknown_are_retried(kind, gateway):
    gateway.intervene("connect_error", "read_timeout")
    assert run(kind, make_client(kind, gateway), ping).item == {"pong": True}
    assert len(gateway.received) == 3


def test_read_429_honours_a_longer_retry_after(kind, clock):
    gateway = MockGateway(clock)

    def limited(request, match, body):
        return 429, envelope_error("request_limit_reached")

    calls = []

    def ping_route(request, match, body):
        calls.append(1)
        if len(calls) == 1:
            return 429, envelope_error("request_limit_reached")
        return 200, envelope_item({"pong": True})

    gateway.route("GET", r"/ping", ping_route)
    original = gateway.__call__

    def with_retry_after(request):
        response = original(request)
        if response.status_code == 429:
            response.headers["retry-after"] = "3"
        return response

    client = make_client(kind, None, clock=clock, transport=httpx.MockTransport(with_retry_after))
    assert run(kind, client, ping).item == {"pong": True}
    assert clock.sleeps == [3.0]


def test_read_gives_up_after_five_attempts(kind, gateway):
    gateway.intervene(*[("status", 503)] * 5)
    error = expect(kind, make_client(kind, gateway), ping, ServerError)
    assert error.status == 503 and len(gateway.received) == 5


def test_read_never_waits_past_the_deadline(kind, gateway, clock):
    gateway.route("GET", r"/ping", lambda request, match, body: (503, envelope_error("unexpected_server_error")))

    def slow(request):
        clock.advance(29.6)  # the answer takes 29.6 s: a 0.5 s backoff would end past the 30 s deadline
        return gateway(request)

    client = make_client(kind, None, clock=clock, transport=httpx.MockTransport(slow))
    expect(kind, client, ping, ServerError)
    assert len(gateway.received) == 1


def test_a_4xx_is_never_retried(kind, gateway):
    gateway.route("GET", r"/ping", lambda request, match, body: (404, envelope_error("resource_not_found")))
    expect(kind, make_client(kind, gateway), ping, Exception)
    assert len(gateway.received) == 1


# -- writes, legacy key (or a key pair not confirmed) ------------------------------------------------


def test_legacy_write_timeout_after_sending_is_outcome_unknown_and_never_resent(kind, gateway):
    gateway.intervene(SIGNED_READ, "read_timeout")
    error = expect(kind, make_client(kind, gateway), transfer, RequestOutcomeUnknownError)
    assert len(gateway.transfers) == 1 and len(posts(gateway)) == 1
    assert error.in_progress is False
    assert error.nonce == posts(gateway)[0].headers["x-api-nonce"]
    assert error.timestamp == posts(gateway)[0].headers["x-api-timestamp"]


def test_legacy_write_5xx_after_running_is_outcome_unknown_with_the_request_id(kind, gateway):
    gateway.intervene(SIGNED_READ, ("after", 500))
    error = expect(kind, make_client(kind, gateway), transfer, RequestOutcomeUnknownError)
    assert len(gateway.transfers) == 1 and len(posts(gateway)) == 1
    assert error.request_id == "6630f1c2a9e4b5d7c8e9f003"


def test_legacy_write_not_sent_is_resent_unchanged(kind, gateway, clock):
    gateway.intervene(SIGNED_READ, "connect_error")
    result = run(kind, make_client(kind, gateway), transfer)
    assert result.item["transactionRequestStatus"] == "created"
    first, second = posts(gateway)
    for name in ("x-api-nonce", "x-api-timestamp", "x-api-sign"):
        assert first.headers[name] == second.headers[name], "the same signed request"
    assert len(gateway.transfers) == 1
    assert clock.sleeps == [0.5]


def test_legacy_write_429_is_resent_unchanged_and_runs_once(kind, gateway):
    gateway.intervene(SIGNED_READ, ("status", 429))
    run(kind, make_client(kind, gateway), transfer)
    first, second = posts(gateway)
    assert first.headers["x-api-sign"] == second.headers["x-api-sign"]
    assert len(gateway.transfers) == 1


def test_a_write_resigned_keeps_its_nonce_and_body(kind, clock):
    # A 429 asking to wait 25 s: the signature would be too old to resend, so the write is signed again, over
    # the same nonce and body (one operation per nonce), and runs once.
    gateway = MockGateway(clock)
    gateway.intervene(SIGNED_READ, ("status", 429))
    original = gateway.__call__

    def with_retry_after(request):
        response = original(request)
        if response.status_code == 429:
            response.headers["retry-after"] = "25"
        return response

    client = make_client(kind, None, clock=clock, transport=httpx.MockTransport(with_retry_after))
    run(kind, client, transfer)
    first, second = posts(gateway)
    assert first.headers["x-api-nonce"] == second.headers["x-api-nonce"]
    assert first.content == second.content
    assert first.headers["x-api-timestamp"] != second.headers["x-api-timestamp"]
    assert first.headers["x-api-sign"] != second.headers["x-api-sign"]
    assert clock.sleeps == [25.0]
    assert len(gateway.transfers) == 1


def test_a_429_until_the_attempts_run_out_is_the_rate_limit_error(kind, gateway):
    gateway.intervene(SIGNED_READ, *[("status", 429)] * 5)
    expect(kind, make_client(kind, gateway), transfer, RateLimitError)
    assert gateway.transfers == []


def test_a_write_with_a_key_pair_the_gateway_does_not_list_counts_as_legacy(kind, clock):
    gateway = MockGateway(clock)  # the key pair is not registered: replay protection may only report
    gateway.intervene(None, "read_timeout")  # the signing-keys check passes; the transfer times out
    expect(kind, keypair_client(kind, gateway), transfer, RequestOutcomeUnknownError)
    assert len(posts(gateway)) == 1 and len(gateway.transfers) == 1


def test_an_unsigned_confirmation_does_not_count(kind, clock):
    """Production does not sign yet: an unsigned 'active' could be forged, so the key stays legacy. (A release
    candidate without roots: a client with roots refuses the unsigned answer, and never sends the write.)"""
    gateway = keypair_gateway(clock, sign_responses=False)
    gateway.intervene(None, "read_timeout")
    expect(kind, keypair_client(kind, gateway, roots=None), transfer, RequestOutcomeUnknownError)
    assert len(posts(gateway)) == 1


def test_a_failed_confirmation_counts_as_legacy(kind, clock):
    gateway = keypair_gateway(clock)
    gateway.intervene(("status", 404), "read_timeout")
    expect(kind, keypair_client(kind, gateway), transfer, RequestOutcomeUnknownError)
    assert len(posts(gateway)) == 1


# -- writes, key pair confirmed ----------------------------------------------------------------------


def test_keypair_write_timeout_is_resent_at_once_and_the_first_answer_replayed(kind, clock):
    gateway = keypair_gateway(clock)
    gateway.intervene(None, "read_timeout")
    result = run(kind, keypair_client(kind, gateway), transfer)
    assert result.meta.replayed is True
    assert result.item["transactionRequestStatus"] == "created"
    first, second = posts(gateway)
    assert first.headers["x-api-keypair-sign"] == second.headers["x-api-keypair-sign"]
    assert len(gateway.transfers) == 1
    assert clock.sleeps == [], "resent at once, inside the 3 s replay window"


def test_keypair_write_5xx_is_resent_and_a_replayed_5xx_is_outcome_unknown(kind, clock):
    gateway = keypair_gateway(clock)
    gateway.intervene(None, ("after", 500))
    expect(kind, keypair_client(kind, gateway), transfer, RequestOutcomeUnknownError)
    assert len(posts(gateway)) == 2 and len(gateway.transfers) == 1


def test_keypair_write_timeout_noticed_too_late_is_outcome_unknown(kind, clock):
    gateway = keypair_gateway(clock)
    gateway.intervene(None, ("read_timeout", 2.6))
    expect(kind, keypair_client(kind, gateway), transfer, RequestOutcomeUnknownError)
    assert len(posts(gateway)) == 1


def test_keypair_resend_refused_as_duplicate_is_outcome_unknown(kind, clock):
    gateway = keypair_gateway(clock, replay_window_ms=-1)
    gateway.intervene(None, "read_timeout")
    error = expect(kind, keypair_client(kind, gateway), transfer, RequestOutcomeUnknownError)
    assert error.in_progress is False
    assert len(posts(gateway)) == 2 and len(gateway.transfers) == 1


def test_keypair_resend_while_the_first_runs_is_outcome_unknown_in_progress(kind, clock):
    gateway = keypair_gateway(clock)
    gateway.intervene(None, "read_timeout", ("in_progress",))
    error = expect(kind, keypair_client(kind, gateway), transfer, RequestOutcomeUnknownError)
    assert error.in_progress is True
    assert len(gateway.transfers) == 1


def test_keypair_write_resends_only_once(kind, clock):
    gateway = keypair_gateway(clock)
    gateway.intervene(None, "read_timeout", "timeout_before")
    expect(kind, keypair_client(kind, gateway), transfer, RequestOutcomeUnknownError)
    assert len(posts(gateway)) == 2


def test_the_confirmation_is_kept_for_ten_minutes(kind, clock):
    gateway = keypair_gateway(clock)

    async def scenario(api):
        await transfer(api)
        clock.advance(300)
        await transfer(api)
        clock.advance(301)
        await transfer(api)

    run(kind, keypair_client(kind, gateway), scenario)
    checks = [request for request in gateway.received if request.url.path == "/api-keys/current/signing-keys"]
    assert len(checks) == 2


def test_a_read_does_not_check_the_key_pair(kind, clock):
    gateway = keypair_gateway(clock)
    run(kind, keypair_client(kind, gateway), ping)
    assert [request.url.path for request in gateway.received] == ["/ping"]


# -- conflicts ---------------------------------------------------------------------------------------


def generate_address(api):
    return api.request(
        "POST", "/vaults/{vaultId}/{blockchain}/{network}/addresses",
        path_params={"vaultId": "v1", "blockchain": "bitcoin", "network": "mainnet"}, item={"label": "deposit"},
    )


@pytest.mark.parametrize("code", ["address_derivation_conflict", "vault_accounts_creation_failed"])
def test_a_conflict_is_retried_once_at_once_with_a_new_nonce(kind, gateway, clock, code):
    # Nothing was executed, so the one retry is signed again with a new nonce and the same body; over the same
    # nonce the gateway would only replay the 409. The retried answer reaches the caller.
    attempts = []

    def conflicted_once(request, match, body):
        attempts.append(request.headers["x-api-nonce"])
        if len(attempts) == 1:
            return 409, envelope_error(code)
        return 201, envelope_item({"address": "bc1qretried", "label": "deposit"})

    gateway.route("POST", r"/vaults/([^/]+)/([^/]+)/([^/]+)/addresses", conflicted_once)
    result = run(kind, make_client(kind, gateway), generate_address)
    assert result.item["address"] == "bc1qretried"
    first, second = posts(gateway)
    assert first.headers["x-api-nonce"] != second.headers["x-api-nonce"]
    assert first.content == second.content
    assert len(attempts) == 2, "the route ran again: the retry was not answered with the replayed 409"
    assert clock.sleeps == []


def test_a_second_conflict_is_returned_retryable(kind, gateway):
    # Only one such retry: the second conflict (to the new nonce, so not a replay) reaches the caller.
    attempts = []

    def conflicted(request, match, body):
        attempts.append(request.headers["x-api-nonce"])
        return 409, envelope_error("address_derivation_conflict")

    gateway.route("POST", r"/vaults/([^/]+)/([^/]+)/([^/]+)/addresses", conflicted)
    error = expect(kind, make_client(kind, gateway), generate_address, ConflictError)
    assert error.retryable is True and error.replayed is False
    assert len(attempts) == 2 and len(set(attempts)) == 2


def test_a_conflict_retry_keeps_its_new_nonce_on_a_later_retry(kind, gateway):
    # The conflict retry gets a new nonce; a 429 to it is then resent as it was, over that new nonce.
    attempts = []

    def conflicted_once(request, match, body):
        attempts.append(request.headers["x-api-nonce"])
        if len(attempts) == 1:
            return 409, envelope_error("address_derivation_conflict")
        return 201, envelope_item({"address": "bc1qretried", "label": "deposit"})

    gateway.route("POST", r"/vaults/([^/]+)/([^/]+)/([^/]+)/addresses", conflicted_once)
    gateway.intervene(SIGNED_READ, None, ("status", 429))
    run(kind, make_client(kind, gateway), generate_address)
    nonces = [request.headers["x-api-nonce"] for request in posts(gateway)]
    assert len(nonces) == 3 and nonces[0] != nonces[1] and nonces[1] == nonces[2]
    assert len(attempts) == 2


# -- the rate limiter --------------------------------------------------------------------------------


def test_a_burst_of_twenty_calls_stays_under_five_a_second(kind, clock):
    gateway = MockGateway(clock)
    seen = []

    def limited(request, match, body):
        now = clock()
        seen.append(now)
        if len([at for at in seen if now - at < 1.0]) > 5:
            return 429, envelope_error("request_limit_reached")
        return 200, envelope_item({"pong": True})

    gateway.route("GET", r"/ping", limited)
    client = make_client(kind, gateway, max_requests_per_second=5)

    async def scenario(api):
        for _ in range(20):
            await ping(api)

    run(kind, client, scenario)
    assert len(gateway.received) == 20, "no 429, so no retry"
    assert 2.9 <= sum(clock.sleeps) <= 3.1
