"""verify_requests_response against a local HTTP server that replays signed responses from the vectors.

The client sends each vector's request for real, so the test also proves that requests' path_url,
body, x-api-sign and x-api-keypair-sign are exactly what reached the server.
"""

import base64
import io
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from vaultody_verify import ResponseSignatureError, VerificationResult, verify_requests_response

from vaultody_vectors import case, root_pem, url_of

requests = pytest.importorskip("requests")


class ReplayHandler(BaseHTTPRequestHandler):
    """Answers any request with the response of the vector the test put on the server."""

    def _replay(self):
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length) if length else b""
        self.server.seen.append(
            {
                "method": self.command,
                "url": self.path,
                "body": body,
                "api_sign": self.headers.get("x-api-sign"),
                "keypair_sign": self.headers.get("x-api-keypair-sign"),
            }
        )

        received = self.server.vector["verify"]["response"]
        payload = base64.b64decode(received["bodyBase64"])
        self.send_response(received["status"])
        for name, value in received["headers"].items():
            self.send_header(name, value)
        if received["status"] not in (204, 304):
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(payload)

    do_GET = do_POST = do_PUT = do_DELETE = do_HEAD = _replay

    def log_message(self, *args):
        pass


@pytest.fixture(scope="module")
def server():
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), ReplayHandler)
    httpd.seen = []
    # A short poll keeps shutdown quick; the default waits half a second.
    thread = threading.Thread(target=httpd.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True)
    thread.start()
    try:
        yield httpd
    finally:
        httpd.shutdown()
        httpd.server_close()


def send(server, name):
    """Sends the vector's request to the local server with requests and returns the response."""
    vector = case(name)
    server.vector = vector
    sent = vector["verify"]["request"]
    headers = {}
    if sent["apiSign"]:
        headers["x-api-sign"] = sent["apiSign"]
    if sent["keypairSign"]:
        headers["x-api-keypair-sign"] = sent["keypairSign"]
    with requests.Session() as session:
        # Never route localhost through a proxy from the environment.
        session.trust_env = False
        resp = session.request(
            sent["method"],
            "http://127.0.0.1:{}{}".format(server.server_address[1], url_of(sent)),
            data=base64.b64decode(sent["bodyBase64"]),
            headers=headers,
            allow_redirects=False,
        )

    # The server saw exactly what the vector says the client sent.
    seen = server.seen[-1]
    assert seen["method"] == sent["method"]
    assert seen["url"] == url_of(sent) == resp.request.path_url
    assert seen["body"] == base64.b64decode(sent["bodyBase64"])
    assert (seen["api_sign"] or "") == sent["apiSign"]
    assert (seen["keypair_sign"] or "") == sent["keypairSign"]
    return vector, resp


def options_for(vector):
    return {
        "roots": [root_pem(name) for name in vector["verify"]["pinnedRoots"]],
        "now": vector["verify"]["now"],
    }


@pytest.mark.parametrize(
    "name",
    ["valid_current_root", "valid_next_root", "valid_get_with_query", "valid_percent_encoded_path",
     "valid_head_empty_body", "valid_204_empty_body", "valid_unauthenticated_error", "valid_utf8_body",
     "valid_with_keypair_sign", "valid_with_keypair_sign_der_length"],
)
def test_signed_response_verifies(server, name):
    vector, resp = send(server, name)
    result = verify_requests_response(resp, **options_for(vector))
    certificate = vector["signed"]["certificate"]
    assert result == VerificationResult(
        verified=True, key_id=certificate["keyId"], root_id=certificate["rootId"], timestamp=vector["signed"]["ts"]
    )


@pytest.mark.parametrize(
    "name",
    ["tampered_response_body", "tampered_status", "response_for_other_request", "request_body_unread",
     "expired_certificate", "unknown_root", "missing_sign", "missing_all", "version_2",
     "tampered_request_keypair_sign", "keypair_sign_dropped", "keypair_sign_added"],
)
def test_rejected_response_raises_with_the_vector_reason(server, name):
    vector, resp = send(server, name)
    with pytest.raises(ResponseSignatureError) as failure:
        verify_requests_response(resp, **options_for(vector))
    assert failure.value.reason == vector["expected"]["reason"]


def test_unsigned_response_in_non_strict_mode(server):
    vector, resp = send(server, "missing_all")
    result = verify_requests_response(resp, require_response_signature=False, **options_for(vector))
    assert result == VerificationResult(verified=False, reason="missing")


def test_str_request_body(server):
    vector = case("valid_current_root")
    server.vector = vector
    sent = vector["verify"]["request"]
    with requests.Session() as session:
        session.trust_env = False
        resp = session.post(
            "http://127.0.0.1:{}{}".format(server.server_address[1], url_of(sent)),
            data=base64.b64decode(sent["bodyBase64"]).decode("utf-8"),
            headers={"x-api-sign": sent["apiSign"]},
        )
    assert isinstance(resp.request.body, str)
    assert verify_requests_response(resp, **options_for(vector)).verified is True


def test_streamed_request_body_is_refused(server):
    vector = case("valid_current_root")
    server.vector = vector
    sent = vector["verify"]["request"]
    body = base64.b64decode(sent["bodyBase64"])
    with requests.Session() as session:
        session.trust_env = False
        resp = session.post(
            "http://127.0.0.1:{}{}".format(server.server_address[1], url_of(sent)),
            data=io.BytesIO(body),
            headers={"x-api-sign": sent["apiSign"]},
        )
    with pytest.raises(TypeError):
        verify_requests_response(resp, **options_for(vector))
