"""test-vectors/signing-keys-v1.json: signed answers of GET /api-keys/current/signing-keys, checked the way
`vaultody keys verify` checks them: the response signature first, over the request as sent, then the list."""

import base64

import pytest

from vaultody_verify import ResponseSignatureError, read_signing_keys_response, verify_response

from vaultody_vectors import VECTORS as RESPONSE_VECTORS
from vaultody_vectors import load

VECTORS = load("signing-keys-v1.json")
ROOTS = [base64.b64decode(RESPONSE_VECTORS["keys"]["roots"][name]["publicKeySpkiDerBase64"]) for name in VECTORS["pinnedRoots"]]


@pytest.mark.parametrize("vector", VECTORS["cases"], ids=[vector["name"] for vector in VECTORS["cases"]])
def test_signing_keys_answer(vector):
    request, response, expected = vector["request"], vector["response"], vector["expected"]
    body = base64.b64decode(response["bodyBase64"])
    try:
        result = verify_response(
            {
                "method": request["method"],
                "url": request["path"] + ("?" + request["query"] if request["query"] else ""),
                "body": base64.b64decode(request["bodyBase64"]),
                "api_sign": request["apiSign"],
                "keypair_sign": request["keypairSign"],
            },
            {"status": response["status"], "headers": response["headers"], "body": body},
            roots=ROOTS,
            now=vector["now"],
            require_response_signature=False,
        )
        signature = "verified" if result.verified else "absent"
    except ResponseSignatureError as error:
        signature = {"error": error.reason}
    assert signature == expected["signature"]
    if not isinstance(signature, str):
        return

    read = read_signing_keys_response(response["status"], body, vector["fingerprint"])
    assert read["outcome"] == expected["outcome"]
    if "code" in expected:
        assert read["error"]["code"] == expected["code"]
