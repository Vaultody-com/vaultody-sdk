"""The live conformance cases through the Python SDK: python -I run_python.py --client sync|async <out-dir>.

Reads cases.json and <out-dir>/fixture.json, writes <out-dir>/results-python-<sync|async>.json. It records
what happened, as run-node.js does; report.js judges every language by the same rules. Nothing secret is
written or printed. Same environment as the Node runner (conformance/live/README.md).
"""

import argparse
import asyncio
import hashlib
import inspect
import json
import logging
import os
import platform
import re
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlsplit

import httpx

import vaultody_sdk
from vaultody_sdk import ApiError, AsyncVaultody, FileVaultKeyStore, MemoryVaultKeyStore, Vaultody, VaultKeyStoreError

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
CONTEXT = "sdk-conformance"
MAX_PAGE = 50
PRODUCTION_ORIGINS = {"https://rest.vaultody.com"}


def snake(name):
    return re.sub(r"(?<!^)(?=[A-Z])", "_", name).lower()


def short(value):
    return value[:6] + "…" + value[-4:] if isinstance(value, str) and len(value) > 12 else value


def env(name):
    value = os.environ.get(name)
    if not value:
        raise SystemExit("{} is not set (conformance/live/README.md)".format(name))
    return value


def wrong_passphrase(passphrase):
    """The same length, the last character changed (lib.js wrongPassphrase)."""
    return passphrase[:-1] + ("y" if passphrase[-1:] == "x" else "x")


def test_root_pem():
    """lib.js testRootPem: the TEST-ONLY response-signing root of test-vectors/v1.json, as SPKI PEM. The case
    rootsOnUnsignedOrigin gives it to a client, which is then strict from its first answer."""
    with open(os.path.join(ROOT, "test-vectors", "v1.json"), encoding="utf-8") as handle:
        der_base64 = json.load(handle)["keys"]["roots"]["current"]["publicKeySpkiDerBase64"]
    lines = [der_base64[i:i + 64] for i in range(0, len(der_base64), 64)]
    return "-----BEGIN PUBLIC KEY-----\n{}\n-----END PUBLIC KEY-----\n".format("\n".join(lines))


def resolve(value, fixture, items, client, run):
    """lib.js resolveParams: "$name" from the fixture, "@caseId.field" from an earlier item, "{client}" and
    "{run}" replaced. Returns (params, missing)."""
    missing = []

    def walk(v):
        if isinstance(v, str):
            if v.startswith("$"):
                if fixture.get(v[1:]) is None:
                    missing.append("fixture." + v[1:])
                    return None
                return fixture[v[1:]]
            if v.startswith("@"):
                case_id, field = v[1:].split(".", 1)
                item = items.get(case_id)
                if not isinstance(item, dict) or field not in item:
                    missing.append("{}.{}".format(case_id, field))
                    return None
                return item[field]
            return v.replace("{client}", client).replace("{run}", run)
        if isinstance(v, list):
            return [walk(x) for x in v]
        if isinstance(v, dict):
            return {k: walk(x) for k, x in v.items()}
        return v

    params = walk(value)
    return params, (missing[0] if missing else None)


class _Warnings(logging.Handler):
    """The vaultody_sdk logger's warnings (they carry no secret), as the Node runner's logger keeps them."""

    def __init__(self):
        super().__init__(logging.WARNING)
        self.messages = []

    def emit(self, record):
        message = record.getMessage()[:200]
        if message not in self.messages:
            self.messages.append(message)


class _Recorder:
    """What the counting transports share: one record per request (method, path, nonce, status)."""

    def __init__(self):
        self.log = []
        self.lock = threading.Lock()

    def start(self, request):
        record = {"method": request.method, "path": request.url.path, "nonce": request.headers.get("x-api-nonce"), "at": time.time()}
        with self.lock:
            self.log.append(record)
        return record

    @staticmethod
    def finish(record, response):
        record["status"] = response.status_code

    @staticmethod
    def limit_of(record, body):
        """The quota a 429 names (error.details: requests, seconds)."""
        try:
            record["limit"] = json.loads(body).get("error", {}).get("details")
        except (ValueError, AttributeError):
            pass


class CountingTransport(httpx.BaseTransport):
    def __init__(self, recorder):
        self.recorder = recorder
        self.inner = httpx.HTTPTransport()

    def handle_request(self, request):
        record = self.recorder.start(request)
        try:
            response = self.inner.handle_request(request)
        except Exception as error:
            record["error"] = type(error).__name__
            raise
        self.recorder.finish(record, response)
        if response.status_code == 429:
            self.recorder.limit_of(record, response.read())
        return response

    def close(self):
        self.inner.close()


class AsyncCountingTransport(httpx.AsyncBaseTransport):
    def __init__(self, recorder):
        self.recorder = recorder
        self.inner = httpx.AsyncHTTPTransport()

    async def handle_async_request(self, request):
        record = self.recorder.start(request)
        try:
            response = await self.inner.handle_async_request(request)
        except Exception as error:
            record["error"] = type(error).__name__
            raise
        self.recorder.finish(record, response)
        if response.status_code == 429:
            self.recorder.limit_of(record, await response.aread())
        return response

    async def aclose(self):
        await self.inner.aclose()


def error_of(error):
    return {
        "class": type(error).__name__,
        "apiError": isinstance(error, ApiError),
        "status": getattr(error, "status", None),
        "code": getattr(error, "code", None),
        "reason": getattr(error, "reason", None),
        "message": str(error)[:200],
    }


def envelope_of(meta):
    return {
        "requestId": isinstance(meta.request_id, str) and meta.request_id != "",
        "apiVersion": meta.api_version,
        "context": meta.context == CONTEXT,
        "replayed": meta.replayed is True,
        "signature": meta.signature,
    }


def count_statuses(checks):
    out = {}
    for check in checks:
        status = check.get("status") if isinstance(check, dict) else check
        out[status] = out.get(status, 0) + 1
    return out


def _seed():
    """lib.js SEED: the vectors' canonical two_origins document, the pin file every client starts from."""
    with open(os.path.join(ROOT, "test-vectors", "vault-keys-file-v1.json"), encoding="utf-8") as handle:
        return next(c for c in json.load(handle)["canonical"] if c["name"] == "two_origins")


SEED = _seed()


def seed_pin_file(path):
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(descriptor, "wb") as handle:
        handle.write(SEED["text"].encode("utf-8"))
    os.chmod(path, 0o600)


def pin_file_facts(path):
    """lib.js pinFileFacts: mode, hash, and whether the file is still the seed."""
    if not os.path.exists(path):
        return {"file": os.path.basename(path), "exists": False}
    with open(path, "rb") as handle:
        digest = hashlib.sha256(handle.read()).hexdigest()
    return {
        "file": os.path.basename(path), "exists": True, "mode": oct(os.stat(path).st_mode & 0o777)[2:], "sha256": digest,
        "unchangedSinceSeed": digest == hashlib.sha256(SEED["text"].encode("utf-8")).hexdigest(),
    }


def read_pins(store, origins):
    """lib.js summarizeRead over what this SDK's own store reads: latch set or not, and each pin without its xpubs."""
    try:
        out = {}
        for origin in origins:
            pins = sorted(store.list(origin), key=lambda pin: pin["vaultId"])
            out[origin] = {
                "latch": "set" if store.get_strict_latch(origin) else None,
                "vaults": [
                    {"vaultId": short(pin["vaultId"]), "type": pin["type"], "status": pin["status"],
                     "algorithms": sorted(name for name, xpub in pin["keys"].items() if xpub)}
                    for pin in pins
                ],
            }
        return {"ok": True, "origins": out}
    except VaultKeyStoreError as error:
        return {"ok": False, "error": error.code}


async def maybe(value):
    return await value if inspect.isawaitable(value) else value


async def collect_pages(pages, max_pages):
    """The first max_pages pages of a Pages / AsyncPages."""
    out = []
    iterator = pages.pages()
    if hasattr(iterator, "__anext__"):
        async for page in iterator:
            out.append(page)
            if len(out) >= max_pages:
                break
    else:
        for page in iterator:
            out.append(page)
            if len(out) >= max_pages:
                break
    return out


async def collect_items(pages):
    if hasattr(pages, "__aiter__"):
        return [item async for item in pages]
    return list(pages)


async def run(client_kind, out):
    base_url = env("VAULTODY_BASE_URL")
    parts = urlsplit(base_url)
    origin = "{}://{}".format(parts.scheme, parts.netloc)
    if origin in PRODUCTION_ORIGINS:
        raise SystemExit("the live conformance run never targets the production API")
    api_key, api_secret, passphrase = env("VAULTODY_API_KEY"), env("VAULTODY_API_SECRET"), env("VAULTODY_PASSPHRASE")
    burst = int(os.environ.get("VAULTODY_CONFORMANCE_BURST") or "0")
    rps = float(os.environ["VAULTODY_CONFORMANCE_RPS"]) if os.environ.get("VAULTODY_CONFORMANCE_RPS") else None
    run_id = os.environ.get("VAULTODY_CONFORMANCE_RUN_ID") or str(int(time.time() * 1000))
    name = "python-" + client_kind
    with open(os.path.join(HERE, "cases.json"), encoding="utf-8") as handle:
        cases = json.load(handle)
    with open(os.path.join(out, "fixture.json"), encoding="utf-8") as handle:
        fixture = json.load(handle)

    recorder = _Recorder()
    events = []
    warnings_seen = _Warnings()
    logging.getLogger("vaultody_sdk").addHandler(warnings_seen)
    pin_file = os.path.join(out, "pins-{}.json".format(name))
    seed_pin_file(pin_file)
    store = FileVaultKeyStore(pin_file)

    def make(pass_phrase=None, rate=rps, roots=None):
        options = dict(
            base_url=base_url,
            # A client given response-signing roots gets its own in-memory store: the run's pin file is never
            # touched by it.
            vault_key_store=store if roots is None else MemoryVaultKeyStore(),
            on_security_event=lambda event: events.append(dict(
                {k: (short(v) if k == "vaultId" else v) for k, v in event.items() if k in ("type", "vaultId", "outcome", "status", "reason", "code", "operationId")},
                # The unsigned notice must carry exactly these fields in every language.
                **({"fields": sorted(event), "originIsRun": event.get("origin") == origin} if event.get("type") == "unsigned_response_accepted" else {}),
            )),
        )
        if rate is not None:
            options["max_requests_per_second"] = rate
        if roots is not None:
            options["roots"] = roots
        if client_kind == "async":
            return AsyncVaultody(api_key, api_secret, pass_phrase or passphrase, transport=AsyncCountingTransport(recorder), **options)
        return Vaultody(api_key, api_secret, pass_phrase or passphrase, transport=CountingTransport(recorder), **options)

    def method(client, group, op):
        return getattr(getattr(client, snake(group)), snake(op))

    client = make()
    opened = [client]
    items = {}
    log = recorder.log

    def resolved(params):
        return resolve(params, fixture, items, name, run_id)

    async def run_case(spec):
        result = {"id": spec["id"], "group": spec["group"], "op": spec["op"], "class": spec["class"], "kind": spec["kind"]}
        params, missing = resolved(spec["params"])
        if missing:
            result["skipped"] = "no " + missing
            return result
        expected = resolved({"v": spec["equals"]})[0]["v"] if "equals" in spec else None
        before = len(log)
        try:
            if spec["kind"] == "item":
                answer = await maybe(method(client, spec["group"], spec["op"])(context=CONTEXT, **params))
                result["outcome"] = "ok"
                result["envelope"] = envelope_of(answer.meta)
                result["typed"] = "{}[{}]".format(type(answer).__name__, type(answer.item).__name__)
                if spec.get("field"):
                    value = answer.item.get(spec["field"]) if isinstance(answer.item, dict) else None
                    result["field"] = {"name": spec["field"], "present": value is not None}
                    if "equals" in spec:
                        result["field"]["equalsExpected"] = value == expected
                if answer.meta.address_checks:
                    result["addressChecks"] = count_statuses(answer.meta.address_checks)
                items[spec["id"]] = answer.item
            else:
                paging = spec.get("paging") or {}
                call = dict(params, limit=paging["limit"]) if paging.get("limit") else dict(params)
                pages = await collect_pages(method(client, spec["group"], spec["op"])(context=CONTEXT, **call), paging.get("maxPages", 1))
                every = [item for page in pages for item in page.items]
                ids = [item.get(paging["idField"]) if isinstance(item, dict) else None for item in every]
                result["outcome"] = "ok"
                result["envelope"] = envelope_of(pages[0].meta)
                result["typed"] = "{}[{}]".format(type(pages[0]).__name__, type(every[0]).__name__ if every else "empty")
                result["paging"] = {
                    "limit": paging.get("limit"),
                    "pages": len(pages),
                    "items": len(every),
                    "hasMoreAfter": bool(pages[-1].has_more),
                    "duplicates": len(ids) - len(set(ids)),
                    "missingIds": len([i for i in ids if not isinstance(i, str) or not i]),
                }
                if spec.get("vaultKeys") or any(page.meta.vault_keys for page in pages):
                    # The per-vault pin results of every page fetched: {vaultId, status, outcome}.
                    result["vaultKeys"] = [
                        {"vaultId": short(entry["vaultId"]), "status": entry["status"], "outcome": entry["outcome"]}
                        for page in pages for entry in page.meta.vault_keys
                    ]
                checks = [check for page in pages for check in page.meta.address_checks]
                if checks or spec.get("addressChecks"):
                    result["addressChecks"] = count_statuses(checks)
                if paging.get("everyItem"):
                    small = method(client, spec["group"], spec["op"])(context=CONTEXT, max_items=MAX_PAGE, **dict(params, limit=paging["limit"]))
                    iterated = [item[paging["idField"]] for item in await collect_items(small)]
                    single = (await collect_pages(method(client, spec["group"], spec["op"])(context=CONTEXT, **dict(params, limit=MAX_PAGE)), 1))[0]
                    single_ids = [item[paging["idField"]] for item in single.items]
                    result["everyItem"] = {
                        "iterator": len(iterated),
                        "singlePage": len(single_ids),
                        "singleHasMore": bool(single.has_more),
                        "stop": small.stop,
                        "equal": iterated == single_ids,
                    }
                items[spec["id"]] = every[0] if every else None
        except Exception as error:  # every failure is recorded, judged in report.js
            result["outcome"] = "error"
            result["error"] = error_of(error)
        result["requests"] = len(log) - before
        result["statuses"] = [r.get("status") or r.get("error") for r in log[before:]]
        limits = [r["limit"] for r in log[before:] if r.get("limit")]
        if limits:
            result["limits"] = limits
        return result

    async def run_negative(spec):
        result = {"id": spec["id"], "group": spec.get("group"), "op": spec.get("op"), "class": spec["class"], "check": spec["check"]}
        if spec["check"] == "burst":
            return await run_burst(spec, result)
        target = client
        if spec["check"] == "wrongPassphrase":
            target = make(pass_phrase=wrong_passphrase(passphrase))
            opened.append(target)
        elif spec["check"] == "rootsOnUnsignedOrigin":
            target = make(roots=[test_root_pem()])
            opened.append(target)
        before = len(log)
        try:
            answer = method(target, spec["group"], spec["op"])(**spec["params"])
            if hasattr(answer, "pages"):
                await collect_pages(answer, 1)
            else:
                await maybe(answer)
            result["outcome"] = "ok"
        except Exception as error:
            result["outcome"] = "error"
            result["error"] = error_of(error)
        result["requests"] = len(log) - before
        result["statuses"] = [r.get("status") or r.get("error") for r in log[before:]]
        return result

    async def run_burst(spec, result):
        if burst <= 0:
            result["skipped"] = "VAULTODY_CONFORMANCE_BURST is 0"
            return result
        read, m1 = resolved(spec["read"]["params"])
        write, m2 = resolved(spec["write"]["params"])
        count, m3 = resolved(spec["count"]["params"])
        if m1 or m2 or m3:
            result["skipped"] = "no " + (m1 or m2 or m3)
            return result
        await asyncio.sleep(1.5)
        fast = make(rate=1000)
        opened.append(fast)
        before = len(log)
        started = time.time()
        reads = []
        state = {"dispatched": 0}
        read_call = method(fast, spec["read"]["group"], spec["read"]["op"])
        write_call = method(fast, spec["write"]["group"], spec["write"]["op"])

        def do_write():
            try:
                answer = write_call(**write)
                return {"outcome": "ok", "answer": answer}
            except Exception as error:
                return {"outcome": "error", "error": error_of(error)}

        if client_kind == "async":
            async def worker():
                while state["dispatched"] < burst:
                    state["dispatched"] += 1
                    try:
                        await read_call(**read)
                        reads.append("ok")
                    except Exception as error:
                        reads.append("{}:{}".format(type(error).__name__, getattr(error, "code", None)))

            async def writer():
                while state["dispatched"] < burst:
                    await asyncio.sleep(0.002)
                try:
                    answer = await write_call(**write)
                    return {"outcome": "ok", "answer": answer}
                except Exception as error:
                    return {"outcome": "error", "error": error_of(error)}

            outcome = await asyncio.gather(writer(), *[worker() for _ in range(4)])
            write_result = outcome[0]
        else:
            lock = threading.Lock()

            def worker():
                while True:
                    with lock:
                        if state["dispatched"] >= burst:
                            return
                        state["dispatched"] += 1
                    try:
                        read_call(**read)
                        reads.append("ok")
                    except Exception as error:
                        reads.append("{}:{}".format(type(error).__name__, getattr(error, "code", None)))

            def writer():
                while state["dispatched"] < burst:
                    time.sleep(0.002)
                return do_write()

            with ThreadPoolExecutor(max_workers=5) as pool:
                write_future = pool.submit(writer)
                for future in [pool.submit(worker) for _ in range(4)]:
                    future.result()
                write_result = write_future.result()

        window = log[before:]
        writes = [r for r in window if r["method"] == "POST"]
        gets = [r for r in window if r["method"] == "GET"]
        answer = write_result.pop("answer", None)
        if answer is not None:
            write_result["addressChecks"] = count_statuses(answer.meta.address_checks)
        result["burst"] = {
            "size": burst,
            "workers": 4,
            "ms": int((time.time() - started) * 1000),
            "readsOk": reads.count("ok"),
            "readErrors": [r for r in reads if r != "ok"],
            "readAttempts": len(gets),
            "read429": len([r for r in gets if r.get("status") == 429]),
            "limits": [r["limit"] for r in window if r.get("limit")],
            "write": dict(write_result, attempts=len(writes), statuses=[r.get("status") or r.get("error") for r in writes], distinctNonces=len({r["nonce"] for r in writes})),
        }
        await asyncio.sleep(1.5)
        wanted = write["label"]
        addresses = await collect_items(method(client, spec["count"]["group"], spec["count"]["op"])(max_items=1000, **dict(count, limit=MAX_PAGE)))
        result["burst"]["write"]["addressesWithLabel"] = len([a for a in addresses if a.get("label") == wanted])
        result["outcome"] = "ok"
        result["requests"] = len(log) - before
        return result

    results = []
    only = set(os.environ["VAULTODY_CONFORMANCE_CASES"].split(",")) if os.environ.get("VAULTODY_CONFORMANCE_CASES") else None
    try:
        for spec in [c for c in cases["cases"] if only is None or c["id"] in only]:
            result = await (run_negative(spec) if spec["class"] == "negative" else run_case(spec))
            results.append(result)
            error = result.get("error")
            sys.stderr.write("{} {}: {}{}\n".format(
                name, spec["id"], "skip ({})".format(result["skipped"]) if result.get("skipped") else result.get("outcome"),
                " {} {} {} {}".format(error["class"], error["code"] or "", error["reason"] or "", error["status"] or "") if error else "",
            ))
    finally:
        for opened_client in opened:
            closing = opened_client.close() if client_kind == "sync" else opened_client.aclose()
            await maybe(closing)

    path = os.path.join(out, "results-{}.json".format(name))
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
        json.dump({
            "client": name,
            "runtime": "python {} ({}) httpx {}".format(platform.python_version(), platform.system().lower(), httpx.__version__),
            "sdkVersion": getattr(vaultody_sdk, "__version__", None),
            "apiVersion": vaultody_sdk.API_VERSION,
            "origin": origin,
            "runId": run_id,
            "finishedAt": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "requests": len(log),
            "cases": results,
            "pins": dict(pin_file_facts(pin_file), read=read_pins(FileVaultKeyStore(pin_file), list(SEED["document"]["origins"]) + [origin])),
            "securityEvents": events,
            "warnings": warnings_seen.messages,
        }, handle, indent=2)
        handle.write("\n")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--client", choices=("sync", "async"), required=True)
    parser.add_argument("out")
    args = parser.parse_args()
    asyncio.run(run(args.client, args.out))


if __name__ == "__main__":
    main()
