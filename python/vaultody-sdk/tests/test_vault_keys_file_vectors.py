"""test-vectors/vault-keys-file-v1.json: the pin file every SDK language reads and writes.

Valid files parse to their origins, and the file store lists exactly their pins and latches; refused files
give the same error code as in Node and PHP; the file-system cases (modes, a symbolic link, a directory, no
file) go through the file store; and the store writes the canonical bytes, byte for byte.
"""

import base64
import os
import subprocess
import sys

import pytest

from vaultody_sdk import FileVaultKeyStore, VaultKeyStoreError
from vaultody_sdk.stores import canonical_json, parse_document

from sdk_vectors import ids, load

VECTORS = load("vault-keys-file-v1.json")
POSIX = sys.platform != "win32"


def by_vault_id(pins):
    return sorted(pins, key=lambda pin: pin["vaultId"])


def content_bytes(case):
    return base64.b64decode(case["base64"]) if "base64" in case else case["text"].encode("utf-8")


def write_file(path, data, mode=0o600):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    if POSIX:
        os.chmod(path, mode)
    return path


def read_through_store(path, origins):
    """What the file store makes of the file: per origin, its pins (by vaultId) and its latch."""
    store = FileVaultKeyStore(path)
    return {origin: {"pins": by_vault_id(store.list(origin)), "latch": store.get_strict_latch(origin)} for origin in origins}


def expected_through_store(origins):
    return {
        origin: {"pins": by_vault_id(entry["vaults"].values()), "latch": entry["responseSignature"]}
        for origin, entry in origins.items()
    }


def test_the_set_is_complete():
    assert VECTORS["format"] == "vaultody vault keys file, v1"
    assert len(VECTORS["valid"]) >= 10 and len(VECTORS["invalid"]) >= 50 and VECTORS["files"] and VECTORS["canonical"]


@pytest.mark.parametrize("case", VECTORS["valid"], ids=ids(VECTORS["valid"]))
def test_valid(case, tmp_path):
    document = parse_document(case["text"].encode("utf-8"))
    assert document["origins"] == case["expected"]["origins"]
    path = write_file(tmp_path / "vault-keys.json", case["text"].encode("utf-8"))
    origins = case["expected"]["origins"]
    assert read_through_store(path, origins) == expected_through_store(origins)
    # An origin the file does not hold has no pins and no latch.
    assert read_through_store(path, ["https://absent.example.test"]) == {"https://absent.example.test": {"pins": [], "latch": None}}


@pytest.mark.parametrize("case", VECTORS["invalid"], ids=ids(VECTORS["invalid"]))
def test_invalid(case, tmp_path):
    with pytest.raises(VaultKeyStoreError) as parsed:
        parse_document(content_bytes(case))
    assert parsed.value.code == case["expected"]["error"]
    path = write_file(tmp_path / "vault-keys.json", content_bytes(case))
    store = FileVaultKeyStore(path, fallback_to_memory=True)
    for read in (lambda: store.list("https://rest.vaultody.com"), lambda: store.get_strict_latch("https://rest.vaultody.com")):
        with pytest.raises(VaultKeyStoreError) as raised:
            read()
        assert raised.value.code == case["expected"]["error"]
    # Never taken as empty: a write fails the same way and leaves the file as it was.
    with pytest.raises(VaultKeyStoreError) as raised:
        store.set_strict_latch("https://rest.vaultody.com", {"latchedAt": 1, "rootId": "r"})
    assert raised.value.code == case["expected"]["error"]
    assert path.read_bytes() == content_bytes(case) and not store.in_memory


def file_content(name):
    if name.startswith("invalid:"):
        case = next(c for c in VECTORS["invalid"] if c["name"] == name[len("invalid:"):])
        return content_bytes(case)
    return next(c for c in VECTORS["valid"] if c["name"] == name)["text"].encode("utf-8")


@pytest.mark.parametrize("case", VECTORS["files"], ids=ids(VECTORS["files"]))
def test_files(case, tmp_path):
    if case["posixOnly"] and not POSIX:
        pytest.skip("POSIX file modes and symbolic links")
    path = tmp_path / "pins" / "vault-keys.json"
    path.parent.mkdir()
    if case.get("directory"):
        path.mkdir()
    elif case.get("symlinkTo"):
        target = write_file(tmp_path / "target.json", file_content(case["symlinkTo"]))
        os.symlink(target, path)
    elif not case.get("absent"):
        write_file(path, file_content(case["content"]), int(case["mode"], 8) if "mode" in case else 0o600)
    expected = case["expected"]
    if "error" in expected:
        with pytest.raises(VaultKeyStoreError) as raised:
            FileVaultKeyStore(path).list("https://rest.vaultody.com")
        assert raised.value.code == expected["error"]
    else:
        origins = expected["origins"]
        assert read_through_store(path, origins) == expected_through_store(origins)


@pytest.mark.parametrize("case", VECTORS["canonical"], ids=ids(VECTORS["canonical"]))
def test_canonical(case, tmp_path):
    assert canonical_json(case["document"]) == case["text"]
    assert canonical_json(parse_document(case["text"].encode("utf-8"))) == case["text"]
    # The store writes the same bytes when it is handed the same content.
    path = tmp_path / "vault-keys.json"
    store = FileVaultKeyStore(path)
    for origin, entry in case["document"]["origins"].items():
        for pin in entry["vaults"].values():
            store.pin_if_absent(origin, pin)
        if entry["responseSignature"] is not None:
            store.set_strict_latch(origin, entry["responseSignature"])
    if case["document"]["origins"] and not any(entry["audit"] for entry in case["document"]["origins"].values()):
        assert path.read_bytes().decode("utf-8") == case["text"]


def test_the_lock_is_shared_between_processes(tmp_path):
    """Four processes pin ten vaults each on one file: the exclusive lock file keeps every pin."""
    path = tmp_path / "vault-keys.json"
    script = (
        "import sys\n"
        "from vaultody_sdk import FileVaultKeyStore\n"
        "pin = {'type': 'main', 'keys': {'ECDSA': 'xpub-test', 'EDDSA': None}, 'status': 'unverified',\n"
        "       'firstSeenAt': 1, 'verifiedAt': None, 'verification': None}\n"
        "store = FileVaultKeyStore(sys.argv[1])\n"
        "for n in range(10):\n"
        "    store.pin_if_absent('https://rest.example.test', dict(pin, vaultId='{}-{}'.format(sys.argv[2], n)))\n"
    )
    processes = [subprocess.Popen([sys.executable, "-c", script, str(path), str(index)]) for index in range(4)]
    assert [process.wait(timeout=60) for process in processes] == [0, 0, 0, 0]
    assert len(FileVaultKeyStore(path).list("https://rest.example.test")) == 40
    assert sorted(os.listdir(tmp_path)) == ["vault-keys.json"], "the lock file is removed"


def test_a_stale_lock_is_taken_over_and_a_live_one_waited_for(tmp_path, monkeypatch):
    import vaultody_sdk.stores as stores

    path = tmp_path / "vault-keys.json"
    lock = tmp_path / "vault-keys.json.lock"
    lock.write_text("1")
    old = os.stat(lock).st_mtime - 60
    os.utime(lock, (old, old))
    pin = {"vaultId": "v1", "type": "main", "keys": {"ECDSA": "xpub-test", "EDDSA": None}, "status": "unverified",
           "firstSeenAt": 1, "verifiedAt": None, "verification": None}
    FileVaultKeyStore(path).pin_if_absent("https://rest.example.test", pin)
    assert not lock.exists()
    # A fresh lock held by someone else: the writer gives up with `locked`.
    lock.write_text("1")
    monkeypatch.setattr(stores, "LOCK_TIMEOUT_SECONDS", 0.1)
    with pytest.raises(VaultKeyStoreError) as raised:
        FileVaultKeyStore(path).set_strict_latch("https://rest.example.test", {"latchedAt": 1, "rootId": "r"})
    assert raised.value.code == "locked"
    # Reading takes no lock.
    assert FileVaultKeyStore(path).get("https://rest.example.test", "v1") == pin
