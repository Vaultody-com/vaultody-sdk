"""The vault key stores: atomic pins, the latch, the file's modes and lock, and failing closed."""

import json
import os
import stat
import sys
import threading

import pytest

from vaultody_sdk import FileVaultKeyStore, MemoryVaultKeyStore, VaultKeyStore, VaultKeyStoreError, default_vault_key_store
from vaultody_sdk.stores import FORMAT, canonical_json

from mock_gateway import ECDSA_XPUB, EDDSA_XPUB, OTHER_ECDSA_XPUB

ORIGIN = "https://rest.example.test"
OTHER_ORIGIN = "https://rest.other.test"

POSIX = sys.platform != "win32"


def pin(vault_id="v1", status="unverified", ecdsa=ECDSA_XPUB):
    return {
        "vaultId": vault_id, "type": "main", "keys": {"ECDSA": ecdsa, "EDDSA": EDDSA_XPUB}, "status": status,
        "firstSeenAt": 10, "verifiedAt": 20 if status == "verified" else None,
        "verification": {"rootId": "r", "timestamp": 19} if status == "verified" else None,
    }


@pytest.fixture(params=["memory", "file"])
def store(request, tmp_path):
    if request.param == "memory":
        return MemoryVaultKeyStore()
    return FileVaultKeyStore(tmp_path / "dir" / "vault-keys.json")


def test_both_follow_the_protocol(store):
    assert isinstance(store, VaultKeyStore)


def test_pin_if_absent_keeps_the_first_pin(store):
    assert store.pin_if_absent(ORIGIN, pin()) == pin()
    assert store.pin_if_absent(ORIGIN, pin(ecdsa=OTHER_ECDSA_XPUB)) == pin()
    assert store.get(ORIGIN, "v1") == pin()
    assert store.list(ORIGIN) == [pin()]


def test_origins_never_mix(store):
    store.pin_if_absent(ORIGIN, pin())
    assert store.get(OTHER_ORIGIN, "v1") is None and store.list(OTHER_ORIGIN) == []


def test_upgrade_trust_is_a_compare_and_set(store):
    store.pin_if_absent(ORIGIN, pin())
    verified = pin(status="verified")
    assert store.upgrade_trust(ORIGIN, "v1", pin(), verified) == verified
    # A second upgrade from a stale expectation changes nothing.
    assert store.upgrade_trust(ORIGIN, "v1", pin(), dict(verified, verifiedAt=99)) == verified
    with pytest.raises(ValueError):
        store.upgrade_trust(ORIGIN, "v1", verified, pin(status="verified", ecdsa=OTHER_ECDSA_XPUB))


def test_replace_is_the_only_way_to_change_a_pin_and_is_audited(store):
    store.pin_if_absent(ORIGIN, pin())
    with pytest.raises(ValueError):
        store.replace(ORIGIN, "v1", pin(ecdsa=OTHER_ECDSA_XPUB), "")
    store.replace(ORIGIN, "v1", pin(ecdsa=OTHER_ECDSA_XPUB), "confirmed with support, ticket TEST-1")
    assert store.get(ORIGIN, "v1")["keys"]["ECDSA"] == OTHER_ECDSA_XPUB
    store.replace(ORIGIN, "v1", None, "vault deleted")
    assert store.get(ORIGIN, "v1") is None


def test_the_latch_is_set_once(store):
    assert store.get_strict_latch(ORIGIN) is None
    assert store.set_strict_latch(ORIGIN, {"latchedAt": 1, "rootId": "a"}) == {"latchedAt": 1, "rootId": "a"}
    assert store.set_strict_latch(ORIGIN, {"latchedAt": 2, "rootId": "b"}) == {"latchedAt": 1, "rootId": "a"}
    store.reset_strict_latch(ORIGIN)
    assert store.get_strict_latch(ORIGIN) is None


def test_a_latch_set_by_an_answer_that_did_not_verify_has_no_root(store):
    assert store.set_strict_latch(ORIGIN, {"latchedAt": 1, "rootId": None}) == {"latchedAt": 1, "rootId": None}
    assert store.set_strict_latch(ORIGIN, {"latchedAt": 2, "rootId": "a"}) == {"latchedAt": 1, "rootId": None}
    assert store.get_strict_latch(ORIGIN) == {"latchedAt": 1, "rootId": None}


@pytest.mark.parametrize("bad", [
    None,
    {"since": 1, "rootId": "a"},
    {"latchedAt": 1},
    {"latchedAt": 1, "rootId": ""},
    {"latchedAt": 1, "rootId": 7},
    {"latchedAt": 1.5, "rootId": "a"},
    {"latchedAt": True, "rootId": "a"},
    {"latchedAt": 1, "rootId": "a", "responseTimestamp": 1},
])
def test_a_malformed_latch_is_refused(store, bad):
    with pytest.raises(VaultKeyStoreError) as raised:
        store.set_strict_latch(ORIGIN, bad)
    assert raised.value.code == "invalid_pin"
    assert store.get_strict_latch(ORIGIN) is None


def test_returned_pins_are_copies(store):
    store.pin_if_absent(ORIGIN, pin())
    got = store.get(ORIGIN, "v1")
    got["keys"]["ECDSA"] = "changed"
    assert store.get(ORIGIN, "v1") == pin()


@pytest.mark.parametrize("bad", [
    {"vaultId": "v1"},
    dict(pin(), keys={"ECDSA": None, "EDDSA": None}),
    dict(pin(), status="trusted"),
    dict(pin(), verifiedAt=5),
    dict(pin(), type="MAIN"),
    dict(pin(), firstSeenAt=1.0),
    dict(pin(), replaced={"reason": "x"}),
])
def test_a_malformed_pin_is_refused(store, bad):
    with pytest.raises(VaultKeyStoreError) as raised:
        store.pin_if_absent(ORIGIN, bad)
    assert raised.value.code == "invalid_pin"
    assert store.list(ORIGIN) == []


def test_replace_is_recorded_in_the_audit_list(tmp_path):
    path = tmp_path / "vault-keys.json"
    store = FileVaultKeyStore(path)
    store.pin_if_absent(ORIGIN, pin())
    store.replace(ORIGIN, "v1", pin(ecdsa=OTHER_ECDSA_XPUB), "confirmed with support")
    store.replace(ORIGIN, "v1", None, "vault deleted")
    audit = json.loads(path.read_text())["origins"][ORIGIN]["audit"]
    assert [(entry["vaultId"], entry["reason"], entry["removed"]) for entry in audit] == [
        ("v1", "confirmed with support", False), ("v1", "vault deleted", True),
    ]
    assert all(isinstance(entry["at"], int) and set(entry) == {"vaultId", "at", "reason", "removed"} for entry in audit)


# -- the file ---------------------------------------------------------------------------------------


def test_the_file_and_its_directory_are_private(tmp_path):
    path = tmp_path / "home" / ".vaultody" / "vault-keys.json"
    store = FileVaultKeyStore(path)
    store.pin_if_absent(ORIGIN, pin())
    document = json.loads(path.read_text())
    assert document["format"] == FORMAT and document["origins"][ORIGIN]["vaults"]["v1"] == pin()
    assert document["origins"][ORIGIN]["responseSignature"] is None and document["origins"][ORIGIN]["audit"] == []
    assert path.read_text() == canonical_json(document), "the canonical bytes every SDK writes"
    if POSIX:
        assert stat.S_IMODE(os.stat(path).st_mode) == 0o600
        assert stat.S_IMODE(os.stat(path.parent).st_mode) & 0o077 == 0
    assert os.listdir(path.parent) == ["vault-keys.json"], "no temporary file, and the lock is removed"


def test_a_file_that_does_not_parse_is_never_taken_as_empty(tmp_path):
    path = tmp_path / "vault-keys.json"
    path.write_text("{not json")
    if POSIX:
        os.chmod(path, 0o600)
    store = FileVaultKeyStore(path, fallback_to_memory=True)
    with pytest.raises(VaultKeyStoreError) as raised:
        store.list(ORIGIN)
    assert raised.value.code == "not_json"
    path.write_text(json.dumps({"format": FORMAT, "origins": {ORIGIN: {"vaults": {"v1": {"vaultId": "v1"}}}}}))
    with pytest.raises(VaultKeyStoreError) as raised:
        store.get(ORIGIN, "v1")
    assert raised.value.code == "malformed"
    with pytest.raises(VaultKeyStoreError):
        store.pin_if_absent(ORIGIN, pin())
    assert not store.in_memory


@pytest.mark.skipif(not POSIX, reason="file modes")
def test_a_file_others_can_write_is_refused(tmp_path):
    path = tmp_path / "vault-keys.json"
    FileVaultKeyStore(path).pin_if_absent(ORIGIN, pin())
    os.chmod(path, 0o666)
    with pytest.raises(VaultKeyStoreError) as raised:
        FileVaultKeyStore(path).list(ORIGIN)
    assert raised.value.code == "insecure_permissions"


@pytest.mark.skipif(not POSIX or os.geteuid() == 0, reason="needs a directory this user can't write")
def test_an_unwritable_default_location_falls_back_to_memory_loudly(tmp_path):
    locked = tmp_path / "locked"
    locked.mkdir()
    os.chmod(locked, 0o500)
    try:
        store = FileVaultKeyStore(locked / "sub" / "vault-keys.json", fallback_to_memory=True)
        with pytest.warns(RuntimeWarning, match="kept in memory"):
            store.pin_if_absent(ORIGIN, pin())
        assert store.in_memory and store.get(ORIGIN, "v1") == pin()
        assert store.pin_if_absent(ORIGIN, pin(ecdsa=OTHER_ECDSA_XPUB)) == pin(), "memory keeps the first pin too"
        # Reading a missing file needs no directory; writing to an explicit path never falls back.
        assert FileVaultKeyStore(locked / "sub" / "vault-keys.json").list(ORIGIN) == []
        with pytest.raises(VaultKeyStoreError) as raised:
            FileVaultKeyStore(locked / "sub" / "vault-keys.json").pin_if_absent(ORIGIN, pin())
        assert raised.value.code == "unwritable"
    finally:
        os.chmod(locked, 0o700)


def test_the_default_store_follows_the_environment(tmp_path, monkeypatch):
    path = tmp_path / "configured.json"
    monkeypatch.setenv("VAULTODY_VAULT_KEYS_FILE", str(path))
    store = default_vault_key_store()
    assert isinstance(store, FileVaultKeyStore) and store.path == path
    monkeypatch.delenv("VAULTODY_VAULT_KEYS_FILE")
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    assert default_vault_key_store().path == tmp_path / "home" / ".vaultody" / "vault-keys.json"


def test_concurrent_writers_keep_every_pin(tmp_path):
    path = tmp_path / "vault-keys.json"

    def writer(index):
        store = FileVaultKeyStore(path)
        for n in range(10):
            store.pin_if_absent(ORIGIN, pin("v{}-{}".format(index, n)))

    threads = [threading.Thread(target=writer, args=(index,)) for index in range(4)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert len(FileVaultKeyStore(path).list(ORIGIN)) == 40


def test_repr_shows_no_xpub(tmp_path):
    store = FileVaultKeyStore(tmp_path / "vault-keys.json")
    store.pin_if_absent(ORIGIN, pin())
    assert ECDSA_XPUB not in repr(store) and ECDSA_XPUB not in repr(MemoryVaultKeyStore())
