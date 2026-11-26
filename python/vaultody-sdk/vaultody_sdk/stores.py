"""Where vault xpub pins (and the response-signature latch) are kept between calls and between runs.

The client keeps, per API origin (``https://rest.vaultody.com``; test and production pins never mix):

- the pins: the xpubs of each vault as first seen in GET /vaults/{main|test} (vault_keys.py);
- the latch (``responseSignature``): whether that origin has sent a signed response, after which an
  unsigned one is refused: ``{"latchedAt", "rootId"}``, rootId the root that verified it, or None when it did
  not verify. Kept here so a restart does not undo it.

Any object with the methods of ``VaultKeyStore`` works (a database, Redis). The client calls them from one
thread at a time per call; the async client calls them through ``asyncio.to_thread``. ``pin_if_absent`` and
``upgrade_trust`` must be atomic. The transport never calls ``replace``: changing a pinned xpub is an
administrative act, done only after the new xpub was confirmed out of band.

``FileVaultKeyStore`` is the default: ``$VAULTODY_VAULT_KEYS_FILE``, else ``~/.vaultody/vault-keys.json``.
Its file is the one every SDK language reads and writes (docs/vault-keys-file.md, the schema in
docs/vault-keys-file-v1.schema.json, the cases in test-vectors/vault-keys-file-v1.json), so Node, Python and
PHP clients can share it:

- a file that is not exactly that layout is refused (``VaultKeyStoreError`` with a code), never taken as
  empty; so is one that is a symbolic link, writable by others, or over 16 MiB;
- the xpub reveals every address of a vault, so the file is mode 0600 in a 0700 directory;
- a change is a read, merge and write under ``<file>.lock``, created exclusively and removed afterwards (the
  lock every language takes; a lock older than 30 s was left by a dead process); the new content, in the
  canonical form every language writes, goes to a temporary file that is synced and renamed over the file.
  Reading takes no lock.
"""

import copy
import errno
import json
import logging
import os
import re
import stat
import sys
import tempfile
import threading
import time
import warnings
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Dict, List, Optional, Protocol, Union, runtime_checkable

from .errors import VaultKeyStoreError
from .vault_keys import ALGORITHMS, PIN_STATUS

FORMAT = "vaultody vault keys v1"
ENV_FILE = "VAULTODY_VAULT_KEYS_FILE"
_LOG = logging.getLogger("vaultody_sdk")

#: A file larger than this is refused (too_large).
MAX_FILE_BYTES = 16 * 1024 * 1024
#: Times are Unix seconds, JSON integers from 0 to 2^53 - 1.
MAX_TIME = 2 ** 53 - 1
#: The lock: polled this often, given up after LOCK_TIMEOUT_SECONDS, stale after LOCK_STALE_SECONDS.
LOCK_RETRY_SECONDS = 0.02
LOCK_TIMEOUT_SECONDS = 10.0
LOCK_STALE_SECONDS = 30.0

_POSIX = sys.platform != "win32"
_ORIGIN = re.compile(r"https?://[^/?#@\s]+")
_NOT_BLANK = re.compile(r"\S")
_DOCUMENT_FIELDS = frozenset(("format", "origins"))
_ENTRY_FIELDS = frozenset(("responseSignature", "vaults", "audit"))
_PIN_FIELDS = frozenset(("vaultId", "type", "keys", "status", "firstSeenAt", "verifiedAt", "verification"))
_LATCH_FIELDS = frozenset(("latchedAt", "rootId"))
_VERIFICATION_FIELDS = frozenset(("rootId", "timestamp"))
_AUDIT_FIELDS = frozenset(("vaultId", "at", "reason", "removed"))
_VAULT_TYPES = ("main", "test")
# Write errors after which the default store keeps pins in memory instead (with a loud warning).
_UNWRITABLE = frozenset((errno.EACCES, errno.EPERM, errno.EROFS, errno.ENOTDIR, errno.ENOENT, errno.ENOSPC, errno.EISDIR))

Pin = Dict[str, Any]


@runtime_checkable
class VaultKeyStore(Protocol):
    """The store interface; every method takes the API origin first."""

    def get(self, origin: str, vault_id: str) -> Optional[Pin]:
        """The pin of one vault, or None."""

    def list(self, origin: str) -> List[Pin]:
        """Every pin of the origin."""

    def pin_if_absent(self, origin: str, pin: Pin) -> Pin:
        """Stores ``pin`` unless the vault is pinned already; returns what is stored. Atomic."""

    def upgrade_trust(self, origin: str, vault_id: str, expected: Pin, upgraded: Pin) -> Pin:
        """Replaces an unverified pin with its verified twin only if the stored pin still equals
        ``expected``; returns what is stored. Atomic."""

    def replace(self, origin: str, vault_id: str, pin: Optional[Pin], reason: str) -> None:
        """Administrative: changes or removes a pin. The transport never calls it."""

    def get_strict_latch(self, origin: str) -> Optional[Dict[str, Any]]:
        """The latch of the origin (``{"latchedAt", "rootId"}``, rootId None when the signed response that set
        it did not verify), or None while no signed response came."""

    def set_strict_latch(self, origin: str, latch: Dict[str, Any]) -> Dict[str, Any]:
        """Sets the latch unless set; returns what is stored."""


# ---------------------------------------------------------------------------------------------------
# The document: parsing, checking, the canonical bytes
# ---------------------------------------------------------------------------------------------------


def _error(code, message):
    return VaultKeyStoreError(message, code)


def _malformed(message):
    return _error("malformed", "the vault key store is malformed ({}); refusing to treat it as empty".format(message))


def _is_time(value):
    # type() rather than isinstance(): a bool is not a time.
    return type(value) is int and 0 <= value <= MAX_TIME


def _is_text(value):
    return isinstance(value, str) and value != ""


def _fields(value, fields, where):
    if not isinstance(value, dict) or set(value) != fields:
        raise _malformed("{} must be an object with exactly {}".format(where, ", ".join(sorted(fields))))


def _check_pin(pin, vault_id=None):
    """A pin exactly as the schema allows it, else VaultKeyStoreError malformed."""
    _fields(pin, _PIN_FIELDS, "a pin")
    if not _is_text(pin["vaultId"]) or (vault_id is not None and pin["vaultId"] != vault_id):
        raise _malformed("a pin has no vaultId, or one that differs from its key")
    where = "the pin of {}".format(pin["vaultId"])
    if pin["type"] not in _VAULT_TYPES or not isinstance(pin["type"], str):
        raise _malformed("{} has a type that is not main or test".format(where))
    keys = pin["keys"]
    _fields(keys, frozenset(ALGORITHMS), "the keys of " + where)
    for name in ALGORITHMS:
        if keys[name] is not None and not _is_text(keys[name]):
            raise _malformed("{} has a malformed {} xpub".format(where, name))
    if all(keys[name] is None for name in ALGORITHMS):
        raise _malformed("{} holds no xpub".format(where))
    if not isinstance(pin["status"], str) or pin["status"] not in PIN_STATUS.values():
        raise _malformed("{} has an unknown status".format(where))
    if not _is_time(pin["firstSeenAt"]):
        raise _malformed("{} has a malformed firstSeenAt".format(where))
    if pin["status"] == PIN_STATUS["VERIFIED"]:
        if not _is_time(pin["verifiedAt"]):
            raise _malformed("{} is verified without verifiedAt".format(where))
        verification = pin["verification"]
        _fields(verification, _VERIFICATION_FIELDS, "the verification of " + where)
        if not _is_text(verification["rootId"]) or not _is_time(verification["timestamp"]):
            raise _malformed("{} has a malformed verification".format(where))
    elif pin["verifiedAt"] is not None or pin["verification"] is not None:
        raise _malformed("{} is unverified but has verifiedAt or verification".format(where))
    return pin


def _check_latch(latch):
    if latch is None:
        return latch
    _fields(latch, _LATCH_FIELDS, "the response-signature latch")
    # rootId is null when the answer that latched did not verify (refused, or no root to check it with).
    if not _is_time(latch["latchedAt"]) or (latch["rootId"] is not None and not _is_text(latch["rootId"])):
        raise _malformed("the response-signature latch needs latchedAt and a rootId (text, or null)")
    return latch


def _check_audit(entries):
    if not isinstance(entries, list):
        raise _malformed("audit must be a list")
    for entry in entries:
        _fields(entry, _AUDIT_FIELDS, "an audit entry")
        if (
            not _is_text(entry["vaultId"]) or not _is_time(entry["at"]) or not isinstance(entry["reason"], str)
            or not _NOT_BLANK.search(entry["reason"]) or not isinstance(entry["removed"], bool)
        ):
            raise _malformed("an audit entry has a malformed field")
    return entries


def _check_document(document):
    """A whole document, the format tag already checked: every deviation is malformed."""
    if set(document) != _DOCUMENT_FIELDS:
        raise _malformed("the top level must hold exactly format and origins")
    origins = document["origins"]
    if not isinstance(origins, dict):
        raise _malformed("origins must be an object")
    for origin, entry in origins.items():
        if not _ORIGIN.fullmatch(origin):
            raise _malformed("an origin key is not an API origin such as https://rest.vaultody.com")
        _fields(entry, _ENTRY_FIELDS, "the entry of an origin")
        _check_latch(entry["responseSignature"])
        if not isinstance(entry["vaults"], dict):
            raise _malformed("vaults must be an object")
        for vault_id, pin in entry["vaults"].items():
            if not _is_text(vault_id):
                raise _malformed("a vault id is empty")
            _check_pin(pin, vault_id)
        _check_audit(entry["audit"])
    return document


def _refuse_constant(name):
    raise ValueError("{} is not JSON".format(name))


def parse_document(data: bytes) -> Dict[str, Any]:
    """The document of a vault keys file, checked against the v1 schema.

    :raises VaultKeyStoreError: ``not_json`` (not strict UTF-8 JSON, a byte-order mark), ``unknown_format``
        (not an object, or not the v1 tag) or ``malformed`` (anything else the schema does not allow)
    """
    if bytes(data[:3]) == b"\xef\xbb\xbf":
        raise _error("not_json", "the vault key store starts with a byte-order mark; it is not treated as empty")
    try:
        document = json.loads(bytes(data).decode("utf-8"), parse_constant=_refuse_constant)
    except (UnicodeDecodeError, ValueError, RecursionError):
        raise _error("not_json", "the vault key store is not UTF-8 JSON; it is not treated as empty") from None
    if not isinstance(document, dict) or not isinstance(document.get("format"), str) or document["format"] != FORMAT:
        raise _error("unknown_format", "the vault key store is not a {} file; it is not treated as empty".format(FORMAT))
    return _check_document(document)


def canonical_json(document: Dict[str, Any]) -> str:
    """The canonical text of a document, what every SDK writes: keys sorted at every level, a two-space
    indent, nothing escaped that JSON does not require, a final newline."""
    return json.dumps(document, indent=2, sort_keys=True, ensure_ascii=False, allow_nan=False) + "\n"


def _argument(check, value, *args):
    """Checks a pin or latch handed to the store: what the file could not hold is invalid_pin."""
    try:
        return check(value, *args)
    except VaultKeyStoreError as error:
        raise _error("invalid_pin", "the value to store is malformed: {}".format(error)) from None


def _empty():
    return {"format": FORMAT, "origins": {}}


def _check_origin(origin, create):
    if not isinstance(origin, str) or not origin:
        raise TypeError("origin must be the API origin, such as https://rest.vaultody.com")
    if create and not _ORIGIN.fullmatch(origin):
        raise TypeError("origin must be an API origin, scheme://host[:port], such as https://rest.vaultody.com")


# ---------------------------------------------------------------------------------------------------
# The stores
# ---------------------------------------------------------------------------------------------------


class _DocumentStore:
    """The store logic over one JSON document; subclasses say where the document lives."""

    @contextmanager
    def _transaction(self, write):  # pragma: no cover - abstract
        raise NotImplementedError
        yield

    @staticmethod
    def _entry(document, origin, create):
        _check_origin(origin, create)
        entry = document["origins"].get(origin)
        if entry is None and create:
            entry = document["origins"][origin] = {"responseSignature": None, "vaults": {}, "audit": []}
        return entry

    def get(self, origin, vault_id):
        with self._transaction(write=False) as document:
            entry = self._entry(document, origin, False)
            pin = entry["vaults"].get(vault_id) if entry else None
            return copy.deepcopy(pin)

    def list(self, origin):
        with self._transaction(write=False) as document:
            entry = self._entry(document, origin, False)
            return [copy.deepcopy(pin) for pin in (entry["vaults"].values() if entry else ())]

    def pin_if_absent(self, origin, pin):
        _argument(_check_pin, pin)
        with self._transaction(write=True) as document:
            entry = self._entry(document, origin, True)
            stored = entry["vaults"].setdefault(pin["vaultId"], copy.deepcopy(pin))
            return copy.deepcopy(stored)

    def upgrade_trust(self, origin, vault_id, expected, upgraded):
        _argument(_check_pin, upgraded, vault_id)
        same = all(upgraded[name] == expected[name] for name in ("vaultId", "type", "keys", "firstSeenAt"))
        if not same or expected["status"] != PIN_STATUS["UNVERIFIED"] or upgraded["status"] != PIN_STATUS["VERIFIED"]:
            raise ValueError("upgrade_trust only turns an unverified pin into a verified one with the same xpubs")
        with self._transaction(write=True) as document:
            entry = self._entry(document, origin, True)
            stored = entry["vaults"].get(vault_id)
            if stored == expected:
                stored = entry["vaults"][vault_id] = copy.deepcopy(upgraded)
            return copy.deepcopy(stored)

    def replace(self, origin, vault_id, pin, reason):
        if not isinstance(reason, str) or not _NOT_BLANK.search(reason):
            raise ValueError("say why the pin is replaced; it is kept in the store's audit list")
        if not _is_text(vault_id):
            raise _error("invalid_pin", "vault_id must be the vault's id")
        if pin is not None:
            _argument(_check_pin, pin, vault_id)
        with self._transaction(write=True) as document:
            entry = self._entry(document, origin, True)
            if pin is None:
                entry["vaults"].pop(vault_id, None)
            else:
                entry["vaults"][vault_id] = copy.deepcopy(pin)
            entry["audit"].append({"vaultId": vault_id, "at": int(time.time()), "reason": reason, "removed": pin is None})

    def get_strict_latch(self, origin):
        with self._transaction(write=False) as document:
            entry = self._entry(document, origin, False)
            return copy.deepcopy(entry["responseSignature"]) if entry else None

    def set_strict_latch(self, origin, latch):
        if latch is None:
            raise _error("invalid_pin", "the latch must be {latchedAt, rootId}")
        _argument(_check_latch, latch)
        with self._transaction(write=True) as document:
            entry = self._entry(document, origin, True)
            if entry["responseSignature"] is None:
                entry["responseSignature"] = copy.deepcopy(latch)
            return copy.deepcopy(entry["responseSignature"])

    def reset_strict_latch(self, origin):
        """Administrative: forgets that the origin signs, for a test environment that stopped signing."""
        with self._transaction(write=True) as document:
            entry = self._entry(document, origin, False)
            if entry is not None:
                entry["responseSignature"] = None


class MemoryVaultKeyStore(_DocumentStore):
    """Pins kept only as long as the process: for tests, and as the fallback when no file can be written."""

    def __init__(self) -> None:
        self._document = _empty()
        self._lock = threading.Lock()

    @contextmanager
    def _transaction(self, write):
        with self._lock:
            if not write:
                yield self._document
                return
            # A change is checked like a file's and applied whole, or not at all.
            document = copy.deepcopy(self._document)
            yield document
            if document != self._document:
                self._document = _check_document(document)

    def __repr__(self):
        return "MemoryVaultKeyStore()"


_PATH_LOCKS: Dict[str, threading.Lock] = {}
_PATH_LOCKS_GUARD = threading.Lock()


def _thread_lock_for(path):
    with _PATH_LOCKS_GUARD:
        return _PATH_LOCKS.setdefault(path, threading.Lock())


def default_vault_keys_path():
    """``$VAULTODY_VAULT_KEYS_FILE``, else ``~/.vaultody/vault-keys.json``."""
    configured = os.environ.get(ENV_FILE)
    if configured:
        return Path(configured)
    return Path.home() / ".vaultody" / "vault-keys.json"


def _reason(error):
    return error.strerror or type(error).__name__


class FileVaultKeyStore(_DocumentStore):
    """Pins in a JSON file, shared safely by every process of the user, in any SDK language.

    :param path: the file; its directory is created with mode 0700 if missing
    :param fallback_to_memory: when the file can't be written at all (no permission, a read-only file
        system), keep pins in memory for this process, starting from what the file holds, and warn loudly
        instead of failing. A file that exists and can't be read, or is refused, always fails
        (VaultKeyStoreError).
    """

    def __init__(self, path: Union[str, "os.PathLike[str]"], *, fallback_to_memory: bool = False) -> None:
        self._path = Path(path)
        self._fallback_to_memory = fallback_to_memory
        self._memory: Optional[MemoryVaultKeyStore] = None

    @property
    def path(self) -> Path:
        return self._path

    @property
    def in_memory(self) -> bool:
        """True once the store fell back to memory (pins then last only as long as the process)."""
        return self._memory is not None

    def __repr__(self):
        return "FileVaultKeyStore({!r}{})".format(str(self._path), ", in memory" if self._memory is not None else "")

    def _lock_path(self):
        return str(self._path) + ".lock"

    # -- reading ------------------------------------------------------------------------------------

    def _read(self):
        """The document in the file; an empty one when there is no file. Never takes the lock."""
        path = str(self._path)
        try:
            info = os.lstat(path)
        except FileNotFoundError:
            return _empty()
        except OSError as error:
            raise _error("unreadable", "cannot read the vault key store {}: {}".format(self._path, _reason(error))) from None
        if not stat.S_ISREG(info.st_mode):
            raise _error("not_regular_file", "the vault key store {} is not a regular file (a symbolic link or a directory)".format(self._path))
        try:
            fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0))
        except FileNotFoundError:
            return _empty()
        except OSError as error:
            if error.errno == errno.ELOOP:
                raise _error("not_regular_file", "the vault key store {} is a symbolic link".format(self._path)) from None
            raise _error("unreadable", "cannot read the vault key store {}: {}".format(self._path, _reason(error))) from None
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode):
                raise _error("not_regular_file", "the vault key store {} is not a regular file".format(self._path))
            if _POSIX and info.st_mode & 0o022:
                raise _error(
                    "insecure_permissions",
                    "the vault key store {} can be written by other users; set its mode to 0600 (chmod 600) before using it".format(self._path),
                )
            if info.st_size > MAX_FILE_BYTES:
                raise _error("too_large", "the vault key store {} is larger than 16 MiB".format(self._path))
            chunks = []
            size = 0
            while True:
                chunk = os.read(fd, 1024 * 1024)
                if not chunk:
                    break
                size += len(chunk)
                if size > MAX_FILE_BYTES:
                    raise _error("too_large", "the vault key store {} is larger than 16 MiB".format(self._path))
                chunks.append(chunk)
        except OSError as error:
            raise _error("unreadable", "cannot read the vault key store {}: {}".format(self._path, _reason(error))) from None
        finally:
            os.close(fd)
        try:
            return parse_document(b"".join(chunks))
        except VaultKeyStoreError as error:
            raise VaultKeyStoreError("{}: {}".format(self._path, error), error.code) from None

    # -- the lock -----------------------------------------------------------------------------------

    def _acquire(self):
        """Creates the lock file exclusively, the protocol every SDK language follows."""
        lock = self._lock_path()
        deadline = time.monotonic() + LOCK_TIMEOUT_SECONDS
        while True:
            try:
                fd = os.open(lock, os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, "O_BINARY", 0), 0o600)
            except FileExistsError:
                pass
            except PermissionError:
                if _POSIX:
                    raise
                # Windows: a lock file being deleted can't be opened for a moment.
            else:
                try:
                    os.write(fd, str(os.getpid()).encode("ascii"))
                finally:
                    os.close(fd)
                return
            try:
                if time.time() - os.stat(lock).st_mtime > LOCK_STALE_SECONDS:
                    # Left by a process that died while holding it.
                    try:
                        os.unlink(lock)
                    except FileNotFoundError:
                        pass
                    continue
            except FileNotFoundError:
                continue
            if time.monotonic() > deadline:
                raise _error("locked", "the vault key store {} stayed locked for {:g} s ({})".format(self._path, LOCK_TIMEOUT_SECONDS, lock))
            time.sleep(LOCK_RETRY_SECONDS)

    def _release(self):
        try:
            os.unlink(self._lock_path())
        except FileNotFoundError:
            pass

    # -- writing ------------------------------------------------------------------------------------

    def _write(self, document):
        directory = str(self._path.parent)
        fd, temp = tempfile.mkstemp(prefix=self._path.name + ".", suffix=".tmp", dir=directory)
        try:
            with os.fdopen(fd, "wb") as handle:
                if _POSIX:
                    os.fchmod(handle.fileno(), 0o600)
                handle.write(canonical_json(document).encode("utf-8"))
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temp, str(self._path))
        except BaseException:
            try:
                os.unlink(temp)
            except OSError:
                pass
            raise
        if _POSIX:
            # Make the rename itself durable; best effort.
            try:
                dir_fd = os.open(directory, os.O_RDONLY)
                try:
                    os.fsync(dir_fd)
                finally:
                    os.close(dir_fd)
            except OSError:
                pass

    def _fall_back(self, error, document):
        """The file can't be written: keep pins in memory from now on (default store only), else fail."""
        if not self._fallback_to_memory or error.errno not in _UNWRITABLE:
            raise _error("unwritable", "cannot write the vault key store {}: {}".format(self._path, _reason(error))) from None
        memory = MemoryVaultKeyStore()
        memory._document = _check_document(copy.deepcopy(document))
        self._memory = memory
        message = (
            "vaultody_sdk: the vault key store {} can't be written ({}); vault xpub pins are kept in memory "
            "and last only as long as this process. Set {} or pass vault_key_store=.".format(self._path, _reason(error), ENV_FILE)
        )
        warnings.warn(message, RuntimeWarning, stacklevel=5)
        _LOG.warning(message)
        return memory

    @contextmanager
    def _transaction(self, write):
        if self._memory is not None:
            with self._memory._transaction(write) as document:
                yield document
            return
        if not write:
            yield self._read()
            return
        with _thread_lock_for(str(self._path.absolute())):
            try:
                directory = self._path.parent
                if not directory.exists():
                    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
                self._acquire()
            except OSError as error:
                # Pins that exist are never set aside: the memory store starts from what the file holds.
                memory = self._fall_back(error, self._read())
                with memory._transaction(write) as document:
                    yield document
                return
            try:
                document = self._read()
                before = copy.deepcopy(document)
                yield document
                if document != before:
                    _check_document(document)
                    try:
                        self._write(document)
                    except OSError as error:
                        self._fall_back(error, document)
            finally:
                self._release()


def default_vault_key_store() -> VaultKeyStore:
    """The store a client uses when none is given.

    ``$VAULTODY_VAULT_KEYS_FILE`` when set (any problem with it fails). Otherwise
    ``~/.vaultody/vault-keys.json``, falling back to memory with a warning when that location can't be
    written (a read-only container, no home directory).
    """
    configured = os.environ.get(ENV_FILE)
    if configured:
        return FileVaultKeyStore(configured)
    try:
        path = default_vault_keys_path()
    except (RuntimeError, KeyError, OSError):
        # No home directory: the same fallback as an unwritable one.
        message = (
            "vaultody_sdk: there is no home directory for the vault key store; vault xpub pins are kept in memory "
            "and last only as long as this process. Set {} or pass vault_key_store=.".format(ENV_FILE)
        )
        warnings.warn(message, RuntimeWarning, stacklevel=3)
        _LOG.warning(message)
        return MemoryVaultKeyStore()
    return FileVaultKeyStore(path, fallback_to_memory=True)


__all__ = [
    "ENV_FILE",
    "FORMAT",
    "FileVaultKeyStore",
    "MemoryVaultKeyStore",
    "VaultKeyStore",
    "canonical_json",
    "default_vault_key_store",
    "default_vault_keys_path",
    "parse_document",
]
