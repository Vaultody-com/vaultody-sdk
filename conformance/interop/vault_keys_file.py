"""The Python side of the vault keys file interop check (run.mjs): drives vaultody_sdk's FileVaultKeyStore.

    python -I vault_keys_file.py < command.json > answer.json

One JSON command on stdin, one JSON answer on stdout (the protocol is in run.mjs):

- ``{"op": "write", "file", "steps": [{"pin": {"origin", "pin"}} | {"latch": {"origin", "latch"}}]}``: each
  step is one store call (pin_if_absent, set_strict_latch), in order → ``{"ok": true}``
- ``{"op": "read", "file", "origins": [...]}`` → ``{"ok": true, "origins": {origin: {"responseSignature",
  "pins"}}}``, pins sorted by vaultId
- a VaultKeyStoreError → ``{"ok": false, "error": code}``
"""

import json
import sys

from vaultody_sdk import FileVaultKeyStore, VaultKeyStoreError


def run(command):
    store = FileVaultKeyStore(command["file"])
    if command["op"] == "write":
        for step in command["steps"]:
            if "pin" in step:
                store.pin_if_absent(step["pin"]["origin"], step["pin"]["pin"])
            elif "latch" in step:
                store.set_strict_latch(step["latch"]["origin"], step["latch"]["latch"])
            else:
                raise ValueError("unknown step {}".format(sorted(step)))
        return {"ok": True}
    if command["op"] == "read":
        return {
            "ok": True,
            "origins": {
                origin: {
                    "responseSignature": store.get_strict_latch(origin),
                    "pins": sorted(store.list(origin), key=lambda pin: pin["vaultId"]),
                }
                for origin in command["origins"]
            },
        }
    raise ValueError("unknown op {!r}".format(command["op"]))


def main():
    command = json.loads(sys.stdin.read())
    try:
        answer = run(command)
    except VaultKeyStoreError as error:
        answer = {"ok": False, "error": error.code}
    sys.stdout.write(json.dumps(answer))


if __name__ == "__main__":
    main()
