"""The error verify_address raises when an address is not proven to belong to the vault."""

from ..errors import VaultodyVerifyError

_REASON_TEXT = {
    "mismatch": "the address is not the one the vault's xpub gives for this account, change and index",
    "not_verifiable": "the address carries no derivation details (for example a smart or automation vault address)",
    "unknown_vault": "no signed GET /vaults response listed this vault",
    "missing_key": "the vault has no usable xpub for this blockchain's algorithm",
    "network_mismatch": "the network does not match the vault type (mainnet needs a main vault, a testnet a test vault)",
    "unsupported": "this helper does not know the blockchain, network or address format",
}


class AddressVerificationError(VaultodyVerifyError):
    """The address is not proven to be the vault's. Don't send funds to it or show it as a deposit address.

    ``reason`` is one of ``REASONS``; the message adds detail for logs.
    """

    REASONS = tuple(_REASON_TEXT)

    def __init__(self, reason, detail=None):
        if reason not in _REASON_TEXT:
            raise ValueError("unknown address verification failure reason: {!r}".format(reason))
        # Both values go to Exception so the error survives pickling, as ResponseSignatureError does.
        super().__init__(reason, detail)
        self.reason = reason
        self.detail = detail if detail is not None else _REASON_TEXT[reason]

    def __str__(self):
        return "{}: {}".format(self.reason, self.detail)
