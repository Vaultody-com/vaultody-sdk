"""Check that an address the Vaultody API returned really belongs to your vault.

Every vault address is derived from the vault's extended public key with public math only. ``check_address``
recomputes an address from the vault's xpub and the path the API returned with it, and raises
``AddressVerificationError`` unless it matches exactly. ``network_of_vault`` gives the network of an address
whose response does not say.
"""

from .check import AddressCheckResult, check_address, network_of_vault
from .errors import AddressVerificationError

__all__ = ["AddressCheckResult", "AddressVerificationError", "check_address", "network_of_vault"]
