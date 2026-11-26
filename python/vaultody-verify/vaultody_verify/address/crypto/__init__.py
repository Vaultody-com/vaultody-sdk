"""The small amount of curve and hash code that address checking needs, vendored in pure Python.

The package keeps ``cryptography`` as its only dependency, and ``cryptography`` exposes neither raw curve
point arithmetic (needed to derive child public keys) nor Keccak-256, and ``hashlib`` may lack RIPEMD-160
when Python is built against OpenSSL 3. So the pieces below live here, each with a note on where it comes
from and each tested against published test vectors.

Everything here handles public data only (extended public keys and values derived from them), so none of
it tries to run in constant time.
"""
