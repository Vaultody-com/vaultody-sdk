"""Edwards25519 point decoding, encoding and scalar multiplication, for public keys only.

Written for this package from RFC 8032: the curve constants of section 5.1, the point encoding of section
5.1.2 and the extended-coordinate addition of section 5.1.4. That addition formula is complete on this curve,
so it handles every input, including the neutral element and points of small order, and also serves for
doubling.

The decoder deliberately copies the JavaScript library the Vaultody server uses (``elliptic``'s
``pointFromY``) rather than RFC 8032's stricter decoder: a y coordinate at or above p is reduced modulo p
instead of being refused. For keys the server itself encoded the two never differ, but matching the server
exactly means an address it derived can always be derived here too.

Points are extended coordinates ``(X, Y, Z, T)`` with x = X/Z, y = Y/Z and x*y = T/Z. Public data only, so
nothing here tries to run in constant time.
"""

P = 2 ** 255 - 19
# The order of the prime-order subgroup (RFC 8032 calls it L).
L = 2 ** 252 + 27742317777372353535851937790883648493
D = -121665 * pow(121666, P - 2, P) % P
_D2 = 2 * D % P
_SQRT_MINUS_ONE = pow(2, (P - 1) // 4, P)

NEUTRAL = (0, 1, 1, 0)


def decode(data):
    """The point of a 32-byte encoded public key. Raises ValueError if the bytes encode no point."""
    data = bytes(data)
    if len(data) != 32:
        raise ValueError("an ed25519 public key is 32 bytes")
    x_is_odd = data[31] >> 7
    y = (int.from_bytes(data, "little") & ((1 << 255) - 1)) % P
    # From the curve equation -x^2 + y^2 = 1 + d x^2 y^2: x^2 = (y^2 - 1) / (d y^2 + 1).
    x_squared = (y * y - 1) * pow(D * y * y + 1, P - 2, P) % P
    if x_squared == 0:
        if x_is_odd:
            raise ValueError("x is 0, so it can't be odd")
        return (0, y, 1, 0)
    # P = 5 (mod 8): one candidate root, times sqrt(-1) when its square comes out as -x^2 (RFC 8032 5.1.3).
    x = pow(x_squared, (P + 3) // 8, P)
    if x * x % P != x_squared:
        x = x * _SQRT_MINUS_ONE % P
    if x * x % P != x_squared:
        raise ValueError("the y coordinate is not on the curve")
    if (x & 1) != x_is_odd:
        x = P - x
    return (x, y, 1, x * y % P)


def encode(point):
    """The 32-byte encoding: y little-endian, with the parity of x in the top bit."""
    x_ext, y_ext, z, _ = point
    z_inverse = pow(z, P - 2, P)
    x = x_ext * z_inverse % P
    y = y_ext * z_inverse % P
    data = bytearray(y.to_bytes(32, "little"))
    data[31] |= (x & 1) << 7
    return bytes(data)


def add(first, second):
    """first + second, by the complete formula of RFC 8032 section 5.1.4."""
    x1, y1, z1, t1 = first
    x2, y2, z2, t2 = second
    a = (y1 - x1) * (y2 - x2) % P
    b = (y1 + x1) * (y2 + x2) % P
    c = t1 * _D2 * t2 % P
    d = z1 * 2 * z2 % P
    e = b - a
    f = d - c
    g = d + c
    h = b + a
    return (e * f % P, g * h % P, f * g % P, e * h % P)


def multiply(scalar, point):
    """scalar x point by double-and-add, with the full scalar.

    The scalar is not reduced modulo L first. The server multiplies by the full 256-bit number, and for a
    point outside the prime-order subgroup the two would differ.
    """
    if scalar < 0:
        raise ValueError("the scalar must not be negative")
    result = NEUTRAL
    addend = point
    while scalar:
        if scalar & 1:
            result = add(result, addend)
        addend = add(addend, addend)
        scalar >>= 1
    return result
