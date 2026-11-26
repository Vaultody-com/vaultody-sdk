"""secp256k1 point arithmetic for deriving child public keys.

Written for this package from the curve definition in SEC 2 v2.0, section 2.4.1 (the same constants every
Bitcoin library uses). Points are ``(x, y)`` integer tuples, and None is the point at infinity. Internally
the arithmetic uses Jacobian coordinates, which need one modular inverse per multiplication instead of one
per step. Public data only, so it does not try to run in constant time.
"""

P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
G = (
    0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
    0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8,
)

_INFINITY = (0, 1, 0)


def decompress(data):
    """The point of a 33-byte compressed public key (``02``/``03`` + x). Raises ValueError if it is not one."""
    data = bytes(data)
    if len(data) != 33 or data[0] not in (2, 3):
        raise ValueError("not a compressed secp256k1 public key")
    x = int.from_bytes(data[1:], "big")
    if x >= P:
        raise ValueError("the x coordinate is not below the field prime")
    y_squared = (pow(x, 3, P) + 7) % P
    # P = 3 (mod 4), so a square root, when one exists, is y_squared^((P + 1) / 4).
    y = pow(y_squared, (P + 1) // 4, P)
    if y * y % P != y_squared:
        raise ValueError("the x coordinate is not on the curve")
    if (y & 1) != (data[0] & 1):
        y = P - y
    return (x, y)


def compress(point):
    """The 33-byte compressed encoding of a point."""
    x, y = point
    return bytes([2 + (y & 1)]) + x.to_bytes(32, "big")


def encode_xy(point):
    """x and y as 32 big-endian bytes each, the 64 bytes Ethereum and Tron hash into an address."""
    x, y = point
    return x.to_bytes(32, "big") + y.to_bytes(32, "big")


def _double(point):
    x1, y1, z1 = point
    if z1 == 0 or y1 == 0:
        return _INFINITY
    y1_squared = y1 * y1 % P
    s = 4 * x1 * y1_squared % P
    m = 3 * x1 * x1 % P  # the curve's a is 0
    x3 = (m * m - 2 * s) % P
    y3 = (m * (s - x3) - 8 * y1_squared * y1_squared) % P
    z3 = 2 * y1 * z1 % P
    return (x3, y3, z3)


def _add(first, second):
    x1, y1, z1 = first
    x2, y2, z2 = second
    if z1 == 0:
        return second
    if z2 == 0:
        return first
    z1_squared = z1 * z1 % P
    z2_squared = z2 * z2 % P
    u1 = x1 * z2_squared % P
    u2 = x2 * z1_squared % P
    s1 = y1 * z2_squared * z2 % P
    s2 = y2 * z1_squared * z1 % P
    if u1 == u2:
        return _double(first) if s1 == s2 else _INFINITY
    h = (u2 - u1) % P
    r = (s2 - s1) % P
    h_squared = h * h % P
    h_cubed = h_squared * h % P
    u1_h_squared = u1 * h_squared % P
    x3 = (r * r - h_cubed - 2 * u1_h_squared) % P
    y3 = (r * (u1_h_squared - x3) - s1 * h_cubed) % P
    z3 = h * z1 * z2 % P
    return (x3, y3, z3)


def _to_jacobian(point):
    return _INFINITY if point is None else (point[0], point[1], 1)


def _to_affine(point):
    x, y, z = point
    if z == 0:
        return None
    z_inverse = pow(z, P - 2, P)
    z_inverse_squared = z_inverse * z_inverse % P
    return (x * z_inverse_squared % P, y * z_inverse_squared * z_inverse % P)


def add(first, second):
    """first + second; either may be None (the point at infinity), and so may the result."""
    return _to_affine(_add(_to_jacobian(first), _to_jacobian(second)))


def multiply(scalar, point=G):
    """scalar x point by double-and-add; None when the result is the point at infinity."""
    if scalar < 0:
        raise ValueError("the scalar must not be negative")
    result = _INFINITY
    addend = _to_jacobian(point)
    while scalar:
        if scalar & 1:
            result = _add(result, addend)
        addend = _double(addend)
        scalar >>= 1
    return _to_affine(result)
