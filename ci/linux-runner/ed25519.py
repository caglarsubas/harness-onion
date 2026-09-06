"""Verification only, RFC 8032 Ed25519; no key generation or signing API.

Strict encodings and prime-order points are required. This is source-tested
candidate code, not a claim of a separately audited cryptographic implementation.
"""
import base64
import hashlib

P = 2 ** 255 - 19
L = 2 ** 252 + 27742317777372353535851937790883648493
D = -121665 * pow(121666, P - 2, P) % P
I = pow(2, (P - 1) // 4, P)
IDENTITY = (0, 1, 1, 0)


def add(a, b):
    x, y, z, t = a
    u, v, w, s = b
    aa = (y - x) * (v - u) % P
    bb = (y + x) * (v + u) % P
    cc = 2 * D * t * s % P
    dd = 2 * z * w % P
    e, f, g, h = bb - aa, dd - cc, dd + cc, bb + aa
    return e * f % P, g * h % P, f * g % P, e * h % P


def multiply(point, scalar):
    result = IDENTITY
    while scalar:
        if scalar & 1:
            result = add(result, point)
        point = add(point, point)
        scalar >>= 1
    return result


def equal(a, b):
    return (a[0] * b[2] - b[0] * a[2]) % P == 0 and (a[1] * b[2] - b[1] * a[2]) % P == 0


def decode(raw):
    if len(raw) != 32:
        raise ValueError("point length")
    value = int.from_bytes(raw, "little")
    sign, y = value >> 255, value & (2 ** 255 - 1)
    if y >= P:
        raise ValueError("point encoding")
    xx = (y * y - 1) * pow(D * y * y + 1, P - 2, P) % P
    x = pow(xx, (P + 3) // 8, P)
    if x * x % P != xx:
        x = x * I % P
    if x * x % P != xx or (x == 0 and sign):
        raise ValueError("invalid curve point")
    if x & 1 != sign:
        x = P - x
    point = (x, y, 1, x * y % P)
    if equal(point, IDENTITY) or not equal(multiply(point, L), IDENTITY):
        raise ValueError("non-prime-order point")
    return point


BASE = decode(bytes.fromhex("5866666666666666666666666666666666666666666666666666666666666666"))


def verify(public, message, signature):
    try:
        if len(public) != 32 or len(signature) != 64:
            return False
        scalar = int.from_bytes(signature[32:], "little")
        if scalar >= L:
            return False
        a, r = decode(public), decode(signature[:32])
        challenge = int.from_bytes(hashlib.sha512(signature[:32] + public + message).digest(), "little") % L
        return equal(multiply(BASE, scalar), add(r, multiply(a, challenge)))
    except (ValueError, TypeError):
        return False


def pem_public(raw):
    lines = raw.strip().splitlines()
    if len(lines) != 3 or lines[0] != b"-----BEGIN PUBLIC KEY-----" or lines[-1] != b"-----END PUBLIC KEY-----":
        raise ValueError("Ed25519 SPKI PEM required")
    der = base64.b64decode(lines[1], validate=True)
    if len(der) != 44 or der[:12] != bytes.fromhex("302a300506032b6570032100"):
        raise ValueError("Ed25519 SPKI encoding")
    decode(der[12:])
    return der[12:]
