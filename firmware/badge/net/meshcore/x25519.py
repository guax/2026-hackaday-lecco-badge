"""Pure-Python X25519 (RFC 7748) plus Ed25519 -> Curve25519 conversion.

MeshCore derives a direct-message shared secret with `ed25519_key_exchange`,
which is X25519 ECDH over the Curve25519 forms of the two nodes' Ed25519
identity keys. The badge's `ucryptography` build has no X25519 primitive, so
this implements it directly.

- The scalar is `clamp(SHA512(seed)[:32])` (the standard Ed25519 expansion);
  the SHA-512 is computed by the caller (see Identity.shared_secret).
- The peer's 32-byte Ed25519 public key (Edwards y) is converted to the
  Montgomery u-coordinate via u = (1 + y) / (1 - y) mod p.
- A standard Montgomery ladder then yields the 32-byte shared secret.

This is not constant-time; it is only used for occasional key agreement.
"""

# Curve25519 field prime and the (a-2)/4 ladder constant.
_P = (1 << 255) - 19
_A24 = 121665


def _decode_scalar(scalar_bytes):
    """Clamp and decode a 32-byte X25519 scalar (RFC 7748 decodeScalar25519)."""
    k = bytearray(scalar_bytes[:32])
    k[0] &= 248
    k[31] &= 127
    k[31] |= 64
    return int.from_bytes(bytes(k), "little")


def _ed25519_pub_to_u(pubkey):
    """Convert a 32-byte Ed25519 public key to the Curve25519 u-coordinate."""
    # The high bit of the last byte is the x-sign; mask it to get y.
    y = int.from_bytes(bytes(pubkey), "little") & ((1 << 255) - 1)
    # u = (1 + y) / (1 - y) mod p
    return ((1 + y) * pow((1 - y) % _P, _P - 2, _P)) % _P


def _ladder(scalar, u):
    """Montgomery ladder: scalar * u on Curve25519, returning the u-coordinate."""
    x1 = u
    x2, z2 = 1, 0
    x3, z3 = u, 1
    swap = 0
    for t in range(254, -1, -1):
        k_t = (scalar >> t) & 1
        swap ^= k_t
        if swap:
            x2, x3 = x3, x2
            z2, z3 = z3, z2
        swap = k_t

        a = (x2 + z2) % _P
        aa = (a * a) % _P
        b = (x2 - z2) % _P
        bb = (b * b) % _P
        e = (aa - bb) % _P
        c = (x3 + z3) % _P
        d = (x3 - z3) % _P
        da = (d * a) % _P
        cb = (c * b) % _P
        x3 = ((da + cb) % _P) ** 2 % _P
        z3 = (x1 * (((da - cb) % _P) ** 2 % _P)) % _P
        x2 = (aa * bb) % _P
        z2 = (e * (aa + (_A24 * e) % _P)) % _P

    if swap:
        x2, x3 = x3, x2
        z2, z3 = z3, z2

    return (x2 * pow(z2, _P - 2, _P)) % _P


def key_exchange(scalar_bytes, peer_ed25519_pub):
    """Return the 32-byte X25519 shared secret.

    `scalar_bytes` is SHA512(seed)[:32] for our Ed25519 seed (clamped here);
    `peer_ed25519_pub` is the other node's 32-byte Ed25519 public key.
    """
    scalar = _decode_scalar(scalar_bytes)
    u = _ed25519_pub_to_u(peer_ed25519_pub)
    shared = _ladder(scalar, u)
    return shared.to_bytes(32, "little")
