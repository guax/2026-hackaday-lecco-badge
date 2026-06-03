"""Node identity: an Ed25519 keypair plus a display name.

Used to sign adverts and to label outgoing group messages.
"""

from cryptography import ed25519, serialization, hashes

from net.meshcore.x25519 import key_exchange

DEFAULT_NAME = "Hackbadge"


class Identity:
    def __init__(self, private_key, name=DEFAULT_NAME):
        self.private_key = private_key
        self.name = name
        self.public_key = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        # X25519 shared secrets are deterministic per peer; cache them since the
        # pure-Python scalar multiplication is relatively expensive.
        self._secret_cache = {}

    @classmethod
    def generate(cls, name=DEFAULT_NAME):
        """Create a fresh identity with a new Ed25519 keypair."""
        return cls(ed25519.Ed25519PrivateKey.generate(), name)

    @classmethod
    def load(cls, raw, name=DEFAULT_NAME):
        """Load an identity from its 32-byte raw private seed."""
        return cls(ed25519.Ed25519PrivateKey.from_private_bytes(bytes(raw)), name)

    def private_raw(self) -> bytes:
        """Return the 32-byte raw private seed for persistence."""
        return self.private_key.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption(),
        )

    def sign(self, message) -> bytes:
        """Ed25519-sign a message, returning 64 bytes."""
        return self.private_key.sign(message)

    def shared_secret(self, peer_public_key) -> bytes:
        """Return the 32-byte MeshCore shared secret with a peer.

        Equivalent to MeshCore's `ed25519_key_exchange`: X25519 ECDH between
        our identity and the peer's Ed25519 public key. The result is cached
        per peer because the pure-Python scalar multiplication is expensive.
        """
        peer = bytes(peer_public_key)
        secret = self._secret_cache.get(peer)
        if secret is None:
            # X25519 private scalar = SHA512(seed)[:32] (clamped inside x25519).
            digest = hashes.Hash(hashes.SHA512())
            digest.update(self.private_raw())
            secret = key_exchange(digest.finalize()[:32], peer)
            self._secret_cache[peer] = secret
        return secret
