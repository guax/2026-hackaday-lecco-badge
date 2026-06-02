"""Node identity: an Ed25519 keypair plus a display name.

Used to sign adverts and to label outgoing group messages.
"""

from cryptography import ed25519, serialization

DEFAULT_NAME = "Hackbadge"


class Identity:
    def __init__(self, private_key, name=DEFAULT_NAME):
        self.private_key = private_key
        self.name = name
        self.public_key = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )

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
