"""Channel model and registry.

A channel's identity is its 16-byte symmetric key (32 hex chars); names are
display-only and may collide, so everything is keyed by `key_hex`.
"""

from net.meshcore.constants import PUBLIC_KEY, PUBLIC_NAME
from net.meshcore.crypto import (
    sha256,
    hmac_sha256,
    encrypt_aes_ecb,
    decrypt_aes_ecb,
)


def derive_channel_key(name):
    """Derive a MeshCore channel key from its name: sha256(name)[:16] as hex.

    This is how '#'-style public channels (other than the well-known 'Public')
    obtain their key."""
    return sha256(name.encode())[:16].hex()


class Channel:
    """A single MeshCore group channel with its crypto material cached."""

    def __init__(self, key_hex, name):
        self.key_hex = key_hex
        self.name = name
        raw = bytes.fromhex(key_hex)
        # 32-byte zero-padded shared secret: AES uses the first 16 bytes, the
        # full 32 bytes are the MAC key.
        self.secret = raw + b"\x00" * (32 - len(raw))
        # 1-byte channel hash = first byte of sha256(raw 16-byte key).
        self.hash = sha256(raw)[:1]

    def matches(self, payload) -> bool:
        """True if a payload's leading channel-hash byte belongs to us."""
        return payload[:1] == self.hash

    def mac(self, ciphertext) -> bytes:
        """2-byte MAC over the ciphertext, keyed by the shared secret."""
        return hmac_sha256(self.secret, ciphertext)[:2]

    def encrypt(self, plaintext) -> bytes:
        return encrypt_aes_ecb(self.secret, plaintext)

    def decrypt(self, ciphertext) -> bytes:
        return decrypt_aes_ecb(self.secret, ciphertext)

    @classmethod
    def from_name(cls, name):
        """Create a '#'-style channel whose key is derived from its name."""
        return cls(derive_channel_key(name), name)

    @classmethod
    def public(cls):
        """The well-known public channel."""
        return cls(PUBLIC_KEY, PUBLIC_NAME)

    def __repr__(self):
        return "Channel({!r}, {!r})".format(self.name, self.key_hex)


class ChannelRegistry:
    """The set of channels the node knows about, keyed by key_hex."""

    def __init__(self, channels=None):
        self._by_key = {}
        if channels:
            for ch in channels:
                self._by_key[ch.key_hex] = ch

    def replace(self, channels):
        """Replace the working set, always keeping the public channel present."""
        self._by_key = {ch.key_hex: ch for ch in channels}
        if PUBLIC_KEY not in self._by_key:
            self._by_key[PUBLIC_KEY] = Channel.public()

    def add(self, channel) -> bool:
        """Register a channel; returns False if its key already exists."""
        if channel.key_hex in self._by_key:
            return False
        self._by_key[channel.key_hex] = channel
        return True

    def remove(self, key_hex):
        """Remove a channel by key; returns its name, or None if absent."""
        ch = self._by_key.pop(key_hex, None)
        return ch.name if ch else None

    def get(self, key_hex):
        return self._by_key.get(key_hex)

    def match(self, payload):
        """Yield channels whose hash matches a payload's leading byte."""
        for ch in self._by_key.values():
            if ch.matches(payload):
                yield ch

    def items(self):
        """List of (key_hex, name) for UI/persistence."""
        return [(ch.key_hex, ch.name) for ch in self._by_key.values()]

    def __iter__(self):
        return iter(self._by_key.values())

    def __len__(self):
        return len(self._by_key)


# Default channels seeded into persistent storage on first run.
DEFAULT_CHANNELS = [
    Channel.public(),
    Channel.from_name("#test"),
    Channel.from_name("#hackaday"),
]

# Shared working registry used by the decoder and the app.
registry = ChannelRegistry(DEFAULT_CHANNELS)
