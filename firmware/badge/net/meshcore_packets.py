import struct
import time
from cryptography import ed25519, serialization
from net.meshcore import (
    channel_shared_secret,
    channel_hash,
    channel_mac,
    encrypt_aes_ecb,
)

# ---------------------------------------------------------------------
# Identity helpers (a MeshCore node's identity is an Ed25519 keypair).
# ---------------------------------------------------------------------
def generate_private_key():
    """Create a fresh Ed25519 private key object."""
    return ed25519.Ed25519PrivateKey.generate()


def load_private_key(raw):
    """Load an Ed25519 private key from its 32-byte raw seed."""
    return ed25519.Ed25519PrivateKey.from_private_bytes(bytes(raw))


def private_key_to_raw(priv):
    """Return the 32-byte raw seed for persistence."""
    return priv.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )

def public_key_to_raw(priv):
    """Return the 32-byte raw public key for the given private key."""
    return priv.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )


class MeshCorePacketBuilder:
    # --- Route Types ---
    ROUTE_TRANSPORT_FLOOD  = 0x00
    ROUTE_FLOOD            = 0x01
    ROUTE_DIRECT           = 0x02
    ROUTE_TRANSPORT_DIRECT = 0x03

    # --- Payload Types ---
    TYPE_REQ        = 0x00
    TYPE_RESPONSE   = 0x01
    TYPE_TXT_MSG    = 0x02
    TYPE_ACK        = 0x03
    TYPE_ADVERT     = 0x04
    TYPE_GRP_TXT    = 0x05
    TYPE_GRP_DATA   = 0x06
    TYPE_ANON_REQ   = 0x07
    TYPE_PATH       = 0x08
    TYPE_TRACE      = 0x09
    TYPE_MULTIPART  = 0x0A
    TYPE_CONTROL    = 0x0B
    TYPE_RAW_CUSTOM = 0x0F

    # Advert app-data flags
    ADV_FLAG_IS_CHAT_NODE = 0x01
    ADV_FLAG_IS_REPEATER  = 0x02
    ADV_FLAG_IS_ROOM      = 0x03
    ADV_FLAG_IS_SENSOR    = 0x04
    ADV_FLAG_HAS_LOCATION = 0x10
    ADV_FLAG_HAS_NAME     = 0x80

    def __init__(self, public_key, private_key, node_name):
        """Initialize MeshCorePacketBuilder with node identity.

        Args:
            public_key: Ed25519 public key, 32 raw bytes
            private_key: Ed25519 private key object (with .sign()), or None for
                         an unsigned (zero-signature) advert
            node_name: Node name string
        """
        if len(public_key) != 32:
            raise ValueError(f"Public key must be 32 bytes, got {len(public_key)}")
        self.public_key = bytes(public_key)
        self.private_key = private_key
        self.node_name = node_name

    def _sign(self, message):
        """Ed25519-sign a message, returning 64 bytes (zeros if no private key)."""
        if self.private_key is None:
            return b"\x00" * 64
        return self.private_key.sign(message)

    def build_packet(self, route_type, payload_type, payload=b"", payload_version=0, 
                     transport_code_1=0, transport_code_2=0, hop_count=0, hash_size=1, path=b""):
        """Builds the outer MeshCore packet frame."""
        if len(payload) > 184:
            raise ValueError("Payload exceeds maximum size of 184 bytes")
        if len(path) > 64:
            raise ValueError("Path exceeds maximum size of 64 bytes")
        
        expected_path_len = hop_count * hash_size
        if len(path) != expected_path_len:
            raise ValueError(f"Path length mismatch. Expected {expected_path_len} bytes.")

        # 1. Header byte
        header = ((payload_version & 0x03) << 6) | ((payload_type & 0x0F) << 2) | (route_type & 0x03)
        packet = bytearray([header])
        
        # 2. Transport Codes (Optional)
        if route_type in (self.ROUTE_TRANSPORT_FLOOD, self.ROUTE_TRANSPORT_DIRECT):
            packet.extend(struct.pack("<HH", transport_code_1, transport_code_2))
            
        # 3. Path Length / Metadata byte
        path_length = (((hash_size - 1) & 0x03) << 6) | (hop_count & 0x3F)
        packet.append(path_length)
        
        # 4. Path & Payload Data
        if expected_path_len > 0:
            packet.extend(path)
        packet.extend(payload)
        
        return bytes(packet)

    # ==========================================
    # Specific Payload Builders
    # ==========================================

    def build_advert_payload(self, timestamp=None):
        """Build an ADVERT payload: pub_key(32) + timestamp(4) + signature(64) + app_data.

        The Ed25519 signature covers pub_key + timestamp + app_data, so app_data
        must be assembled before signing.
        """
        if timestamp is None:
            timestamp = int(time.time())
        ts_bytes = struct.pack("<I", timestamp & 0xFFFFFFFF)

        # App data: flags byte (chat node + has name) followed by the node name.
        # We don't advertise the optional location/feature fields for now.
        flags = self.ADV_FLAG_IS_CHAT_NODE | self.ADV_FLAG_HAS_NAME
        name_bytes = (
            self.node_name.encode("utf-8")
            if isinstance(self.node_name, str)
            else bytes(self.node_name)
        )
        app_data = bytes([flags]) + name_bytes

        # Signature over pub_key + timestamp + app_data.
        signature = self._sign(self.public_key + ts_bytes + app_data)

        payload = bytearray()
        payload.extend(self.public_key)  # 32 bytes
        payload.extend(ts_bytes)         # 4 bytes
        payload.extend(signature)        # 64 bytes
        payload.extend(app_data)         # flags + name
        return bytes(payload)

    def build_advert(self, route_type=ROUTE_FLOOD, timestamp=None):
        """Build a complete, ready-to-transmit ADVERT packet."""
        payload = self.build_advert_payload(timestamp=timestamp)
        return self.build_packet(route_type, self.TYPE_ADVERT, payload)
    

    def build_group_txt(self, channel_key, message: str):
        """Build a complete, ready-to-transmit GROUP_TXT packet.

        Uses the shared channel-crypto primitives from net.meshcore so the
        channel hash, AES key and MAC stay byte-for-byte compatible with the
        decoder. `channel_key` is the 32-char hex channel key.
        """
        # 32-byte padded shared secret (MAC key); AES uses its first 16 bytes.
        shared_secret = channel_shared_secret(channel_key)

        full_message = self.node_name + ": " + message

        # Plaintext: 4-byte LE timestamp + 1-byte flags + UTF-8 text.
        timestamp = int(time.time())
        plaintext = struct.pack('<IB', timestamp, 0x00) + full_message.encode('UTF-8')

        # Zero-pad to a 16-byte multiple for AES-ECB.
        pad_len = 16 - (len(plaintext) % 16)
        padded_plaintext = plaintext + (b'\x00' * pad_len)

        encrypted_data = encrypt_aes_ecb(shared_secret, padded_plaintext)

        # 2-byte MAC over the ciphertext, 1-byte channel hash prefix.
        mac = channel_mac(shared_secret, encrypted_data)
        payload = channel_hash(channel_key) + mac + encrypted_data

        return self.build_packet(self.ROUTE_FLOOD, self.TYPE_GRP_TXT, payload)
    