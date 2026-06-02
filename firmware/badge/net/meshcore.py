import hashlib
import hmac
import struct
import binascii
import ucryptolib as cryptolib

# The well-known MeshCore public channel key (always available; protected).
PUBLIC_KEY = "8b3387e9c5cdea6ac9e5edbaa115cd72"
PUBLIC_NAME = "Public"

def derive_channel_key(name):
    """Derive a MeshCore channel key from its name: sha256(name)[:16] as hex.

    This is how '#'-style public channels (other than the well-known 'Public')
    obtain their key."""
    return hashlib.sha256(name.encode()).digest()[:16].hex()


# A channel's identity is its 16-byte symmetric key (hex string); names are
# display-only and may collide, so everything is keyed by key_hex -> name.
# These are seeded into persistent storage on first run.
DEFAULT_CHANNELS = {
    PUBLIC_KEY: PUBLIC_NAME,
    derive_channel_key("#test"): "#test",
    derive_channel_key("#hackaday"): "#hackaday",
}

# Working set of known channels (key_hex -> name), used by the decoder.
# Populated from persistent storage at app start via set_channels(); defaults
# apply until then (and for IDE/testing without a badge filesystem).
CHANNELS = dict(DEFAULT_CHANNELS)

def set_channels(mapping):
    """Replace the working channel set in place (key_hex -> name) so existing
    `CHANNELS` references (e.g. in apps) stay valid. Ensures Public is present."""
    CHANNELS.clear()
    CHANNELS.update(mapping)
    if PUBLIC_KEY not in CHANNELS:
        CHANNELS[PUBLIC_KEY] = PUBLIC_NAME


def add_group_channel(key_hex, name):
    """Register a channel by its key (32 hex chars) with a display name.

    Returns True if added, False if the key already exists (no overwrite)."""
    if key_hex in CHANNELS:
        return False
    CHANNELS[key_hex] = name
    return True


def remove_group_channel(key_hex):
    """Remove a channel by its key. Returns the removed name, or None."""
    return CHANNELS.pop(key_hex, None)

def decrypt_aes_ecb(key: bytes, ciphertext: bytes) -> bytes:
    # ucryptolib.aes expects 16, 24, or 32 byte keys. Mode 1 is ECB.
    cipher = cryptolib.aes(key[:16], 1)
    return cipher.decrypt(ciphertext)


def encrypt_aes_ecb(key: bytes, plaintext: bytes) -> bytes:
    # AES-128-ECB (Mode 1) using the first 16 bytes of the key.
    cipher = cryptolib.aes(key[:16], 1)
    return cipher.encrypt(plaintext)


# ----------------------------------------------------------------------------
# Channel crypto primitives. These are the single source of truth shared by the
# decoder (try_decrypt_group_text) and the encoder (MeshCorePacketBuilder), so
# the two can never drift. A channel's hex key is 32 chars / 16 raw bytes.
# ----------------------------------------------------------------------------
def channel_shared_secret(key_hex: str) -> bytes:
    """Return the 32-byte zero-padded shared secret used as the MAC key.

    AES uses the first 16 bytes of this (the raw channel key)."""
    key = bytes.fromhex(key_hex)
    return key + b"\x00" * (32 - len(key))


def channel_hash(key_hex: str) -> bytes:
    """1-byte channel hash = first byte of sha256(raw 16-byte channel key)."""
    return hashlib.sha256(bytes.fromhex(key_hex)).digest()[:1]


def channel_mac(shared_secret: bytes, ciphertext: bytes) -> bytes:
    """2-byte MAC over the ciphertext, keyed by the 32-byte shared secret."""
    return hmac.new(shared_secret, ciphertext, hashlib.sha256).digest()[:2]

def try_decrypt_group_text(payload_bytes):
    """Attempt to decrypt a group text message payload using known keys.

    Returns a tuple (channel_id, room_name, sender, text, timestamp) on success, or None.
    - channel_id: the channel's symmetric key (hex string) - the stable identity of a
                  channel in MeshCore. Names can collide, keys do not.
    - room_name:  the human-friendly channel name for display (e.g. "#test")
    - sender:     the sender name parsed from the plaintext ("" if none found)
    - text:       the decoded message body
    - timestamp:  the 4-byte little-endian unix timestamp embedded in the message
    """
    for key_hex, room_name in CHANNELS.items():
        try:
            # Channel hash is always exactly 1 byte at the start of the payload.
            if payload_bytes[:1] != channel_hash(key_hex):
                continue  # This key does not match the channel hash of the packet

            # MAC is always 2 bytes, placed right after the 1-byte channel hash.
            mac_idx = 1
            cipher_idx = mac_idx + 2
            if len(payload_bytes) < cipher_idx:
                continue

            mac = payload_bytes[mac_idx:cipher_idx]
            ciphertext = payload_bytes[cipher_idx:]

            # Verify the 2-byte MAC keyed by the 32-byte padded shared secret.
            shared_secret = channel_shared_secret(key_hex)
            if mac != channel_mac(shared_secret, ciphertext):
                print(f"[Decrypt Debug] MAC mismatch for {room_name}")
                continue

            plaintext = decrypt_aes_ecb(shared_secret, ciphertext)
            
            # plaintext format: [timestamp:4][flags:1][sender_name: message]
            if len(plaintext) < 5:
                continue

            timestamp = struct.unpack("<I", plaintext[:4])[0]
            msg_bytes = plaintext[5:].rstrip(b'\x00')
            message = msg_bytes.decode('utf-8')

            # MeshCore channel messages embed the sender as "sender: message"
            if ": " in message:
                sender, _, body = message.partition(": ")
            else:
                sender, body = "", message

            print(f"[MeshCore Decrypt] {room_name} <{sender}>: {body}")
            return key_hex, room_name, sender, body, timestamp
        except Exception as e:
            import sys
            print(f"[Decrypt Debug] Error decrypting with key for {room_name}: {e}")
            if hasattr(sys, "print_exception"):
                sys.print_exception(e)
            else:
                import traceback
                traceback.print_exc()
    return None

def parse_meshcore_packet(frame):
    """Parse a raw frame into MeshCore components with verbose console logging on failures."""
    if not frame or len(frame) < 2:
        print(f"[MeshCore Debug] Rejecting: Frame too short (len={len(frame) if frame else 0})")
        return None
    
    print(f"[MeshCore Debug] Parsing frame: len={len(frame)}, raw={binascii.hexlify(frame).decode()}")
        
    header = frame[0]
    # Check version (bits 6-7)
    version = (header & 0xC0) >> 6
    if version != 0:
        print(f"[MeshCore Debug] Rejecting: Unsupported packet version={version} (header=0x{header:02x})")
        return None  # Only support MeshCore V1
        
    payload_type_val = (header & 0x3C) >> 2
    route_type_val = header & 0x03
    
    ROUTE_TYPES = {
        0x00: "TX_FLOOD",
        0x01: "FLOOD",
        0x02: "DIRECT",
        0x03: "TX_DIR",
        0x04: "REPEATER",
        0x05: "CLIENT",
        0x0F: "LOCAL",
    }
    
    PAYLOAD_TYPES = {
        0x00: "NODE",
        0x01: "PING",
        0x02: "PONG",
        0x03: "REQ",
        0x04: "TXT",
        0x05: "GRP_TXT",
        0x06: "GRP_DAT",
        0x07: "ANON",
        0x08: "PATH",
        0x09: "TRACE",
        0x0A: "MULTI",
        0x0B: "CTRL",
        0x0F: "RAW",
    }
    
    route = ROUTE_TYPES.get(route_type_val, f"R{route_type_val}")
    payload = PAYLOAD_TYPES.get(payload_type_val, f"P{payload_type_val}")
    
    idx = 1
    # Check transport codes
    if route_type_val in (0x00, 0x03):
        if len(frame) < idx + 4:
            print(f"[MeshCore Debug] Rejecting: Expected 4-byte transport code, frame size={len(frame)}")
            return None
        idx += 4
        
    # Path length byte is bit-packed:
    # Bits 0-5: hop count (0-63)
    # Bits 6-7: hash size code (0b00 = 1-byte, 0b01 = 2-byte, 0b10 = 3-byte -> hash_size = code + 1)
    if len(frame) < idx + 1:
        print(f"[MeshCore Debug] Rejecting: No path length byte, frame size={len(frame)}")
        return None
    path_length_byte = frame[idx]
    idx += 1
    
    hop_count = path_length_byte & 0x3F
    hash_size_code = (path_length_byte & 0xC0) >> 6
    parsed_hash_size = hash_size_code + 1
    path_bytes_len = hop_count * parsed_hash_size
    
    # Path
    if len(frame) < idx + path_bytes_len:
        print(f"[MeshCore Debug] Rejecting: Path length too large ({path_bytes_len} bytes requested, remaining={len(frame) - idx})")
        return None
    path_data = frame[idx:idx+path_bytes_len]
    idx += path_bytes_len
    
    # Payload
    payload_bytes = frame[idx:]
    
    print(f"[MeshCore Debug] Parsed OK: Route={route}, MsgType={payload}, Hops={hop_count}, HashSize={parsed_hash_size}B, PayloadSize={len(payload_bytes)}B")
    return route, payload, hop_count, parsed_hash_size, path_data, payload_bytes
