"""TXT_MSG (direct message) packet.

End-to-end encrypted 1:1 message. The key is the X25519 ECDH shared secret
between the two nodes' Ed25519 identities (see Identity.shared_secret); the
cipher is AES-128-ECB with a 2-byte HMAC-SHA256 tag, exactly as channels.

Payload layout:  dest_hash(1) + src_hash(1) + mac(2) + ciphertext
  - dest_hash / src_hash are the first byte of the destination / source pubkey.
Plaintext layout: timestamp(4 LE) + flags(1) + text (UTF-8), zero-padded to 16.
"""

import struct
import time
from collections import namedtuple

from net.meshcore.constants import RouteType, PayloadType
from net.meshcore.crypto import encrypt_aes_ecb, decrypt_aes_ecb, hmac_sha256, sha256
from net.meshcore.packet.base import Packet

# Decoded result returned by DirectText.decode(). `ack_hash` is the 4-byte
# value to echo back in an ACK so the sender stops retransmitting.
DecodedDirectText = namedtuple(
    "DecodedDirectText",
    ["sender_key", "sender_name", "text", "timestamp", "ack_hash"],
)

# Text-message flags byte; low bits are the text type (0 = plain UTF-8).
_TXT_TYPE_PLAIN = 0x00


class DirectText(Packet):
    payload_type = PayloadType.TXT_MSG

    def __init__(self, identity, contact, message, route_type=RouteType.FLOOD,
                 timestamp=None):
        """Build an encrypted direct message to `contact`."""
        self.identity = identity
        self.contact = contact
        self.message = message
        ts = int(time.time()) if timestamp is None else timestamp
        peer_pub = bytes.fromhex(contact.pubkey_hex)
        secret = identity.shared_secret(peer_pub)
        super().__init__(self._build_payload(ts, secret, peer_pub), route_type)

    def _build_payload(self, timestamp, secret, peer_pub):
        plaintext = struct.pack("<IB", timestamp, _TXT_TYPE_PLAIN) \
            + self.message.encode("utf-8")
        pad_len = 16 - (len(plaintext) % 16)
        plaintext += b"\x00" * pad_len

        ciphertext = encrypt_aes_ecb(secret, plaintext)
        mac = hmac_sha256(secret, ciphertext)[:2]
        dest_hash = peer_pub[:1]
        src_hash = self.identity.public_key[:1]
        return dest_hash + src_hash + mac + ciphertext

    @classmethod
    def decode(cls, payload, identity, contacts):
        """Try to decrypt a direct message addressed to us.

        Resolves the sender by matching `src_hash` against known contacts and
        verifying the per-contact MAC. Returns a DecodedDirectText or None.
        """
        if identity is None or len(payload) < 4:
            return None
        dest_hash = payload[0]
        if dest_hash != identity.public_key[0]:
            return None  # Not addressed to this node.
        src_hash = payload[1]
        mac = payload[2:4]
        ciphertext = payload[4:]
        if not ciphertext or len(ciphertext) % 16 != 0:
            return None

        for contact in contacts.all():
            raw = bytes.fromhex(contact.pubkey_hex)
            if not raw or raw[0] != src_hash:
                continue
            try:
                secret = identity.shared_secret(raw)
                if hmac_sha256(secret, ciphertext)[:2] != mac:
                    continue
                plaintext = decrypt_aes_ecb(secret, ciphertext)
                if len(plaintext) < 5:
                    continue
                timestamp = struct.unpack("<I", plaintext[:4])[0]
                # Text runs from offset 5 up to the first null (zero padding).
                body = plaintext[5:]
                nul = body.find(b"\x00")
                if nul >= 0:
                    body = body[:nul]
                # ACK hash = SHA256(timestamp + flags + text + sender_pubkey)[:4],
                # over the raw plaintext bytes (matches MeshCore's onPeerDataRecv).
                ack_hash = sha256(plaintext[:5] + body + raw)[:4]
                text = body.decode("utf-8")
                print("[MeshCore] DM <{}>: {}".format(contact.display_name, text))
                return DecodedDirectText(
                    contact.pubkey_hex, contact.display_name, text, timestamp,
                    ack_hash)
            except Exception as e:
                import sys
                print("[MeshCore] DM decode error:", e)
                if hasattr(sys, "print_exception"):
                    sys.print_exception(e)
        return None
