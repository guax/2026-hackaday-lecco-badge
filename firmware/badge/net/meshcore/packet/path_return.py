"""PATH packet: a return path sent back to the originator of a flood message.

When we receive a flood-routed direct message we reply with this so the sender
learns the route to us and can switch to efficient direct routing (less mesh
noise). We pigg-back the ACK in the `extra` field, exactly as MeshCore's
`createPathReturn(..., PAYLOAD_TYPE_ACK, ack_hash, 4)`.

Payload layout:  dest_hash(1) + src_hash(1) + mac(2) + ciphertext
Plaintext (encrypted) layout:
    path_len(1) + path(path_len bytes) + extra_type(1) + extra
where `path_len` is the inbound packet's path byte (hash-size + hop-count) and
`path` is the inbound packet's accumulated path. Encryption is AES-128-ECB with
a 2-byte HMAC, keyed by the X25519 shared secret (same as direct messages).
"""

from net.meshcore.constants import RouteType, PayloadType
from net.meshcore.crypto import encrypt_aes_ecb, hmac_sha256
from net.meshcore.packet.base import Packet


class PathReturn(Packet):
    payload_type = PayloadType.PATH

    def __init__(self, identity, peer_pubkey, return_path, return_path_len_byte,
                 extra_type, extra, route_type=RouteType.FLOOD):
        self.identity = identity
        peer = bytes(peer_pubkey)
        secret = identity.shared_secret(peer)
        payload = self._build_payload(
            secret, peer, return_path, return_path_len_byte, extra_type, extra)
        super().__init__(payload, route_type)

    def _build_payload(self, secret, peer, return_path, path_len_byte,
                       extra_type, extra):
        data = bytes([path_len_byte & 0xFF]) + bytes(return_path) \
            + bytes([extra_type & 0x0F]) + bytes(extra)
        # Zero-pad to a 16-byte AES block (MeshCore's encrypt pads the same way).
        pad_len = 16 - (len(data) % 16)
        data += b"\x00" * pad_len

        ciphertext = encrypt_aes_ecb(secret, data)
        mac = hmac_sha256(secret, ciphertext)[:2]
        dest_hash = peer[:1]
        src_hash = self.identity.public_key[:1]
        return dest_hash + src_hash + mac + ciphertext
