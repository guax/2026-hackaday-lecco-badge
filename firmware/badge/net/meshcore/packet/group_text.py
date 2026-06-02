"""GROUP_TXT packet: an AES-128-ECB encrypted, MAC-authenticated channel message.

Payload layout: channel_hash(1) + mac(2) + ciphertext.
Plaintext layout: timestamp(4 LE) + flags(1) + "sender: message" (UTF-8).
"""

import struct
import time
from collections import namedtuple

from net.meshcore.constants import RouteType, PayloadType
from net.meshcore.packet.base import Packet

# Decoded result returned by GroupText.decode().
DecodedGroupText = namedtuple(
    "DecodedGroupText", ["channel_id", "room_name", "sender", "text", "timestamp"]
)


class GroupText(Packet):
    payload_type = PayloadType.GRP_TXT

    def __init__(self, identity, channel, message, route_type=RouteType.FLOOD,
                 timestamp=None):
        """Build an encrypted group-text packet for `channel`.

        `message` is the user's text; the sender name is prepended automatically.
        """
        self.identity = identity
        self.channel = channel
        self.message = message
        ts = int(time.time()) if timestamp is None else timestamp
        super().__init__(self._build_payload(ts), route_type)

    def _build_payload(self, timestamp):
        full_message = self.identity.name + ": " + self.message

        # timestamp(4 LE) + flags(1) + UTF-8 text, zero-padded to 16-byte AES blocks.
        plaintext = struct.pack("<IB", timestamp, 0x00) + full_message.encode("utf-8")
        pad_len = 16 - (len(plaintext) % 16)
        plaintext += b"\x00" * pad_len

        ciphertext = self.channel.encrypt(plaintext)
        mac = self.channel.mac(ciphertext)
        return self.channel.hash + mac + ciphertext

    @classmethod
    def decode(cls, payload, registry):
        """Try to decrypt a GROUP_TXT payload against known channels.

        Returns a DecodedGroupText on success, or None.
        """
        for channel in registry.match(payload):
            try:
                if len(payload) < 3:
                    continue
                mac = payload[1:3]
                ciphertext = payload[3:]
                if mac != channel.mac(ciphertext):
                    print("[MeshCore] MAC mismatch for", channel.name)
                    continue

                plaintext = channel.decrypt(ciphertext)
                if len(plaintext) < 5:
                    continue

                timestamp = struct.unpack("<I", plaintext[:4])[0]
                body = plaintext[5:].rstrip(b"\x00").decode("utf-8")

                # Channel messages embed the sender as "sender: message".
                if ": " in body:
                    sender, _, text = body.partition(": ")
                else:
                    sender, text = "", body

                print("[MeshCore] {} <{}>: {}".format(channel.name, sender, text))
                return DecodedGroupText(channel.key_hex, channel.name, sender, text, timestamp)
            except Exception as e:
                import sys
                print("[MeshCore] decode error for {}: {}".format(channel.name, e))
                if hasattr(sys, "print_exception"):
                    sys.print_exception(e)
        return None
