"""ADVERT packet: broadcasts a node's identity (pubkey + signed app-data)."""

import struct
import time
from collections import namedtuple

from net.meshcore.constants import RouteType, PayloadType, AdvertFlag
from net.meshcore.packet.base import Packet

# Fixed advert header: pubkey(32) + timestamp(4) + signature(64) = 100 bytes.
_ADVERT_HEADER_LEN = 100

# Decoded result returned by Advert.decode().
DecodedAdvert = namedtuple(
    "DecodedAdvert", ["pubkey_hex", "name", "flags", "timestamp"]
)


class Advert(Packet):
    payload_type = PayloadType.ADVERT

    def __init__(self, identity, route_type=RouteType.FLOOD, timestamp=None):
        """Build a ready-to-send advert for the given node identity.

        The Ed25519 signature covers pub_key + timestamp + app_data, so the
        app_data is assembled before signing.
        """
        self.identity = identity
        self.timestamp = int(time.time()) if timestamp is None else timestamp
        super().__init__(self._build_payload(), route_type)

    def _build_payload(self):
        ts_bytes = struct.pack("<I", self.timestamp & 0xFFFFFFFF)

        # App data: flags byte (chat node + has name) followed by the node name.
        flags = AdvertFlag.IS_CHAT_NODE | AdvertFlag.HAS_NAME
        name = self.identity.name
        name_bytes = name.encode("utf-8") if isinstance(name, str) else bytes(name)
        app_data = bytes([flags]) + name_bytes

        signature = self.identity.sign(self.identity.public_key + ts_bytes + app_data)

        payload = bytearray()
        payload.extend(self.identity.public_key)  # 32 bytes
        payload.extend(ts_bytes)                   # 4 bytes
        payload.extend(signature)                  # 64 bytes
        payload.extend(app_data)                   # flags + name
        return bytes(payload)

    @classmethod
    def decode(cls, payload):
        """Decode an ADVERT payload into a DecodedAdvert, or None if malformed.

        Layout: pubkey(32) + timestamp(4 LE) + signature(64) + app_data.
        app_data = flags(1) [+ lat(4)+lon(4) if HAS_LOCATION] + name (UTF-8).
        The signature is not verified here.
        """
        if len(payload) < _ADVERT_HEADER_LEN + 1:
            return None

        pubkey = payload[:32]
        timestamp = struct.unpack("<I", payload[32:36])[0]
        app_data = payload[_ADVERT_HEADER_LEN:]
        if not app_data:
            return None

        flags = app_data[0]
        idx = 1
        if flags & AdvertFlag.HAS_LOCATION:
            idx += 8  # int32 lat + int32 lon

        name = ""
        if flags & AdvertFlag.HAS_NAME:
            try:
                name = app_data[idx:].rstrip(b"\x00").decode("utf-8")
            except Exception:
                name = ""

        return DecodedAdvert(
            "".join("%02x" % b for b in pubkey), name, flags, timestamp
        )
