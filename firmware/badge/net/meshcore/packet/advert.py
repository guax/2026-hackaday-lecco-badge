"""ADVERT packet: broadcasts a node's identity (pubkey + signed app-data)."""

import struct
import time

from net.meshcore.constants import RouteType, PayloadType, AdvertFlag
from net.meshcore.packet.base import Packet


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
