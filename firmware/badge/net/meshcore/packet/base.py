"""The Packet base class: the MeshCore wire envelope plus payload.

Frame (envelope) and payload are merged into one object. Concrete payload
types subclass `Packet`, set their `payload_type`, and build their `payload`.
Incoming frames are decoded with `Packet.parse(raw)`.
"""

import struct
import binascii

from net.meshcore.constants import RouteType, ROUTE_NAMES, PAYLOAD_NAMES

MAX_PAYLOAD = 184
MAX_PATH = 64

# Routes that carry a 4-byte transport-code block after the header.
_TRANSPORT_ROUTES = (RouteType.TRANSPORT_FLOOD, RouteType.TRANSPORT_DIRECT)


class Packet:
    # Subclasses override `payload_type`; `route_type` is the default route.
    payload_type = None
    route_type = RouteType.FLOOD

    def __init__(self, payload=b"", route_type=None, payload_type=None, version=0,
                 hop_count=0, hash_size=1, path=b"", transport_code_1=0,
                 transport_code_2=0):
        if route_type is not None:
            self.route_type = route_type
        if payload_type is not None:
            self.payload_type = payload_type
        self.payload = bytes(payload)
        self.version = version
        self.hop_count = hop_count
        self.hash_size = hash_size
        self.path = bytes(path)
        self.transport_code_1 = transport_code_1
        self.transport_code_2 = transport_code_2

    # -- introspection ---------------------------------------------------
    @property
    def route_name(self):
        return ROUTE_NAMES.get(self.route_type, "R{}".format(self.route_type))

    @property
    def payload_name(self):
        return PAYLOAD_NAMES.get(self.payload_type, "P{}".format(self.payload_type))

    # -- encoding --------------------------------------------------------
    def to_bytes(self) -> bytes:
        """Assemble the complete MeshCore frame for transmission."""
        if len(self.payload) > MAX_PAYLOAD:
            raise ValueError("Payload exceeds maximum size of {} bytes".format(MAX_PAYLOAD))
        if len(self.path) > MAX_PATH:
            raise ValueError("Path exceeds maximum size of {} bytes".format(MAX_PATH))

        expected_path_len = self.hop_count * self.hash_size
        if len(self.path) != expected_path_len:
            raise ValueError("Path length mismatch. Expected {} bytes.".format(expected_path_len))

        header = (((self.version & 0x03) << 6)
                  | ((self.payload_type & 0x0F) << 2)
                  | (self.route_type & 0x03))
        frame = bytearray([header])

        if self.route_type in _TRANSPORT_ROUTES:
            frame.extend(struct.pack("<HH", self.transport_code_1, self.transport_code_2))

        path_length = (((self.hash_size - 1) & 0x03) << 6) | (self.hop_count & 0x3F)
        frame.append(path_length)

        if expected_path_len > 0:
            frame.extend(self.path)
        frame.extend(self.payload)
        return bytes(frame)

    # -- decoding --------------------------------------------------------
    @classmethod
    def parse(cls, frame):
        """Parse a raw frame into a Packet. Returns None on malformed input."""
        if not frame or len(frame) < 2:
            return None

        header = frame[0]
        version = (header & 0xC0) >> 6
        if version != 0:
            return None  # Only MeshCore V1 supported.

        payload_type = (header & 0x3C) >> 2
        route_type = header & 0x03

        idx = 1
        tc1 = tc2 = 0
        if route_type in _TRANSPORT_ROUTES:
            if len(frame) < idx + 4:
                return None
            tc1, tc2 = struct.unpack("<HH", frame[idx:idx + 4])
            idx += 4

        if len(frame) < idx + 1:
            return None
        path_length_byte = frame[idx]
        idx += 1

        hop_count = path_length_byte & 0x3F
        hash_size = ((path_length_byte & 0xC0) >> 6) + 1
        path_len = hop_count * hash_size

        if len(frame) < idx + path_len:
            return None
        path = frame[idx:idx + path_len]
        idx += path_len

        return cls(
            payload=frame[idx:],
            route_type=route_type,
            payload_type=payload_type,
            version=version,
            hop_count=hop_count,
            hash_size=hash_size,
            path=path,
            transport_code_1=tc1,
            transport_code_2=tc2,
        )

    def __repr__(self):
        return "<{} {} {} payload={}B>".format(
            type(self).__name__, self.route_name, self.payload_name, len(self.payload))
