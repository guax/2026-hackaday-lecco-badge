"""MeshCore protocol constants: route types, payload types and advert flags."""

# The well-known MeshCore public channel key (always available; protected).
PUBLIC_KEY = "8b3387e9c5cdea6ac9e5edbaa115cd72"
PUBLIC_NAME = "Public"


class RouteType:
    """Routing mode, encoded in the low 2 bits of the header byte."""
    TRANSPORT_FLOOD = 0x00
    FLOOD = 0x01
    DIRECT = 0x02
    TRANSPORT_DIRECT = 0x03


class PayloadType:
    """Payload (message) type, encoded in bits 2-5 of the header byte."""
    REQ = 0x00
    RESPONSE = 0x01
    TXT_MSG = 0x02
    ACK = 0x03
    ADVERT = 0x04
    GRP_TXT = 0x05
    GRP_DATA = 0x06
    ANON_REQ = 0x07
    PATH = 0x08
    TRACE = 0x09
    MULTIPART = 0x0A
    CONTROL = 0x0B
    RAW_CUSTOM = 0x0F


class AdvertFlag:
    """Flags byte in an advert's app-data section."""
    IS_CHAT_NODE = 0x01
    IS_REPEATER = 0x02
    IS_ROOM = 0x03
    IS_SENSOR = 0x04
    HAS_LOCATION = 0x10
    HAS_NAME = 0x80


# Human-readable names for logging / debugging.
ROUTE_NAMES = {
    RouteType.TRANSPORT_FLOOD: "TX_FLOOD",
    RouteType.FLOOD: "FLOOD",
    RouteType.DIRECT: "DIRECT",
    RouteType.TRANSPORT_DIRECT: "TX_DIR",
}

PAYLOAD_NAMES = {
    PayloadType.REQ: "REQ",
    PayloadType.RESPONSE: "RESPONSE",
    PayloadType.TXT_MSG: "TXT",
    PayloadType.ACK: "ACK",
    PayloadType.ADVERT: "ADVERT",
    PayloadType.GRP_TXT: "GRP_TXT",
    PayloadType.GRP_DATA: "GRP_DAT",
    PayloadType.ANON_REQ: "ANON",
    PayloadType.PATH: "PATH",
    PayloadType.TRACE: "TRACE",
    PayloadType.MULTIPART: "MULTI",
    PayloadType.CONTROL: "CTRL",
    PayloadType.RAW_CUSTOM: "RAW",
}
