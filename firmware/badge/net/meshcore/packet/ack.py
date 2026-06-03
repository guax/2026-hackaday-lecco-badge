"""ACK packet.

A 4-byte truncated hash proving to the sender that we received their message,
which stops their retransmits. The hash is computed by the message receiver as
SHA256(timestamp + flags + text + sender_pubkey)[:4] (see DirectText.decode).
The payload is just those 4 bytes; senders match it against their expected ack.
"""

from net.meshcore.constants import RouteType, PayloadType
from net.meshcore.packet.base import Packet


class Ack(Packet):
    payload_type = PayloadType.ACK

    def __init__(self, ack_hash, route_type=RouteType.FLOOD):
        super().__init__(bytes(ack_hash)[:4], route_type)
