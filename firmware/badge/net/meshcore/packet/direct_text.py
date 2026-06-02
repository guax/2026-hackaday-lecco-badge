"""TXT_MSG (direct message) packet.

Stub for the upcoming DM feature; the envelope/encoding will be filled in when
we implement direct messaging.
"""

from net.meshcore.constants import PayloadType
from net.meshcore.packet.base import Packet


class DirectText(Packet):
    payload_type = PayloadType.TXT_MSG
