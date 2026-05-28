"""MeshCore listening and packet decoding application."""

from collections import deque, namedtuple
import binascii
import time
from apps.base_app import BaseApp
from net.net import register_raw_receiver, unregister_raw_receiver
from net.meshcore import parse_meshcore_packet, try_decrypt_group_text
from ui import styles

APP_NAME = "MeshCore"

# A single decoded channel message held in memory for later display.
ChannelMessage = namedtuple(
    "ChannelMessage", ["recv_time", "msg_time", "sender", "text", "rssi", "snr"]
)


class MeshcoreApp(BaseApp):
    def __init__(self, name: str, badge):
        super().__init__(name, badge)
        self.packet_queue = deque([], 10)  # Store last 10 raw packet frames and RSSI/SNR
        # Decoded group-channel message history, keyed by channel_id (the channel's
        # symmetric key in hex) since names can collide but keys are unique.
        # Each value is a deque of ChannelMessage, newest last.
        self.channels = {}
        # Display names for each channel_id, for UI / user organization only.
        self.channel_names = {}
        self.channel_buffer_len = 50
        self.labels = []
        self.foreground_sleep_ms = 200
        self.background_sleep_ms = 500
        self.last_parsed_timestamp = None

    def start(self):
        super().start()
        # Register the raw packet receiver callback
        register_raw_receiver(self.handle_raw_packet)

    def handle_raw_packet(self, frame):
        rssi = self.badge.lora.get_rssi()
        snr = self.badge.lora.get_snr()
        recv_time = time.time()
        # Append tuple of (time, raw_frame_bytes, rssi, snr)
        self.packet_queue.append((recv_time, frame, rssi, snr))
        # Decode and persist group channel messages so they can be viewed later,
        # even if this happens while the app is in the background.
        self._store_group_message(frame, recv_time, rssi, snr)

    def _store_group_message(self, frame, recv_time, rssi, snr):
        """Parse a raw frame and, if it's a decodable group text, save it per-channel."""
        parsed = parse_meshcore_packet(frame)
        if not parsed:
            return
        _route, payload, _hops, _hash_size, _path, payload_bytes = parsed
        if payload not in ("GRP_TXT", "GRP_DAT"):
            return
        decrypted = try_decrypt_group_text(payload_bytes)
        if not decrypted:
            return
        channel_id, room_name, sender, text, msg_time = decrypted
        message = ChannelMessage(recv_time, msg_time, sender, text, rssi, snr)
        channel = self.channels.get(channel_id)
        if channel is None:
            channel = deque([], self.channel_buffer_len)
            self.channels[channel_id] = channel
        self.channel_names[channel_id] = room_name
        channel.append(message)
        print(
            f"[MeshCore] Stored '{room_name}' msg (channel now has {len(channel)}). "
            f"Known channels: {list(self.channel_names.values())}"
        )

    def run_foreground(self):
        if self.badge.keyboard.f5():  # Go back to Main Menu
            self.badge.display.clear()
            self.switch_to_background()
            return

        # Update the UI labels
        self.draw_packets()

    def draw_packets(self):
        # Clear screen labels or show detailed packet breakdown
        if not self.packet_queue:
            self.labels[0].set_text("Waiting for MeshCore packets...")
            for i in range(1, 8):
                self.labels[i].set_text("")
            return

        timestamp, frame, rssi, snr = self.packet_queue[-1]  # Analyze the absolute latest packet
        
        # Avoid constant parsing and screen drawing if the frame hasn't changed
        if timestamp == self.last_parsed_timestamp:
            return
            
        self.last_parsed_timestamp = timestamp

        t_struct = time.localtime(timestamp)
        time_str = f"{t_struct[3]:02d}:{t_struct[4]:02d}:{t_struct[5]:02d}"

        # Line 0: Header Section
        self.labels[0].set_text(f"--- MeshCore Analyzer @ {time_str} ---")

        # Line 1: RF State
        self.labels[1].set_text(f"RF Signal: RSSI={int(rssi)}dBm | SNR={int(snr)}dB | Size={len(frame)}B")

        # Parse MeshCore packet
        parsed = parse_meshcore_packet(frame)
        if parsed:
            route, payload, hop_count, parsed_hash_size, path_data, payload_bytes = parsed
            
            # Line 2: Header info
            self.labels[2].set_text(f"Protocol:  Route={route} | MsgType={payload}")
            
            # Line 3: Path / Hops
            path_hex = binascii.hexlify(path_data).decode()
            self.labels[3].set_text(f"Topology:  Hops={hop_count} (Hash={parsed_hash_size}B) | Path={path_hex}")
            
            # Line 4: Payload Decoded Info
            details = "None"
            if payload == "TXT" and len(payload_bytes) >= parsed_hash_size * 2:
                dest_bytes = payload_bytes[0 : parsed_hash_size]
                src_bytes = payload_bytes[parsed_hash_size : parsed_hash_size * 2]
                dest = binascii.hexlify(dest_bytes).decode()
                src = binascii.hexlify(src_bytes).decode()
                details = f"Private Msg: {src} -> {dest}"
            elif payload == "ADV" and len(payload_bytes) >= 32:
                node_hash_bytes = payload_bytes[0 : parsed_hash_size]
                node_hash = binascii.hexlify(node_hash_bytes).decode()
                details = f"Advert Node: {node_hash}"
                if len(payload_bytes) > 101:
                    appdata = payload_bytes[101:]
                    # Extract printable ASCII names
                    printable = "".join([chr(b) for b in appdata if 32 <= b < 127]).strip()
                    if len(printable) >= 2:
                        details += f" Name: '{printable}'"
            elif payload == "ACK" and len(payload_bytes) >= 4:
                details = f"Ack CRC: {binascii.hexlify(payload_bytes[:4]).decode()}"
            elif payload in ("GRP_TXT", "GRP_DAT") and len(payload_bytes) >= 1:
                chan_bytes = payload_bytes[0 : 1]
                chan = binascii.hexlify(chan_bytes).decode()
                details = f"Group Chan: {chan}"
                decrypted = try_decrypt_group_text(payload_bytes)
                if decrypted:
                    _chan_id, room_name, sender, decoded_msg, _ts = decrypted
                    details += f" ({room_name}) {sender}: '{decoded_msg}'"
                
            self.labels[4].set_text(f"Decoded:   {details}")
            
            # Line 5: Payload Hex
            pay_hex = binascii.hexlify(payload_bytes).decode()
            display_pay = pay_hex[:45] + ".." if len(pay_hex) > 45 else pay_hex
            self.labels[5].set_text(f"Payload:   {display_pay}")
        else:
            self.labels[2].set_text("Protocol:  Non-V1 or Invalid MeshCore Frame")
            self.labels[3].set_text("")
            self.labels[4].set_text("")
            self.labels[5].set_text("")

        # Line 6 & 7: Raw Hex Dump
        raw_hex = binascii.hexlify(frame).decode()
        self.labels[6].set_text(f"Raw Frame: {raw_hex[:45]}")
        if len(raw_hex) > 45:
            self.labels[7].set_text(f"           {raw_hex[45:]}")
        else:
            self.labels[7].set_text("")

    def switch_to_foreground(self):
        self.last_parsed_timestamp = None  # Force a clean redraw on load
        super().switch_to_foreground()
        self.badge.display.clear()
        self.badge.display.screen.set_style_bg_color(styles.lvg_color_black, 0)
        
        # Create Title in legendary Matrix Green
        self.title_label = self.badge.display.text(0, 0, "MeshCore Listener", color=0x39FF14) 
        self.badge.display.f5("Home")
        
        # Pre-create labels with dynamic Matrix terminal shades
        self.labels = []
        char_height = self.badge.display.CHAR_HEIGHT
        
        # Matrix phosphor shades: bright active green down to deep background glow
        matrix_greens = [
            0x00DD00,  # Line 0: Analyzer Header (Mid Neon Green)
            0x00BB00,  # Line 1: RF State (Medium Terminal Green)
            0x00FF00,  # Line 2: Protocol Type (Bright Green)
            0x00CC00,  # Line 3: Hops/Topology (Classic Green)
            0x39FF14,  # Line 4: Decrypted Message / Payload Decode (Super Bright Neon!)
            0x008800,  # Line 5: Payload Hex Chunk (Dimmer Green)
            0x005500,  # Line 6: Raw Hex Part 1 (Deep Phosphor Glow)
            0x003300,  # Line 7: Raw Hex Part 2 (Shadow Phosphor Glow)
        ]
        
        for i in range(8):
            lbl = self.badge.display.text((i + 1) * char_height, 0, "", color=matrix_greens[i])
            self.labels.append(lbl)
            
        self.draw_packets()

    def switch_to_background(self):
        self.labels = []
        self.title_label = None
        super().switch_to_background()
