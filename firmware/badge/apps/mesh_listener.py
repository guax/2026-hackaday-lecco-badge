"""MeshCore listening and packet decoding application."""

from collections import deque
import binascii
import time
from apps.base_app import BaseApp
from net.net import register_raw_receiver, unregister_raw_receiver

APP_NAME = "MeshCore"

class MeshCoreListener(BaseApp):
    def __init__(self, name: str, badge):
        super().__init__(name, badge)
        self.packet_queue = deque([], 10)  # Store last 10 raw packet frames and RSSI/SNR
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
        # Append tuple of (time, raw_frame_bytes, rssi, snr)
        self.packet_queue.append((time.time(), frame, rssi, snr))

    def parse_meshcore_packet(self, frame):
        """Parse a raw frame into MeshCore components with verbose console logging on failures."""
        if not frame or len(frame) < 2:
            print(f"[MeshCore Debug] Rejecting: Frame too short (len={len(frame) if frame else 0})")
            return None
        
        print(f"[MeshCore Debug] Parsing frame: len={len(frame)}, raw={binascii.hexlify(frame).decode()}")
            
        header = frame[0]
        # Check version (bits 6-7)
        version = (header & 0xC0) >> 6
        if version != 0:
            print(f"[MeshCore Debug] Rejecting: Unsupported packet version={version} (header=0x{header:02x})")
            return None  # Only support MeshCore V1
            
        payload_type_val = (header & 0x3C) >> 2
        route_type_val = header & 0x03
        
        ROUTE_TYPES = {
            0x00: "TX_FLOOD",
            0x01: "FLOOD",
            0x02: "DIRECT",
            0x03: "TX_DIR",
        }
        PAYLOAD_TYPES = {
            0x00: "REQ",
            0x01: "RESP",
            0x02: "TXT",
            0x03: "ACK",
            0x04: "ADV",
            0x05: "GRP_TXT",
            0x06: "GRP_DAT",
            0x07: "ANON",
            0x08: "PATH",
            0x09: "TRACE",
            0x0A: "MULTI",
            0x0B: "CTRL",
            0x0F: "RAW",
        }
        
        route = ROUTE_TYPES.get(route_type_val, f"R{route_type_val}")
        payload = PAYLOAD_TYPES.get(payload_type_val, f"P{payload_type_val}")
        
        idx = 1
        # Check transport codes
        if route_type_val in (0x00, 0x03):
            if len(frame) < idx + 4:
                print(f"[MeshCore Debug] Rejecting: Expected 4-byte transport code, frame size={len(frame)}")
                return None
            idx += 4
            
        # Path length byte is bit-packed:
        # Bits 0-5: hop count (0-63)
        # Bits 6-7: hash size code (0b00 = 1-byte, 0b01 = 2-byte, 0b10 = 3-byte -> hash_size = code + 1)
        if len(frame) < idx + 1:
            print(f"[MeshCore Debug] Rejecting: No path length byte, frame size={len(frame)}")
            return None
        path_length_byte = frame[idx]
        idx += 1
        
        hop_count = path_length_byte & 0x3F
        hash_size_code = (path_length_byte & 0xC0) >> 6
        parsed_hash_size = hash_size_code + 1
        path_bytes_len = hop_count * parsed_hash_size
        
        # Path
        if len(frame) < idx + path_bytes_len:
            print(f"[MeshCore Debug] Rejecting: Path length too large ({path_bytes_len} bytes requested, remaining={len(frame) - idx})")
            return None
        path_data = frame[idx:idx+path_bytes_len]
        idx += path_bytes_len
        
        # Payload
        payload_bytes = frame[idx:]
        
        print(f"[MeshCore Debug] Parsed OK: Route={route}, MsgType={payload}, Hops={hop_count}, HashSize={parsed_hash_size}B, PayloadSize={len(payload_bytes)}B")
        return route, payload, hop_count, parsed_hash_size, path_data, payload_bytes

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
        parsed = self.parse_meshcore_packet(frame)
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
            elif payload in ("GRP_TXT", "GRP_DAT") and len(payload_bytes) >= parsed_hash_size:
                chan_bytes = payload_bytes[0 : parsed_hash_size]
                chan = binascii.hexlify(chan_bytes).decode()
                details = f"Group Text on Chan: {chan}"
                
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
        
        # Create Title
        self.title_label = self.badge.display.text(0, 0, "MeshCore Listener", color=0x00FF00) # Green title
        self.badge.display.f5("Home")
        
        # Pre-create labels
        self.labels = []
        char_height = self.badge.display.CHAR_HEIGHT
        for i in range(8):
            lbl = self.badge.display.text((i + 1) * char_height, 0, "")
            self.labels.append(lbl)
            
        self.draw_packets()

    def switch_to_background(self):
        self.labels = []
        self.title_label = None
        super().switch_to_background()
