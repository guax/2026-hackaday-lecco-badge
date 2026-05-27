"""MeshCore listening application."""

from collections import deque
import binascii
import time
from apps.base_app import BaseApp
from net.net import register_raw_receiver, unregister_raw_receiver

APP_NAME = "MeshCore"

class MeshCoreListener(BaseApp):
    def __init__(self, name: str, badge):
        super().__init__(name, badge)
        self.packet_queue = deque([], 10)  # Store last 10 packets
        self.labels = []
        self.foreground_sleep_ms = 200
        self.background_sleep_ms = 500

    def start(self):
        super().start()
        # Register the raw packet receiver callback
        register_raw_receiver(self.handle_raw_packet)

    def handle_raw_packet(self, frame):
        rssi = self.badge.lora.get_rssi()
        snr = self.badge.lora.get_snr()
        # Convert frame to hex string
        hex_data = binascii.hexlify(frame).decode()
        self.packet_queue.append((time.time(), hex_data, len(frame), rssi, snr))

    def run_foreground(self):
        if self.badge.keyboard.f5():  # Go back to Main Menu
            self.badge.display.clear()
            self.switch_to_background()
            return

        # Update the UI labels
        self.draw_packets()

    def draw_packets(self):
        # Update the text of pre-created labels to avoid memory fragmentation/allocation in the loop
        packets = list(self.packet_queue)[-8:]  # Display last 8 packets
        for idx in range(8):
            if idx < len(packets):
                timestamp, hex_data, length, rssi, snr = packets[idx]
                t_struct = time.localtime(timestamp)
                time_str = f"{t_struct[3]:02d}:{t_struct[4]:02d}:{t_struct[5]:02d}"
                
                # Truncate hex to fit screen cleanly
                display_hex = hex_data[:28] + ".." if len(hex_data) > 28 else hex_data
                txt = f"{time_str} ({length}B) R:{int(rssi)} S:{int(snr)}: {display_hex}"
                
                if idx < len(self.labels):
                    self.labels[idx].set_text(txt)
            else:
                if idx < len(self.labels):
                    self.labels[idx].set_text("")

    def switch_to_foreground(self):
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
