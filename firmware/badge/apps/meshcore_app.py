"""MeshCore listening and packet decoding application."""

from collections import deque, namedtuple
import lvgl
import time
from apps.base_app import BaseApp
from net.net import register_raw_receiver, unregister_raw_receiver
from net.meshcore import parse_meshcore_packet, try_decrypt_group_text, GROUP_KEYS
from ui import styles
from ui.page import Page

APP_NAME = "MeshCore"

# Application modes. MENU is the landing screen reached via F4.
MODE_MENU = 0
MODE_CHANNELS = 1
MODE_CHANNEL_VIEW = 2
MODE_DM = 3
MODE_ANALYSER = 4

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
        self.foreground_sleep_ms = 50
        self.background_sleep_ms = 500
        # UI state
        self.page = None
        self.mode = MODE_MENU
        # Channels list state: ordered list of (channel_id, name) and the selection cursor.
        self._channel_order = []
        self._channel_rows_cache = []
        self.channel_sel = 0
        # Channel view state
        self.active_channel_id = None
        self._view_msg_count = -1

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

    # ------------------------------------------------------------------
    # App lifecycle
    # ------------------------------------------------------------------
    def switch_to_foreground(self):
        super().switch_to_foreground()
        self._set_mode(MODE_MENU)

    def switch_to_background(self):
        self.page = None
        super().switch_to_background()

    def run_foreground(self):
        # F5 always returns to the main badge menu.
        if self.badge.keyboard.f5():
            self.badge.display.clear()
            self.switch_to_background()
            return

        # F4 always returns to the MeshCore main menu.
        if self.badge.keyboard.f4():
            self._set_mode(MODE_MENU)
            return

        # Dispatch contextual input to the active mode.
        if self.mode == MODE_MENU:
            self._run_menu()
        elif self.mode == MODE_CHANNELS:
            self._run_channels()
        elif self.mode == MODE_CHANNEL_VIEW:
            self._run_channel_view()
        elif self.mode == MODE_DM:
            self._run_dm()
        elif self.mode == MODE_ANALYSER:
            self._run_analyser()

    # ------------------------------------------------------------------
    # Mode switching / screen building
    # ------------------------------------------------------------------
    def _set_mode(self, mode):
        self.mode = mode
        if mode == MODE_MENU:
            self._build_menu()
        elif mode == MODE_CHANNELS:
            self._build_channels()
        elif mode == MODE_CHANNEL_VIEW:
            self._build_channel_view()
        elif mode == MODE_DM:
            self._build_placeholder("Direct Messages", "DM mode coming soon.")
        elif mode == MODE_ANALYSER:
            self._build_placeholder("Packet Analyser", "Packet analyser coming soon.")

    def _content_label(self, text):
        """Create a left-aligned multiline label inside the current page content."""
        label = lvgl.label(self.page.content)
        label.add_style(styles.content_style, 0)
        label.set_width(lvgl.pct(96))
        label.align(lvgl.ALIGN.TOP_LEFT, 8, 6)
        label.set_text(text)
        return label

    def _build_menu(self):
        self.page = Page()
        self.page.create_infobar(["MeshCore", "Main Menu"])
        self.page.create_content()
        self._content_label(
            "Select a mode:\n"
            "F1  Channels  - browse decoded channel messages\n"
            "F2  Direct Msg - send/read direct messages\n"
            "F3  Packets    - raw packet analyser"
        )
        self.page.create_menubar(["Channels", "Direct", "Packets", "Menu", "Home"])
        self.page.replace_screen()

    def _refresh_channel_order(self):
        """Build the ordered list of channels: every configured channel, plus any
        channel we have received messages for that isn't in the config."""
        order = [(key_hex, name) for name, key_hex in GROUP_KEYS.items()]
        order.sort(key=lambda c: c[1])
        known = set(cid for cid, _ in order)
        for cid in self.channels:
            if cid not in known:
                order.append((cid, self.channel_names.get(cid, cid[:8])))
        self._channel_order = order
        if self.channel_sel >= len(order):
            self.channel_sel = max(0, len(order) - 1)

    def _channel_rows(self):
        rows = []
        for cid, name in self._channel_order:
            count = len(self.channels.get(cid, ()))
            rows.append((name, "{} msg".format(count)))
        return rows

    def _build_channels(self):
        self._refresh_channel_order()
        self.page = Page()
        self.page.create_infobar(["Channels", "Up/Dn select"])
        self.page.create_content()
        rows = self._channel_rows()
        self.page.add_message_rows(max(1, len(rows)), left_width=300)
        self._populate_channel_list(rows)
        self.page.create_menubar(["Open", "Add", "Del", "Menu", "Home"])
        self.page.replace_screen()

    def _populate_channel_list(self, rows):
        table = self.page.message_rows
        if not rows:
            table.set_row_count(1)
            table.set_cell_value(0, 0, "(no channels configured)")
            table.set_cell_value(0, 1, "")
            return
        table.set_row_count(len(rows))
        self._channel_rows_cache = rows
        self._render_channel_selection()

    def _render_channel_selection(self):
        """Draw a '>' marker on the selected row so the cursor is clearly visible."""
        table = self.page.message_rows
        rows = self._channel_rows_cache
        for i, (name, count) in enumerate(rows):
            marker = "> " if i == self.channel_sel else "  "
            table.set_cell_value(i, 0, marker + name)
            table.set_cell_value(i, 1, count)
        table.set_selected_cell(self.channel_sel, 0)

    def _build_channel_view(self):
        cid = self.active_channel_id
        name = self.channel_names.get(cid) or self._name_for(cid)
        self.page = Page()
        self.page.create_infobar(["Channel: {}".format(name), ""])
        self.page.create_content()
        self.page.add_message_rows(1, left_width=90)
        self._view_msg_count = -1
        self._refresh_channel_view()
        self.page.create_menubar(["Back", "", "", "Menu", "Home"])
        self.page.replace_screen()

    def _refresh_channel_view(self):
        """Re-populate the message table only when the message count changed."""
        msgs = self.channels.get(self.active_channel_id)
        count = len(msgs) if msgs else 0
        if count == self._view_msg_count:
            return
        self._view_msg_count = count
        display = []
        if msgs:
            for m in msgs:
                display.append((m.sender or "?", m.text))
        self.page.populate_message_rows(display)

    def _name_for(self, channel_id):
        for name, key_hex in GROUP_KEYS.items():
            if key_hex == channel_id:
                return name
        return channel_id[:8]

    def _build_placeholder(self, title, body):
        self.page = Page()
        self.page.create_infobar(["MeshCore", title])
        self.page.create_content()
        self._content_label(body)
        self.page.create_menubar(["", "", "", "Menu", "Home"])
        self.page.replace_screen()

    # ------------------------------------------------------------------
    # Per-mode input handling
    # ------------------------------------------------------------------
    def _run_menu(self):
        if self.badge.keyboard.f1():
            self._set_mode(MODE_CHANNELS)
        elif self.badge.keyboard.f2():
            self._set_mode(MODE_DM)
        elif self.badge.keyboard.f3():
            self._set_mode(MODE_ANALYSER)

    def _run_channels(self):
        if not self._channel_order:
            return
        key = self.badge.keyboard.read_key()
        if key == self.badge.keyboard.UP:
            self.channel_sel = max(0, self.channel_sel - 1)
            self._render_channel_selection()
        elif key == self.badge.keyboard.DOWN:
            self.channel_sel = min(len(self._channel_order) - 1, self.channel_sel + 1)
            self._render_channel_selection()

        if self.badge.keyboard.f1():  # Open selected channel
            self.active_channel_id = self._channel_order[self.channel_sel][0]
            self._set_mode(MODE_CHANNEL_VIEW)
        # F2 (Add) and F3 (Delete) are reserved for future channel management.

    def _run_channel_view(self):
        if self.badge.keyboard.f1():  # Back to channel list
            self._set_mode(MODE_CHANNELS)
            return
        # Keep the view in sync as new messages arrive while open.
        self._refresh_channel_view()
        key = self.badge.keyboard.read_key()
        scroll = 13
        if self.badge.keyboard.shift_pressed:
            scroll *= 5
        if key == self.badge.keyboard.UP:
            self.page.scroll_up(scroll)
        elif key == self.badge.keyboard.DOWN:
            self.page.scroll_down(scroll)

    def _run_dm(self):
        pass

    def _run_analyser(self):
        pass
