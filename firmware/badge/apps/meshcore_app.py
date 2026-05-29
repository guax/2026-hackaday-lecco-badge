"""MeshCore listening and packet decoding application."""

from collections import deque, namedtuple
import asyncio as aio
import binascii
from struct import pack
import lvgl
import time
from apps.base_app import BaseApp
from hardware.datafile import DataFile
from net.net import register_raw_receiver, unregister_raw_receiver
from net.meshcore import (
    parse_meshcore_packet,
    try_decrypt_group_text,
    CHANNELS,
    DEFAULT_CHANNELS,
    PUBLIC_KEY,
    set_channels,
    derive_channel_key,
    add_group_channel,
    remove_group_channel,
)
from net.meshcore_packets import (
    MeshCorePacketBuilder,
    generate_private_key,
    load_private_key,
    public_key_to_raw,
    private_key_to_raw,
)
from ui import styles
from ui.page import Page

# Persistent store (separate from the main badge config) holding user channels.
CHANNEL_STORE_NAME = "meshcore_channels"
# Persistent store holding this node's Ed25519 identity (raw private key seed).
IDENTITY_STORE_NAME = "meshcore_identity"

APP_NAME = "MeshCore"

MAX_MESSAGE_LEN = 130

# Application modes. MENU is the landing screen reached via F4.
MODE_MENU = 0
MODE_CHANNELS = 1
MODE_CHANNEL_VIEW = 2
MODE_CHANNEL_ADD = 3
MODE_CHANNEL_DELETE = 4
MODE_DM = 5
MODE_ADVERT = 6

# Built-in channels that may not be deleted, identified by their key (hex).
PROTECTED_CHANNELS = (PUBLIC_KEY,)

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
        self._chan_labels = []
        self.channel_sel = 0
        # Channel view state
        self.active_channel_id = None
        self.compose_active = False
        self._view_msg_count = -1
        # Add-channel flow state
        self.add_step = "type"   # "type" -> "name" -> "key"
        self.add_kind = None     # "public" or "private"
        self.add_name = ""
        # Persistent channel store (separate /data file, not the main config).
        self.channel_store = None
        # Node identity / packet builder, loaded at start.
        self.identity_store = None
        self.packet_builder = None
        # Info about the most recently sent advert, for display.
        self.last_advert = None
        # Some singletons
        self.node_name = None

    def start(self):
        super().start()
        # Load persisted channels into the decoder before listening starts.
        self._load_channels()
        # Load (or create) this node's Ed25519 identity and packet builder.
        self._load_identity()
        # Register the raw packet receiver callback
        register_raw_receiver(self.handle_raw_packet)

    def _node_name(self):
        """Display name for this node, taken from the badge alias if set."""
        if self.node_name:
            return self.node_name
        try:
            alias = self.badge.config.get("nametag")
            if alias:
                alias = alias.decode() if isinstance(alias, (bytes, bytearray)) else str(alias)
                alias = alias.strip()
                if alias:
                    self.node_name = alias[:32]
                    return self.node_name
        except Exception as e: 
            print(f"[MeshCore] Error getting node name: {e}")
            pass
        return "Hackbadge"

    def _load_identity(self):
        """Load the node's Ed25519 keypair from storage, generating and
        persisting a new one on first run, then build the packet builder."""
        try:
            self.identity_store = DataFile(IDENTITY_STORE_NAME)
            raw = self.identity_store.get("priv")
            if raw:
                priv = load_private_key(bytes(raw))
            else:
                priv = generate_private_key()
                self.identity_store.set("priv", private_key_to_raw(priv))
                self.identity_store.flush()
                print("[MeshCore] Generated new node identity")
            pub_raw = public_key_to_raw(priv)
            self.packet_builder = MeshCorePacketBuilder(pub_raw, priv, self._node_name())
            print("[MeshCore] Node '{}' pubkey={}".format(
                self.packet_builder.node_name, binascii.hexlify(pub_raw).decode()))
        except Exception as e:
            import sys
            print("[MeshCore] Identity load failed:", e)
            sys.print_exception(e)
            self.packet_builder = None

    def _transmit(self, packet):
        """Schedule a raw packet for transmission over LoRa (bypasses BadgeNet
        framing). run_foreground is sync, so the async send is fired as a task."""
        try:
            aio.create_task(self.badge.lora.send(packet))
            return True
        except Exception as e:
            print("[MeshCore] TX schedule error:", e)
            return False

    def _load_channels(self):
        """Open the channel store, seeding defaults on first run, and apply the
        persisted channel set (key_hex -> name) to the decoder's CHANNELS."""
        self.channel_store = DataFile(CHANNEL_STORE_NAME)
        if not list(self.channel_store.db.keys()):
            for key_hex, name in DEFAULT_CHANNELS.items():
                self.channel_store.set(key_hex, name)
            self.channel_store.flush()
        mapping = {}
        for k, v in self.channel_store.db.items():
            key_hex = k.decode() if isinstance(k, bytes) else k
            name = v.decode() if isinstance(v, bytes) else v
            mapping[key_hex] = name
        set_channels(mapping)

    def _persist_channel(self, key_hex, name):
        if self.channel_store:
            self.channel_store.set(key_hex, name)
            self.channel_store.flush()

    def _unpersist_channel(self, key_hex):
        if self.channel_store:
            self.channel_store.delete(key_hex)
            self.channel_store.flush()

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
        elif self.mode == MODE_CHANNEL_ADD:
            self._run_channel_add()
        elif self.mode == MODE_CHANNEL_DELETE:
            self._run_channel_delete()
        elif self.mode == MODE_DM:
            self._run_dm()
        elif self.mode == MODE_ADVERT:
            self._run_advert()

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
        elif mode == MODE_CHANNEL_ADD:
            self.add_step = "type"
            self.add_kind = None
            self.add_name = ""
            self._build_channel_add()
        elif mode == MODE_CHANNEL_DELETE:
            self._build_channel_delete()
        elif mode == MODE_DM:
            self._build_placeholder("Direct Messages", "DM mode coming soon.")
        elif mode == MODE_ADVERT:
            self._build_advert()

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
            "F3  Advert     - broadcast this node's identity"
        )
        self.page.create_menubar(["Channels", "Direct", "Advert", "Menu", "Home"])
        self.page.replace_screen()

    def _refresh_channel_order(self):
        """Build the ordered list of channels: every configured channel, plus any
        channel we have received messages for that isn't in the config."""
        order = [(key_hex, name) for key_hex, name in CHANNELS.items()]
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

    # Number of channel rows visible at once in the list (windowed scrolling).
    LIST_MAX_VISIBLE = 5
    LIST_ROW_PX = 18

    def _build_channels(self):
        self._refresh_channel_order()
        self.page = Page()
        self.page.create_infobar(["Channels", "Up/Dn select"])
        self.page.create_content()
        self._chan_labels = []
        self._draw_channel_list()
        self.page.create_menubar(["Open", "Add", "Del", "Menu", "Home"])
        self.page.replace_screen()

    def _draw_channel_list(self):
        """Render a windowed, highlight-bar selection list of channels.

        Windowing keeps the selected row on screen (scroll-into-view), and the
        selected row gets a filled background bar instead of a text marker."""
        for label in self._chan_labels:
            label.delete()
        self._chan_labels = []
        if not self.page or not self.page.content:
            return

        rows = self._channel_rows()
        if not rows:
            empty = lvgl.label(self.page.content)
            empty.add_style(styles.content_style, 0)
            empty.align(lvgl.ALIGN.TOP_LEFT, 8, 5)
            empty.set_text("(no channels configured)")
            self._chan_labels.append(empty)
            return

        # Determine the visible window, centering the selection when possible.
        max_visible = self.LIST_MAX_VISIBLE
        start = 0
        if len(rows) > max_visible:
            start = max(0, self.channel_sel - max_visible // 2)
            start = min(start, len(rows) - max_visible)
        end = min(start + max_visible, len(rows))

        y = 4
        for i in range(start, end):
            name, count = rows[i]
            label = lvgl.label(self.page.content)
            label.add_style(styles.content_style, 0)
            label.set_width(lvgl.pct(100))
            label.set_style_pad_top(2, 0)
            label.set_style_pad_bottom(2, 0)
            label.set_style_pad_left(8, 0)
            label.set_text("{}   {}".format(name, count))
            if i == self.channel_sel:
                # Highlight bar: filled background with inverted text.
                label.set_style_bg_color(styles.lcd_color_fg, 0)
                label.set_style_bg_opa(255, 0)
                label.set_style_text_color(styles.lcd_color_bg, 0)
            label.align(lvgl.ALIGN.TOP_LEFT, 0, y)
            self._chan_labels.append(label)
            y += self.LIST_ROW_PX

    def _build_channel_view(self):
        cid = self.active_channel_id
        name = self.channel_names.get(cid) or self._name_for(cid)
        self.page = Page()
        self.page.create_infobar(["Channel: {}".format(name), ""])
        self.page.create_content()
        self.page.add_message_rows(1, left_width=90)
        self._view_msg_count = -1
        self._refresh_channel_view()
        self.page.create_menubar(["Transmit", "", "Back", "Menu", "Home"])
        self.page.replace_screen()

    def _refresh_channel_view(self):
        """Re-populate the message table only when the message count changed.

        Each row is rendered as: time (HH:MM) | "sender: text"."""
        msgs = self.channels.get(self.active_channel_id)
        count = len(msgs) if msgs else 0
        if count == self._view_msg_count:
            return
        self._view_msg_count = count
        if not msgs:
            self.page.populate_message_rows([("", "No messages yet on this channel.")])
            return
        display = []
        for m in msgs:
            t = time.localtime(m.recv_time)
            time_str = "{:02d}:{:02d}".format(t[3], t[4])
            who = m.sender or "?"
            display.append((time_str, "{}: {}".format(who, m.text)))
        self.page.populate_message_rows(display)

    def _name_for(self, channel_id):
        return CHANNELS.get(channel_id, channel_id[:8])

    def _build_placeholder(self, title, body):
        self.page = Page()
        self.page.create_infobar(["MeshCore", title])
        self.page.create_content()
        self._content_label(body)
        self.page.create_menubar(["", "", "", "Menu", "Home"])
        self.page.replace_screen()

    # ------------------------------------------------------------------
    # Add-channel flow
    # ------------------------------------------------------------------
    def _build_channel_add(self):
        """Step 1: choose the channel type."""
        self.page = Page()
        self.page.create_infobar(["Add Channel", "Choose type"])
        self.page.create_content()
        self._content_label(
            "F1  # Channel  - public, key derived from the name\n"
            "F2  Private    - enter name and key separately"
        )
        self.page.create_menubar(["# Chan", "Private", "", "Menu", "Home"])
        self.page.replace_screen()

    def _build_text_input(self, prompt, default="", char_limit=0):
        self.page = Page()
        self.page.create_infobar([prompt, "F1=OK  ESC=cancel"])
        self.page.create_content()
        self.page.create_text_box(
            default_text=default, one_line=True, char_limit=char_limit
        )
        self.page.create_menubar(["OK", "", "", "Menu", "Home"])
        self.page.replace_screen()

    def _start_name_input(self):
        self.add_step = "name"
        if self.add_kind == "public":
            self._build_text_input("New # channel name:", default="#", char_limit=24)
        else:
            self._build_text_input("New private channel name:", char_limit=24)

    @staticmethod
    def _valid_key_hex(s):
        if len(s) != 32:
            return False
        try:
            int(s, 16)
            return True
        except ValueError:
            return False

    def _finish_add(self, key_hex):
        """Return to the channel list with the newly added channel selected."""
        self._set_mode(MODE_CHANNELS)
        for idx, (cid, _nm) in enumerate(self._channel_order):
            if cid == key_hex:
                self.channel_sel = idx
                self._draw_channel_list()
                break

    def _commit_public(self):
        name = self.add_name
        if not name.startswith("#"):
            name = "#" + name
        key_hex = derive_channel_key(name)
        if add_group_channel(key_hex, name):
            self._persist_channel(key_hex, name)
            print("[MeshCore] Added # channel '{}' key={}".format(name, key_hex))
            self._finish_add(key_hex)
        else:
            self.page.infobar_right.set_text("Channel exists")

    def _commit_private(self, key_hex):
        if add_group_channel(key_hex, self.add_name):
            self._persist_channel(key_hex, self.add_name)
            print(
                "[MeshCore] Added private channel '{}' key={}".format(
                    self.add_name, key_hex
                )
            )
            self._finish_add(key_hex)
        else:
            self.page.infobar_right.set_text("Key exists")

    # ------------------------------------------------------------------
    # Delete-channel flow
    # ------------------------------------------------------------------
    def _build_channel_delete(self):
        cid, name = self._channel_order[self.channel_sel]
        self.page = Page()
        self.page.create_infobar(["Delete Channel", ""])
        self.page.create_content()
        if cid in PROTECTED_CHANNELS:
            self._content_label(
                "'{}' is a built-in channel and cannot be deleted.".format(name)
            )
            self.page.create_menubar(["", "", "", "Menu", "Home"])
        else:
            count = len(self.channels.get(cid, ()))
            self._content_label(
                "Delete channel '{}'?\n"
                "This removes its key and {} stored message(s).".format(name, count)
            )
            self.page.create_menubar(["Delete", "", "Cancel", "Menu", "Home"])
        self.page.replace_screen()

    def _commit_delete(self):
        cid, name = self._channel_order[self.channel_sel]
        if cid in PROTECTED_CHANNELS:
            return
        remove_group_channel(cid)
        self._unpersist_channel(cid)
        self.channels.pop(cid, None)
        self.channel_names.pop(cid, None)
        print("[MeshCore] Deleted channel '{}' key={}".format(name, cid))
        self._set_mode(MODE_CHANNELS)

    # ------------------------------------------------------------------
    # Per-mode input handling
    # ------------------------------------------------------------------
    def _run_menu(self):
        if self.badge.keyboard.f1():
            self._set_mode(MODE_CHANNELS)
        elif self.badge.keyboard.f2():
            self._set_mode(MODE_DM)
        elif self.badge.keyboard.f3():
            self._set_mode(MODE_ADVERT)

    def _run_channels(self):
        if not self._channel_order:
            return
        key = self.badge.keyboard.read_key()
        if key == self.badge.keyboard.UP:
            self.channel_sel = max(0, self.channel_sel - 1)
            self._draw_channel_list()
        elif key == self.badge.keyboard.DOWN:
            self.channel_sel = min(len(self._channel_order) - 1, self.channel_sel + 1)
            self._draw_channel_list()

        if self.badge.keyboard.f1():  # Open selected channel
            self.active_channel_id = self._channel_order[self.channel_sel][0]
            self._set_mode(MODE_CHANNEL_VIEW)
        elif self.badge.keyboard.f2():  # Add a new channel
            self._set_mode(MODE_CHANNEL_ADD)
        elif self.badge.keyboard.f3():  # Delete the selected channel
            self._set_mode(MODE_CHANNEL_DELETE)

    def _run_channel_view(self):
        if not self.compose_active and self.badge.keyboard.f1():  # Compose a message
            self.page.create_text_box()
            self.compose_active = True
        
        if self.compose_active:
            key, text = self.page.text_box_type(self.badge.keyboard)
            self.page.infobar_right.set_text(f"{len(text)}/{MAX_MESSAGE_LEN}  F1 to send")
            if self.badge.keyboard.escape_pressed:
                self.page.close_text_box()
                self.compose_active = False
            if self.badge.keyboard.f1():  # Send
                if self.page.text_box.get_text():
                    message_text = self.page.close_text_box()
                    self._send_group_txt(message_text)
                    self.compose_active = False
            return

        if self.badge.keyboard.f3():  # Back to channel list
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

    def _send_group_txt(self, message):
        try:
            packet = self.packet_builder.build_group_txt(self.active_channel_id, message)
        except Exception as e:
            import sys
            print("[MeshCore] Group TXT packet build failed:", e)
            sys.print_exception(e)
            self.page.infobar_right.set_text("Build error")
            return
        print("[MeshCore] Sending groupt text Packet:", packet.hex())
        self._transmit(packet)

        now = int(time.time())
        messageObj = ChannelMessage(now, now, self._node_name(), message, 0, 0)
        channel = self.channels.get(self.active_channel_id)
        # If no message arrived channels is not initialized, this whole thing needs a good refactoring
        if channel is None:
            channel = deque([], self.channel_buffer_len)
            self.channels[self.active_channel_id] = channel
        channel.append(messageObj)

    def _run_channel_add(self):
        # Step 1: pick the channel type.
        if self.add_step == "type":
            if self.badge.keyboard.f1():
                self.add_kind = "public"
                self._start_name_input()
            elif self.badge.keyboard.f2():
                self.add_kind = "private"
                self._start_name_input()
            return

        # Steps 2/3: text input for name (and key for private channels).
        key, _text = self.page.text_box_type(self.badge.keyboard)
        if self.badge.keyboard.escape_pressed:
            self._set_mode(MODE_CHANNELS)  # Cancel
            return

        confirm = self.badge.keyboard.f1() or key == self.badge.keyboard.ENTER
        if not confirm:
            return
        value = self.page.text_box.get_text().strip()

        if self.add_step == "name":
            if not value:
                self.page.infobar_right.set_text("Name required")
                return
            self.add_name = value
            if self.add_kind == "public":
                self._commit_public()
            else:
                self.add_step = "key"
                self._build_text_input("Channel key (32 hex chars):", char_limit=32)
        elif self.add_step == "key":
            key_hex = value.replace(" ", "").lower()
            if not self._valid_key_hex(key_hex):
                self.page.infobar_right.set_text("Need 32 hex chars")
                return
            self._commit_private(key_hex)

    def _run_channel_delete(self):
        cid, _name = self._channel_order[self.channel_sel]
        if self.badge.keyboard.escape_pressed or self.badge.keyboard.f3():
            self._set_mode(MODE_CHANNELS)  # Cancel
            return
        if self.badge.keyboard.f1() and cid not in PROTECTED_CHANNELS:
            self._commit_delete()

    def _run_dm(self):
        pass

    # ------------------------------------------------------------------
    # Advert flow
    # ------------------------------------------------------------------
    def _build_advert(self):
        self.page = Page()
        self.page.create_infobar(["Advert", ""])
        self.page.create_content()
        if not self.packet_builder:
            self._content_label(
                "Node identity unavailable.\nCannot build adverts."
            )
            self.page.create_menubar(["", "", "", "Menu", "Home"])
            self.page.replace_screen()
            return
        pub_hex = binascii.hexlify(self.packet_builder.public_key).decode()
        lines = [
            "Node: {}".format(self.packet_builder.node_name),
            "Key:  {}...".format(pub_hex[:24]),
            "",
        ]
        if self.last_advert:
            lines.append("Last: {}".format(self.last_advert["route"]))
            lines.append("  ts={}  len={}B".format(
                self.last_advert["ts"], self.last_advert["len"]))
            lines.append("  {}".format(self.last_advert["hex"]))
        else:
            lines.append("F1 Direct    F2 Flood")
        self._content_label("\n".join(lines))
        self.page.create_menubar(["Direct", "Flood", "", "Menu", "Home"])
        self.page.replace_screen()

    def _run_advert(self):
        if not self.packet_builder:
            return
        if self.badge.keyboard.f1():
            self._send_advert(MeshCorePacketBuilder.ROUTE_DIRECT, "Direct")
        elif self.badge.keyboard.f2():
            self._send_advert(MeshCorePacketBuilder.ROUTE_FLOOD, "Flood")

    def _send_advert(self, route_type, label):
        ts = int(time.time())
        try:
            packet = self.packet_builder.build_advert(route_type=route_type, timestamp=ts)
        except Exception as e:
            print("[MeshCore] Advert build failed:", e)
            self.page.infobar_right.set_text("Build error")
            return
        ok = self._transmit(packet)
        hexstr = binascii.hexlify(packet).decode()
        self.last_advert = {
            "route": "{} {}".format(label, "sent" if ok else "FAILED"),
            "ts": ts,
            "len": len(packet),
            "hex": hexstr[:48] + ("..." if len(hexstr) > 48 else ""),
        }
        print("[MeshCore] Advert ({}) {}B: {}".format(label, len(packet), hexstr))
        self._build_advert()
