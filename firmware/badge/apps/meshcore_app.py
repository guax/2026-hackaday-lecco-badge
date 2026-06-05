"""MeshCore listening and packet decoding application."""

from collections import deque, namedtuple
import asyncio as aio
import binascii
import lvgl
import time
from apps.base_app import BaseApp
from hardware.datafile import DataFile
from net.net import register_raw_receiver, unregister_raw_receiver
from net.meshcore import (
    Packet,
    Advert,
    GroupText,
    DirectText,
    Ack,
    PathReturn,
    Channel,
    Identity,
    DEFAULT_CHANNELS,
    PUBLIC_KEY,
    PayloadType,
    RouteType,
    derive_channel_key,
    registry,
    contacts,
)
from ui import styles
from ui.pagebutbetter import PageButBetter

# Persistent store (separate from the main badge config) holding user channels.
CHANNEL_STORE_NAME = "meshcore_channels"
# Persistent store holding this node's Ed25519 identity (raw private key seed).
IDENTITY_STORE_NAME = "meshcore_identity"
# Persistent store holding favorite contacts (pubkey hex -> display name).
CONTACT_STORE_NAME = "meshcore_contacts"

APP_NAME = "MeshCore"

MAX_MESSAGE_LEN = 130
PACKET_BUFFER_LEN = 10

# Application modes. MENU is the landing screen reached via F4.
MODE_MENU = 0
MODE_CHANNELS = 1
MODE_CHANNEL_VIEW = 2
MODE_CHANNEL_ADD = 3
MODE_CHANNEL_DELETE = 4
MODE_DM = 5
MODE_ADVERT = 6
MODE_CONTACTS_ALL = 7
MODE_CONTACT_DETAILS = 8
MODE_DM_CHAT = 9
MODE_ANALYSER = 10

# Built-in channels that may not be deleted, identified by their key (hex).
PROTECTED_CHANNELS = (PUBLIC_KEY,)

# A single decoded channel message held in memory for later display.
ChannelMessage = namedtuple(
    "ChannelMessage", ["recv_time", "msg_time", "sender", "text", "rssi", "snr"]
)

# A single direct message (1:1). `outgoing` marks messages we sent.
class DirectMessage:
    def __init__(self, recv_time, msg_time, outgoing, text, ack_hash=None, delivered=False):
        self.recv_time = recv_time
        self.msg_time = msg_time
        self.outgoing = outgoing
        self.text = text
        self.ack_hash = ack_hash
        self.delivered = delivered

class MeshcoreApp(BaseApp):
    def __init__(self, name: str, badge):
        super().__init__(name, badge)
        self.packet_queue = deque([], PACKET_BUFFER_LEN)
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
        # Contacts list state: ordered list of Contact for the active contacts
        # screen, its selection cursor, label widgets, and the selected pubkey.
        self._contact_order = []
        self._contact_labels = []
        self.contact_sel = 0
        self.active_contact_key = None
        self.contact_store = None
        # Direct-message history keyed by peer pubkey hex -> deque of DirectMessage.
        self.dm_messages = {}
        self.dm_buffer_len = 50
        self.active_dm_key = None
        # Recent (sender_key, timestamp, text) keys to drop duplicate DMs that
        # arrive from sender retransmits / flood paths before our ACK lands.
        self._recent_dm = deque([], 30)
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
        self.identity = None
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
        # Load persisted favorite contacts into the contact book.
        self._load_contacts()
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
                self.identity = Identity.load(bytes(raw), self._node_name())
            else:
                self.identity = Identity.generate(self._node_name())
                self.identity_store.set("priv", self.identity.private_raw())
                self.identity_store.flush()
                print("[MeshCore] Generated new node identity")
            print("[MeshCore] Node '{}' pubkey={}".format(
                self.identity.name, binascii.hexlify(self.identity.public_key).decode()))
        except Exception as e:
            import sys
            print("[MeshCore] Identity load failed:", e)
            sys.print_exception(e)
            self.identity = None

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
            for ch in DEFAULT_CHANNELS:
                self.channel_store.set(ch.key_hex, ch.name)
            self.channel_store.flush()
        channels = []
        for k, v in self.channel_store.db.items():
            key_hex = k.decode() if isinstance(k, bytes) else k
            name = v.decode() if isinstance(v, bytes) else v
            channels.append(Channel(key_hex, name))
        registry.replace(channels)

    def _persist_channel(self, key_hex, name):
        if self.channel_store:
            self.channel_store.set(key_hex, name)
            self.channel_store.flush()

    def _unpersist_channel(self, key_hex):
        if self.channel_store:
            self.channel_store.delete(key_hex)
            self.channel_store.flush()

    def _load_contacts(self):
        """Open the contacts store and seed persisted favorites into the book."""
        self.contact_store = DataFile(CONTACT_STORE_NAME)
        for k, v in self.contact_store.db.items():
            pubkey_hex = k.decode() if isinstance(k, bytes) else k
            name = v.decode() if isinstance(v, bytes) else v
            contacts.load_favorite(pubkey_hex, name)

    def _persist_favorite(self, contact):
        if self.contact_store:
            self.contact_store.set(contact.pubkey_hex, contact.name)
            self.contact_store.flush()

    def _unpersist_favorite(self, pubkey_hex):
        if self.contact_store:
            self.contact_store.delete(pubkey_hex)
            self.contact_store.flush()

    def handle_raw_packet(self, frame):
        rssi = self.badge.lora.get_rssi()
        snr = self.badge.lora.get_snr()
        recv_time = time.time()
        # Append tuple of (time, raw_frame_bytes, rssi, snr)
        self.packet_queue.append((recv_time, frame, rssi, snr))
        # Parse once and dispatch by payload type. This runs even in the
        # background so channel history and contacts stay up to date.
        packet = Packet.parse(frame)
        if not packet:
            return
        if packet.payload_type in (PayloadType.GRP_TXT, PayloadType.GRP_DATA):
            self._store_group_message(packet, recv_time, rssi, snr)
        elif packet.payload_type == PayloadType.ADVERT:
            self._store_advert(packet)
        elif packet.payload_type == PayloadType.TXT_MSG:
            self._store_direct_message(packet, recv_time)
        elif packet.payload_type == PayloadType.ACK:
            self._process_ack(packet)
        elif packet.payload_type == PayloadType.PATH:
            self._process_path(packet)

    def _process_ack(self, packet):
        if len(packet.payload) >= 4:
            ack_hash = packet.payload[:4]
            self._mark_delivered(ack_hash)

    def _process_path(self, packet):
        from net.meshcore.packet.path_return import PathReturn
        decoded = PathReturn.decode(packet.payload, self.identity, contacts)
        if decoded and decoded.extra_type == PayloadType.ACK:
            if len(decoded.extra) >= 4:
                ack_hash = decoded.extra[:4]
                self._mark_delivered(ack_hash)

    def _mark_delivered(self, ack_hash):
        for thread in self.dm_messages.values():
            for msg in thread:
                if msg.outgoing and msg.ack_hash == ack_hash:
                    msg.delivered = True
                    self._view_msg_count = -1
                    print("[MeshCore] Delivered", ack_hash.hex())

    def _store_direct_message(self, packet, recv_time):
        """Decode a direct message addressed to us, ACK it, and store it."""
        decoded = DirectText.decode(packet.payload, self.identity, contacts)
        if not decoded:
            return
        # Always reply (even to duplicates) so the sender stops retransmitting.
        self._send_dm_ack(packet, decoded)
        # Drop duplicates: the timestamp is stable across the sender's retries.
        dedup_key = (decoded.sender_key, decoded.timestamp, decoded.text)
        if dedup_key in self._recent_dm:
            return
        self._recent_dm.append(dedup_key)
        self._append_dm(
            decoded.sender_key,
            DirectMessage(recv_time, decoded.timestamp, False, decoded.text))
        print("[MeshCore] DM from '{}': {}".format(decoded.sender_name, decoded.text))

    def _send_dm_ack(self, packet, decoded):
        """Reply to a received DM, delayed so the sender is back in RX.

        For flood-routed messages we return a PATH packet (with the ACK embedded)
        so the sender learns the route to us and can switch to direct routing,
        reducing flood noise on the mesh. For already-direct messages we send a
        plain ACK.
        """
        is_flood = packet.route_type in (RouteType.FLOOD, RouteType.TRANSPORT_FLOOD)
        try:
            if is_flood:
                peer = bytes.fromhex(decoded.sender_key)
                path_len_byte = (((packet.hash_size - 1) & 0x03) << 6) \
                    | (packet.hop_count & 0x3F)
                reply = PathReturn(
                    self.identity, peer, packet.path, path_len_byte,
                    PayloadType.ACK, decoded.ack_hash).to_bytes()
            else:
                reply = Ack(decoded.ack_hash).to_bytes()
        except Exception as e:
            import sys
            print("[MeshCore] ACK/path build failed:", e)
            sys.print_exception(e)
            return
        try:
            aio.create_task(self._delayed_send(reply, 200))
        except Exception as e:
            print("[MeshCore] ACK schedule error:", e)

    async def _delayed_send(self, packet, delay_ms):
        try:
            await aio.sleep_ms(delay_ms)
            await self.badge.lora.send(packet)
        except Exception as e:
            print("[MeshCore] delayed send error:", e)

    def _append_dm(self, pubkey_hex, message):
        thread = self.dm_messages.get(pubkey_hex)
        if thread is None:
            thread = deque([], self.dm_buffer_len)
            self.dm_messages[pubkey_hex] = thread
        thread.append(message)

    def _store_advert(self, packet):
        """Decode an advert and create/update the corresponding contact."""
        decoded = Advert.decode(packet.payload)
        if not decoded:
            return
        contact = contacts.upsert_from_advert(decoded)
        print("[MeshCore] Advert from '{}' ({})".format(
            contact.display_name, contact.short_key))

    def _store_group_message(self, packet, recv_time, rssi, snr):
        """Store a decodable group text in its channel's message history."""
        decoded = GroupText.decode(packet.payload, registry)
        if not decoded:
            return
        channel_id, room_name, sender, text, msg_time = decoded
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

        # F4 is the menu button everywhere except at the main menu, where it opens the analyser
        if self.badge.keyboard.f4():
            if self.mode == MODE_MENU:
                self._set_mode(MODE_ANALYSER)
            else:
                self._set_mode(MODE_MENU)

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
        elif self.mode == MODE_CONTACTS_ALL:
            self._run_contacts_all()
        elif self.mode == MODE_CONTACT_DETAILS:
            self._run_contact_details()
        elif self.mode == MODE_DM_CHAT:
            self._run_dm_chat()
        elif self.mode == MODE_ADVERT:
            self._run_advert()
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
        elif mode == MODE_CHANNEL_ADD:
            self.add_step = "type"
            self.add_kind = None
            self.add_name = ""
            self._build_channel_add()
        elif mode == MODE_CHANNEL_DELETE:
            self._build_channel_delete()
        elif mode == MODE_DM:
            self._build_dm()
        elif mode == MODE_CONTACTS_ALL:
            self._build_contacts_all()
        elif mode == MODE_CONTACT_DETAILS:
            self._build_contact_details()
        elif mode == MODE_DM_CHAT:
            self._build_dm_chat()
        elif mode == MODE_ADVERT:
            self._build_advert()
        elif mode == MODE_ANALYSER:
            self._build_analyser()

    def _content_label(self, text):
        """Create a left-aligned multiline label inside the current page content."""
        label = lvgl.label(self.page.content)
        label.add_style(styles.content_style, 0)
        label.set_width(lvgl.pct(96))
        label.align(lvgl.ALIGN.TOP_LEFT, 8, 6)
        label.set_text(text)
        return label

    def _build_menu(self):
        self.page = PageButBetter()
        self.page.create_infobar(["MeshCore", "Main Menu"])
        self.page.create_content()
        self._content_label(
            "Select a mode:\n"
            "F1  Channels  - browse decoded channel messages\n"
            "F2  Direct Msg - send/read direct messages\n"
            "F3  Advert     - broadcast this node's identity\n"
            "F4  Analyser   - inspect raw packet traffic"
        )
        self.page.create_menubar(["Channels", "Direct", "Advert", "Analyser", "Home"])
        self.page.replace_screen()

    def _refresh_channel_order(self):
        """Build the ordered list of channels: every configured channel, plus any
        channel we have received messages for that isn't in the config."""
        order = list(registry.items())
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
        self.page = PageButBetter();
        self.page.create_infobar(["Channels", "Up/Dn select"])
        self.page.create_content()
        self._chan_labels = []
        self._draw_channel_list()
        self.page.create_menubar(["Open", "Add", "Del", "Menu", "Home"])
        self.page.replace_screen()

    def _render_list(self, rows, sel, empty_text):
        """Render a windowed, highlight-bar selection list of strings.

        Windowing keeps the selected row on screen (scroll-into-view), and the
        selected row gets a filled background bar. Returns the created label
        widgets so the caller can store and later delete them.
        """
        labels = []
        if not self.page or not self.page.content:
            return labels

        if not rows:
            empty = lvgl.label(self.page.content)
            empty.add_style(styles.content_style, 0)
            empty.align(lvgl.ALIGN.TOP_LEFT, 8, 5)
            empty.set_text(empty_text)
            labels.append(empty)
            return labels

        # Determine the visible window, centering the selection when possible.
        max_visible = self.LIST_MAX_VISIBLE
        start = 0
        if len(rows) > max_visible:
            start = max(0, sel - max_visible // 2)
            start = min(start, len(rows) - max_visible)
        end = min(start + max_visible, len(rows))

        y = 4
        for i in range(start, end):
            label = lvgl.label(self.page.content)
            label.add_style(styles.content_style, 0)
            label.set_width(lvgl.pct(100))
            label.set_style_pad_top(2, 0)
            label.set_style_pad_bottom(2, 0)
            label.set_style_pad_left(8, 0)
            label.set_text(rows[i])
            if i == sel:
                # Highlight bar: filled background with inverted text.
                label.set_style_bg_color(styles.lcd_color_fg, 0)
                label.set_style_bg_opa(255, 0)
                label.set_style_text_color(styles.lcd_color_bg, 0)
            label.align(lvgl.ALIGN.TOP_LEFT, 0, y)
            labels.append(label)
            y += self.LIST_ROW_PX
        return labels

    def _draw_channel_list(self):
        """Render the channel selection list."""
        for label in self._chan_labels:
            label.delete()
        rows = ["{}   {}".format(name, count) for name, count in self._channel_rows()]
        self._chan_labels = self._render_list(
            rows, self.channel_sel, "(no channels configured)")

    def _build_channel_view(self):
        cid = self.active_channel_id
        name = self.channel_names.get(cid) or self._name_for(cid)
        self.page = PageButBetter()
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
        ch = registry.get(channel_id)
        return ch.name if ch else channel_id[:8]

    def _build_placeholder(self, title, body):
        self.page = PageButBetter()
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
        self.page = PageButBetter()
        self.page.create_infobar(["Add Channel", "Choose type"])
        self.page.create_content()
        self._content_label(
            "F1  # Channel  - public, key derived from the name\n"
            "F2  Private    - enter name and key separately"
        )
        self.page.create_menubar(["# Chan", "Private", "", "Menu", "Home"])
        self.page.replace_screen()

    def _build_text_input(self, prompt, default="", char_limit=0):
        self.page = PageButBetter()
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
        if registry.add(Channel(key_hex, name)):
            self._persist_channel(key_hex, name)
            print("[MeshCore] Added # channel '{}' key={}".format(name, key_hex))
            self._finish_add(key_hex)
        else:
            self.page.infobar_right.set_text("Channel exists")

    def _commit_private(self, key_hex):
        if registry.add(Channel(key_hex, self.add_name)):
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
        self.page = PageButBetter()
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
        registry.remove(cid)
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
        elif self.badge.keyboard.f4():
            self._set_mode(MODE_ANALYSER)

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
        channel = registry.get(self.active_channel_id)
        if channel is None:
            self.page.infobar_right.set_text("Unknown channel")
            return
        try:
            packet = GroupText(self.identity, channel, message).to_bytes()
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

    # ------------------------------------------------------------------
    # Contacts / Direct Messages
    # ------------------------------------------------------------------
    def _contact_rows(self):
        """Format the active contact order into display strings (star + name)."""
        rows = []
        for c in self._contact_order:
            star = "* " if c.favorite else "  "
            rows.append("{}{}".format(star, c.display_name))
        return rows

    def _draw_contact_list(self, empty_text):
        for label in self._contact_labels:
            label.delete()
        self._contact_labels = self._render_list(
            self._contact_rows(), self.contact_sel, empty_text)

    def _set_contact_order(self, order):
        self._contact_order = order
        if self.contact_sel >= len(order):
            self.contact_sel = max(0, len(order) - 1)

    def _selected_contact(self):
        if 0 <= self.contact_sel < len(self._contact_order):
            return self._contact_order[self.contact_sel]
        return None

    def _build_dm(self):
        """DM landing screen: the user's favorite contacts."""
        self._set_contact_order(contacts.favorites())
        self.page = PageButBetter()
        self.page.create_infobar(["Direct Messages", "Favorites"])
        self.page.create_content()
        self._contact_labels = []
        self._draw_contact_list("(no favorites - F2 for all contacts)")
        self.page.create_menubar(["Open", "Contacts", "", "Menu", "Home"])
        self.page.replace_screen()

    def _run_dm(self):
        key = self.badge.keyboard.read_key()
        if key == self.badge.keyboard.UP:
            self.contact_sel = max(0, self.contact_sel - 1)
            self._draw_contact_list("(no favorites - F2 for all contacts)")
        elif key == self.badge.keyboard.DOWN:
            self.contact_sel = min(
                max(0, len(self._contact_order) - 1), self.contact_sel + 1)
            self._draw_contact_list("(no favorites - F2 for all contacts)")

        if self.badge.keyboard.f1():  # Open chat with the selected favorite
            c = self._selected_contact()
            if c:
                self.active_dm_key = c.pubkey_hex
                self._set_mode(MODE_DM_CHAT)
        elif self.badge.keyboard.f2():  # All contacts
            self.contact_sel = 0
            self._set_mode(MODE_CONTACTS_ALL)

    def _build_contacts_all(self):
        """All known contacts (favorites first)."""
        self._set_contact_order(contacts.all())
        self.page = PageButBetter()
        self.page.create_infobar(["All Contacts", "{} known".format(len(contacts))])
        self.page.create_content()
        self._contact_labels = []
        self._draw_contact_list("(no contacts yet)")
        self.page.create_menubar(["Details", "Back", "", "Menu", "Home"])
        self.page.replace_screen()

    def _run_contacts_all(self):
        key = self.badge.keyboard.read_key()
        if key == self.badge.keyboard.UP:
            self.contact_sel = max(0, self.contact_sel - 1)
            self._draw_contact_list("(no contacts yet)")
        elif key == self.badge.keyboard.DOWN:
            self.contact_sel = min(
                max(0, len(self._contact_order) - 1), self.contact_sel + 1)
            self._draw_contact_list("(no contacts yet)")

        if self.badge.keyboard.f1():  # Details
            c = self._selected_contact()
            if c:
                self.active_contact_key = c.pubkey_hex
                self._set_mode(MODE_CONTACT_DETAILS)
        elif self.badge.keyboard.f2():  # Back to favorites landing
            self.contact_sel = 0
            self._set_mode(MODE_DM)

    def _build_contact_details(self):
        c = contacts.get(self.active_contact_key)
        self.page = PageButBetter()
        self.page.create_infobar(["Contact", ""])
        self.page.create_content()
        if not c:
            self._content_label("Contact no longer available.")
            self.page.create_menubar(["", "", "Back", "Menu", "Home"])
            self.page.replace_screen()
            return
        if c.last_seen:
            t = time.localtime(c.last_seen)
            seen = "{:04d}-{:02d}-{:02d} {:02d}:{:02d}".format(
                t[0], t[1], t[2], t[3], t[4])
        else:
            seen = "never"
        lines = [
            "Name: {}".format(c.display_name),
            "Key:  {}".format(c.pubkey_hex[:32]),
            "      {}".format(c.pubkey_hex[32:]),
            "Favorite: {}".format("yes" if c.favorite else "no"),
            "Flags: 0x{:02x}".format(c.flags),
            "Last seen: {}".format(seen),
        ]
        self._content_label("\n".join(lines))
        fav_label = "Unfav" if c.favorite else "Fav"
        self.page.create_menubar([fav_label, "Delete", "Back", "Menu", "Home"])
        self.page.replace_screen()

    def _run_contact_details(self):
        if self.badge.keyboard.escape_pressed or self.badge.keyboard.f3():  # Back
            self._set_mode(MODE_CONTACTS_ALL)
            return
        if self.badge.keyboard.f1():  # Toggle favorite
            c = contacts.toggle_favorite(self.active_contact_key)
            if c:
                if c.favorite:
                    self._persist_favorite(c)
                else:
                    self._unpersist_favorite(c.pubkey_hex)
                self._build_contact_details()  # Refresh state + button label
            return
        if self.badge.keyboard.f2():  # Delete
            key = self.active_contact_key
            c = contacts.get(key)
            was_fav = c.favorite if c else False
            contacts.remove(key)
            if was_fav:
                self._unpersist_favorite(key)
            self.active_contact_key = None
            self.contact_sel = 0
            self._set_mode(MODE_CONTACTS_ALL)

    # ------------------------------------------------------------------
    # Direct-message chat
    # ------------------------------------------------------------------
    def _build_dm_chat(self):
        c = contacts.get(self.active_dm_key)
        name = c.display_name if c else (self.active_dm_key or "?")[:8]
        self.page = PageButBetter()
        self.page.create_infobar(["DM: {}".format(name), ""])
        self.page.create_content()
        self.page.add_message_rows(1, left_width=90)
        self._view_msg_count = -1
        self.compose_active = False
        self._refresh_dm_view()
        self.page.create_menubar(["Send", "", "Back", "Menu", "Home"])
        self.page.replace_screen()

    def _refresh_dm_view(self):
        """Re-populate the DM thread."""
        msgs = self.dm_messages.get(self.active_dm_key)
        count = len(msgs) if msgs else 0

        has_sending = False
        if msgs:
            for m in msgs:
                if m.outgoing and not m.delivered and (time.time() - m.msg_time <= 15):
                    has_sending = True
                    break

        if count == self._view_msg_count and not has_sending:
            return

        self._view_msg_count = count
        if not msgs:
            self.page.populate_message_rows([("", "No messages yet.")])
            return
        display = []
        for m in msgs:
            t = time.localtime(m.recv_time)
            time_str = "{:02d}:{:02d}".format(t[3], t[4])
            who = "me" if m.outgoing else "them"

            if m.outgoing:
                if m.delivered:
                    status = ("Delivered", styles.lvg_color_green, styles.hackaday_white)
                elif time.time() - m.msg_time > 15:
                    status = ("Failed", styles.lvg_color_red, styles.hackaday_white)
                else:
                    status = ("Sending", styles.hackaday_grey, styles.hackaday_white)
                display.append((time_str, "{}: {}".format(who, m.text), status))
            else:
                display.append((time_str, "{}: {}".format(who, m.text)))
        self.page.populate_message_rows(display)

    def _run_dm_chat(self):
        if not self.compose_active and self.badge.keyboard.f1():  # Compose
            self.page.create_text_box()
            self.compose_active = True

        if self.compose_active:
            key, text = self.page.text_box_type(self.badge.keyboard)
            self.page.infobar_right.set_text(
                "{}/{}  F1 to send".format(len(text), MAX_MESSAGE_LEN))
            if self.badge.keyboard.escape_pressed:
                self.page.close_text_box()
                self.compose_active = False
            if self.badge.keyboard.f1():  # Send
                if self.page.text_box.get_text():
                    message_text = self.page.close_text_box()
                    self._send_direct_txt(message_text)
                    self.compose_active = False
            return

        if self.badge.keyboard.f3():  # Back to favorites
            self._set_mode(MODE_DM)
            return
        # Keep the view in sync as new messages arrive while open.
        self._refresh_dm_view()
        key = self.badge.keyboard.read_key()
        scroll = 13
        if self.badge.keyboard.shift_pressed:
            scroll *= 5
        if key == self.badge.keyboard.UP:
            self.page.scroll_up(scroll)
        elif key == self.badge.keyboard.DOWN:
            self.page.scroll_down(scroll)

    def _send_direct_txt(self, message):
        if not self.identity:
            self.page.infobar_right.set_text("No identity")
            return
        c = contacts.get(self.active_dm_key)
        if c is None:
            self.page.infobar_right.set_text("Unknown contact")
            return
        try:
            packet_obj = DirectText(self.identity, c, message)
            packet = packet_obj.to_bytes()
            expected_ack = packet_obj.expected_ack
        except Exception as e:
            import sys
            print("[MeshCore] DM packet build failed:", e)
            sys.print_exception(e)
            self.page.infobar_right.set_text("Build error")
            return
        print("[MeshCore] Sending DM packet:", packet.hex())
        self._transmit(packet)
        now = int(time.time())
        self._append_dm(self.active_dm_key, DirectMessage(now, now, True, message, expected_ack))

    # ------------------------------------------------------------------
    # Advert flow
    # ------------------------------------------------------------------
    def _build_advert(self):
        self.page = PageButBetter()
        self.page.create_infobar(["Advert", ""])
        self.page.create_content()
        if not self.identity:
            self._content_label(
                "Node identity unavailable.\nCannot build adverts."
            )
            self.page.create_menubar(["", "", "", "Menu", "Home"])
            self.page.replace_screen()
            return
        pub_hex = binascii.hexlify(self.identity.public_key).decode()
        lines = [
            "Node: {}".format(self.identity.name),
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
        if not self.identity:
            return
        if self.badge.keyboard.f1():
            self._send_advert(RouteType.DIRECT, "Direct")
        elif self.badge.keyboard.f2():
            self._send_advert(RouteType.FLOOD, "Flood")

    def _send_advert(self, route_type, label):
        ts = int(time.time())
        try:
            packet = Advert(self.identity, route_type=route_type, timestamp=ts).to_bytes()
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

    # ------------------------------------------------------------------
    # Packet Analyser
    # ------------------------------------------------------------------
    # Map payload type -> (label, bg_color, fg_color)
    _PKT_TYPE_COLORS = None

    @staticmethod
    def _pkt_type_colors():
        if MeshcoreApp._PKT_TYPE_COLORS is None:
            MeshcoreApp._PKT_TYPE_COLORS = {
                PayloadType.ADVERT:   ("ADVERT",  styles.pkt_color_advert,  styles.hackaday_white),
                PayloadType.GRP_TXT:  ("GRP_TXT", styles.pkt_color_grp,     styles.hackaday_white),
                PayloadType.GRP_DATA: ("GRP_DAT", styles.pkt_color_grp,     styles.hackaday_white),
                PayloadType.TXT_MSG:  ("TXT_MSG", styles.pkt_color_txt,     styles.hackaday_white),
                PayloadType.ACK:      ("ACK",     styles.pkt_color_ack,     styles.hackaday_white),
                PayloadType.PATH:     ("PATH",    styles.pkt_color_path,    styles.hackaday_white),
            }
        return MeshcoreApp._PKT_TYPE_COLORS

    def _analyser_pkt_info(self, packet):
        """Return a short context string for the analyser row."""
        if packet.payload_type == PayloadType.ADVERT:
            from net.meshcore.packet.advert import Advert as AdvPkt
            dec = AdvPkt.decode(packet.payload)
            if dec:
                return dec.name or dec.pubkey_hex[:8]
            return "advert"
        elif packet.payload_type in (PayloadType.GRP_TXT, PayloadType.GRP_DATA):
            return "group msg"
        elif packet.payload_type == PayloadType.TXT_MSG:
            if len(packet.payload) >= 2:
                return "dst:{:02x} src:{:02x}".format(packet.payload[0], packet.payload[1])
            return "dm"
        elif packet.payload_type == PayloadType.ACK:
            if len(packet.payload) >= 4:
                return packet.payload[:4].hex()
            return "ack"
        elif packet.payload_type == PayloadType.PATH:
            return "hops:{}".format(packet.hop_count)
        return "?"

    def _build_analyser(self):
        self.page = PageButBetter()
        self.page.create_infobar(["Packet Analyser", "{} pkts".format(len(self.packet_queue))])
        self.page.create_content()
        self._analyser_paused = False
        self._analyser_last_count = -1
        self._analyser_rows = []
        self._refresh_analyser()
        self.page.create_menubar(["", "Pause", "Clear", "Menu", "Home"])
        self.page.replace_screen()

    def _refresh_analyser(self):
        count = len(self.packet_queue)
        if count == self._analyser_last_count:
            return
        self._analyser_last_count = count
        self.page.infobar_right.set_text("{} pkts".format(count))

        # Clean up old row objects
        for row in self._analyser_rows:
            row.delete()
        self._analyser_rows = []

        if not self.packet_queue:
            lbl = lvgl.label(self.page.content)
            lbl.add_style(styles.content_style, 0)
            lbl.set_text("No packets received yet.")
            lbl.align(lvgl.ALIGN.TOP_LEFT, 8, 6)
            self._analyser_rows.append(lbl)
            return

        # Create a scrollable container
        container = lvgl.obj(self.page.content)
        container.add_style(styles.content_style, 0)
        container.set_width(lvgl.pct(100))
        container.set_height(lvgl.pct(100))
        container.set_flex_flow(lvgl.FLEX_FLOW.COLUMN)
        container.set_style_pad_left(2, 0)
        container.set_style_pad_row(1, 0)
        container.set_scrollbar_mode(lvgl.SCROLLBAR_MODE.AUTO)
        self._analyser_container = container
        self._analyser_rows.append(container)

        type_colors = self._pkt_type_colors()

        for recv_time, frame, rssi, snr in self.packet_queue:
            packet = Packet.parse(frame)

            # Row container
            row = lvgl.obj(container)
            row.add_style(styles.content_style, 0)
            row.set_width(lvgl.pct(100))
            row.set_height(lvgl.SIZE_CONTENT)
            row.set_style_min_height(14, 0)
            row.set_style_pad_all(0, 0)
            row.set_style_border_width(0, 0)

            x = 0

            # Time
            t = time.localtime(recv_time)
            time_str = "{:02d}:{:02d}:{:02d}".format(t[3], t[4], t[5])
            time_lbl = lvgl.label(row)
            time_lbl.set_text(time_str)
            time_lbl.set_style_text_color(styles.pkt_color_rssi, 0)
            time_lbl.align(lvgl.ALIGN.TOP_LEFT, x, 0)
            x += 58

            # Type badge
            if packet:
                tc = type_colors.get(packet.payload_type)
                if tc:
                    type_text, type_bg, type_fg = tc
                else:
                    type_text = "T{}".format(packet.payload_type)
                    type_bg = styles.pkt_color_unknown
                    type_fg = styles.hackaday_white
            else:
                type_text = "ERR"
                type_bg = styles.pkt_color_unknown
                type_fg = styles.hackaday_white

            type_lbl = lvgl.label(row)
            type_lbl.set_text(type_text)
            type_lbl.set_style_bg_opa(255, 0)
            type_lbl.set_style_bg_color(type_bg, 0)
            type_lbl.set_style_text_color(type_fg, 0)
            type_lbl.set_style_pad_left(3, 0)
            type_lbl.set_style_pad_right(3, 0)
            type_lbl.set_style_pad_top(1, 0)
            type_lbl.set_style_pad_bottom(1, 0)
            type_lbl.align(lvgl.ALIGN.TOP_LEFT, x, 0)
            x += 65

            # Route
            if packet:
                is_flood = packet.route_type in (RouteType.FLOOD, RouteType.TRANSPORT_FLOOD)
                route_text = "FLD" if is_flood else "DIR"
                route_color = styles.pkt_color_route_fld if is_flood else styles.pkt_color_route_dir
            else:
                route_text = "?"
                route_color = styles.pkt_color_rssi

            route_lbl = lvgl.label(row)
            route_lbl.set_text(route_text)
            route_lbl.set_style_text_color(route_color, 0)
            route_lbl.align(lvgl.ALIGN.TOP_LEFT, x, 0)
            x += 30

            # RSSI
            rssi_lbl = lvgl.label(row)
            rssi_lbl.set_text("{}dBm".format(rssi))
            rssi_lbl.set_style_text_color(styles.pkt_color_rssi, 0)
            rssi_lbl.align(lvgl.ALIGN.TOP_LEFT, x, 0)
            x += 55

            # Info
            if packet:
                info = self._analyser_pkt_info(packet)
            else:
                info = "parse failed"
            info_lbl = lvgl.label(row)
            info_lbl.set_text(info)
            info_lbl.align(lvgl.ALIGN.TOP_LEFT, x, 0)

        # Scroll to bottom
        container.update_layout()
        dy = container.get_scroll_bottom()
        container.scroll_by_bounded(0, -1 * dy, False)

    def _run_analyser(self):
        if self.badge.keyboard.f1():  # Details TBD
            # self._set_mode(MODE_ADVERT)
            return
        if self.badge.keyboard.f2():  # Pause / Resume
            self._analyser_paused = not self._analyser_paused
            label = "Resume" if self._analyser_paused else "Pause"
            self.page.set_menubar_button_label(1, label)
            return
        if self.badge.keyboard.f3():  # Clear
            self.packet_queue = deque([], PACKET_BUFFER_LEN)
            self._analyser_last_count = -1
            self._refresh_analyser()
            return
        key = self.badge.keyboard.read_key()
        if hasattr(self, '_analyser_container'):
            scroll = 13
            if self.badge.keyboard.shift_pressed:
                scroll *= 5
            if key == self.badge.keyboard.UP:
                self._analyser_container.scroll_by_bounded(0, scroll, False)
            elif key == self.badge.keyboard.DOWN:
                self._analyser_container.scroll_by_bounded(0, -1 * scroll, False)
        if not self._analyser_paused:
            self._refresh_analyser()
