"""Contacts: other MeshCore nodes we've heard adverts from.

A contact is keyed by its Ed25519 public key (hex). Adverts auto-populate the
book; the user can favorite contacts (persisted) and delete them. Non-favorite
contacts are evicted oldest-first once the book exceeds MAX_CONTACTS; favorites
are never evicted automatically.
"""

# Maximum number of contacts kept in memory; favorites don't count against
# eviction (they are always retained).
MAX_CONTACTS = 64


class Contact:
    def __init__(self, pubkey_hex, name="", flags=0, favorite=False, last_seen=0):
        self.pubkey_hex = pubkey_hex
        self.name = name
        self.flags = flags
        self.favorite = favorite
        self.last_seen = last_seen

    @property
    def display_name(self):
        return self.name or self.pubkey_hex[:12]

    @property
    def short_key(self):
        return self.pubkey_hex[:12]

    def __repr__(self):
        return "Contact({!r}, fav={})".format(self.display_name, self.favorite)


class ContactBook:
    """In-memory set of contacts keyed by pubkey hex."""

    def __init__(self):
        self._by_key = {}

    # -- ingest ----------------------------------------------------------
    def upsert_from_advert(self, decoded):
        """Create or refresh a contact from a DecodedAdvert. Returns the Contact."""
        c = self._by_key.get(decoded.pubkey_hex)
        if c:
            if decoded.name:
                c.name = decoded.name
            c.flags = decoded.flags
            c.last_seen = decoded.timestamp
            return c
        c = Contact(decoded.pubkey_hex, decoded.name, decoded.flags, False,
                    decoded.timestamp)
        self._by_key[c.pubkey_hex] = c
        self._evict()
        return c

    def load_favorite(self, pubkey_hex, name):
        """Seed a persisted favorite at startup (no last_seen yet)."""
        c = self._by_key.get(pubkey_hex)
        if c:
            c.favorite = True
            if name:
                c.name = name
        else:
            self._by_key[pubkey_hex] = Contact(pubkey_hex, name, 0, True, 0)

    # -- mutation --------------------------------------------------------
    def toggle_favorite(self, pubkey_hex):
        """Flip a contact's favorite flag. Returns the Contact, or None."""
        c = self._by_key.get(pubkey_hex)
        if not c:
            return None
        c.favorite = not c.favorite
        return c

    def remove(self, pubkey_hex):
        """Delete a contact. Returns its name, or None if absent."""
        c = self._by_key.pop(pubkey_hex, None)
        return c.name if c else None

    # -- queries ---------------------------------------------------------
    def get(self, pubkey_hex):
        return self._by_key.get(pubkey_hex)

    def favorites(self):
        favs = [c for c in self._by_key.values() if c.favorite]
        favs.sort(key=lambda c: c.display_name.lower())
        return favs

    def all(self):
        # Favorites first, then by name.
        items = list(self._by_key.values())
        items.sort(key=lambda c: (0 if c.favorite else 1, c.display_name.lower()))
        return items

    def __len__(self):
        return len(self._by_key)

    # -- internal --------------------------------------------------------
    def _evict(self):
        if len(self._by_key) <= MAX_CONTACTS:
            return
        non_fav = [c for c in self._by_key.values() if not c.favorite]
        non_fav.sort(key=lambda c: c.last_seen)  # oldest first
        overflow = len(self._by_key) - MAX_CONTACTS
        for c in non_fav[:overflow]:
            self._by_key.pop(c.pubkey_hex, None)


# Shared working contact book used by the app and the advert handler.
contacts = ContactBook()
