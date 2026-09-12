# wcopy-nfc

A reverse-engineered Python driver for the cheap USB "smart card copier"
NFC reader/writers sold under names like **wCopy**, **NSCCN**, and
**rfcardwriter.com** (USB ID `0416:b030`). These devices have no PC/SC,
CCID, or libnfc-compatible interface and no Linux support at all from the
vendor — just a closed-source Windows GUI. This project exists so nobody
else has to sit down with Wireshark/USBPcap and reverse-engineer the USB
protocol from scratch to use one of these from Linux (or from any
non-Windows, non-vendor-GUI context) — the full protocol write-up lives
in [`src/wcopy_nfc/reader.py`](src/wcopy_nfc/reader.py)'s module
docstring, and the driver itself is a small, dependency-light library you
can build on.

**This is unofficial, reverse-engineered software with no affiliation
to, and no support from, the manufacturer.** Use at your own risk — see
[Caveats](#caveats-and-known-limitations) below, and in particular be
aware that keys written by this tool are *not* what the vendor's own
Windows software expects, so switching a tag back and forth between the
two isn't guaranteed to work smoothly.

## Supported devices

| USB ID | Marketed as | Notes |
|---|---|---|
| `0416:b030` | wCopy Smart Reader / NSCCN / rfcardwriter.com | Confirmed working — this is the device the protocol was reverse-engineered from. |

Only this exact USB ID has been confirmed. The chip vendor string that
shows up (`Winbond Electronics Corp.`) is the silicon vendor, not the
brand printed on the device — these cheap copier gadgets get rebadged
under many storefront names, so a device sold under a different name may
well be this same hardware.

### How to check if your device is compatible

1. Plug the reader in and run:
   ```
   lsusb
   ```
   Look for a line containing `ID 0416:b030`. If you see that exact ID,
   your device is confirmed-compatible — skip to
   [Installation](#installation).

2. If you see a **different** VID:PID but the device is sold under a
   similar name (wCopy/NSCCN/rfcardwriter.com or a visually identical
   clone), it might still be this same hardware rebadged. To find out:
   ```
   lsusb -v -d <vid>:<pid>
   ```
   and check that it exposes **two interfaces**:
   - Interface 0: HID class (`bInterfaceClass 3`) — this is the one this
     driver talks to.
   - Interface 1: Mass Storage class (`bInterfaceClass 8`) — this is a
     small auto-mounting "USB DISK" partition that ships the Windows GUI
     installer. This driver never touches it.

   That two-interface shape (HID + mass storage, no CCID/PC-SC
   descriptor anywhere) is the fingerprint of this whole device family.
   If your device matches it but has a different VID:PID, try pointing
   this driver at it (`wcopy_nfc.reader.VENDOR_ID` /
   `wcopy_nfc.reader.PRODUCT_ID`, or open a `usb.core.find()` call
   yourself) — the framing and command set may well be identical.

3. If you want to be sure before trusting any of your tags to it, the
   most reliable check is to capture real USB traffic from the vendor's
   Windows GUI (via USBPcap + Wireshark, or `usbmon` under a Windows VM)
   while it writes a tag, and compare the frame shape against the layout
   documented at the top of
   [`reader.py`](src/wcopy_nfc/reader.py): outgoing HID reports start
   with marker byte `0x01` and end with terminator `0xFE`; incoming ones
   start with `0x02` and end with `0xFD`. If your capture matches that
   shape, this driver should work as-is or with only minor changes.

**Found a working variant with a different USB ID?** Please open an
issue (or a PR against the table above) with your `lsusb -v` output and,
ideally, a short USBPcap capture — that's exactly the kind of
contribution this project is meant to collect.

### Supported tags

The devices in this family write **Mifare Classic 1K** cards (or
Classic-compatible "magic"/UID-changeable clones commonly sold for these
copier gadgets) — not NTAG/Ultralight, and not MAD-formatted. Any
Mifare Classic 1K tag should work.

## Installation

```
pip install .
```
or, for local development:
```
pip install -e .
```

### Linux USB permissions

By default only root can open the reader's raw USB device. Install the
provided udev rule so a normal user (in the `plugdev` group) can:

```
sudo cp udev/99-wcopy-nfc.rules /etc/udev/rules.d/
sudo udevadm control --reload-rules
sudo udevadm trigger
```

Then unplug and replug the reader (or reboot) for the new permissions to
take effect.

## Quick start

```python
from wcopy_nfc import WCopyReader, ndef

with WCopyReader() as reader:
    tag = reader.poll_for_tag(timeout_s=10)
    print("UID:", tag.uid.hex())

    payload = ndef.build_uri_tlv("https://example.com")
    reader.write_data(tag.uid, payload, verify=True)

    raw = reader.read_ndef(tag.uid)
    print("Wrote:", ndef.parse_uri_tlv(raw))
```

See [`examples/`](examples/) for standalone scripts:
- [`poll.py`](examples/poll.py) — detect a tag and print its UID.
- [`write_uri.py`](examples/write_uri.py) — write a URL to a tag and
  verify it.
- [`read_uri.py`](examples/read_uri.py) — read back whatever URL is on a
  tag.

## API overview

- **`WCopyReader`** — one instance per physical reader. Use as a context
  manager (`with WCopyReader() as reader:`) or call `.close()` yourself.
  - `poll_for_tag(timeout_s=3.0) -> TagInfo` — waits for a tag, raises
    `NoTagPresentError` on timeout.
  - `write_data(uid, payload, verify=True)` — writes raw bytes starting
    at block 4 (sector 1), authenticating and best-effort updating each
    sector's trailer as it goes. Never touches sector 0.
  - `read_data(uid, num_blocks)` — reads a known number of data blocks
    back.
  - `read_ndef(uid, max_blocks=64)` — reads exactly as many blocks as a
    previously written NDEF TLV needs, without knowing the length ahead
    of time.
- **`ndef`** module — `build_uri_tlv(url) -> bytes` and
  `parse_uri_tlv(data) -> str` encode/decode a bare NDEF URI record the
  way this device's own tool writes it.
- Exceptions: `WCopyError` (base), `NoTagPresentError`,
  `AuthenticationError` — all importable from `wcopy_nfc`.

`on_warning` can be passed to `WCopyReader(on_warning=...)` to redirect
non-fatal notices (currently just best-effort trailer-write failures)
away from `print()` — useful if your application owns the terminal (e.g.
a `curses` UI) and a raw `print()` would corrupt its display.

## Caveats and known limitations

- **Sector 0 (blocks 0-3) is never read or written.** It holds the
  UID/manufacturer block.
- **Trailer writes are best-effort.** A sector's trailer (its key/access
  bits) can fail to update even when the sector's actual data write
  succeeds — some tags' access-bit configuration only accepts Key B for
  the trailer even though Key A works fine for data blocks, and some
  trailers are simply locked. Either way, the NDEF data itself remains a
  perfectly valid, phone-readable tag; only this driver's own
  "remember which key unlocks this tag next time" bookkeeping is
  affected.
- **Authentication tries 8 known keys** (factory default, NXP's
  AN10787 MAD/NDEF default, several other long-published Mifare Classic
  defaults, and this driver's own post-write key) against both Key A and
  Key B commands, matching what the vendor's own tool does. A tag locked
  with a key outside this list won't authenticate.
- **RF session drops.** These tags/readers can drop their RF session
  (subsequent auth failing even with a previously-good key) after a
  burst of failed authentication attempts, such as probing a locked
  trailer. The driver recovers by re-running the full anticollision
  sequence (`_reselect`) before each new sector, and retries once on a
  failed read within a sector.
- Status code `0x14` from the underlying PN532-style controller means
  "Mifare authentication error."

## License

MIT — see [LICENSE](LICENSE).
