"""Low-level driver for the "wCopy Smart Reader" USB NFC reader/writer
(USB ID 0416:b030, sold under the NSCCN/wCopy/rfcardwriter.com brand — see
the project README for the full list of known-compatible devices and how
to identify one).

This device has no PC/SC, CCID, or libnfc-compatible interface — it's a
plain HID device (bInterfaceClass 3) that wraps a Mifare-Classic-capable
NFC controller (PN532-style command set: TFI 0xD4 host->chip, 0xD5
chip->host) inside a small custom framing. There is no vendor SDK, driver,
or protocol documentation for Linux (or at all, beyond a closed-source
Windows GUI) — everything below was reverse-engineered from a USBPcap
capture of that Windows tool writing real NDEF URI tags, byte-checked
against the exact strings written until every field's meaning and the
frame checksum were independently confirmed.

HID report framing (both directions are 64-byte HID reports, but the two
directions are NOT laid out the same way — host->device reports carry an
extra 4-byte marker and an explicit PN532-length byte that device->host
reports don't):

  Host->device (OUT, EP 0x02), marker byte 0x01:
    byte 0      : 0x01
    byte 1      : total meaningful length of this report, INCLUDING the
                  trailing checksum and terminator bytes (everything after
                  is zero padding out to 64 bytes)
    bytes 2-3   : a 2-byte running sequence counter (little-endian). Not
                  validated by the device as far as observed — any
                  incrementing value works — but incremented here to match
                  real traffic.
    bytes 4-7   : 0xFF 0x00 0x00 0x00 (fixed marker).
    byte 8      : PN532 frame LEN — the number of bytes from TFI through
                  the last data byte, inclusive.
    next LEN B  : the PN532-style body: TFI (0xD4, host->chip), command,
                  then command-specific data.
    next byte   : checksum, see below.
    next byte   : terminator, 0xFE.
    remainder   : zero padding to 64 bytes.

  Device->host (IN, EP 0x81), marker byte 0x02:
    byte 0      : 0x02
    byte 1      : total meaningful length (same convention as above).
    bytes 2-3   : sequence counter, echoing/continuing the host's.
    byte 4      : the PN532-style body starts immediately here — no 4-byte
                  marker and no separate length byte the way host->device
                  reports have: TFI (0xD5, chip->host), command, data.
    byte (total_len - 2) : checksum, see below.
    byte (total_len - 1) : terminator, 0xFD.
    remainder   : zero padding to 64 bytes.

Checksum (verified against 260 real write-command frames, and separately
against real InListPassiveTarget/InDataExchange responses, with zero
mismatches either way): checksum = (T - sum(bytes[1 : end_of_body])) &
0xFF, i.e. sum(everything from the length byte through the last body
byte) plus the checksum byte itself always equals T mod 256, where T is
that direction's OWN terminator byte value (0xFE for host->device, 0xFD
for device->host) — the vendor evidently seeded each direction's running
checksum accumulator with its own terminator constant rather than 0.
Assuming both directions shared one checksum scheme (and one frame
layout) was an early mistake here that made every real tag response look
malformed and get silently discarded, surfacing as a false "no tag
detected" even though the tag was being read fine.

Tag protocol: despite being marketed as an "NFC" reader/writer, the tags
used are Mifare Classic 1K (or Classic-compatible "magic"/UID-changeable
clones popular for these cheap copier gadgets) addressed in 16-byte
blocks/4-block sectors — NOT NTAG/Ultralight 4-byte pages, and NOT MAD
(Mifare Application Directory) formatted. This driver writes a bare NDEF
message starting at block 4 (sector 1), skipping sector 0 (blocks 0-3)
entirely — sector 0 holds the UID/manufacturer block, which this module
also never touches. Each sector after sector 0 needs, in order:
  1. Authenticate (Mifare command 0x60/0x61, Auth-with-KeyA/KeyB) for that
     sector, using whichever of the known keys currently unlocks it.
  2. Write each of that sector's 3 data blocks (16 bytes each) via
     COMPATIBILITY_WRITE (0xA0) — this device's firmware treats it as a
     genuine 16-byte/whole-block write, not the official Mifare-Classic
     spec's "only the first 4 bytes matter" compatibility semantics.
  3. Write that sector's trailer block (block 4n+3) via COMPATIBILITY_WRITE
     to: KeyA=WCOPY_KEY (6B) + AccessBits/GPB (7F 07 88 40) + KeyB=all-FF
     (6B) — the same fixed value the vendor tool always uses. Writing this
     changes the sector's key from whatever it was to WCOPY_KEY, which is
     why a tag already written by this tool needs WCOPY_KEY, not the
     factory default, to authenticate the next time. On some tags the
     trailer write itself can fail (a locked/unwritable trailer, or an
     access-bit configuration that only accepts Key B for the trailer
     even though Key A already worked for the data blocks) without that
     affecting the NDEF data already written, which remains a perfectly
     valid, phone-readable tag — see _try_write_trailer.
"""

from __future__ import annotations

import struct
import time
from dataclasses import dataclass
from typing import Callable

import usb.core
import usb.util

VENDOR_ID = 0x0416
PRODUCT_ID = 0xB030

EP_OUT = 0x02
EP_IN = 0x81
REPORT_SIZE = 64

OUT_MARKER = 0x01
IN_MARKER = 0x02
OUT_TERMINATOR = 0xFE
IN_TERMINATOR = 0xFD

# Mifare Classic block/sector geometry.
BLOCK_SIZE = 16
BLOCKS_PER_SECTOR = 4
FIRST_DATA_SECTOR = 1  # sector 0 (blocks 0-3) is UID/manufacturer — never touched
FIRST_DATA_BLOCK = FIRST_DATA_SECTOR * BLOCKS_PER_SECTOR  # block 4

# The key this driver's own trailer-write leaves behind — a sector already
# written by this tool (or by the vendor's own tool) unlocks with this.
KEY_WCOPY = bytes.fromhex("d3f7d3f7d3f7")
TRAILER_ACCESS_GPB = bytes.fromhex("7f078840")
TRAILER_KEY_B = bytes.fromhex("ffffffffffff")

# Real Mifare Classic tags (and the "magic"/UID-changeable clones these
# cheap copier gadgets use) can turn up already locked with any of a
# handful of long-published default keys, not just one — the vendor's own
# tool visibly runs a small dictionary attack (this exact list, in this
# order, confirmed from a real capture) rather than assuming a single
# known key. KEY_WCOPY is deliberately listed first since it's the most
# likely key for a tag this tool has already written once (a re-write).
KNOWN_KEYS = [
    KEY_WCOPY,
    bytes.fromhex("ffffffffffff"),  # Mifare Classic factory default
    bytes.fromhex("a0a1a2a3a4a5"),  # NXP AN10787 MAD/NDEF sector default
    bytes.fromhex("000000000000"),
    bytes.fromhex("b0b1b2b3b4b5"),
    bytes.fromhex("4d3a99c351dd"),
    bytes.fromhex("1a982c7e459a"),
    bytes.fromhex("aabbccddeeff"),
]

# Mifare/PN532 command bytes used here.
CMD_INLIST_PASSIVE_TARGET = 0x4A
CMD_IN_DATA_EXCHANGE = 0x40
TAG_CMD_AUTH_KEY_A = 0x60
TAG_CMD_AUTH_KEY_B = 0x61
TAG_CMD_COMPATIBILITY_WRITE = 0xA0
TAG_CMD_READ = 0x30

TFI_HOST_TO_CHIP = 0xD4
TFI_CHIP_TO_HOST = 0xD5


class WCopyError(Exception):
    pass


class NoTagPresentError(WCopyError):
    pass


class AuthenticationError(WCopyError):
    pass


@dataclass
class TagInfo:
    uid: bytes
    sens_res: bytes
    sel_res: int


def _checksum(body_from_length_byte: bytes) -> int:
    return (0xFE - (sum(body_from_length_byte) & 0xFF)) & 0xFF


class WCopyReader:
    """Talks to one wCopy Smart Reader (or compatible device — see the
    README) over USB HID."""

    def __init__(self, on_warning: Callable[[str], None] | None = None) -> None:
        """`on_warning` receives non-fatal notices (currently just
        best-effort trailer-write failures — see _try_write_trailer).
        Defaults to `print`; callers with their own display (e.g. a
        curses UI, which owns the whole terminal and would get its
        screen corrupted by a raw print) should pass their own sink
        instead."""
        self._on_warning = on_warning if on_warning is not None else print
        self._seq = 0
        self.device = usb.core.find(idVendor=VENDOR_ID, idProduct=PRODUCT_ID)
        if self.device is None:
            raise WCopyError(
                f"No wCopy reader found (looking for USB ID {VENDOR_ID:04x}:{PRODUCT_ID:04x}). "
                "Is it plugged in?"
            )
        # This device has a second interface (mass storage — the "USB
        # DISK" partition it auto-mounts, see README) that the kernel's
        # usb-storage driver holds onto for as long as that's mounted.
        # set_configuration() operates on the whole device, not just one
        # interface, and fails with EBUSY if another interface is still
        # claimed — so it's deliberately not called here at all: the
        # device already has an active configuration from being plugged
        # in (proven by the mass-storage partition already being
        # mountable), and only interface 0 (HID) needs to be touched.
        try:
            if self.device.is_kernel_driver_active(0):
                self.device.detach_kernel_driver(0)
        except (usb.core.USBError, NotImplementedError):
            pass
        usb.util.claim_interface(self.device, 0)

    def close(self) -> None:
        try:
            usb.util.release_interface(self.device, 0)
            usb.util.dispose_resources(self.device)
        except usb.core.USBError:
            pass

    def __enter__(self) -> "WCopyReader":
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    # -- low-level framing -------------------------------------------------

    def _next_seq(self) -> bytes:
        self._seq = (self._seq + 1) & 0xFFFF
        return struct.pack("<H", self._seq)

    def _send_pn532_body(self, body: bytes) -> None:
        """body is TFI + command + data (no length/checksum) for a
        host->device frame."""
        header = bytes([OUT_MARKER, 0]) + self._next_seq() + bytes([0xFF, 0x00, 0x00, 0x00])
        header += bytes([len(body)]) + body
        total_len = len(header) + 2  # + checksum + terminator
        report = bytearray(header)
        report[1] = total_len
        report.append(_checksum(bytes(report[1:])))
        report.append(OUT_TERMINATOR)
        report.extend(b"\x00" * (REPORT_SIZE - len(report)))
        assert len(report) == REPORT_SIZE
        self.device.write(EP_OUT, bytes(report), timeout=2000)

    def _read_report(self, timeout_ms: int = 2000) -> bytes:
        data = self.device.read(EP_IN, REPORT_SIZE, timeout=timeout_ms)
        return bytes(data)

    def _read_pn532_response(self, timeout_ms: int = 2000, retries: int = 30) -> bytes:
        """Reads IN reports until one carrying a genuine 0x02-marked
        response frame arrives, returning its PN532 body (TFI + command +
        data, checksum/terminator stripped). The device streams a lot of
        unrelated periodic status traffic on this same endpoint, so a
        handful of reports are often skipped before the real response
        shows up.

        Unlike host->device (0x01) reports, device->host (0x02) reports
        have no separate PN532-length byte and no "FF 00 00 00" marker —
        the body starts immediately at byte 4 (right after the 2-byte
        sequence counter) and runs through total_len - 2 (the checksum
        sits at total_len - 2, the terminator at total_len - 1). Their
        checksum's target constant is also 0xFD (their own terminator
        byte), not 0xFE (verified against real captured responses) —
        each direction's checksum targets its own terminator's value.
        """
        last_err: Exception | None = None
        for _ in range(retries):
            try:
                report = self._read_report(timeout_ms=timeout_ms)
            except usb.core.USBError as e:
                last_err = e
                continue
            if len(report) < 6 or report[0] != IN_MARKER:
                continue
            total_len = report[1]
            if total_len < 6 or total_len > len(report):
                continue
            body = report[4 : total_len - 2]
            if not body or body[0] != TFI_CHIP_TO_HOST:
                continue
            return body
        raise WCopyError(f"No response from reader" + (f" ({last_err})" if last_err else ""))

    def _in_data_exchange(self, tag_body: bytes, timeout_ms: int = 2000) -> bytes:
        """Sends InDataExchange(target=1, <tag_body>) and returns the tag
        command's response bytes (status byte + any data), after checking
        the status byte is 0x00 (success)."""
        self._send_pn532_body(bytes([TFI_HOST_TO_CHIP, CMD_IN_DATA_EXCHANGE, 0x01]) + tag_body)
        resp = self._read_pn532_response(timeout_ms=timeout_ms)
        # resp = D5, 0x41, status, data...
        if len(resp) < 3 or resp[1] != CMD_IN_DATA_EXCHANGE + 1:
            raise WCopyError(f"Unexpected response to InDataExchange: {resp.hex()}")
        status = resp[2]
        if status != 0x00:
            raise WCopyError(f"Tag command failed, status={status:#04x}")
        return resp[3:]

    # -- tag-level operations -----------------------------------------------

    def poll_for_tag(self, timeout_s: float = 3.0) -> TagInfo:
        """Polls for a single ISO14443 Type A tag. Raises NoTagPresentError
        if none is found within timeout_s."""
        deadline = time.monotonic() + timeout_s
        while time.monotonic() < deadline:
            self._send_pn532_body(bytes([TFI_HOST_TO_CHIP, CMD_INLIST_PASSIVE_TARGET, 0x01, 0x00]))
            try:
                resp = self._read_pn532_response(timeout_ms=500, retries=10)
            except WCopyError:
                continue
            if len(resp) < 3 or resp[1] != CMD_INLIST_PASSIVE_TARGET + 1:
                continue
            nb_tg = resp[2]
            if nb_tg == 0:
                time.sleep(0.1)
                continue
            # resp[3]=Tg, resp[4:6]=SENS_RES, resp[6]=SEL_RES, resp[7]=NFCIDLen
            if len(resp) < 8:
                # Malformed/truncated frame (seen under rapid back-to-back
                # polling) — not a real "no tag" answer, just skip it and
                # keep polling rather than crashing on a short slice below.
                continue
            nfcid_len = resp[7]
            if len(resp) < 8 + nfcid_len:
                continue
            sens_res = resp[4:6]
            sel_res = resp[6]
            uid = resp[8 : 8 + nfcid_len]
            return TagInfo(uid=uid, sens_res=sens_res, sel_res=sel_res)
        raise NoTagPresentError("No tag detected — place a tag on the reader and try again.")

    def _reselect(self, expected_uid: bytes) -> None:
        """Re-runs the full ISO14443 anticollision/selection sequence.
        Needed before starting a new sector: this reader's tags drop their
        RF session (later auth attempts fail even with a previously-good
        key) after a run of failed authentications like a locked-trailer
        probe — the same recovery a real HALT+WAKE would give, without
        needing a dedicated halt command. Raises WCopyError if a different
        tag answers instead of the one being operated on (moved, or
        swapped).
        """
        tag = self.poll_for_tag(timeout_s=3)
        if tag.uid != expected_uid:
            raise WCopyError(
                f"A different tag answered on re-select (expected UID {expected_uid.hex()}, "
                f"got {tag.uid.hex()}) — did the tag move or get swapped?"
            )

    def _authenticate_sector(
        self, sector: int, uid: bytes, auth_cmds: tuple[int, ...] = (TAG_CMD_AUTH_KEY_A, TAG_CMD_AUTH_KEY_B)
    ) -> bytes:
        """Tries every key in KNOWN_KEYS against each command in
        `auth_cmds`, in order; returns whichever key worked. Raises
        AuthenticationError if none does.

        Authenticating with Key A doesn't necessarily grant every
        operation Key B would — depending on this sector's access bits,
        Key A can be enough to read/write its data blocks while updating
        the trailer itself still requires Key B specifically (a common
        Mifare Classic configuration, and exactly what this reader's
        tags turned out to need — passing auth_cmds=(TAG_CMD_AUTH_KEY_B,)
        re-authenticates for that case instead of assuming the earlier,
        broader authentication still covers it).
        """
        block = sector * BLOCKS_PER_SECTOR + (BLOCKS_PER_SECTOR - 1)
        for key in KNOWN_KEYS:
            for auth_cmd in auth_cmds:
                try:
                    self._in_data_exchange(bytes([auth_cmd, block]) + key + uid)
                    return key
                except WCopyError:
                    continue
        raise AuthenticationError(
            f"Could not authenticate sector {sector} with any known key — this tag may use "
            "a key outside the known list, or isn't a compatible Mifare Classic tag."
        )

    def _write_block(self, block: int, data16: bytes) -> None:
        assert len(data16) == BLOCK_SIZE
        self._in_data_exchange(bytes([TAG_CMD_COMPATIBILITY_WRITE, block]) + data16)

    def _read_block(self, block: int) -> bytes:
        data = self._in_data_exchange(bytes([TAG_CMD_READ, block]))
        return data[:BLOCK_SIZE]

    def _read_block_resilient(self, sector: int, block: int, uid: bytes) -> bytes:
        """Reads one block, retrying once with a fresh reselect+re-auth if
        it fails — the tag's RF session can drop mid-sector, not just at
        sector boundaries (see _reselect's docstring), so a bare
        _read_block can hit a stale-session auth error (status 0x14) even
        right after a successful _authenticate_sector for this sector."""
        try:
            return self._read_block(block)
        except WCopyError:
            self._reselect(uid)
            self._authenticate_sector(sector, uid)
            return self._read_block(block)

    def _try_write_trailer(self, sector: int, uid: bytes) -> None:
        """Best-effort: sets this sector's trailer to a known key (so a
        future re-write knows what unlocks it) if that's possible, but
        never raises. A locked/unwritable trailer (or one that only ever
        authenticates with Key A, never Key B, for the update itself — a
        real Mifare Classic access-bit configuration, and what this
        reader's own tags turned out to have) doesn't stop the NDEF data
        already written from being a perfectly valid, phone-readable tag
        — the trailer's key is only this driver's own bookkeeping
        convenience, not something an NFC reader cares about at all.
        """
        block = sector * BLOCKS_PER_SECTOR + (BLOCKS_PER_SECTOR - 1)
        try:
            # Fresh select before probing (up to) every known key against
            # Key B — see _reselect and write_data's own call to it.
            self._reselect(uid)
            # Updating the trailer itself can require Key B even when Key A
            # already authenticated fine for this sector's data blocks —
            # see _authenticate_sector's docstring.
            self._authenticate_sector(sector, uid, auth_cmds=(TAG_CMD_AUTH_KEY_B,))
            trailer = KEY_WCOPY + TRAILER_ACCESS_GPB + TRAILER_KEY_B
            self._write_block(block, trailer)
        except WCopyError as e:
            self._on_warning(
                f"Note: couldn't update sector {sector}'s trailer ({e}) — the data itself was still written fine."
            )

    def write_data(self, uid: bytes, payload: bytes, verify: bool = True) -> None:
        """Writes `payload` as raw bytes starting at block 4 (sector 1),
        authenticating each sector and best-effort updating its trailer as
        needed. Never touches sector 0 (blocks 0-3, the UID/manufacturer
        block).
        """
        block = FIRST_DATA_BLOCK
        offset = 0
        current_sector = None
        while offset < len(payload):
            sector = block // BLOCKS_PER_SECTOR
            if sector != current_sector:
                # A fresh select before every sector, not just after a
                # failure: cheap, and protects uniformly against whatever
                # RF-session quirks a given tag has (see _reselect).
                self._reselect(uid)
                self._authenticate_sector(sector, uid)
                current_sector = sector
            is_trailer_block = (block % BLOCKS_PER_SECTOR) == (BLOCKS_PER_SECTOR - 1)
            if is_trailer_block:
                self._try_write_trailer(sector, uid)
                block += 1
                continue
            chunk = payload[offset : offset + BLOCK_SIZE]
            if len(chunk) < BLOCK_SIZE:
                chunk = chunk + b"\x00" * (BLOCK_SIZE - len(chunk))
            self._write_block(block, chunk)
            if verify:
                readback = self._read_block(block)
                if readback != chunk:
                    raise WCopyError(
                        f"Verification failed at block {block}: wrote {chunk.hex()}, "
                        f"read back {readback.hex()}"
                    )
            offset += BLOCK_SIZE
            block += 1
        # Always close out the sector we finished in with its trailer, even
        # if the payload ended exactly on a data block boundary.
        sector = (block - 1) // BLOCKS_PER_SECTOR
        trailer_block = sector * BLOCKS_PER_SECTOR + (BLOCKS_PER_SECTOR - 1)
        if block <= trailer_block:
            self._try_write_trailer(sector, uid)

    def read_data(self, uid: bytes, num_blocks: int) -> bytes:
        """Reads `num_blocks` worth of data starting at block 4, skipping
        trailer blocks, and concatenates just the data-block contents."""
        out = bytearray()
        block = FIRST_DATA_BLOCK
        current_sector = None
        read = 0
        while read < num_blocks:
            sector = block // BLOCKS_PER_SECTOR
            if sector != current_sector:
                self._reselect(uid)
                self._authenticate_sector(sector, uid)
                current_sector = sector
            if (block % BLOCKS_PER_SECTOR) != (BLOCKS_PER_SECTOR - 1):
                out.extend(self._read_block_resilient(sector, block, uid))
                read += 1
            block += 1
        return bytes(out)

    def read_ndef(self, uid: bytes, max_blocks: int = 64) -> bytes:
        """Reads only as many blocks as needed to capture one NDEF TLV
        (03 <len> ... FE, see ndef.py) written by write_data, rather than
        requiring the caller to already know the payload length up front
        the way read_data does. Stops as soon as the declared TLV length
        is satisfied, so a short tag never pulls in (and never needs to
        authenticate) sectors past the one actually written."""
        out = bytearray()
        block = FIRST_DATA_BLOCK
        current_sector = None
        needed: int | None = None
        while needed is None or len(out) < needed:
            if len(out) >= max_blocks * BLOCK_SIZE:
                raise WCopyError("No complete NDEF TLV found within the read limit — tag may be blank or corrupt.")
            sector = block // BLOCKS_PER_SECTOR
            if sector != current_sector:
                self._reselect(uid)
                self._authenticate_sector(sector, uid)
                current_sector = sector
            if (block % BLOCKS_PER_SECTOR) != (BLOCKS_PER_SECTOR - 1):
                out.extend(self._read_block_resilient(sector, block, uid))
                if needed is None and len(out) >= 2:
                    if out[0] != 0x03:
                        raise WCopyError("No NDEF TLV found (tag may be blank or written by something else).")
                    needed = 2 + out[1] + 1  # tag byte + length byte + record + terminator
            block += 1
        return bytes(out[:needed])
