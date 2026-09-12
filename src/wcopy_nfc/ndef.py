"""Builds and parses a bare NDEF URI record wrapped in a Type 2 Tag NDEF
TLV, matching exactly what the vendor's wCopy tool writes (confirmed
byte-for-byte against a real capture): no Capability Container is written
(the tags used are apparently already usable without one, or the
reader/phone side is lenient) — just `03 <len> <NDEF record> FE` starting
at block 4.
"""

from __future__ import annotations

# NFC Forum "URI Record Type Definition" abbreviation codes — only the
# ones plausible for a short link are listed; anything else falls back to
# 0x00 (no abbreviation, the full URI is stored literally).
_URI_PREFIXES = [
    (0x04, "https://"),
    (0x03, "http://"),
    (0x02, "https://www."),
    (0x01, "http://www."),
]


def _uri_code_and_rest(url: str) -> tuple[int, str]:
    for code, prefix in _URI_PREFIXES:
        if url.startswith(prefix):
            return code, url[len(prefix) :]
    return 0x00, url


def build_uri_tlv(url: str) -> bytes:
    """Returns the full NDEF TLV byte string (TLV tag + length + NDEF
    message + terminator TLV) for a single URI record containing `url`."""
    uri_code, rest = _uri_code_and_rest(url)
    payload = bytes([uri_code]) + rest.encode("ascii")
    if len(payload) > 0xFF:
        # A short record (SR=1, used below) needs a 1-byte payload length;
        # nothing realistic for a short URL gets close to this, but fail
        # loudly rather than silently truncate.
        raise ValueError(f"URI too long for a short NDEF record ({len(payload)} bytes)")

    record_header = 0b11010001  # MB=1, ME=1, CF=0, SR=1, IL=0, TNF=001 (Well Known)
    record_type = b"U"  # URI record type
    ndef_record = bytes([record_header, len(record_type), len(payload)]) + record_type + payload

    if len(ndef_record) > 0xFF:
        raise ValueError(f"NDEF message too long for a single-byte TLV length ({len(ndef_record)} bytes)")

    return bytes([0x03, len(ndef_record)]) + ndef_record + bytes([0xFE])


def parse_uri_tlv(data: bytes) -> str:
    """Reverses build_uri_tlv: given the raw NDEF TLV bytes read back off
    a tag, returns the URI. Raises ValueError if `data` doesn't look like
    a single URI record in this exact layout."""
    if len(data) < 2 or data[0] != 0x03:
        raise ValueError("No NDEF TLV found (tag may be blank or written by something else).")
    ndef_len = data[1]
    ndef_record = data[2 : 2 + ndef_len]
    if len(ndef_record) < 4:
        raise ValueError("NDEF record is too short to be a URI record.")
    type_len = ndef_record[1]
    payload_len = ndef_record[2]
    record_type = ndef_record[3 : 3 + type_len]
    payload = ndef_record[3 + type_len : 3 + type_len + payload_len]
    if record_type != b"U":
        raise ValueError(f"Not a URI record (type={record_type!r}).")
    if not payload:
        raise ValueError("URI record has an empty payload.")
    prefix = next((p for code, p in _URI_PREFIXES if code == payload[0]), "")
    return prefix + payload[1:].decode("ascii", errors="replace")
