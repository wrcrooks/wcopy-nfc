#!/usr/bin/env python3
"""Writes a URL to whatever tag is on the reader, then reads it back to
confirm the write.

Usage:
    python3 write_uri.py https://example.com/some/path
"""

import sys

from wcopy_nfc import ndef
from wcopy_nfc import WCopyReader

if len(sys.argv) != 2:
    print(f"Usage: {sys.argv[0]} <url>")
    sys.exit(1)

url = sys.argv[1]

with WCopyReader() as reader:
    print("Polling for a tag (10s timeout)...")
    tag = reader.poll_for_tag(timeout_s=10)
    print(f"Tag detected, UID={tag.uid.hex()}")

    payload = ndef.build_uri_tlv(url)
    print(f"Writing {len(payload)} bytes: {url!r}")
    reader.write_data(tag, payload, verify=True)
    print("Write + verify-on-write succeeded.")

    print("Re-reading from scratch to double check...")
    raw = reader.read_ndef(tag)
    read_back = ndef.parse_uri_tlv(raw)
    print("Read back:", read_back)
    print("Matches what was written:", read_back == url)
