#!/usr/bin/env python3
"""Reads whatever URI record is on the tag currently on the reader and
prints it."""

from wcopy_nfc import ndef
from wcopy_nfc import NoTagPresentError, WCopyError, WCopyReader

with WCopyReader() as reader:
    print("Polling for a tag (10s timeout)...")
    try:
        tag = reader.poll_for_tag(timeout_s=10)
    except NoTagPresentError as e:
        print(e)
        raise SystemExit(1)
    print(f"Tag detected, UID={tag.uid.hex()}")

    try:
        raw = reader.read_ndef(tag.uid)
        url = ndef.parse_uri_tlv(raw)
    except (WCopyError, ValueError) as e:
        print(f"Read failed: {e}")
        raise SystemExit(1)

    print("URL:", url)
