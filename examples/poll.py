#!/usr/bin/env python3
"""Waits for a tag to be placed on the reader and prints its UID."""

from wcopy_nfc import WCopyReader

with WCopyReader() as reader:
    print("Polling for a tag (10s timeout)...")
    tag = reader.poll_for_tag(timeout_s=10)
    print("Tag detected!")
    print("  UID:", tag.uid.hex())
    print("  SENS_RES:", tag.sens_res.hex())
    print("  SEL_RES:", f"{tag.sel_res:#04x}")
