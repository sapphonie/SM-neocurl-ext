# Copyright 2026 davenonymous
"""What the test modules share."""

import time

# Files the test plugins work on, relative to the game directory. The two in the game directory itself are for
# sm_demos_compress, which compresses and deletes every demo there; the one in upload/ stays as it is.
DEMO_BYTES = b"HL2DEMO" + b"tick data " * 40000
UPLOAD_FILE = "upload/match.dem"
SERVER_FILES = {UPLOAD_FILE: DEMO_BYTES, "demo1.dem": DEMO_BYTES, "demo2.dem": DEMO_BYTES}


def wait_until(condition, description, timeout=20):
    """Waits until condition() is true."""
    deadline = time.monotonic() + timeout
    while not condition():
        assert time.monotonic() < deadline, "Timed out waiting for " + description
        time.sleep(0.2)
