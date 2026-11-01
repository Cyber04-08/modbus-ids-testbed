"""
Authenticated Modbus/TCP envelope: a stand-in for Modbus/TCP Security.

The detectors in this project work on traffic that carries no proof of who
sent it. The limitation that survived every passive countermeasure (see
docs/EVALUATION_PROTOCOL.md section 6) is an injection that comes from the
operator's own address and copies normal timing and values: nothing in the
bytes separates it from the operator. The real fix is authentication.

Modbus/TCP Security (the Modbus Organization's TLS profile) provides
mutual authentication, integrity and role-based authorization. TLS itself is
not rebuilt here. This module implements the property that matters for the
comparison, a keyed integrity tag plus an anti-replay counter, so the cost
and the protection can be measured on the same traffic as the detectors.

Envelope (one per Modbus request, carried instead of the bare frame):

    counter (8 bytes, big endian) | frame (MBAP header + PDU) | tag (16 bytes)

    tag = HMAC-SHA256(key, counter || frame)[:16]

The gateway (Verifier) accepts a request only if the tag verifies under the
shared key AND the counter is greater than the highest counter accepted so
far for that key. The first rule stops forged and modified requests (including
a replay whose transaction ID was rewritten: the tag covers the whole frame).
The second stops a verbatim resend of a captured envelope. Neither stops an
attacker who holds the key; that is the honest boundary, and key management
is out of scope here.

Real TLS would add confidentiality and certificate-based identity; the
24 bytes and the HMAC here are a lower bound on its per-message cost.
"""

from __future__ import annotations

import hashlib
import hmac
import struct

COUNTER_BYTES = 8
TAG_BYTES = 16
OVERHEAD = COUNTER_BYTES + TAG_BYTES

# Verdicts
OK = "ok"
BAD_TAG = "bad_tag"
STALE_COUNTER = "stale_counter"
MALFORMED = "malformed"


def _tag(key: bytes, counter: int, frame: bytes) -> bytes:
    msg = struct.pack(">Q", counter) + frame
    return hmac.new(key, msg, hashlib.sha256).digest()[:TAG_BYTES]


def seal(key: bytes, counter: int, frame: bytes) -> bytes:
    """Wrap a Modbus frame in an authenticated envelope."""
    return struct.pack(">Q", counter) + frame + _tag(key, counter, frame)


class Signer:
    """Client side: seals each request with the next counter value."""

    def __init__(self, key: bytes, start: int = 1):
        self._key = key
        self._next = start

    def seal(self, frame: bytes) -> bytes:
        env = seal(self._key, self._next, frame)
        self._next += 1
        return env


class Verifier:
    """Gateway side: checks the tag, then the anti-replay counter. State is
    updated only by an envelope that passes both checks, so a flood of bad
    envelopes cannot move the counter window."""

    def __init__(self, key: bytes):
        self._key = key
        self.high_water = 0

    def verify(self, envelope: bytes) -> tuple[str, bytes | None]:
        """Return (verdict, frame). frame is the bare Modbus frame when the
        verdict is OK, else None."""
        if len(envelope) < OVERHEAD + 8:          # 7-byte MBAP + function code
            return MALFORMED, None
        counter = struct.unpack(">Q", envelope[:COUNTER_BYTES])[0]
        frame = envelope[COUNTER_BYTES:-TAG_BYTES]
        tag = envelope[-TAG_BYTES:]
        if not hmac.compare_digest(tag, _tag(self._key, counter, frame)):
            return BAD_TAG, None
        if counter <= self.high_water:
            return STALE_COUNTER, None
        self.high_water = counter
        return OK, frame
