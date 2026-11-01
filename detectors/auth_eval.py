"""
Authenticated-Modbus comparison (closes the gap the passive detectors leave).

Replays the labeled sessions in data/harder (txid-rewriting replay and the
timing-mimicking in-band injection, from a separate host and from the
operator's own address) and data/varied through the authentication gateway of
testbed/secure_modbus.py, under four attacker capabilities:

  no-key     the attacker sends its request with a made-up tag
  resend     the attacker re-sends an envelope it sniffed from the operator
             (verbatim, so the tag is valid but the counter is stale)
  rewrite    the attacker re-uses a sniffed tag on a changed frame
             (new transaction ID or value), as a rewritten replay would
  key-theft  the attacker holds the shared key and seals with a fresh counter
             (the case no passive or protocol-level check can separate)

The operator's requests are sealed in capture order with an incrementing
counter. Reported per session set and capability: the share of attack
requests the gateway rejects, and the share of benign operator requests it
wrongly rejects, plus the measured per-request cost (microseconds, bytes
added) to set beside the detectors' figures.

Usage:
    python detectors/auth_eval.py
"""

from __future__ import annotations

import csv
import struct
import sys
import timeit
from pathlib import Path

import pandas as pd

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "testbed"))
import secure_modbus as sm                               # noqa: E402

KEY = bytes.fromhex("00112233445566778899aabbccddeeff" * 2)
CAPABILITIES = ("no-key", "resend", "rewrite", "key-theft")
ATTACK_LABELS = ("replay", "injection")


def attacker_envelope(capability: str, frame: bytes, sniffed: bytes,
                      next_counter: int, signer: "sm.Signer") -> bytes:
    """The envelope an attacker with `capability` puts on the wire for `frame`."""
    if capability == "no-key":
        return struct.pack(">Q", next_counter) + frame + b"\x00" * sm.TAG_BYTES
    if capability == "resend":
        return sniffed
    if capability == "rewrite":
        # old counter and tag, new frame bytes
        return sniffed[:sm.COUNTER_BYTES] + frame + sniffed[-sm.TAG_BYTES:]
    if capability == "key-theft":
        # Holding the key, the attacker seals like the operator. It takes the
        # next value of the operator's counter (as it would on the operator's
        # own machine), so the operator is not locked out by a counter clash.
        return signer.seal(frame)
    raise ValueError(capability)


def run_session(df: pd.DataFrame, capability: str) -> dict:
    """Push one labeled session through the gateway. Returns counts."""
    verifier = sm.Verifier(KEY)
    signer = sm.Signer(KEY)
    counts = {"benign": 0, "benign_blocked": 0, "replay": 0, "replay_blocked": 0,
              "injection": 0, "injection_blocked": 0}
    sniffed = None
    reqs = df[df["direction"] == "req"].sort_values("wall_time", kind="stable")
    for _, r in reqs.iterrows():
        label = r.get("label")
        if label not in ("benign",) + ATTACK_LABELS:
            continue                                  # seed / cover / response: unscored
        frame = bytes.fromhex(r["raw_hex"])
        if label == "benign":
            env = signer.seal(frame)
            sniffed = env
        else:
            if sniffed is None:                       # nothing sniffed yet
                sniffed = sm.seal(KEY, 1, frame)
            env = attacker_envelope(capability, frame, sniffed, verifier.high_water + 1, signer)
        verdict, _ = verifier.verify(env)
        counts[label] += 1
        if verdict != sm.OK:
            counts[f"{label}_blocked"] += 1
    return counts


def pooled(files: list[Path], capability: str) -> dict:
    total: dict[str, int] = {}
    for f in files:
        df = pd.read_csv(f, dtype={"values": str})
        for k, v in run_session(df, capability).items():
            total[k] = total.get(k, 0) + v
    return total


def cost(n: int = 20000) -> dict:
    frame = bytes.fromhex("000100000006010600010050")
    signer = sm.Signer(KEY)
    envs = [signer.seal(frame) for _ in range(n)]
    ver = sm.Verifier(KEY)
    seal_us = timeit.timeit(lambda: sm.seal(KEY, 1, frame), number=n) / n * 1e6
    t0 = timeit.default_timer()
    for e in envs:
        ver.verify(e)
    verify_us = (timeit.default_timer() - t0) / n * 1e6
    return {"seal_us": round(seal_us, 2), "verify_us": round(verify_us, 2),
            "bytes_added": sm.OVERHEAD, "frame_bytes": len(frame)}


def rate(a: int, b: int) -> str:
    return "n/a" if b == 0 else f"{a / b:.3f} ({a}/{b})"


def main() -> None:
    sets = {
        "harder/separate": sorted((ROOT / "data" / "harder" / "separate").glob("run_*.csv")),
        "harder/spoof": sorted((ROOT / "data" / "harder" / "spoof").glob("run_*.csv")),
        "varied": sorted((ROOT / "data" / "varied" / "runs").glob("run_*.csv")),
    }
    rows = []
    for name, files in sets.items():
        if not files:
            print(f"[auth_eval] no sessions for {name}; skipped")
            continue
        for cap in CAPABILITIES:
            t = pooled(files, cap)
            rows.append({"set": name, "capability": cap, "sessions": len(files),
                         "replay_blocked": rate(t["replay_blocked"], t["replay"]),
                         "injection_blocked": rate(t["injection_blocked"], t["injection"]),
                         "benign_blocked": rate(t["benign_blocked"], t["benign"])})
    out = pd.DataFrame(rows)
    print(out.to_string(index=False))
    c = cost()
    print(f"\nPer-request cost: seal {c['seal_us']} us, verify {c['verify_us']} us, "
          f"+{c['bytes_added']} bytes on a {c['frame_bytes']}-byte frame")
    out_path = ROOT / "data" / "auth_results.csv"
    out.to_csv(out_path, index=False)
    with open(ROOT / "data" / "auth_cost.csv", "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(c))
        w.writeheader()
        w.writerow(c)
    print(f"wrote {out_path}")


if __name__ == "__main__":
    main()
