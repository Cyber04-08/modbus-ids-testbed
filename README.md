# Modbus/TCP Intrusion Detection Testbed

Senior Seminar I project: comparing a rule-based detector against an ML
anomaly detector for replay and command-injection attacks on Modbus/TCP,
evaluated on accuracy *and* operational cost (latency, per-packet processing
time, memory).

## Layout

- `testbed/` - the simulated/real PLC and client code (Phase 1)
- `attacks/` - replay and injection attack scripts, timestamp-labeled (Phase 2)
- `detectors/` - rule-based detector and ML anomaly detector (Phase 3)
- `data/` - captured traffic and labeled datasets (gitignored; regenerate via scripts)
- `docs/` - setup log and design notes

## Status

- **Phase 1 (testbed) - done.** A pure-Python Modbus/TCP PLC simulator
  (`testbed/plc_simulator.py`) running and verified reachable, plus the full
  GRFICSv2 VM testbed as the higher-fidelity option. See `docs/SETUP_LOG.md`.
- **Phase 2 (data generation) - done.** A one-command scenario captures a
  labeled dataset of normal traffic with a replay attack and a
  command-injection attack injected at known times. See below and
  `docs/SETUP_LOG.md`.
- **Phase 3 (detectors) + Phase 4 (evaluation) - done.** A rule-based detector
  and an Isolation Forest anomaly detector, compared head-to-head on the same
  traffic with precision/recall/F1/FPR, detection latency, and per-request
  cost/memory. See below.

## Quick start

Phase 1 - sanity-check the simulator:

```
pip install pymodbus==3.7.4
python testbed/plc_simulator.py     # starts the simulated PLC on 127.0.0.1:5020
python testbed/client_test.py       # sanity-check read/write against it
```

Phase 2 - generate the labeled dataset (starts the PLC, a passive capture
tap, normal HMI traffic, and both attacks; writes `data/labeled.csv`):

```
python attacks/run_scenario.py            # full run (~50s); add --quick for a short run
python data/label_dataset.py              # -> data/labeled.csv (benign/replay/injection)
```

### How Phase 2 fits together

- `testbed/hmi_client.py` - normal operator traffic (the benign baseline):
  frequent level polls plus occasional setpoint/valve changes, with jitter so
  the baseline isn't artificially uniform.
- `testbed/modbus_tap.py` - a passive bump-in-the-wire logger between clients
  and the PLC; records every Modbus frame to `data/capture.csv`. Works on
  Windows loopback with no npcap/admin (unlike raw-socket sniffing).
- `attacks/replay_attack.py` - captures a legitimate write and retransmits it
  verbatim (reused transaction ID) - the replay signature.
- `attacks/command_injection.py` - crafts unauthorized FC5/FC6/FC16 writes to
  actuator/setpoint addresses, including an out-of-range value.
- `attacks/run_scenario.py` - orchestrates the run and writes
  `data/attack_manifest.json` (ground truth).
- `data/label_dataset.py` - merges capture + manifest into `data/labeled.csv`.

Ground truth is by source port (each client reports its ephemeral port to the
orchestrator) and cross-checked against each attack's recorded time window.
On this single-host loopback testbed every client shares IP 127.0.0.1, so
they are told apart by source port; GRFICSv2 provides true per-host IP
separation when higher fidelity is wanted.

## Detectors and evaluation (Phases 3-4)

```
pip install numpy pandas scikit-learn
python testbed/capture_baseline.py            # -> data/baseline_capture.csv (normal only, for ML training)
python attacks/run_scenario.py && python data/label_dataset.py   # -> data/labeled.csv (mixed, test set)
python detectors/evaluate.py                  # head-to-head comparison
```

- `detectors/features.py` - shared feature extraction (both detectors score
  the same request frames from the same CSVs).
- `detectors/rule_based.py` - passive invariant checks on unmodified traffic:
  function-code allowlist, writes only to writable addresses (HR0/tank level
  is read-only), plausible value ranges, and replay detection via reused
  transaction ID with identical payload (so a legitimately repeated setpoint,
  which uses fresh incrementing IDs, is not flagged).
- `detectors/ml_anomaly.py` - Isolation Forest trained on normal traffic only;
  features are function code, register address/value, request size, and
  per-connection inter-arrival time; `contamination` is set to the observed
  attack fraction, not left at default.
- `detectors/evaluate.py` - runs both over the same test set and reports
  precision/recall/F1/FPR, mean detection latency, and per-request processing
  time + peak memory.

Representative result (exact numbers vary per capture; the trade-off is
stable): the rule-based detector reaches precision ~1.0 with a 0 false-positive
rate at a few microseconds and KB per request, but misses *well-formed*
malicious commands (recall ~0.67); the Isolation Forest reaches higher recall
(~0.80) and lower injection-detection latency, but at a ~15% false-positive
rate and roughly two orders of magnitude more processing time and memory. That
accuracy-versus-operational-cost trade-off, measured head-to-head on unmodified
Modbus/TCP, is the project's contribution.
