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
- **Multi-run statistics - done.** `detectors/multi_run.py` repeats the whole
  capture + evaluation 10 times and reports mean +/- 95% confidence intervals.

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

Ground truth is per packet: each attack script logs every request it sends
(exact bytes, transaction ID), and the labeler matches each captured request
on that attack's connection (identified by its reported source port) to its
log record, with the attack's time window as a cross-check. PLC responses are
labeled `response` and the replay's seed packet `replay_seed`; neither is
scored. Normal traffic, labels and the train/tune/test sessions are defined in
`docs/EVALUATION_PROTOCOL.md`. On this single-host loopback testbed every
client shares IP 127.0.0.1, so they are told apart by source port; GRFICSv2
provides true per-host IP separation when higher fidelity is wanted.

## Detectors and evaluation (Phases 3-4)

```
pip install numpy pandas scikit-learn
python testbed/capture_baseline.py            # train session -> data/baseline_capture.csv (normal only)
python attacks/capture_tuning.py              # tune session  -> data/tuning_labeled.csv
python attacks/run_scenario.py && python data/label_dataset.py   # test session -> data/labeled.csv
python detectors/evaluate.py                  # head-to-head comparison
python detectors/multi_run.py 10              # 10 fresh runs -> mean +/- 95% CI
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
  per-connection inter-arrival time; `contamination` is set to the attack
  fraction of the separate tuning session, not left at default and never
  taken from the test set.
- `detectors/evaluate.py` - runs both over the same test set and reports
  precision/recall/F1/FPR, mean detection latency, and detector processing
  cost (per-request time + memory). Training and detection memory are
  measured in separate windows: the one-time training peak, the memory the
  built model keeps holding, and the peak while scoring traffic. The
  detectors read a recorded copy of the traffic and are not in the control
  path, so this is the monitoring host's cost, not a control-loop delay.

Result over 10 independent test sessions (750 scored requests, 140 attacks;
mean +/- 95% CI): the rule-based detector reaches precision 1.00 with a 0
false-positive rate at ~0.003 ms per request and ~3 KB while detecting, but
misses *well-formed* malicious commands (recall 0.71, identical every run);
the Isolation Forest reaches higher recall (0.87 +/- 0.02) and lower
injection-detection latency (0.50 s vs 1.50 s), but at a 0.18 +/- 0.03
false-positive rate and roughly 200x the processing time (~0.56 ms per
request). Memory, split fairly: while detecting, the forest uses ~26 KB
(vs ~3 KB) but must also keep its ~723 KB trained model in memory (the rules
need under 1 KB); training is a separate one-time step (~2 s, ~747 KB peak).
That accuracy-versus-processing-cost trade-off, measured head-to-head on
unmodified Modbus/TCP, is the project's contribution.
