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
- **Second half, item 1 (ML false alarms) - done.** Fixed a parsing bug that
  zeroed every write value in the training data; added a tuned ML detector
  whose alert threshold is chosen on the tuning session; measured how training
  length affects it (`detectors/training_curve.py`). See `docs/SETUP_LOG.md`.
- **Second half, item 2 (one-class SVM) - done.** `detectors/ocsvm.py`, with
  a transaction-ID-change feature the forest cannot use. Over the 10 runs it
  matches the rules' zero false alarms and catches more attacks (F1 0.96 vs
  0.83), at ~0.03 ms per request.
- **Second half, item 3 (off-the-shelf NIDS) - done.** Suricata 8 and Zeek 9
  on the same 10 sessions (exported to pcap), in a separate sensor VM. Out of
  the box neither detects any attack; Suricata with our rules misses every
  replay (no memory of transaction IDs); Zeek with our script matches our
  rule-based detector. See `docs/SETUP_LOG.md`.
- **Second half, item 4 (GRFICSv2 replication) - done.** Repeated the
  comparison on the GRFICSv2 plant (real OpenPLC, process simulation, HMI,
  firewall), captured passively from a sensor VM. The one-class SVM again
  leads (F1 0.957, 0 false alarms); it misses only in-range writes to the
  actuator register (a sender-identity case). See `docs/SETUP_LOG.md`.
- **Reproducibility check and silent-failure fixes (2026-10-20) - done.** The
  training/tuning files behind the reported results had been overwritten by a
  later capture; they were recovered from the exported pcaps and reproduce the
  reported numbers exactly. Fixed a set of places where the pipeline could
  fail quietly (labeler warnings ignored, tied-timestamp ordering, malformed
  frames read as normal ones, the pcap exporter dropping tied final frames,
  undefined metrics shown as 0); results unchanged. Added pooled Wilson 95%
  intervals, per-attack-type recall, a provenance file and a test suite
  (`tests/`). See `docs/SETUP_LOG.md`.
- **Second half, item 5 (varied / harder attacks) - done.** Three limitations
  of the earlier results were addressed in turn (see
  `docs/EVALUATION_PROTOCOL.md` sections 5-6):
  - *Varied attacks* (`attacks/run_scenario.py --vary`,
    `detectors/generalization.py`): with attacks that differ every session, the
    one-class SVM's separation is intact (ROC AUC / PR AUC 1.000). The fragile
    part was threshold selection; a **label-free threshold** (set from
    normal-only traffic, no attack labels) gives F1 0.993 on varied attacks.
  - *Harder attacks* (`attacks/txid_replay.py`, `attacks/mimic_injection.py`,
    `attacks/harder_scenario.py`, `detectors/harder_attacks.py`): a replay with
    rewritten transaction IDs and a timing-mimicking in-band injection, from a
    separate host and from the operator's own address. **Sender identity**
    recovers detection against a separate-host attacker; **value-change
    features** recover the rewritten replay even from the operator's address; a
    timing-mimicking in-band injection from the operator's own address is the
    case that motivates Modbus/TCP authentication, and is reported as such.

## Tests

```
pip install pytest
python -m pytest tests
```

58 tests: Modbus framing, feature extraction, every rule, the labeler, the
metrics and session-separation checks, the pcap round trip, and one
regression test for each silent failure fixed on 2026-10-20.

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
python detectors/evaluate.py                  # head-to-head comparison (refuses if test = tune)
python detectors/multi_run.py 10              # 10 fresh runs -> mean +/- 95% CI, pooled Wilson CIs
python testbed/capture_baseline.py 3600 data/baseline_60min.csv   # long normal session
python detectors/training_curve.py            # ML quality vs training length
python tools/export_pcap.py --all data/pcap    # sessions -> pcap for Suricata/Zeek
# inside the sensor VM: sudo sh tools/setup_sensor.sh; bash tools/nids/run_nids.sh
python detectors/nids_compare.py              # score Suricata/Zeek like our detectors

# varied and harder attacks (second-half item 5; see docs/EVALUATION_PROTOCOL.md 5-6)
python detectors/generalization.py --capture 10   # varied attacks; fixed vs varied vs label-free threshold
python detectors/harder_attacks.py  --capture 10  # txid-rewrite replay + mimic injection, 2 origins, countermeasures
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
  taken from the test set. A second, *tuned* variant instead places its alert
  threshold at the best F1 on that tuning session and fills each connection's
  first (placeholder) inter-arrival with the median training gap; both are
  reported side by side.
- `detectors/ocsvm.py` - one-class SVM (RBF kernel) trained on normal
  traffic only, on the same five features plus the change in transaction ID
  on the connection (normal = +1, verbatim replay = 0); alert threshold at
  the best F1 on the tuning session, or label-free (`calibrate_normal`) at a
  target false-alarm rate on a normal-only session. An optional context
  feature set adds `repeat_run` and `write_step` for the harder replay.
- `detectors/generalization.py` - varied-attack check: fixed vs varied vs
  label-free threshold, leave-one-attack-type-out, and ROC/PR AUC
  (`attacks/run_scenario.py --vary`).
- `detectors/harder_attacks.py` - harder attacks and countermeasures
  (`attacks/txid_replay.py`, `attacks/mimic_injection.py` via
  `attacks/harder_scenario.py`): sender identity and value-change features,
  scored across a separate-host and a spoofed-operator origin.
- `detectors/evaluate.py` - runs all four over the same test set and reports
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
the Isolation Forest reaches higher recall (0.93) and lower
injection-detection latency (0 s vs 1.50 s), but at a 0.18 +/- 0.04
false-positive rate with the contamination cut-off (0.14 +/- 0.03 with the
threshold tuned on the tuning session, precision 0.61) and roughly 200x the
processing time (~0.58 ms per request). Memory, split fairly: while
detecting, the forest uses ~26 KB (vs ~3 KB) but must also keep its ~720 KB
trained model in memory (the rules need under 1 KB); training is a separate
one-time step (~2 s, ~740 KB peak). (Figures updated 2026-10-15 after fixing
a bug that zeroed write values in the training data; see `docs/SETUP_LOG.md`.)
That accuracy-versus-processing-cost trade-off, measured head-to-head on
unmodified Modbus/TCP, is the project's contribution.

Adding a one-class SVM (2026-10-15) changes that picture: on the same 10 runs
it reaches precision 1.00, recall 0.93 (F1 0.96) and a 0 false-positive rate,
catching every replay and all injections but one, at ~0.03 ms per request with
a 10 KB model and 14 ms of training. Caveats (see `docs/SETUP_LOG.md`): some
injections are caught by timing alone, the replay signal depends on reused
transaction IDs, and the tuning and test sessions share one attack sequence.

Those three caveats are the subject of second-half item 5 (varied and harder
attacks; `docs/EVALUATION_PROTOCOL.md` sections 5-6). In short: against attacks
that vary every session the one-class SVM's score still separates attacks
perfectly (ROC AUC / PR AUC 1.000), and a label-free threshold set from
normal-only traffic reaches F1 0.993 with no attack labels to overfit. Against
attacks built to erase the timing and transaction-ID signals, a sender-identity
rule recovers detection of a separate-host attacker and value-change features
recover the rewritten replay even from the operator's own address; a
timing-mimicking in-band injection sent from the operator's address is the
residual case that needs Modbus/TCP authentication, and is reported as such
rather than hidden.
