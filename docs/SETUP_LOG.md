# Setup Log

Running log of environment decisions and setup steps, kept so the testbed is
reproducible without reconstructing it from memory later.

## 2026-09-15 - Environment survey and Phase 1 start

**Environment found:**
- Windows 11, Python 3.12/3.13, git available.
- VirtualBox is installed (`C:\Program Files\Oracle\VirtualBox`) - GRFICS's
  VM-based route is viable if we go that way later.
- No WSL, no Docker. This rules out the easiest OpenPLC Docker install path
  and any Linux-only tooling without extra setup.

**Decision: start with a pure-Python Modbus/TCP simulator, not GRFICS VMs.**
Per the kickoff checklist's own advice to time-box VM networking and have a
fallback ready, chose to get a real Modbus/TCP testbed talking *today*
rather than start a multi-GB VirtualBox appliance download mid-session.
GRFICS remains an option later for the 3D process visualization if there's
time; it is not required for generating valid, labeled Modbus/TCP traffic.

**Built:** `testbed/plc_simulator.py` - a Modbus/TCP server (pymodbus) that
models a small water storage tank: inlet/outlet valves (coils 0/1), pump
setpoint (holding register 1), tank level (holding register 0). A background
thread advances tank level from valve/pump state each tick, with small
timing jitter, so baseline traffic isn't perfectly uniform (a too-uniform
baseline would make both detectors look artificially good later).

`testbed/client_test.py` - sanity-check client confirming normal reads and
coil/register writes work end-to-end.

**pymodbus version pin: 3.7.4, not latest.** Installed 3.15.0 first; its
classic datastore API (`ModbusSlaveContext`, `getValues`/`setValues`, 0-based
addressing) has been renamed/restructured ahead of a v4 release
(`ModbusDeviceContext`, new addressing, `SimData`/`SimDevice` replacing the
old classes) and the compatibility shim is incomplete - `getValues` isn't
implemented on the new context, so the classic API breaks outright. Nearly
all existing Modbus/ICS tutorials (including the ones in
`Groundwork/Project Study Material.pdf`) assume the classic API. Pinned to
`pymodbus==3.7.4` (last release before this transition) instead of chasing
the new API. **If pymodbus is reinstalled or upgraded later, re-pin to
3.7.4** or explicitly migrate to SimData/SimDevice - don't install latest by
default.

**Verified working:** started `plc_simulator.py`, ran `client_test.py`
against it - read tank level (50.0%) and pump setpoint (40%), wrote inlet
valve open + pump setpoint 60%, read back coil state correctly. Killed the
background server after verifying (see note below on background-process
cleanup).

**Gotcha - duplicate background listeners on Windows:** two backgrounded
instances of the simulator ended up bound to port 5020 simultaneously after
an earlier crashed attempt didn't fully exit (the background *thread* threw,
but the main server thread kept listening). Checked with
`netstat -ano | grep 5020` and killed stray PIDs with `taskkill /F /PID`.
Worth checking for stray listeners before assuming a "connection refused"
means the server never started.

## 2026-09-15 - GRFICSv2 networking prep

Decided to also stand up GRFICSv2 (VirtualBox VMs) for the 3D process
visualization and a real OpenPLC/HMI/firewall topology, alongside (not
replacing) the Python simulator. Went with **v2 over v3**: v3 is Docker
Compose-based and this machine has no Docker/WSL2 installed (would need a
reboot to add); v2 works with VirtualBox, which is already installed.

**Existing VirtualBox state found first:** two VMs already present -
`kali-linux-2026.2-virtualbox-amd64` and `Metasploitable2` - both attached
to `VirtualBox Host-Only Ethernet Adapter #2` (192.168.185.1/24), clearly
an existing isolated attack-lab setup from other coursework. Left that
adapter and both VMs untouched.

**Created two new host-only adapters** for GRFICS instead of reusing/
renumbering existing ones, matching the exact IPs the GRFICSv2 README
specifies:

```
VBoxManage hostonlyif create                                   # -> "...Adapter #3"
VBoxManage hostonlyif create                                   # -> "...Adapter #4"
VBoxManage hostonlyif ipconfig "VirtualBox Host-Only Ethernet Adapter #3" \
    --ip 192.168.90.111 --netmask 255.255.255.0                # DMZ
VBoxManage hostonlyif ipconfig "VirtualBox Host-Only Ethernet Adapter #4" \
    --ip 192.168.95.111 --netmask 255.255.255.0                # ICS
```

Result: Adapter #3 = DMZ (192.168.90.111/24), Adapter #4 = ICS
(192.168.95.111/24) - matches GRFICSv2's `plc_2`/HMI/pfSense/workstation
addressing scheme.

**VM downloads:** the GRFICSv2 README's 5 VM links (Simulation, HMI,
pfSense, PLC, Workstation) are SharePoint links that redirect to a sign-in
page for automated tools (curl, WebFetch) - no Chrome extension connected
in this environment to complete it via browser automation either. User is
downloading manually into `C:\Users\nwane\Projects\GRFICSv2_VMs\`. Once
files land: `VBoxManage import <file>.ova` for each, then attach each VM's
NIC to the correct adapter per the IP table in the README, then boot in
order (ICS subnet + pfSense first, then ScadaBR/HMI).

**Note:** partway through this session, the whole `Projects` folder
(including `GRFICSv2_VMs`) was moved from `C:\Users\nwane\Projects` to
`C:\Users\nwane\OneDrive\Desktop\SENIOR SEMINAR I\Projects`, for the
deliverable folder to be self-contained. Confirmed safe: git uses relative
paths internally and the GitHub remote is a URL, so the repo wasn't
affected; VirtualBox's actual VM files live in the separate, non-synced
`C:\Users\nwane\VirtualBox VMs`, so no OneDrive-vs-running-VM write
conflicts either. All paths below reflect the new location.

## 2026-09-15 - GRFICSv2 VMs imported and networked

All 5 `.ova` files downloaded (~6.4GB total: ChemicalPlant 1.3GB, ScadaBR
0.7GB, pfSense 0.6GB, plc_2 1.2GB, workstation 2.9GB) and imported with
`VBoxManage import`. Host has plenty of headroom (32GB RAM total, ~19GB
free vs. ~4GB combined configured for all 5 VMs).

**Import did not reliably preserve network mappings** - some VMs' NICs
ended up pointing at a host-only adapter name (`...Adapter #5`) that
doesn't actually exist on this host (the OVA's embedded network reference
didn't match anything real, so VirtualBox left a dangling reference rather
than erroring). Fixed by explicitly setting every VM's host-only adapter
with `VBoxManage modifyvm`, rather than trusting the import's guess:

```
VBoxManage modifyvm plc_2 --nic1 hostonly --hostonlyadapter1 "VirtualBox Host-Only Ethernet Adapter #4"
VBoxManage modifyvm ChemicalPlant --nic2 hostonly --hostonlyadapter2 "VirtualBox Host-Only Ethernet Adapter #4"
VBoxManage modifyvm pfSense --nic1 hostonly --hostonlyadapter1 "VirtualBox Host-Only Ethernet Adapter #3" --nic2 hostonly --hostonlyadapter2 "VirtualBox Host-Only Ethernet Adapter #4"
VBoxManage modifyvm ScadaBR --nic1 hostonly --hostonlyadapter1 "VirtualBox Host-Only Ethernet Adapter #3"
VBoxManage modifyvm workstation --nic1 hostonly --hostonlyadapter1 "VirtualBox Host-Only Ethernet Adapter #4"
```

Note `ChemicalPlant`'s active NIC is slot 2, not 1 (NIC 1 comes disabled
from the OVA) - don't assume slot 1 for every VM, check `showvminfo` first.

Final mapping (verified via `showvminfo | grep NIC`):

| VM | NIC(s) | Network |
|---|---|---|
| plc_2 | NIC1 | ICS (Adapter #4, 192.168.95.111/24) |
| ChemicalPlant | NIC2 | ICS (Adapter #4) |
| pfSense | NIC1 / NIC2 | DMZ (Adapter #3) / ICS (Adapter #4) |
| ScadaBR | NIC1 | DMZ (Adapter #3) |
| workstation | NIC1 | ICS (Adapter #4) |

This matches the README's IP table (pfSense bridges DMZ↔ICS as the only
dual-homed VM; everything else is single-homed on whichever side its IP
puts it on).

**Booted all 5 in the required order** (ICS subnet + pfSense first, then
ScadaBR) via `VBoxManage startvm`. All came up clean - no errors on any
console (verified via `VBoxManage controlvm <vm> screenshotpng`, since
there's no Chrome extension connected in this environment to view the VM
windows directly).

**Guest Additions aren't installed/running** on these appliances -
`VBoxManage guestcontrol` failed with "guest execution service is not
ready". Logged into `plc_2` and `ChemicalPlant` via
`VBoxManage controlvm <vm> keyboardputstring "<text>"` +
`keyboardputscancode 1c 9c` (Enter) instead, to check whether the
simulation/PLC processes were already running before attempting to start
them manually - they were:

- **plc_2:** `sudo nodejs server.js` auto-starts on boot (found via
  `ps aux`: root-owned `nodejs server.js` already running since boot).
  Manually re-running it correctly failed with `EADDRINUSE :::8080`,
  confirming the real one was already up. No action needed.
- **ChemicalPlant:** the `simulation` binary and all 6 Modbus remote_io
  scripts (`tank.py`, `feed1.py`, `feed2.py`, `purge.py`, `product.py`,
  `analyzer.py`) are likewise already running since boot. No action
  needed.

**End-to-end verification from the host:**

```
ping 192.168.95.2        # plc_2 (ICS)          -> reply, TTL=64
ping 192.168.90.5        # ScadaBR (DMZ)        -> reply, TTL=64
curl -I http://192.168.90.5:8080/ScadaBR/       -> HTTP/1.1 200 OK
python -c "socket connect to 192.168.95.2:502"  -> Modbus/TCP port OPEN
```

pfSense's own console confirms the same addressing independently (WAN
192.168.90.100/24, LAN 192.168.95.1/24), so the network wiring is correct
end to end, not just "looks right in `showvminfo`."

**Result: the full GRFICSv2 testbed is live** - real OpenPLC on plc_2,
real 3D chemical-process simulation on ChemicalPlant feeding it live
Modbus/TCP traffic, real ScadaBR HMI, real pfSense routing between DMZ and
ICS. This runs *alongside* (not replacing) the Python simulator from
Phase 1 - GRFICS is the higher-fidelity option when it's wanted (3D
visualization, real ladder-logic PLC, real firewall segmentation); the
Python simulator remains the faster/lighter option for iterating on
detector code.

**VM console credentials** (from the README, for reference):

| VM | Login | Password |
|---|---|---|
| plc_2 | user | password |
| ChemicalPlant | simulation | Fortiphyd |
| ScadaBR (console/SSH) | scadabr | scadabr |
| ScadaBR (web, admin) | admin | admin |
| pfSense (console) | admin | pfsense |
| workstation | workstation | password |

ScadaBR web UI: http://192.168.90.5:8080/ScadaBR (reachable from the host
directly, since the host sits on both host-only networks).

## Next steps (Phase 1 remainder / Phase 2 start)

- [ ] Validate the rule-based detector's invariant list against what the
      Wiley paper (Rajesh & Satyanarayana, 2021) actually checks before
      finalizing it (see `docs/PREWORK_NOTES.md`).
- [ ] Capture a baseline "normal" traffic window - from the Python
      simulator (with varying setpoints) and/or from GRFICS's live Modbus
      traffic on plc_2/ChemicalPlant - to build the normal-traffic
      dataset.
- [ ] Decide which testbed is the system of record for Phase 2/3 (attack
      scripts, detectors): the Python simulator (fast iteration) or
      GRFICS (higher fidelity, but slower to reset/re-run against). Could
      also do both and note the difference in the report.
- [ ] Log into ScadaBR's web UI (admin/admin) and confirm it's actually
      showing live tank/process data from ChemicalPlant, not just that the
      login page loads.

## 2026-09-24 - Phase 2: data generation (labeled dataset)

Built the full Phase 2 data-generation pipeline against the Python simulator
(chosen as the system of record for iterating on detectors - fast, disposable,
deterministic to reset; GRFICS remains the higher-fidelity cross-check). One
command now produces a labeled Modbus/TCP dataset of normal traffic with a
replay attack and a command-injection attack injected at known times.

**Components built:**
- `testbed/hmi_client.py` - benign operator traffic: frequent level polls plus
  occasional setpoint/valve writes, with poll-timing and setpoint jitter so the
  baseline isn't artificially uniform (per the proposal).
- `testbed/modbus_tap.py` - a passive bump-in-the-wire logger (TCP proxy) that
  forwards clients<->PLC and records every Modbus frame in both directions to
  `data/capture.csv`, decoding function code / address / count / values.
  **Chose an application-level tap over raw-socket/pcap sniffing** because
  loopback capture on Windows needs npcap with loopback support + admin; the
  tap needs neither and is fully reproducible. It never drops/alters a frame,
  so it's a faithful stand-in for tcpdump.
- `attacks/modbus_frames.py` - raw MBAP+PDU frame builders. Attacks craft
  frames at the byte level (not via pymodbus) so they fully control the
  transaction ID - a replay must reuse it verbatim, injection sets it freely.
- `attacks/replay_attack.py` - captures a legitimate write and retransmits it
  verbatim with its original transaction ID reused (the replay signature).
- `attacks/command_injection.py` - crafts unauthorized FC5/FC6/FC16 writes to
  actuator/setpoint addresses, including an out-of-range setpoint (60000) to
  exercise value-range checks later.
- `attacks/run_scenario.py` - orchestrator: starts PLC + tap + HMI, injects the
  two attacks at timed offsets, writes `data/attack_manifest.json` (ground
  truth). ~50s default, `--quick` for a short run.
- `data/label_dataset.py` - merges capture + manifest into `data/labeled.csv`
  with `label` (benign/replay/injection) and `is_attack` columns. Stdlib only
  (no pandas needed until Phase 3).

**Ground-truth labeling - by source port, cross-checked by time window.**
Each client uses an ephemeral source port and reports it back to the
orchestrator, which records port->role in the manifest; the labeler assigns
each captured frame's label from its client port, then verifies every
attack-labeled frame falls inside that attack's recorded wall-clock window and
warns on any disagreement. No label is embedded in the traffic the detectors
will see.

**Gotcha - fixed source ports break back-to-back runs (Windows TIME_WAIT).**
First cut pinned each client to a fixed local port (55000/55010/55020) so
labeling could identify it. It worked once, then a second run captured zero
attack frames: `bind()` to the same local port failed because the prior run's
connection was still in TIME_WAIT, and SO_REUSEADDR on Windows doesn't allow
reusing a TIME_WAIT local port for a new outbound connect to the same 4-tuple.
The attack scripts aborted in ~0.1s (visible as 0.1s attack windows in the
manifest). Fix: clients use ephemeral ports and *report* the actual port
(attackers print `SOURCE_PORT=<n>`; the HMI writes it to `data/.hmi_port`),
so there's nothing to collide. Verified two full runs back-to-back both label
cleanly.

**Result - representative dataset produced:** a full run yields ~156 frames,
~126 benign / 18 replay / 12 injection (requests alone: ~63 / 9 / 6) - a
realistically benign-heavy, imbalanced set, which is why Phase 4 will score
precision/recall/F1/FPR and detection latency rather than raw accuracy. The
replay's reused transaction ID and the injection's out-of-range/actuator
writes are both clearly visible in `data/labeled.csv`. Generated artifacts
(`capture.csv`, `labeled.csv`, `attack_manifest.json`, `.hmi_port`) are
gitignored and regenerated by re-running the scenario.

## Next steps (Phase 3 - detectors)

- [ ] Rule-based detector over `data/labeled.csv`: function-code allowlist,
      register/coil address-range checks, value-range (plausible setpoint)
      checks, and duplicate-payload/reused-transaction-ID replay detection
      gated on timing so legitimate repeated writes aren't flagged. Validate
      the invariant list against the Wiley paper's frame-filter (IP /
      function-code / address-range allowlists) per PREWORK_NOTES.
- [ ] ML anomaly detector (Isolation Forest, scikit-learn) trained on benign
      traffic only - features: inter-packet timing, function-code
      distribution, register address/value, request rate per connection;
      contamination tuned to the benign/attack imbalance, not left default.
      (Installs needed: pandas, numpy, scikit-learn.)
- [ ] Evaluation harness: replay the labeled dataset through each detector;
      report precision/recall/F1/FPR, mean detection latency, and per-packet
      processing time + memory.

## 2026-09-24 - Phase 3 (detectors) + Phase 4 (evaluation)

Built both detectors and the head-to-head evaluation harness, and ran the full
comparison end to end on freshly generated data.

**Dependencies installed:** numpy 2.5.3, pandas 3.0.6, scikit-learn 1.9.1
(the pymodbus 3.7.4 pin is unaffected - separate concern).

**Datasets (kept separate to avoid train/test leakage):**
- `testbed/capture_baseline.py` -> `data/baseline_capture.csv`: a normal-only
  window (PLC + tap + HMI, no attacks). The ML model trains ONLY on this.
- `attacks/run_scenario.py` + `data/label_dataset.py` -> `data/labeled.csv`:
  the mixed benign+replay+injection set, used as the test set.

**Components built:**
- `detectors/features.py` - shared feature extraction. Both detectors score the
  same unit (Modbus *request* frames; responses are PLC-generated and can't
  carry an attack) from the same CSVs, so the comparison is apples-to-apples.
  ML features: function_code, address, value0, count, per-connection
  inter_arrival.
- `detectors/rule_based.py` - passive invariant checks on unmodified traffic:
  (1) function-code allowlist; (2) write-to-read-only/out-of-range address
  (HR0/tank level is a sensor - any write to it is illegitimate; catches the
  injection's FC16 block write); (3) value-range (setpoint 0-100, coils
  ON/OFF; catches the 60000 setpoint); (4) replay via reused transaction ID
  with identical payload on a connection (a well-behaved master strictly
  increments its txid, so a legit repeated setpoint is NOT flagged).
- `detectors/ml_anomaly.py` - Isolation Forest (200 trees, StandardScaler),
  trained on benign only; `contamination` set to the observed attack fraction
  rather than default.
- `detectors/evaluate.py` - runs both over the same test set; reports
  precision/recall/F1/FPR, per-attack detection latency (first malicious packet
  -> first alert), and operational cost (mean ms/request via perf_counter,
  peak memory via tracemalloc).

**Representative result (one run; exact figures vary per capture, the
trade-off is stable):**

| metric | rule-based | ML (iForest) |
|---|---|---|
| precision | 1.000 | 0.545 |
| recall | 0.667 | 0.800 |
| F1 | 0.800 | 0.649 |
| false-positive rate | 0.000 | 0.154 |
| injection detection latency | 1.506 s | 0.502 s |
| ms/request | 0.0029 | 0.6064 |
| peak memory | 3 KB | 802 KB (+~2 s train) |

**Reading of the result (for the report):** the rule-based detector is precise
and near-free to run but blind to *well-formed* malicious commands - it misses
the injected setpoint->100%, the valve toggles, and setpoint->0, because each is
individually a valid Modbus write; it only catches the malformed/out-of-range
write, the read-only write, and the replayed frames. The Isolation Forest
catches more of the well-formed-but-anomalous commands (higher recall, faster
on injection) but pays with a ~15% false-positive rate and ~200x the
per-request cost plus training time and memory. This is exactly the
accuracy-versus-operational-cost trade-off the project set out to quantify, and
neither prior work (Rajesh & Satyanarayana 2021; Morris & Gao 2014) reports it
head-to-head on unmodified Modbus/TCP.

**Honest limitations to carry into the write-up:**
- Small dataset (tens of attack requests). Numbers are illustrative; a larger
  multi-run capture would tighten them.
- Source-IP allowlisting (a rule the Wiley paper uses) can't apply on a
  single-host loopback testbed - all clients are 127.0.0.1. The rule-based
  detector therefore leans on content/behaviour invariants; GRFICSv2 provides
  real per-host IPs if that rule is wanted later.
- The rule set is tuned to this specific process (a known register/coil map).
  That's realistic for a rule-based ICS detector but means it doesn't
  generalize to an unknown process without re-specification - a point in the
  ML detector's favour worth stating.

## 2026-10-04 - Multi-run statistical evaluation (10 runs)

Addressed the "small dataset" limitation above: `detectors/multi_run.py`
repeats the whole pipeline (fresh scenario capture -> labeling -> both
detectors) N times and reports each metric as mean, standard deviation and a
95% Student-t confidence interval, plus a pooled (micro-averaged) confusion
matrix. The ML training set (`data/baseline_capture.csv`) is captured once and
reused, mirroring deployment (train once, face many unseen windows); the
Isolation Forest is re-seeded per run so its own randomness is part of the
spread (small change: `MLAnomalyDetector` and `eval_ml` now accept a
`random_state`).

Run: `python detectors/multi_run.py 10` -> 10 independent captures, 734 request
frames in total, 150 of them malicious (15 per run). Each run's labeled set is
kept in `data/runs/run_XX.csv`; `--reuse` re-scores them without re-capturing.

| metric (mean +/- 95% CI half-width) | rule-based | ML (iForest) |
|---|---|---|
| precision | 1.000 +/- 0.000 | 0.496 +/- 0.041 |
| recall | 0.667 +/- 0.000 | 0.853 +/- 0.020 |
| F1 | 0.800 +/- 0.000 | 0.625 +/- 0.034 |
| false-positive rate | 0.000 +/- 0.000 | 0.227 +/- 0.031 |
| replay detection latency | 0.001 s | 0.081 +/- 0.121 s |
| injection detection latency | 1.504 s | 0.501 s |
| ms/request | 0.0035 +/- 0.0006 | 0.921 +/- 0.054 |
| peak memory | 2 KB | 756 +/- 14 KB |

**What changed versus the single run:** the trade-off is confirmed, and the
rule-based detector is fully deterministic (identical TP10/FP0/FN5 in every
run). The single run in Progress Report 2 *understated* the ML detector's false
alarms: over 10 runs its false-positive rate is ~23% (range 14-28%), not ~15%,
while its recall is slightly higher (0.80-0.87). Its per-request cost is ~260x
the rule-based detector's. Tuning the ML false-alarm rate is therefore the
first item for the second half of the semester.

## 2026-10-05 - Evaluation-protocol fixes from instructor feedback

Instructor feedback on Assignments 01 and 02 asked for (1) training, tuning
and testing separated by capture session, (2) attack labels from script logs
and packet identifiers rather than injection timestamps, (3) malicious
requests distinguished from legitimate responses, (4) the overhead claim
narrowed to detector processing cost (or control-cycle delay measured), and
(5) a definition of normal traffic. All are written up in
`docs/EVALUATION_PROTOCOL.md`. Code changes:

- `attacks/modbus_frames.py` `log_packet()`; both attack scripts now log every
  request they send (`PACKET=<json>`: exact bytes, txid, kind). The replay's
  first send is logged as kind `seed` (its stand-in for the recorded operator
  command, not itself a replay). `attacks/run_scenario.py` stores the records
  in the manifest.
- `data/label_dataset.py` matches each attack-connection request to its logged
  record by exact bytes, in order (15/15 per session), keeps the time window
  as a cross-check, labels PLC replies `response` and the seed `replay_seed`;
  both are left unscored (blank `is_attack`).
- `detectors/features.py` adds a `scored` column; `evaluate.py`,
  `multi_run.py` and the detectors' standalone modes grade scored requests
  only. Detectors still see the whole request stream.
- `attacks/capture_tuning.py` captures a separate tuning session
  (`data/tuning_labeled.csv`); the ML contamination comes from it (0.177),
  never from a test session.
- The overhead claim is narrowed to detector processing cost: the detectors
  read a recorded copy and are not in the control path.

Previous 10 runs kept in `data/v1_before_feedback/`. Re-run with the fixes:
`python detectors/multi_run.py 10` -> 750 scored requests, 140 attacks (14 per
run).

| metric (mean +/- 95% CI half-width) | rule-based | ML (iForest) |
|---|---|---|
| precision | 1.000 +/- 0.000 | 0.531 +/- 0.053 |
| recall | 0.714 +/- 0.000 | 0.871 +/- 0.022 |
| F1 | 0.833 +/- 0.000 | 0.657 +/- 0.037 |
| false-positive rate | 0.000 +/- 0.000 | 0.182 +/- 0.032 (range 0.09-0.27) |
| injection detection latency | 1.503 s | 0.501 s |
| detector processing cost | 0.0035 ms/request, 3 KB | 0.80 ms/request, 755 KB |

What changed and why: rule-based recall 0.667 -> 0.714 because the replay
seed, which no detector should flag, is no longer scored as a miss (rule
results are otherwise identical: TP10 FP0, now FN4). ML: recall up from the
seed exclusion, but the leak-free contamination (0.177) is lower than the
test fractions the old method used (0.17-0.20), so ML flags slightly less:
FPR 0.227 -> 0.182, precision 0.496 -> 0.531. Scoring the same new data with
the old leaky setting gives P 0.507 / R 0.900 / FPR 0.203 - the leak flattered
ML recall a little. The accuracy-versus-cost trade-off is unchanged.

## Separating training memory from detection memory (A4 feedback)

Instructor feedback on Progress Report 2 (A4): "separate ML training memory
from detection memory to make the cost comparison fair." Confirmed in code:
`eval_ml()` measured one tracemalloc peak across both `fit()` and `predict()`,
so the reported ML "peak memory" (~755 KB) was really the training peak, while
the rule-based figure covered detection only. (Per-request time was already
measured on `predict()` alone.)

Fix in `detectors/evaluate.py` (used by `multi_run.py`): three separate
measurements per detector.
- `train_peak_kb` / `train_ms`: building the detector (ML: fitting the
  forest; rules: loading the config). One-time, offline.
- `model_kb`: memory the built detector keeps holding while it detects.
- `peak_kb`: peak extra memory while scoring the test traffic.

Each detector is also exercised once, unmeasured, before it is measured. The
first scikit-learn fit in a process loads code and caches; without the
warm-up, run 1 showed ~790 KB model memory against ~723 KB for runs 2-10.

Re-scored the same 10 saved test runs (`python detectors/multi_run.py
--reuse`); detection-quality numbers are unchanged (same runs, same seeds).
Previous results kept in `data/v2_before_memory_split/`.

| cost (mean +/- 95% CI half-width) | rule-based | ML (iForest) |
|---|---|---|
| detection time per request | 0.0027 ms | 0.565 +/- 0.022 ms |
| detection peak memory | 3 KB | 26 KB |
| model held in memory | 0.3 KB | 723 +/- 3 KB |
| training peak memory (one-time) | 0.3 KB | 747 +/- 3 KB |
| training time (one-time) | 0 | 1985 +/- 16 ms |

Per-request time is lower than the earlier 0.80 ms figure; timing varies with
machine load, the ~200x ratio holds.

## 2026-10-15 - Second half, item 1: reducing the ML detector's false alarms

### Bug found: training write values were all read as 0

`features.load_requests()` read the `values` column with pandas' type
guessing. Test and tuning sessions contain one multi-value FC16 write
(`"999 ..."`), so the column stayed text and parsed correctly. The normal-only
training session never sends FC16, so pandas read the column as numbers and
`_first_value()` (which only parses text) turned every training write value
into 0. The Isolation Forest was therefore trained on setpoint and valve
writes that all had value 0, then tested on real values. The rule-based
detector only reads test files and was not affected.

Fix: `pd.read_csv(..., dtype={"values": str})`. Re-scoring the same 10 saved
runs (previous results kept in `data/v3_before_value_fix/`):

| ML (contamination 0.177) | precision | recall | FPR |
|---|---|---|---|
| before the fix (Midterm / A4 figures) | 0.531 | 0.871 | 0.182 |
| after the fix | 0.549 | 0.929 | 0.182 |

### Tuned ML detector (threshold from the tuning session)

The contamination cut-off flags a fixed share (17.7%) of the *normal-only*
training data, so the false-positive rate tracks that number by design. New
variant `ml-tuned` (kept alongside the original in `evaluate.py` and
`multi_run.py`):
- `MLAnomalyDetector.calibrate(tune_df)`: alert threshold = the anomaly score
  with the best F1 on the separate labeled tuning session (ties go to fewer
  false alarms). Test labels are still never used.
- `fill_first_gap`: the first request on each connection has no predecessor,
  so its inter-arrival was a placeholder 0; it is replaced by the median gap
  seen in training (`features.py` now marks `first_on_connection`).

10 saved runs, 60 s training session (`python detectors/multi_run.py --reuse`,
idle machine):

| mean +/- 95% CI | rule-based | ML (contamination) | ML (tuned) |
|---|---|---|---|
| precision | 1.000 | 0.549 +/- 0.064 | 0.614 +/- 0.058 |
| recall | 0.714 | 0.929 | 0.929 |
| F1 | 0.833 | 0.686 +/- 0.048 | 0.736 +/- 0.042 |
| FPR | 0.000 | 0.182 +/- 0.037 | 0.139 +/- 0.032 |
| detection ms/request | 0.0026 | 0.588 | 0.577 |
| model held | 0.3 KB | 717 KB | 735 KB |
| training (one-time) | 0 | 2.0 s | 2.1 s |

### Does more training data help? (`detectors/training_curve.py`)

Recorded one 60-minute normal-only session (`python testbed/capture_baseline.py
3600 data/baseline_60min.csv`; the script now takes an optional output path)
and trained on its first 1-60 minutes, scoring the same 10 runs (pooled):

| minutes | train requests | FPR contamination | FPR tuned | tuned precision / recall |
|---|---|---|---|---|
| 1 | 73 | 0.287 | 0.184 | 0.527 / 0.893 |
| 2 | 163 | 0.257 | 0.220 | 0.498 / 0.950 |
| 5 | 414 | 0.266 | 0.059 | 0.769 / 0.857 |
| 10 | 830 | 0.248 | 0.107 | 0.668 / 0.936 |
| 20 | 1656 | 0.275 | 0.179 | 0.546 / 0.936 |
| 30 | 2474 | 0.285 | 0.208 | 0.510 / 0.943 |
| 45 | 3710 | 0.300 | 0.220 | 0.498 / 0.950 |
| 60 | 4939 | 0.300 | 0.220 | 0.498 / 0.950 |

The tuned threshold beats the contamination cut-off at every length, but more
training data does not steadily help. Two label-free feature changes were also
tried (coil values normalized to 0/1; a one-hot "command type" per function
code + address) and did not fix this either (best: 0.079 at 10 min, 0.195 at
60 min). Not adopted; the official training session stays at 60 s.

Why: replays are 8 of the 14 attacks per session, and each is a byte-exact
copy of a normal setpoint write. Per request, the only clue left in these
features is a 0.4 s gap, so the threshold has to reach into normal traffic to
catch them, and the more normal traffic the forest learns, the more ordinary
that gap looks. The real replay signature (a reused transaction ID) needs
memory of earlier requests; it is constant in normal traffic (always +1), and
an Isolation Forest cannot split on a feature that never varies in training.
This motivates the one-class SVM (distance-based) as the next item.

Caveat: the threshold is set on one tuning session of 79 scored requests (14
attacks) whose attack sequence is the same as the test sessions', so the tuned
numbers are likely optimistic and the chosen point is coarse (wide per-run FPR
ranges). Varied attacks are a later item.

## 2026-10-15 - Second half, item 2: one-class SVM

New detector `detectors/ocsvm.py` (`OneClassSVMDetector`): RBF one-class SVM,
standardized features, trained on normal traffic only, alert threshold at the
best F1 on the tuning session (`ml_anomaly.best_f1_threshold`, now shared),
first-gap fill as in the tuned forest. `nu = 0.05`; with the tuned threshold,
nu = 0.01, 0.05 and 0.177 gave identical results. With sklearn's own nu
boundary instead (no tuning) its FPR was 0.25-0.31, worse than the forest.

Features: the forest's five plus `txid_delta`, the change in transaction ID
from the previous request on the same connection (`features.py`; first
request -> 1). Normal masters always add 1; a verbatim replay repeats the ID
(0). Tested on both models (scratch experiment, 10 saved runs, tuned
threshold):

| model / features | precision | recall | FPR |
|---|---|---|---|
| Isolation Forest, 5 features | 0.605 | 0.929 | 0.139 |
| Isolation Forest + txid_delta | 0.591 | 0.929 | 0.148 |
| One-class SVM, 5 features | 1.000 | 0.514 | 0.000 |
| One-class SVM + txid_delta | 1.000 | 0.929 | 0.000 |

The forest cannot use the feature (it is constant in normal training data, so
no tree ever cuts on it); the SVM measures distance, so a 0 change sits away
from every normal request. Without it the SVM misses every replay; with it
the SVM recovers them. The forest keeps its original five features.

Official 10 saved runs (`python detectors/multi_run.py --reuse`, 60 s training
session), mean +/- 95% CI:

| | rule-based | iForest (contamination) | iForest (tuned) | one-class SVM |
|---|---|---|---|---|
| precision | 1.000 | 0.549 +/- 0.064 | 0.614 +/- 0.058 | 1.000 |
| recall | 0.714 | 0.929 | 0.929 | 0.929 |
| F1 | 0.833 | 0.686 +/- 0.048 | 0.736 +/- 0.042 | 0.963 |
| FPR | 0.000 | 0.182 +/- 0.037 | 0.139 +/- 0.032 | 0.000 |
| injection latency | 1.50 s | 0 s | 0 s | 0 s |
| detection ms/request | 0.0031 | 0.577 | 0.603 | 0.034 |
| detection peak memory | 3 KB | 26 KB | 23 KB | 14 KB |
| model held | 0.3 KB | 718 KB | 737 KB | 10 KB (8 support vectors) |
| training (one-time) | 0 | 2.0 s, 742 KB | 2.1 s, 778 KB | 14 ms, 49 KB |

Robustness checks: every normal request scores well below every attack at
60 s, 5 min and 60 min of training (FPR 0 at all three). The one miss per run
is always the same injection, a well-formed "close outlet valve" (FC5 coil 1
OFF), which the rules also miss; it scores just under the threshold.

Limitations to state with this result:
- Some injections are separated only by timing (sent 0.5 s apart, while
  normal writes follow a poll within ~2 ms). An attacker matching normal
  timing would likely evade the SVM on those.
- The replay signal is the reused transaction ID. A replay that rewrites the
  ID to the next expected value would remove it (for the rules too).
- Tuning and test sessions use the same attack sequence, so the threshold is
  set on attacks identical to the test attacks. Varied/harder attacks are the
  next items to test these three points.

Training-length curve with the SVM added (`python detectors/training_curve.py`,
same 60-minute capture, 10 runs pooled): the one-class SVM has precision
1.000 and FPR 0.000 at every length from 1 to 60 minutes (recall 0.950 at
1 min, 0.929 from 2 min on). Training time grows from 13 ms to 78 ms and the
model from 10 KB to 23 KB; the forests stay at ~2 s and ~1 MB.

## 2026-10-15/16 - Second half, item 3: off-the-shelf NIDS (Suricata, Zeek)

### Setup

- Sensor VM `ids-sensor` (VirtualBox, `C:\Users\nwane\VirtualBox VMs\ids-sensor`):
  a fresh import of the Kali 2026.2 image with a new disk UUID, separate from
  every other VM; snapshot `fresh-import` = unmodified image. The repo is
  shared into it at `/media/sf_ids`. Installed with `tools/setup_sensor.sh`:
  Suricata 8.0.7, Zeek 9.0.0 (Zeek project repository; Kali's 5.1.1 package
  cannot install on Kali 2026.2), tshark 4.6.6, ET Open ruleset (69,163
  rules, 53,203 enabled). The install upgrades systemd, which stops the
  VirtualBox guest service until a reboot.
- `tools/export_pcap.py` turns each saved session CSV into a pcap: the
  captured Modbus bytes and timestamps unchanged, TCP/IP rebuilt around them
  (handshake, sequence numbers, FIN), one client IP for all clients (as on
  the loopback testbed), PLC on port 502. tshark reports no errors on them.
  Known artifact: Zeek logs `FIN_advanced_last_seq` on ~2 connection
  teardowns per run (rebuilt TCP close, not Modbus); not counted.
- `tools/nids/run_nids.sh` runs four configurations on all 12 pcaps:
  suricata-stock (ET Open + Suricata's `modbus-events.rules`), suricata-project
  (`tools/nids/modbus_project.rules`, our rules in Suricata syntax),
  zeek-stock (default scripts), zeek-project (`tools/nids/modbus_project.zeek`,
  our rules incl. the replay check). Suricata's Modbus parser is off by
  default and is enabled for both Suricata runs.
- `detectors/nids_compare.py` maps alerts to requests and scores them like
  our detectors (same 10 test runs, same ground truth).

### Pitfalls found (and fixed)

1. Suricata Modbus `address` numbers are 1-based (protocol address 0 = rule
   `address 1`) and `>N` is strict on that number. Found by probing with
   hand-built writes to addresses 0-3. The first, 0-based rule version fired
   on normal setpoint writes (148 false alarms over 10 runs).
2. Suricata stamps an alert with the time of the packet that triggered
   inspection, which can be a later packet than the request (e.g. the next
   poll). Alerts are therefore mapped by Suricata's per-flow `tx_id`
   (n-th request on the connection), cross-checked against the logged Modbus
   transaction ID: 0 mismatches.
3. Stock rule "SURICATA Modbus Data mismatch" fires on every FC3 read
   *response* (478 alerts over the 10 runs, ~48 per run, also on the
   normal-only training session), including on a hand-built minimal exchange
   with spec-compliant byte counts for 1, 2 and 3 registers. tshark and Zeek
   report nothing wrong with those responses. They are on PLC responses, so
   they are not graded, but an operator would see them as alert noise.

### Results (10 test runs, pooled; 140 attack requests, 610 benign)

| detector | precision | recall | F1 | FPR | s per run |
|---|---|---|---|---|---|
| Suricata, stock (ET Open + modbus-events) | - | 0.000 | 0.000 | 0.000 | 101 (rule loading) |
| Zeek, stock | - | 0.000 | 0.000 | 0.000 | 2.9 |
| Suricata + our rules | 1.000 | 0.143 | 0.250 | 0.000 | 0.9 |
| Zeek + our script | 1.000 | 0.714 | 0.833 | 0.000 | 2.1 |
| ours: rule-based (Python) | 1.000 | 0.714 | 0.833 | 0.000 | |
| ours: Isolation Forest (tuned) | 0.605 | 0.929 | 0.732 | 0.139 | |
| ours: one-class SVM | 1.000 | 0.929 | 0.963 | 0.000 | |

Reading:
- Out of the box, neither tool detects any attack. Of 53,203 enabled ET Open
  rules, one mentions Modbus (an exploit for one product); nothing checks
  which registers are written or whether a request is a replay. Zeek's
  default scripts log every Modbus request (`modbus.log`) but raise nothing.
- Suricata with our rules catches only the 2 injections that break a
  per-request rule (FC16 write to HR0, setpoint 60000): signature rules
  cannot remember earlier transaction IDs, so all 8 replays per run pass.
- Zeek with our script reproduces the Python rule-based detector exactly
  (same 100 TP, 0 FP): the replay check needs per-connection state, which a
  Zeek script can keep.
- The one-class SVM remains the best detector on this traffic.
- "s per run" is a whole tool run on one ~45 s session including start-up;
  stock Suricata spends most of its 101 s loading 53k rules, which a live
  sensor does once. Not comparable to the per-request times of our detectors.

## 2026-10-16 - Second half, item 4: GRFICSv2 replication (higher-fidelity cross-check)

Repeated the detector comparison on the GRFICSv2 plant (real OpenPLC master,
3D chemical-process simulation feeding 6 Modbus remote-IO devices, ScadaBR
HMI, pfSense segmentation) instead of the Python testbed.

### Setup

- Sensor VM `ids-sensor` given a second NIC on the plant's ICS network
  (host-only #5) in promiscuous/listen-only mode (no IP while capturing), so
  it passively sees all plant Modbus/TCP traffic, like a switch mirror port.
- GRFICS VMs' host-only adapter had to be repointed #4 -> #5 (Windows had
  renamed the adapter); snapshots `before-adapter-5` taken first. The DMZ
  adapter (#3) needed a `Restart-NetAdapter` (admin) before pfSense/ScadaBR
  would attach - a VirtualBox host-only driver binding that goes stale.
- `tools/pcap_to_csv.py`: converts a passively captured pcap to our CSV
  schema (reuses the tap's frame decoder), reassembling each TCP stream by
  sequence number and skipping retransmitted bytes, and adds src_ip/dst_ip
  (the plant has real per-host IPs). Handles Ethernet and Linux-cooked links.
- `tools/grfics_attack.py`: run from the sensor (given a temporary plant IP),
  the same two attack classes against a remote-IO device - injection (FC16
  writes the PLC never makes) and replay (one verbatim reused-txid write
  resent 8x). Ground truth is by source IP.
- `detectors/grfics_eval.py`: trains on the plant's normal traffic, labels by
  source IP, groups per-connection features by (src_ip, client_port), and
  scores the same detectors.

### Normal plant traffic (3 min, 35,520 requests)

- The PLC (192.168.95.2) polls six remote-IO devices (.10-.15): FC4 reads and
  FC16 writes to register 1. The HMI (192.168.90.5) reads from the PLC through
  the firewall: FC1 (40 coils) and FC4 (13 registers). Two distinct, real
  Modbus clients - richer than the testbed's single operator.
- Connections are short-lived (the PLC reconnects), unlike the testbed's
  long-lived ones, so per-connection features had to be grouped by
  (src_ip, client_port), not port alone.

### Pitfalls found

1. Back-to-back captures with overlapping tcpdump windows put several attack
   runs in one file (counts ~2x, sessions not independent). Fixed by waiting
   for each capture window to finish before the next attack (`wait $TPID`).
2. The actuator register legitimately takes the full 0-65535 range (scaled
   process values), so the water-tank value-range rule does not apply here -
   an injected 65000 or 0 to the actuator is value-wise normal.

### Results (4 independent attack sessions; 48 attack / 11,644 benign requests)

| detector | precision | recall | F1 | FPR |
|---|---|---|---|---|
| rule-based (plant register map) | 1.000 | 0.833 | 0.909 | 0.000 |
| Isolation Forest (tuned) | 1.000 | 0.167 | 0.286 | 0.000 |
| one-class SVM | 1.000 | 0.917 | 0.957 | 0.000 |

Per attack type (one-class SVM): replay 32/32, injection 12/16.

Reading (consistent with the testbed, where the SVM led at F1 0.96):
- The one-class SVM is again the best detector, F1 0.957, no false alarms. It
  catches every replay (the transaction-ID-change feature) and the injections
  that touch an unused register.
- It misses 4 injections: the writes to the *actuator* register with in-range
  values (65000, 0). Those are "right register, in-range value, wrong sender"
  - indistinguishable on content alone. GRFICSv2 exposes the real source IP,
  so a sender-identity feature is the fix, which ties directly into the
  deferred limitation-1 work.
- Isolation Forest stays weak (0.167): it cannot use the transaction-ID
  feature (constant in normal traffic), so it catches only the unused-register
  injections.
- The rule-based detector transfers well once its register map is set to the
  plant (writes only to the actuator register; reused-txid replay): F1 0.909,
  missing the same in-range actuator injections the SVM misses.

The headline accuracy-vs-cost trade-off and the SVM's lead both hold on the
higher-fidelity plant, which is the cross-check this item set out to provide.
