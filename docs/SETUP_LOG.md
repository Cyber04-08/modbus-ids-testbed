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
