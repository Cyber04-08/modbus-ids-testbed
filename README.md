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

Phase 1 in progress: a pure-Python Modbus/TCP PLC simulator
(`testbed/plc_simulator.py`) is running and verified reachable, standing in
for OpenPLC/GRFICS while the VM-based testbed is evaluated. See
`docs/SETUP_LOG.md` for details and the current plan.

## Quick start

```
pip install pymodbus==3.7.4
python testbed/plc_simulator.py     # starts the simulated PLC on 127.0.0.1:5020
python testbed/client_test.py       # sanity-check read/write against it
```
