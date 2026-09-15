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

## Next steps (Phase 1 remainder / Phase 2 start)

- [ ] Validate the rule-based detector's invariant list against what the
      Wiley paper (Rajesh & Satyanarayana, 2021) actually checks before
      finalizing it (see `docs/PREWORK_NOTES.md`).
- [ ] Capture a baseline "normal" traffic window from the simulator with
      varying setpoints to build the normal-traffic dataset.
- [ ] Decide whether to also stand up OpenPLC (native ladder-logic PLC) in
      parallel for a more authentic PLC, or keep the Python simulator as the
      system of record and treat OpenPLC/GRFICS as a stretch goal.
