# Pre-Work Notes: Related Work

Notes on the two papers named in the kickoff checklist. Initial pass
(2026-09-15, morning) was built from abstracts/indexed excerpts only,
since Wiley Online Library, ResearchGate, and the MSU repository all
returned HTTP 403 to automated fetching from this environment. **Updated
2026-09-15 (afternoon) after getting the full PDFs directly** (both are
open access - the 403s were bot-blocking, not a real paywall; a browser
got through fine). All metrics below are now confirmed from the full
text, not inferred.

Full PDFs saved locally:
`Downloads/Security and Communication Networks - 2021 - L - Detection and
Blocking of Replay  False Command  and False Access.pdf` and
`Downloads/Morris & Gao.pdf`.

## Wiley paper - Rajesh, L. & Satyanarayana, P. (2021)

"Detection and Blocking of Replay, False Command, and False Access
Injection Commands in SCADA Systems with Modbus Protocol." *Security and
Communication Networks*, vol. 2021, Article ID 8887666, 15 pages. DOI:
[10.1155/2021/8887666](https://onlinelibrary.wiley.com/doi/10.1155/2021/8887666).
Open access (Hindawi/Wiley, CC-BY).

- **Attack scope:** replay attacks, False Command Injection (FCI), False
  Access Injection (FAI) - same replay + injection focus as this project,
  plus FAI (essentially a DoS variant: flooding the PLC with malformed
  requests) which isn't currently in this project's scope.
- **Testbed: real hardware, not simulated.** A physical SCADA testbed in
  their lab - Schneider M340 PLC, two real water tanks, real pumps/valves,
  Vijeo Citect SCADA HMI, Ettercap for MITM/ARP spoofing, Wireshark for
  capture. This is a meaningfully different validation approach from this
  project's simulated/virtualized testbed - worth noting explicitly as a
  limitation/difference, not just a similarity.
- **Method: rule-based / deterministic, not ML.** Two components:
  1. **Replay detection:** adds a 2-byte sequence number + 8-byte
     timestamp to every Modbus frame (10 bytes total). Receiver checks the
     sequence number matches and the timestamp is within a threshold
     (they used 500 ms in testing); rejects the frame otherwise.
  2. **Frame-filtering module (FCI/FAI):** a gateway process between
     HMI and PLC that only forwards requests from configured IPs, with
     configured function codes, within configured memory-address ranges;
     everything else is dropped.
  Both are implemented as separate gateway modules (not built into the
  PLC/HMI), so existing legacy devices don't need firmware changes -
  though the *frame itself* is still modified in transit for the replay
  scheme, and both peers must run the gateway software.
- **Metrics - now confirmed:**
  - **Attack Block Rate (ABR) = 97%** of simulated FCI/FAI attacks
    blocked. This is their headline metric, not precision/recall/F1 in
    the conventional ML sense - it's closer to a true-positive rate for
    the filtering module specifically (they separately describe 3%
    getting through as escaping). No false-positive rate on *legitimate*
    traffic is reported - they don't show the module rejecting valid
    HMI commands, so FPR on benign traffic is not directly measurable
    from this paper.
  - **Frame-size overhead:** 4% on read requests, 77% on
    write/command frames (Table 5) - the higher figure for writes makes
    sense since write frames are naturally shorter to begin with, so the
    fixed 10-byte addition is a bigger relative hit.
  - **Latency: yes, they do measure it** - 16 ms average round-trip delay
    at a 1000 ms poll interval, i.e. **1.6% timing overhead**. (Corrects
    the earlier note that this was unconfirmed.)
  - They compare against two other papers' overhead numbers: 291% frame
    overhead in Fovino et al. and 66% latency in Ferst et al. - their
    solution is presented as far lighter-weight than those.
- **Key structural difference from this project:** their replay defense
  requires modifying the Modbus frame format itself and running gateway
  software at both ends - it isn't a passive detector, it's a protocol
  change. It's also evaluated as a single combined system (ABR across
  both attack types together), not as two independently comparable
  detection approaches. This project's rule-based and ML detectors are
  both passive observers of *unmodified* Modbus/TCP traffic - no protocol
  or endpoint changes required - and are evaluated head-to-head on the
  same traffic with the same metrics.

## Morris dataset paper - Morris, T. & Gao, W. (2014)

"Industrial Control System Traffic Data Sets for Intrusion Detection
Research." *Critical Infrastructure Protection VIII*, IFIP AICT vol. 441,
pp. 65-78, 2014.

- **Attack categories (7, from 28 individual attacks):** Naive Malicious
  Response Injection (NMRI, 8 variants - e.g. zeroed/randomized payloads,
  negative sensor values, out-of-bounds injection), Complex Malicious
  Response Injection (CMRI, 5 variants - designed to *look* normal, e.g.
  constant-value masking, replayed measurements), Malicious State Command
  Injection (MSCI, 3 variants - e.g. flipping auto/manual mode then
  toggling the pump/compressor), Malicious Parameter Command Injection
  (MPCI, 2 variants - altering setpoints/PID parameters), Malicious
  Function Code Injection (MFCI, 4 variants - e.g. forcing listen-only
  mode, forcing a device restart), Denial of Service (2 variants - bad
  CRC flooding, traffic jamming), Reconnaissance (4 variants - address
  scan, function-code scan, device ID, points/memory-map scan).
- **Testbeds:** laboratory-scale gas pipeline (pressure, PID-controlled,
  compressor + relief valve) and water storage tank (level, on/off
  controlled, pump + manual drain valve) - notably **Modbus RTU over
  RS-232 serial, not Modbus/TCP.** Captured via a bump-in-the-wire serial
  logger, not a network tap.
- **Labeling:** every instance is one merged query/response transaction
  pair, labeled 0-7 (Normal, NMRI, CMRI, MSCI, MPCI, MFCI, DoS,
  Reconnaissance) - explicitly modeled on the KDD Cup 1999 labeling
  convention. This project's planned timestamp-based labeling is
  compatible in spirit (ground truth from known attack-injection timing)
  but per-packet/per-transaction rather than requiring a merged
  query+response instance - worth deciding whether to match their
  per-transaction granularity or label at the raw-packet level.
- **Public availability: yes**, 4 datasets in ARFF/WEKA format (full +
  10%-sample for each of the two systems), hosted at
  https://sites.google.com/a/uah.edu/tommy-morris-uah/ics-data-sets.
  (This page also lists related later datasets - an improved "New Gas
  Pipeline" set and a power-system set - not from this 2014 paper itself.)
- **No detection results in this paper** - it is purely a dataset/testbed
  description paper, not an evaluation of any detector. (The "unintended
  patterns that inflate ML accuracy" caveat for the original release comes
  from the UAH hosting page's own notes, not from this paper - the paper
  itself makes no such claim, which is worth being precise about when
  citing it.)

### Is the Morris/MSU dataset usable as a validation baseline?

Usable only as a **secondary sanity check or feature reference, not a
primary training/validation set**, for two reasons:

1. **Protocol mismatch.** It's Modbus RTU (serial framing), this project is
   Modbus/TCP (MBAP header framing). A detector's features/invariants
   won't transfer directly - TCP-specific fields (transaction ID, MBAP
   header) that this project's rule-based detector will likely use don't
   exist in RTU traffic.
2. **Known artifact contamination** flagged on the dataset's own hosting
   page (not in the paper) for the original release; a corrected "New Gas
   Pipeline" dataset exists but is also RTU.

Reasonable use: cite it in related work, optionally borrow its attack
taxonomy (NMRI/CMRI/MSCI/MPCI/MFCI/DoS/Reconnaissance) as a reference
point for how comprehensively this project's own attack set covers known
ICS attack classes, but generate the actual training/evaluation data from
this project's own Modbus/TCP testbed.

## Differentiation note (for the report's related-work section)

> Rajesh & Satyanarayana (2021) defend Modbus against replay, false
> command, and false access injection using a rule-based approach that
> modifies the wire format itself (a sequence number and timestamp added
> to every frame) and a gateway frame-filter, validated on a real hardware
> SCADA testbed; it reports a 97% attack block rate with 4-77% frame-size
> overhead and 1.6% latency overhead, but evaluates only its own combined
> rule-based system - not a comparison against a learned/statistical
> detector - and requires both communicating endpoints to run new gateway
> software rather than passively observing unmodified traffic. Morris &
> Gao (2014) provide a labeled attack dataset covering a broader attack
> taxonomy (7 classes, 28 attacks) but over Modbus **RTU/serial**, not
> TCP, with no detector evaluation of their own. This project instead runs
> a live, **unmodified** Modbus/TCP testbed and directly compares a
> rule-based detector against an ML anomaly detector on the *same*
> traffic under the *same* conditions, reporting not just detection
> accuracy but per-packet processing latency and memory overhead for each
> - the head-to-head, passive-detection, operational-cost comparison that
> neither prior work provides.

## Open TODOs

- [x] ~~Get full-text access to the Wiley paper~~ - done 2026-09-15, both
      papers downloaded directly, metrics above are confirmed from source.
- [ ] Cross-check the rule-based detector's invariant list against what
      the Wiley paper's frame-filtering module actually checks (IP
      allowlist, function-code allowlist, address-range allowlist per
      master) before finalizing it, per the checklist.
- [ ] Decide whether to adopt Morris & Gao's per-transaction labeling
      granularity (merged query+response instance) or label at the raw
      packet level for this project's dataset.
