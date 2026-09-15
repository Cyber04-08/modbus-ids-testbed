# Pre-Work Notes: Related Work

Notes on the two papers named in the kickoff checklist, gathered 2026-09-15.
Full text of both papers is paywalled/blocked to automated fetching from
this environment (Wiley Online Library and ResearchGate both returned
HTTP 403); notes below are built from the papers' own abstracts, indexed
excerpts, and (for the Morris dataset) its public hosting page. Treat the
Wiley paper's metrics as **unconfirmed** until read directly - flagged below.

## Wiley paper - Rajesh, L. & Satyanarayana, P. (2021)

"Detection and Blocking of Replay, False Command, and False Access
Injection Commands in SCADA Systems with Modbus Protocol." *Security and
Communication Networks*, 2021. DOI: [10.1155/2021/8887666](https://onlinelibrary.wiley.com/doi/10.1155/2021/8887666)

- **Attack scope:** replay attacks, false command injection, false access
  injection - the same two attack classes (replay, injection) this project
  targets, plus a third (false access) not currently in scope here.
- **Method: rule-based / deterministic, not ML.** Adds a 2-byte sequence
  number and 8-byte timestamp into the Modbus frame (10 bytes total
  overhead), then uses a frame-filtering module that validates
  sequence/timestamp on receipt and blocks frames that fail (catches
  replay) or aren't authorized (catches false command/access injection).
- **Metrics confirmed so far:** frame-size overhead (10 bytes/frame),
  reported in the paper's Table 5.
- **Metrics NOT yet confirmed:** precision, recall, F1, false-positive
  rate, and whether they measure end-to-end detection *latency* (ms) as
  opposed to just static frame-size overhead - **read the full PDF to
  confirm before citing any number in the report.**
- **Key structural difference from this project:** their approach modifies
  the Modbus wire format itself (adding fields to every frame), which
  requires both ends to be updated and isn't backward-compatible with
  unmodified Modbus devices. A rule-based *or* ML detector that watches
  unmodified traffic (this project's approach) requires no protocol
  changes and works against existing devices as-is.

## Morris dataset paper - Morris, T. & Gao, W. (2014)

"Industrial Control System Traffic Data Sets for Intrusion Detection
Research." *Critical Infrastructure Protection VIII*, IFIP AICT vol. 441,
2014.

- **Attack categories (7):** Naive Malicious Response Injection (NMRI),
  Complex Malicious Response Injection (CMRI), Malicious State Command
  Injection (MSCI), Malicious Parameter Command Injection (MPCI),
  Malicious Function Code Injection (MFCI), Denial of Service (DoS),
  Reconnaissance.
- **Testbeds:** laboratory-scale gas pipeline and water storage tank
  systems - notably **Modbus RTU (serial), not Modbus/TCP.** This is an
  important protocol-format caveat, see below.
- **Labeling:** ground-truth labels applied from the timing of scripted
  attack execution against the testbed (matches this project's planned
  timestamp-based labeling approach).
- **Public availability: yes.** Hosted at Tommy Morris's dataset page:
  https://sites.google.com/a/uah.edu/tommy-morris-uah/ics-data-sets -
  raw data (ARFF format) and 10%-sample subsets for both the gas pipeline
  and water storage tank systems, plus related power-system and gas
  pipeline datasets from follow-on work.
- **Known dataset flaw (per the authors' own site):** the original gas
  pipeline / water storage tank dataset contains "unintended patterns"
  that produce artificially inflated ML detection results. A corrected
  "New Gas Pipeline" dataset (Turnipseed's thesis) was released later to
  fix this - use that corrected version, not the original, if the MSU data
  is used at all.

### Is the Morris/MSU dataset usable as a validation baseline?

Usable only as a **secondary sanity check or feature reference, not a
primary training/validation set**, for two reasons:

1. **Protocol mismatch.** It's Modbus RTU (serial framing), this project is
   Modbus/TCP (MBAP header framing). A detector's features/invariants
   won't transfer directly - TCP-specific fields (transaction ID, MBAP
   header) that this project's rule-based detector will likely use don't
   exist in RTU traffic.
2. **Known artifact contamination** in the original release (see above);
   would need the corrected New Gas Pipeline dataset specifically, and
   even that is still RTU.

Reasonable use: cite it in related work, optionally use it to sanity-check
that the *attack categories* (esp. command injection) look similar in
shape, but generate the actual training/evaluation data from this
project's own Modbus/TCP testbed.

## Differentiation note (for the report's related-work section)

> Prior work either hardens the Modbus/TCP wire format itself (Rajesh &
> Satyanarayana, 2021 - a rule-based timestamp/sequence-number scheme that
> requires modifying every frame and both endpoints, evaluated on frame-size
> overhead rather than runtime detection cost) or supplies labeled attack
> traffic for offline model training on Modbus **RTU/serial** testbeds
> (Morris & Gao, 2014 - with the authors' own documented caveat that the
> released dataset contains artifacts that inflate ML accuracy). This
> project instead runs a live, unmodified Modbus**/TCP** testbed and
> directly compares a rule-based detector against an ML anomaly detector on
> the same traffic, measuring not just detection accuracy but per-packet
> processing latency and memory overhead - the operational-cost dimension
> neither prior work reports for their own method.

## Open TODOs

- [ ] Get full-text access to the Wiley paper (library proxy / interlibrary
      loan) and confirm or correct the precision/recall/F1/FPR and latency
      claims above before the report is finalized.
- [ ] Cross-check the rule-based detector's invariant list against what the
      Wiley paper's frame-filtering module actually checks, per the
      checklist.
