# Reverse Engineering Evidence and Claim Boundaries

This document records how reverse engineering evidence is interpreted in
`goodix550a-linux`. It exists to keep implementation decisions, validation results,
and security claims separate from one another.

The project reconstructs the Linux host behavior required to operate the Goodix
`27c6:550a` fingerprint reader (GF3258 WN2 / GM168SEC). No public protocol or
matcher specification was available. Proprietary source code was not available.
Static binary analysis, USB traces, runtime instrumentation, and controlled
experiments were therefore used as evidence for an independently written
implementation.

This file does not attempt to reproduce the full engineering history. It defines
what kinds of evidence support a claim, how disagreements are handled, and where
the current evidence stops.

## Evidence terms

The project uses the following terms consistently.

| Term | Meaning |
| --- | --- |
| **Observed** | Present in a captured trace, runtime value, device response, or other recorded output under stated conditions |
| **Recovered** | Established from the structure or instruction behavior of the analyzed host binary |
| **Validated** | Reproduced by the independent implementation at an observable boundary, or confirmed by a controlled hardware trial |
| **Inferred** | Consistent with the available evidence but not uniquely established by it |
| **Unresolved** | Evidence is insufficient to choose among plausible explanations or to implement the behavior without guessing |

These terms are not a confidence ranking. They describe the source and status of a
claim.

A fact can be both recovered and validated. For example, an arithmetic operation
may first be recovered from instructions in the reference binary and later
validated when the independent implementation reproduces the same intermediate
output. An observation obtained only through runtime instrumentation remains an
instrumented observation until another source of evidence supports the same claim.

`Validated` is always scoped. Agreement on one retained fixture establishes
agreement for that fixture. A successful trial on the development sensor
establishes behavior for that sensor and experimental condition. Neither implies
population-wide behavior.

## Sources of evidence

### Static binary analysis

The stripped reference host binary was used to recover call relationships,
structure offsets, constants, packet construction, fixed-point arithmetic,
cryptographic data flow, and bounded verification control flow.

Static analysis is strongest when instruction behavior determines a result
directly. It becomes less conclusive when meaning depends on data supplied by
another component, hidden device state, asynchronous behavior, or a caller whose
semantics have not yet been recovered.

Names assigned during analysis are descriptive conveniences. They are not evidence
that the reference implementation used the same abstractions or terminology.

### USB traces

Controlled runs of the reference stack were used to observe command framing,
transfer ordering, APP and IAP behavior, persisted-object reads, D2 session setup,
finger-detection sequencing, image transfers, and firmware-transfer behavior.

A trace establishes what crossed the USB boundary during that run. It does not, by
itself, establish why a value was chosen, whether another device would behave the
same way, or whether the value is security-sensitive.

Trace absence is also weak evidence. A host-side operation may leave no visible USB
effect, and device state may persist across commands or sessions.

### Runtime instrumentation

Runtime instrumentation was used when USB observations or static analysis did not
expose enough state to distinguish competing models. Selected function and buffer
boundaries provided intermediate image planes, feature records, descriptors,
enrollment state, matcher candidates, and verification decisions.

Instrumentation is treated as an observation mechanism, not as a neutral window
into the system. Breakpoints, tracing, altered process layout, and additional
runtime work can change timing or execution state. When a conclusion depends only
on an instrumented run, the documentation says so. Where possible, the conclusion
is checked against an independent trace, deterministic fixture, or physical-device
trial.

### Controlled experiments

Controlled experiments vary one relevant condition while holding the rest of the
setup as stable as practical. The project has used startup state, power loss,
capture quality, spatial transformations, genuine and impostor comparisons, and
selected intermediate values to distinguish competing explanations.

The aim is not to collect examples until an implementation appears to work. The
aim is to choose experiments whose outcomes separate plausible models.

A negative result can therefore be useful. If replay, endpoint substitution, or a
candidate reconstruction fails at a specific boundary, that failure can identify
state or behavior that the current model does not explain.

## Reconstruction loop

The working loop is:

```text
observation
    -> hypothesis
    -> minimal independent implementation
    -> differential comparison
    -> controlled hardware trial where needed
    -> retain, revise, or reject
```

Not every recovered component exposes the same intermediate state. Where an
observable boundary is available, a candidate reconstruction is retained only when
the independent implementation reproduces the expected intermediate state or
device behavior.

End-to-end success is not treated as sufficient evidence of parity. Two different
internal models can produce the same enrollment or verification result. When an
intermediate value, protocol transition, failure path, or state change is
observable, disagreement there takes precedence over a plausible final outcome.

Conversely, the independent implementation is not required to reproduce internal
details that are not externally relevant merely because they exist in the
reference binary. Compatibility claims concern behavior that can be tied to the
device, persisted state, public interface, or desktop authentication path.
Implementation choices may differ where the evidence does not require equivalence.

## Differential evidence

Differential tests compare the independent implementation with retained reference
evidence at selected boundaries. Depending on the component, this may include
packet bytes, reconstructed image values, feature records, descriptors, template
state, matcher candidates, or final decisions.

A differential match supports the specific boundary and input under test. It does
not prove that two implementations are equivalent for all inputs.

A mismatch is not repaired by tuning thresholds or changing semantics until the
test passes. The mismatch is first treated as evidence that at least one assumption
is wrong or incomplete. The relevant stage is isolated before the recovered
behavior is changed.

Some verification-policy regions are represented in the source tree as compact
transcriptions of bounded integer control flow from the analyzed binary. Their
source-artifact and program-manifest hashes provide traceability. A change to those
semantics requires new evidence rather than stylistic cleanup alone.

## Hardware validation

Hardware tests answer questions that deterministic software tests cannot.

The current validation layers are:

| Layer | What it establishes |
| --- | --- |
| Unit and public API tests | Deterministic software behavior for arithmetic, parsers, packets, state machines, persistence, and cross-module invariants |
| Offline parity tools | Agreement with retained reference evidence at selected intermediate boundaries |
| Live diagnostics | Narrow device behavior such as version, OTP, configuration, D2, and chip identification |
| Standalone workflows | Capture, enrollment, persistence reload, and verification on the physical sensor |
| libfprint probes | Enrollment and verification through the public libfprint integration path |

Ordinary `cargo test` does not open the sensor. A green test run therefore does not
establish live-device correctness or security.

Current hardware evidence comes from one physical sensor. Claims about provisioning,
device uniqueness, biometric accuracy, firmware variation, or population behavior
require additional devices or data. The README states this limit explicitly.

## State and lifecycle claims

The device and host stack are stateful. A response observed after warm startup
cannot automatically be generalized to cold IAP state, a restarted service,
re-enumeration, suspend, or a later D2 session.

When a claim depends on lifecycle state, the relevant state belongs in the evidence
record. Important distinctions include:

* APP versus IAP firmware state;
* warm startup versus cold bootstrap;
* volatile state before and after power loss;
* state within one D2 capture session versus a later session;
* process restart versus device reset or USB re-enumeration;
* enrollment state versus persisted template state.

Unexplained state dependence is recorded as unresolved rather than normalized away
in the implementation.

## Security claim boundary

Recovered behavior is not automatically a vulnerability.

The project uses the following progression:

```text
recovered or observed mechanism
    -> security-relevant question
    -> attacker model
    -> reproducible experiment
    -> demonstrated security impact
```

A security-relevant observation becomes an attack hypothesis only when the attacker
capability and the property that may be violated are stated. A vulnerability claim
requires a reproducible path and demonstrated impact.

For example, the current reconstruction establishes that the D2 command and image
response together contain the inputs used by the legitimate host to decrypt a
capture. That does not, by itself, establish that an attacker can obtain those
transfers on a deployed system, authenticate a replayed image, or bypass desktop
authentication.

Similarly, the recovered mode-1 persisted-object HMAC does not cover the CBC IV.
That cryptographic property is reproducible offline. Its system impact remains a
separate question until object substitution and a security-relevant consequence are
demonstrated.

The repository therefore distinguishes:

* a structural or cryptographic property;
* an attacker capability;
* a successful manipulation;
* an authentication or confidentiality consequence.

The first does not imply the last three.

## Biometric evidence boundary

The project uses researcher-owned biometric samples to exercise enrollment and
verification. These trials establish that the reconstructed path operates on the
development sensor and that selected genuine and impostor cases reach the expected
workflow outcomes.

They do not establish population-level false match or false nonmatch rates,
presentation attack resistance, demographic performance, or general biometric
accuracy.

Population studies, presentation attacks, or experiments involving additional
participants require a separate evaluation design and appropriate data handling.

## Provenance and public artifacts

The Rust and C implementation was written independently from analysis of a stripped
reference binary, USB traces, runtime instrumentation, and controlled experiments.
The finished driver does not load or link the proprietary Goodix host library.

The public repository does not include fingerprint images, biometric templates,
USB captures, memory dumps, vendor binaries, firmware images, decompiler projects,
disassembly dumps, credentials, or device-specific secrets.

Recovered constants, protocol fields, structure layouts, hashes, and small
non-biometric regression values may remain in the source where they are necessary
to implement or trace a recovered behavior. These are recorded as implementation or
evidence artifacts; their presence does not establish that a value is
device-specific.

External parity fixtures are not distributed. They were retained outside the public
tree as reference evidence. Independent reproduction of those comparisons requires
separately collected evidence.

## What this document does not claim

This evidence process does not establish that:

* the reconstructed implementation is equivalent to the reference implementation
  for every possible input;
* behavior seen on the development sensor applies to every `27c6:550a` device;
* encrypted image transport authenticates image origin or freshness;
* a recovered weakness is exploitable on a deployed system;
* a successful genuine or impostor trial measures biometric error rates;
* the current implementation has been security audited;
* every internal behavior of the reference implementation should be preserved.

These are separate claims and require separate evidence.

## Updating a recovered behavior

A change to parity-sensitive behavior should identify why the previous model was
insufficient and what new evidence supports the replacement.

Useful evidence includes:

* a new reference trace under a controlled state;
* a runtime observation at a previously unavailable boundary;
* a deterministic differential mismatch that isolates the responsible stage;
* a hardware trial that distinguishes competing state models;
* a correction to the analyzed instruction semantics.

A refactor that changes naming, ownership, module boundaries, or ordinary Rust
structure need not preserve the shape of the reference binary. A refactor that
changes recovered arithmetic, protocol bytes, state transitions, persistence
layout, matcher policy, or other parity-sensitive behavior requires new evidence
and corresponding tests.

## Relationship to the other project documents

[README.md](README.md) describes what currently works, the main validation limits,
the security-relevant observations, and the research questions that follow from the
reconstruction.

[RESEARCH.md](RESEARCH.md) contains the broader threat models, prior-work discussion,
and study designs. Questions in that document are proposals for experiments, not
claims that the corresponding attacks or protections have already been
demonstrated.

This file sits between them. Its purpose is narrower: to make clear what the project
knows, how it knows it, and where the evidence ends.