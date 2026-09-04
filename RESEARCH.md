# Research Questions and Experimental Design

This note expands the research questions listed in [README.md](README.md). It
describes the experiments that the reconstructed Goodix `27c6:550a` host path
makes possible, the attacker and failure models needed to interpret those
experiments, and the evidence required before a result is generalized.

The independent implementation provides the experimental surface. It exposes
protocol state, decrypted sensor data, host-side biometric processing, enrollment
and template state, verification decisions, and the libfprint integration path
without loading the proprietary Goodix host library.

The starting evidence and claim rules are defined in
[REVERSE_ENGINEERING.md](REVERSE_ENGINEERING.md). Proposed experiments in this
file do not change those rules. An experiment may refine a model, reject a
hypothesis, or establish a security consequence. Listing an experiment here is
not a claim that the corresponding attack or protection has already been
demonstrated.

Current hardware evidence comes from one physical GF3258 WN2 sensor. Studies that
depend on device variation, biometric population behavior, or comparisons with a
different architecture require additional hardware or data.

## Questions

The README identifies four questions that grew out of the reconstruction. They
form the structure of the work below.

### 1. Specification recovery

How much of a stateful hardware and software interface can be described reliably
when there is no authoritative specification and the reference implementation is
visible only through binary structure and runtime behavior?

The immediate goal is not a complete formal specification. It is an explicit
behavioral model that records:

* commands and responses that are stable at the USB boundary;
* host and device state required before those commands are accepted;
* state that persists across capture sessions, process restarts, reset, or power
  loss;
* failure and recovery behavior that changes later transitions;
* observations that remain dependent on runtime instrumentation;
* behavior that is known only for the development sensor or firmware identity.

A useful model must predict held-out behavior. If two candidate models explain the
same recorded trace, the next experiment should be chosen to separate them rather
than to collect another example of the same path.

Instrumentation effects are part of this question. A transition seen only while a
process is stopped at a breakpoint is weaker evidence than the same transition
confirmed through a USB trace or an uninstrumented hardware trial. Timing-sensitive
claims should therefore include an uninstrumented baseline before they are treated
as stable behavior.

### 2. Conformance

What should it mean for an independent implementation to conform to an
undocumented reference stack?

Final enrollment or verification results are too coarse. At the same time, an
independent implementation should not be required to reproduce internal data
structures or control flow that have no externally relevant effect.

The working conformance surface should therefore be limited to behavior that can
be tied to the device, persisted state, public API, or desktop authentication path.
Candidate dimensions include:

* packet contents and transaction ordering;
* state transitions required by the device;
* session-scoped and persisted state visible across operations;
* accepted and rejected failure paths;
* recovery after disconnect, reset, restart, and suspend;
* serialized template behavior at the public boundary;
* final libfprint enrollment and verification outcomes;
* ranges of device responses that may legitimately vary across repeated runs.

A conformance test should state which dimension it exercises and which variations
are allowed. A match on one fixture or one physical trial does not establish
equivalence for all inputs.

### 3. Compatibility and isolation

Which externally required behaviors can be preserved while reducing privilege,
shared sensitive state, or the amount of host code that must be trusted?

The current match-on-host path handles the reconstructed image, feature state,
template data, matcher state, and final decision on the host. Before proposing a
different architecture, the existing trust path needs to be measured.

A baseline should identify:

* which processes can open the sensor;
* which principals can enroll and request verification;
* which components can read or replace persisted templates;
* where raw images, keys, feature records, scores, and final decisions exist;
* which components can influence the terminal authentication result;
* how cancellation, process failure, restart, suspend, and teardown cross those
  boundaries.

Only after that baseline is known does an isolation prototype become informative.
A comparison can then ask whether moving device I/O, parsing, biometric processing,
storage, or decision generation behind a narrower boundary changes privilege,
reachable interfaces, sensitive-state exposure, fault containment, or login
behavior.

Process separation is not a research result by itself. The result would come from
a stated attacker or failure model and a measured difference from the baseline.

### 4. Runtime checks and interference

Can recovered protocol or state invariants be checked during normal execution
without materially changing the behavior they are intended to check?

Candidate checks must come from recovered or validated behavior. Examples include
legal lifecycle transitions, session ownership, packet and state relationships,
template-state consistency, or teardown conditions. A new rule invented solely as
a security policy should be labeled as such rather than presented as recovered
behavior.

For each check, the experiment should identify:

* the event that triggers it;
* the component in which it runs;
* the state it reads or retains;
* the violation it can observe;
* the expected response to a violation;
* the added work on the normal path.

The baseline and checked paths should then be compared for capture latency,
end-to-end login latency, cancellation, suspend and resume, recovery after device
or process failure, and any change in protocol behavior. If checking changes the
frequency or type of failures, that change is itself a result that must be
explained.

The aim is not simply to minimize overhead. A check that is inexpensive but misses
the relevant transition is not useful, and a check that perturbs the device enough
to change the behavior under study cannot be treated as a neutral monitor.

## Attacker and failure models

Security experiments need narrower capabilities than "the host is compromised."
A fully compromised host can forge a host-side match decision directly, which
makes it a poor model for testing whether USB replay alone is sufficient.

The following capabilities should be kept separate:

| Model | Capability |
| --- | --- |
| Passive USB observer | Records transfers but cannot alter them |
| Active USB intermediary | Delays, drops, reorders, replays, or substitutes transfers |
| Replacement endpoint | Presents the expected USB identity and implements some or all of the device protocol |
| Local process with sensor access | Opens the reader using permissions available to a local session |
| Local process with template access | Reads or replaces persisted print data |
| Compromised host component | Controls one selected host component but not the complete authentication path |
| Fully compromised authentication host | Controls host-side processing and authorization; useful as an upper bound, not as proof of a USB-only attack |

Failure experiments should also distinguish accidental faults from adversarial
behavior. Relevant failures include malformed responses, stalls, disconnects,
unexpected re-enumeration, process termination, service restart, and loss of
volatile device state.

An experiment should state the smallest capability needed to produce the tested
variation. A result obtained with a replacement endpoint does not automatically
apply to a passive observer or an unprivileged local process.

## Near-term study

The current repository already supports three direct experiments. These come
before broader architecture changes.

### Trace recovery and replay

The D2 command carries 32 host-generated bytes. Bytes 16 through 31 are used as the
AES-128 image key. The image response contains a 5-byte header, 10,560 bytes of
AES-128-CBC ciphertext, and a CRC over the decrypted image. A complete trace
containing both transfers therefore contains the decryption inputs used by the
legitimate host.

The first step is an offline tool that accepts a recorded D2 command and image
response and reconstructs the `80 x 64` sensor samples. This tests what the trace
contains, not who can obtain it.

The next step is controlled response substitution:

1. replay a response within the same D2 session;
2. replay it under a new D2 session;
3. alter the timing or ordering without changing the recorded response;
4. record the first layer and state that accepts or rejects each variation.

Successful offline recovery establishes a confidentiality consequence for an
observer that already has the trace. It does not establish USB access on a deployed
system or an authentication bypass.

A failed replay is equally useful when the reason is isolated. It may identify a
session relationship, challenge, device state, or higher-layer check that is absent
from the current model.

### Endpoint identity and lifecycle continuity

USB vendor and product IDs identify the vendor and product values reported by an
endpoint; they are not cryptographic proof of physical device identity. Linux's
USB authorization documentation explicitly warns against relying on descriptor
information for secure identity and recommends cryptographic authentication when
identity matters.

A minimal virtual endpoint can reproduce only the startup and capture behavior
needed for a controlled replacement experiment. The endpoint can then be inserted
at selected lifecycle transitions:

* before initial startup;
* after a completed capture;
* after USB re-enumeration;
* after a service restart;
* after device reset;
* after suspend and resume;
* across APP and IAP transitions where the experiment can be performed safely.

The useful result is not simply whether replacement succeeds. The experiment
should identify which component and which state distinguish the expected endpoint
from a protocol-compatible replacement.

The same harness can test stale state. If state from an earlier session is accepted
after restart or re-enumeration, the experiment should determine whether the
continuity comes from the device, driver, daemon, persisted storage, or another
layer.

### Authentication policy composition

The desktop path spans the kernel USB model, libfprint, fprintd, D-Bus, PAM, and
template storage. Retry, cancellation, enrollment authority, failure handling, and
authorization may therefore be properties of the composed path rather than of one
component.

One authentication request should be traced end to end while varying:

* matcher rejection;
* malformed or rejected device input;
* cancellation;
* disconnect and reconnect;
* fprintd restart;
* process termination;
* device reset;
* suspend and resume.

The result should be a state and authority map. In particular, it should record
which component increments, preserves, resets, or ignores attempt-related state,
and which component ultimately turns a matcher result into an authentication
decision.

This study is related to prior work on biometric attempt-limit failures, but it
does not assume that a smartphone attack transfers to this Linux path. The object
of study is the invariant implemented by this particular composition of device,
driver, daemon, and authorization layers.

## Studies enabled by the baseline

The following studies become defensible after the near-term measurements establish
the current lifecycle and trust boundaries.

### Authority and sensitive-data lifetime

The baseline should identify which local principals can open the sensor, enroll a
print, request verification, read or replace templates, or obtain intermediate
data.

Sensitive data should be tracked by type and lifetime rather than described as one
undifferentiated "biometric data" category. Relevant objects include:

* raw reconstructed images;
* D2 session material;
* extracted feature state;
* enrollment state;
* persisted TGLA data;
* matcher scores and candidate state;
* the terminal match decision.

The study can examine process memory, core-dump eligibility, swap behavior, logs,
temporary files, serialized print data, and persistent storage as applicable. It
must account for the active udev rules, D-Bus policy, PAM entry points, file
permissions, and mandatory access-control policy.

A data item being present on the host is not itself a vulnerability. The security
question depends on which principal can obtain it, how long it remains available,
and what property that access would violate.

### Isolation and failure containment

Once the current authority and data paths are measured, one narrow boundary can be
changed and compared with the baseline.

A useful first prototype would isolate only a component with a clear untrusted
input boundary, such as device I/O or packet parsing, rather than redesigning the
entire biometric stack at once.

Evaluation should include:

* privileges removed from the isolated component;
* interfaces still reachable from it;
* state shared across the boundary;
* malformed-input containment;
* behavior after a stalled or terminated component;
* cancellation and teardown;
* suspend and resume;
* recovery without reboot or re-enrollment;
* capture and login latency.

The contribution, if any, comes from the measured trust reduction and system cost.
Choosing a process boundary, sandbox, or language mechanism is an implementation
decision unless the comparison establishes something broader.

### Runtime invariant checking

After protocol and lifecycle invariants are stable enough to state, selected rules
can be checked on the independent path.

A first study should use a small number of invariants with different trigger
locations, for example one at USB transaction completion, one at a session
transition, and one at template or decision handling. The exact invariants should
come from the reconstruction rather than from a desire to maximize the number of
checks.

For each rule, compare:

```text
baseline path
checked path
fault-injected path
```

Measurements should include the normal latency distribution, the extra state
retained by the checker, detection point, response to a violation, recovery
behavior, and any new timeouts or retries.

The experiment should also test the observer effect directly. If enabling a check
changes protocol timing enough to alter device behavior, the checked execution is
not equivalent to the baseline merely because both eventually return the same
authentication result.

A later comparison can ask whether a smaller set of checks retains useful
diagnostic or security value at lower runtime cost. The tradeoff should be measured
rather than assumed from a fixed overhead target.

### Hardwareless-test fidelity

The deterministic suite validates pure logic and selected protocol invariants, but
it cannot predict every physical-device behavior.

A virtual endpoint can be extended incrementally with:

* packet ordering;
* zero-length transfers;
* delays and deadlines;
* reset behavior;
* re-enumeration;
* stale or missing state;
* malformed responses;
* disconnects.

Each additional behavior should earn its place by improving prediction of a known
hardware outcome. Model variants can be evaluated against held-out traces and
controlled hardware trials.

The useful result is the minimum fidelity required to predict each class of
failure. A larger emulator is not automatically a better experimental model.

## Later biometric studies

The recovered TGLA representation and executable matcher permit questions about
template binding, linkability, mutation, and reconstruction. These are separate
from the immediate systems work.

Possible studies include:

1. whether templates from separate enrollments of the same finger can be linked;
2. whether a persisted template is bound to a sensor, user, installation, or host;
3. whether controlled template mutation changes acceptance under the recovered
   matcher;
4. how much fingerprint structure can be approximated from the stored
   representation;
5. whether a reconstructed representation transfers to a different matcher;
6. whether any reconstruction eventually supports a physical presentation.

These questions require different success criteria and should not be collapsed
into a single "template inversion" claim.

The current single-device, researcher-owned dataset is not sufficient for
population conclusions. Broad matching, linkability rates, reconstruction quality,
presentation attacks, and population-level false match or false nonmatch
measurements require additional sensors, controlled biometric data, fixed operating
points, and appropriate review and data handling.

## Relationship to prior work

The references below provide threat models, comparison points, and experimental
methods. Their findings do not automatically transfer to this device.

| Prior work | Boundary studied | Relationship to this project |
| --- | --- | --- |
| [InfinityGauntlet, USENIX Security 2023](https://www.usenix.org/conference/usenixsecurity23/presentation/chen-yu) | Smartphone fingerprint authentication, SPI interception and injection, and failures in effective attempt limiting | Motivates replay and attempt-accounting experiments. This project concerns a USB desktop reader with host-side matching and different component lifetimes. |
| [A Touch of Pwn, Blackwing Intelligence 2023](https://blackwinghq.com/blog/posts/a-touch-of-pwn-part-i/) | Windows Hello and match-on-chip sensors, including a different Goodix design, with emphasis on SDCP, device identity, and implementation failures | Provides a concrete comparison for endpoint identity and trust placement. The GF3258 path studied here performs biometric processing on the Linux host, so the trust boundary is different. |
| [An Empirical Study on Fingerprint API Misuse with Lifecycle Analysis in Real-world Android Apps, NDSS 2025](https://www.ndss-symposium.org/ndss-paper/an-empirical-study-on-fingerprint-api-misuse-with-lifecycle-analysis-in-real-world-android-apps/) | Fingerprint API misuse across the Android authentication lifecycle | Demonstrates why security properties can depend on lifecycle composition above a biometric primitive. It does not establish analogous failures in this lower-level Linux path. |
| [MasterPrint, IEEE TIFS 2017](https://doi.org/10.1109/TIFS.2017.2691658) | Population-level broad matching against partial fingerprints | Supplies a later biometric attack model. Applying it here requires an appropriate dataset and fixed operating point. |
| [Ross, Shah, and Jain, SPIE 2005](https://cse.msu.edu/~rossarun/pubs/RossReconstruct_SPIE05.pdf) | Reconstruction of fingerprint structure from minutiae | Supplies a method for studying template leakage. TGLA stores a different combination of geometry, descriptors, maps, and graph state, so leakage must be measured rather than presumed. |
| [Martinez-Diaz et al., ICCST 2006](https://doi.org/10.1109/CCST.2006.313444) | Adaptive hill-climbing and brute-force attacks against fingerprint verification | Motivates later experiments on score exposure and adaptive queries. This implementation can distinguish internal matcher state from the binary decision exposed by the desktop authentication path. |

[NIST SP 800-63B-4](https://pages.nist.gov/800-63-4/sp800-63b.html)
provides a useful evaluation reference for biometric authentication, including
failed-attempt limits, injection-attack detection, and consideration of sensor and
endpoint performance and integrity. It does not certify or describe this Goodix
design.

[ISO/IEC 24745:2022](https://www.iso.org/standard/75302.html) provides a separate
reference for confidentiality, integrity, renewability or revocability of biometric
information, secure binding between biometric and identity references, and
privacy-aware processing. The project does not claim conformance to either
standard.

Relevant systems mechanisms and comparison points include:

* [Linux USB device authorization](https://docs.kernel.org/usb/authorization.html)
* [libfprint](https://fprint.freedesktop.org/)
* [Microsoft Secure Device Connection Protocol](https://github.com/microsoft/SecureDeviceConnectionProtocol)
* [Linux USB Raw Gadget](https://www.kernel.org/doc/html/latest/usb/raw-gadget.html)
* [Provos, Preventing Privilege Escalation](https://www.usenix.org/conference/12th-usenix-security-symposium/preventing-privilege-escalation)
* [Swift, Bershad, and Levy, Improving the Reliability of Commodity Operating Systems](https://dl.acm.org/doi/10.1145/945445.945466)

These references are starting points for comparison. Using one of their mechanisms
does not make the corresponding implementation a contribution.

## Experimental record

Each experiment should record enough context to make a failure interpretable.

At minimum:

| Field | Record |
| --- | --- |
| Question | The property or competing models being tested |
| Scope | Device, firmware state, host state, and software path |
| Capability | Attacker or failure model |
| Independent variable | The state, message, timing, component, or policy being changed |
| Baseline | The corresponding unmodified run |
| Observable | The value, transition, rejection, latency, or failure being measured |
| Decision point | The first component that accepts, rejects, or loses the tested state |
| Outcome | Result without extending the claim beyond the experiment |
| Artifacts | Non-sensitive logs, hashes, manifests, or regression vectors retained for reproduction |

Timing studies should report distributions rather than a single run. Measurements
that use runtime instrumentation should say so and should include an uninstrumented
baseline when instrumentation could change the outcome.

Negative results should be retained when the experiment separates plausible
explanations. A null result from an under-specified test is not automatically
informative.

## Claim discipline

This file proposes experiments. It does not upgrade their hypotheses into findings.

The following boundaries remain in force:

* trace recovery does not imply attacker access to USB traffic;
* encryption does not establish capture origin or freshness;
* one provisioning observation does not describe all devices;
* a protocol-compatible endpoint is not automatically an authenticated endpoint;
* readable host-side biometric state is not automatically an authentication bypass;
* process isolation is not a security contribution without a stated model and
  comparison;
* a runtime check is not useful merely because its measured overhead is small;
* genuine and impostor trials on the development sensor are not population
  biometric error rates;
* results from smartphone, match-on-chip, or mobile API studies do not transfer
  automatically to this match-on-host Linux system.

If an experiment establishes a practical vulnerability, coordinated disclosure
should precede publication of operational exploit material.

## Relationship to the project documents

[README.md](README.md) is the project front page. It states what works, what is
currently observed, and the four questions raised by the reconstruction.

[REVERSE_ENGINEERING.md](REVERSE_ENGINEERING.md) defines how evidence is classified
and how recovered behavior is validated.

This file describes how unresolved questions can be turned into controlled studies.
It is intentionally broader than the README, but it remains bounded by the evidence
rules in `REVERSE_ENGINEERING.md`.