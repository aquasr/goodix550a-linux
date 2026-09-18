# Project History and Research Progression

This document summarizes how the Goodix `27c6:550a` / GF3258 work progressed
from an undocumented USB device to an independently executable Linux host
implementation and then to an experimental research baseline.

The project did not begin with a complete model of the fingerprint stack.
Each stage exposed enough behavior to make the next uncertainty testable.

## 1. Establishing observable device behavior

The first problem was narrower than implementing a fingerprint driver: determine
whether the device could be controlled reproducibly without loading the
proprietary Goodix host library.

USB enumeration and trace analysis established the device interface, bulk
endpoints, A0 packet framing, command transactions, and basic APP behavior.
Standalone Rust code reproduced version queries and finger-detection
transitions on the physical sensor. The work also distinguished the normal APP
state from the IAP state encountered after loss of the running application
firmware.

The device could be identified, addressed, and driven through a
small independent transport layer. Warm APP operation became reproducible
without the proprietary host implementation.

Later failures could now be separated from basic USB
transport problems. Startup state, authentication, capture, and biometric
processing became independently investigable layers rather than one opaque
failure mode.

## 2. Recovering startup, persistent state, and cold bootstrap

Warm operation did not explain what happened after the sensor lost volatile
state or appeared in IAP mode. The next question was how persistent device
state, host authentication, firmware transfer, and reset interacted.

Static binary analysis, USB traces, and controlled startup experiments exposed
OTP-derived configuration, persisted-PSK handling, the F0/F4
firmware-transfer authentication path, firmware metadata checks,
reset/re-enumeration, and restoration of configuration after the device
returned to APP mode.

The independent implementation was kept deliberately narrow: firmware
identity, resource size, metadata, and checksums are checked against the
studied APP/IAP pair rather than accepting loosely compatible images.

The standalone path reproduced authenticated IAP-to-APP bootstrap,
reset and re-enumeration, APP identity validation, and recovery of the
volatile configuration needed by later operations.

The project now had an experimentally usable model of
the device lifecycle and of the split between persistent and volatile state.
That lifecycle later became relevant to questions about identity, continuity,
recovery, and trust across restart.

## 3. Recovering the protected image path

Once startup was independently controllable, the next unknown was the
protected capture path: how a touch became an image that an independent host
implementation could interpret.

Trace and binary evidence established a fresh D2 exchange for capture, the
session material used for AES-128-CBC image decryption, the encrypted image
response layout, and CRC-32/MPEG-2 integrity checking. The packed 12-bit
sensor samples were then decoded and transformed into the sensor's `80 × 64`
image layout.

The reconstructed path validates the response before exposing the image to
later biometric processing.

A physical touch could be detected, acquired, decrypted, checked,
and reconstructed into an independent host-side sensor image without the
proprietary Goodix host library.

This was the first point at which the project had a
rich intermediate artifact that could be compared independently. Image
processing and biometric reconstruction could now be investigated using
differential evidence rather than judged only by final success or failure.

## 4. Moving from plausible behavior to intermediate-state parity

Reconstructing the biometric pipeline introduced a different problem.
Multiple candidate implementations could produce plausible-looking outputs
while still differing from the reference implementation internally.

Static analysis recovered fixed-point arithmetic, image transformations,
feature construction, registration logic, and matcher-related control flow.
Runtime instrumentation exposed selected reference intermediate states,
including image planes, feature records, descriptors, enrollment state,
matcher candidates, and verification decisions.

Offline validation programs were then used to compare independent
reimplementations against those retained observations. Competing
interpretations were kept separate when the available evidence did not yet
distinguish them and were revised or rejected when an observable intermediate
boundary disagreed.

A small example is feature-point polarity. Two plausible mappings from the
signed detector response to the stored polarity field were evaluated against
an instrumented reference fixture. The mapping that disagreed with the
observed intermediate state was rejected, and the surviving rule was encoded
in the implementation with regression coverage. The root
[README](README.md) includes this example in more detail.

The reconstructed feature path developed through testable
intermediate boundaries rather than final-output imitation alone.

The evidentiary standard of the project changed here.
End-to-end success was no longer treated as sufficient evidence that the
internal model was correct. The broader reconstruction methodology is
documented in
[REVERSE_ENGINEERING.md](REVERSE_ENGINEERING.md).

## 5. Reconstructing enrollment and persistent biometric state

A single reconstructed capture was not enough to reproduce a usable
fingerprint stack. The next problem was how repeated captures became
persistent enrollment state that could survive beyond the process that
created it.

The enrollment path was reconstructed as a 12-sample process with retained
sample state, enrollment-graph construction, raw template representation,
TGLA serialization, parsing, persistence, and reload.

Validation therefore moved beyond individual image and feature fixtures to
state accumulated across multiple touches and subsequently restored from a
persisted representation.

The standalone implementation could complete enrollment, persist
the resulting biometric state, reload it, and use the restored representation
in later operations.

The project became a stateful system rather than a
one-shot capture experiment. Persistence also enlarged the correctness and
security boundary: behavior now depended on state crossing process and
authentication lifetimes.

## 6. Recovering gallery verification and decision behavior

Verification was one of the later and more difficult parts of the
reconstruction because the recovered behavior was not reducible to a single
similarity threshold.

The reconstructed path includes registration, correspondence scoring,
candidate handling, geometry, refinement and rescue behavior, and bounded
late and terminal verification policy. As with feature extraction, retained
intermediate evidence was used where available to distinguish candidate
implementations that could otherwise agree on the same final outcome.

Hardware validation then exercised repeated genuine comparisons and
different-finger comparisons on the development sensor.

The independent implementation produced usable gallery
match/no-match behavior on the studied hardware and combined capture, feature
extraction, enrollment state, persistence, and verification into one
executable path.

These trials are functional validation on one physical sensor
and a limited set of fingers and captures. They are not population-level false
match or false nonmatch measurements and do not establish biometric accuracy
for the Goodix product family.

The project had crossed from reconstructing isolated
algorithms to reproducing an end-to-end host-side biometric decision path while
retaining explicit limits on what the available experiments could establish.

## 7. Integrating the reconstruction with libfprint

The standalone implementation established that the reconstructed components
could operate together, but desktop integration introduced a different class
of problems: asynchronous operation, USB ownership, cancellation, persistence
semantics, and the boundary between the reconstructed engine and the Linux
fingerprint stack.

A Rust C ABI and libfprint driver overlay were added while keeping
libfprint's `GUsbDevice` as the USB owner. Enrollment exports the persisted
TGLA representation through `FpPrint`, while verification exports the
terminal match, no-match, or retry result rather than internal matcher state.

Live integration trials completed capture, enrollment, persistence reload, and
verification through the libfprint path on the development sensor.

The independent reconstruction became usable through the standard
Linux fingerprint-driver interface without loading the proprietary Goodix host
library.

Integration exposed a larger systems boundary than the
USB protocol alone. Device I/O, decrypted biometric state, template
persistence, the host-side match decision, libfprint, fprintd, D-Bus, and
desktop authentication policy form a composed path with different
responsibilities and trust assumptions.

The current architecture and placement of security-relevant state are
summarized in the root [README](README.md). The libfprint-specific design is
documented in
[libfprint-overlay/README.md](libfprint-overlay/README.md).

## 8. From reverse-engineering artifact to research baseline

Completing the executable path changed the central question of the project.

The initial question was approximately:

> What behavior must be recovered to make this undocumented device work
> independently?

The current questions are different:

* What externally relevant behavior is sufficient to specify an undocumented,
  stateful hardware/software interface?
* What should conformance require when reproducing a final result is weaker
  evidence than reproducing observable intermediate behavior?
* Which identities and security properties survive reset, re-enumeration,
  restart, persistence, and substitution?
* Which parts of the host-side path actually require trust, and which could be
  isolated or given less authority without breaking compatibility?
* Which recovered invariants can be checked at runtime without materially
  changing the behavior being measured?

The current implementation provides an executable baseline on which these
questions can be tested. Proposed attacker models, comparison points, and
experiments are kept separate from established findings in
[RESEARCH.md](RESEARCH.md).

The project remains intentionally bounded. Hardware evidence currently comes
from one physical `27c6:550a` sensor and the documented APP/IAP firmware pair.
The driver remains experimental, is not an audited authentication component,
and does not establish product-wide security conclusions or population
biometric error rates.

## Progression at a glance

| Stage                      | Primary uncertainty reduced                                                             | What became possible next                                                                      |
| -------------------------- | --------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------- |
| USB and APP communication  | Whether the device could be controlled independently                                    | Separate transport behavior from higher-level failures                                         |
| Startup and bootstrap      | How persistent state, IAP, firmware authentication, and volatile configuration interact | Repeat experiments across warm and cold lifecycle states                                       |
| Protected capture          | How encrypted sensor data becomes a valid host image                                    | Compare reproducible image-level intermediate state                                            |
| Feature reconstruction     | Which candidate interpretations agree with observable reference internals               | Validate behavior at intermediate boundaries                                                   |
| Enrollment and persistence | How repeated captures become durable biometric state                                    | Study state across process and authentication lifetimes                                        |
| Gallery verification       | How reconstructed state becomes a terminal biometric decision                           | Exercise genuine/impostor behavior and decision semantics                                      |
| libfprint integration      | How the engine behaves inside the Linux desktop stack                                   | Study ownership, cancellation, persistence, and composed trust                                 |
| Research baseline          | Which behavior is established and which properties remain unknown                       | Run explicit conformance, lifecycle, substitution, isolation, and runtime-checking experiments |

## Documentation map

The project documents serve different purposes:

* [README.md](README.md) — current implementation status, architecture,
  supported behavior, validation boundaries, and concise research state.
* [REVERSE_ENGINEERING.md](REVERSE_ENGINEERING.md) — evidence hierarchy,
  reconstruction method, differential validation, and claim discipline.
* [RESEARCH.md](RESEARCH.md) — open research questions, attacker models,
  comparison points, and proposed experiments.
* [PROJECT_HISTORY.md](PROJECT_HISTORY.md) — technical progression from
  initial device access to the current research baseline.
* [tools/README.md](tools/README.md) — validation programs and focused
  hardware diagnostics.
* [libfprint-overlay/README.md](libfprint-overlay/README.md) — desktop
  integration architecture, ownership, persistence, and operation semantics.

