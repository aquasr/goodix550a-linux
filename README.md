# Goodix 27c6:550a Linux Driver

`goodix550a-linux` is an independently written Linux host implementation for
the Goodix `27c6:550a` USB fingerprint reader (GF3258 WN2 / GM168SEC). It was
developed from binary analysis, USB traces, runtime instrumentation, and
controlled experiments because no public protocol or matcher specification was
available.

The driver covers device startup, encrypted image acquisition, image
reconstruction, enrollment, template persistence, verification, and
experimental libfprint integration. It does not load or link the proprietary
Goodix host library. The sensor firmware remains proprietary and is not
distributed here.

> **Status:** Experimental support for one sensor in its APP and IAP firmware
> states. This is not an audited authentication component. Keep another login
> method available while testing it.

## Current research state

This repository serves two roles: it is an independent executable
reconstruction of the studied fingerprint stack, and it provides an
experimental baseline for studying the behavior and trust boundaries of an
undocumented hardware/software interface.

| State | Current status |
| --- | --- |
| **Established** | An independent host path covers startup, authenticated firmware bootstrap, encrypted capture, image reconstruction, enrollment, persistence, verification, and experimental libfprint integration without loading the proprietary Goodix host library. |
| **Validated** | Reconstructed components are checked with deterministic tests, retained intermediate-state parity evidence, standalone hardware workflows, persistence reload, and live libfprint enrollment and verification on the development sensor. |
| **Evidence standard** | End-to-end success is not treated as proof of internal parity. Where an observable intermediate boundary exists, candidate reconstructions are compared against that boundary and revised or rejected when they disagree. |
| **Security-relevant observations** | The studied host exposes capture-decryption inputs in the D2 USB exchange; the recovered mode-1 sealed-object HMAC does not authenticate its CBC IV; and reconstructed images, templates, matcher state, and final match decisions are handled on the host. |
| **Current boundary** | Hardware evidence currently comes from one physical `27c6:550a` sensor and the documented APP/IAP firmware pair. The repository does not establish population biometric error rates, product-wide vulnerabilities, or production security. |
| **Research enabled** | The reconstruction makes it possible to test behavioral conformance, device and session continuity, replay and substitution boundaries, host-side trust composition, isolation strategies, and runtime checking against an independently executable baseline. |

Proposed experiments are kept separate from established findings. Their attacker
models, comparison points, measurements, and current evidence are described in
[RESEARCH.md](RESEARCH.md). The progression from initial device access to the
current executable research baseline is summarized in
[PROJECT_HISTORY.md](PROJECT_HISTORY.md).

## What works

| | |
| --- | --- |
| **Device** | Goodix USB `27c6:550a`, GF3258 WN2 / GM168SEC |
| **Firmware states** | APP `GFUSB_GM168SEC_APP_15045`; IAP `MILAN_GM168SEC_IAP_10007` |
| **Startup** | Warm APP startup and authenticated IAP-to-APP firmware transfer |
| **Capture** | Finger detection, encrypted acquisition, decryption, CRC validation, and `80 × 64` image reconstruction |
| **Biometric path** | 12-sample enrollment, TGLA persistence, gallery verification, and libfprint integration |
| **Vendor dependency** | No proprietary Goodix host library at runtime |

On the development sensor, the standalone and libfprint paths have completed
live capture, enrollment, persistence reload, and verification. These trials
show that the reconstructed components operate together. They do not establish
population-level false match or false nonmatch rates, and hardware results
currently come from one physical sensor.

## Implementation

The reconstructed host path includes:

* A0 packet framing, endpoint discovery, APP/IAP identification, command
  transactions, and USB re-enumeration;
* OTP validation, persisted-PSK handling, and recovery of volatile sensor
  configuration after power loss;
* an IAP-to-APP firmware transfer authenticated with the device's persisted
  PSK and firmware supplied by the caller;
* D2 session setup for each capture, finger detection, AES-128-CBC image decryption,
  and CRC-32/MPEG-2 validation;
* conversion of the `5 + 10,560 + 4` byte image response into `80 × 64`
  12-bit sensor samples;
* fixed-point preprocessing, feature extraction, registration,
  correspondence scoring, and the recovered verification policy;
* enrollment graph construction, raw template encoding, TGLA persistence, and
  gallery matching;
* a Rust C ABI bridge and an asynchronous libfprint driver overlay.

Firmware is accepted only when a cold bootstrap is required. The driver checks
the USB ID, current IAP identity, target APP identity, resource size, metadata,
and checksums before exposing firmware transfer data.

## Architecture and host trust boundary

For this reconstructed desktop path, authentication is a composition of
multiple host components rather than a direct sensor-to-PAM decision. The
sensor supplies protocol responses and encrypted capture data; biometric
processing and the terminal gallery decision occur in the host-side
implementation.

```text
application / PAM
       |
       | D-Bus authentication interface
       v
     fprintd
       |
       | libfprint API
       v
    libfprint
       |
       | driver operations
       v
Goodix C driver overlay
       |
       | Rust C ABI
       v
  Goodix Rust core
       |
       | USB actions / responses
       v
libfprint-owned GUsbDevice
       |
       v
      USB
       |
       v
Goodix 27c6:550a sensor
```

Security-relevant state and authority are distributed across this path rather
than confined to the sensor:

| Boundary or component | Security-relevant state or responsibility |
| --- | --- |
| **USB boundary** | The host-generated D2 value and encrypted image response cross this boundary. Bytes 16 through 31 of D2 are used as the AES-128 image key for that capture. |
| **Goodix Rust core** | D2 session material, decrypted sensor samples, reconstructed images, feature records, enrollment state, persisted-template data, matcher state, and the terminal gallery decision are handled here. |
| **Rust/C and libfprint boundary** | Enrollment exports the persisted TGLA representation through `FpPrint`; verification exports the terminal match, no-match, or retry result rather than intermediate matcher evidence. |
| **fprintd and host persistence** | Persisted print data and the desktop authentication lifecycle extend the effective trust boundary beyond the driver and USB protocol. |
| **D-Bus / PAM / applications** | Authentication requests, cancellation, policy, and consumption of the terminal result belong to the composed desktop authentication path rather than to the sensor protocol itself. |

For this reconstructed path, the sensor does not produce the terminal gallery
match decision; that decision is produced by the host-side Rust
implementation. Device I/O, biometric processing, template handling, decision
generation, persistence, and desktop authentication therefore span multiple
components and interfaces. This composition motivates the isolation,
lifecycle, and authority experiments described in [RESEARCH.md](RESEARCH.md).

## How it was reconstructed

The implementation was developed through four forms of evidence:

1. **Static binary analysis** recovered call relationships, structure offsets,
   constants, packet construction, fixed-point arithmetic, cryptographic data
   flow, and bounded verification control flow from a stripped host binary.
2. **USB trace analysis** established A0 framing, ACK and completion ordering,
   APP/IAP behavior, persisted-object reads, D2 setup, finger-detection
   sequencing, image layout, and firmware-transfer authentication.
3. **Runtime instrumentation** exposed selected intermediate image planes,
   feature records, descriptors, enrollment state, matcher candidates, and
   verification decisions.
4. **Controlled experiments** varied startup state, power loss, capture
   quality, spatial transformations, genuine and impostor comparisons, and
   selected intermediate values to distinguish competing explanations.

Where an observable boundary was available, a candidate reconstruction was retained
only when the independent implementation reproduced the expected intermediate state
or device behavior. End-to-end success was not treated as sufficient evidence of
parity. Reconstructions that produced plausible final behavior but disagreed at an
observable intermediate boundary were revised or rejected. The documentation
distinguishes observed behavior, recovered implementation details, validated
reproductions, inferences, and unresolved questions. Observations that depend on
runtime instrumentation remain separate from behavior confirmed through an
independent trace or hardware trial.
See [REVERSE_ENGINEERING.md](REVERSE_ENGINEERING.md) for the evidence and
provenance rules.

### Worked reconstruction example: resolving feature polarity

One small but representative ambiguity appeared in the recovered feature-point
records: a binary polarity field could plausibly encode either a negative or a
nonnegative signed detector response. Rather than choose from decompiler output
alone, the validation path kept both mappings as competing hypotheses.

[`tools/validation/feature_polarity_parity_v1.rs`](tools/validation/feature_polarity_parity_v1.rs)
independently recomputes the primary feature candidates for a retained
instrumented fixture and compares both candidate mappings against the
corresponding vendor `FeaturePoint` polarity. The tool accepts a mapping only
when it has zero mismatches across the fixture. The retained result is
implemented as `polarity = (raw_response < 0)`, and the production helper has
explicit regression coverage for negative, zero, and positive responses.

This is representative of the broader reconstruction process: ambiguity is
kept explicit until an observable intermediate value separates the candidate
models; the surviving rule is then encoded in production code and regression
tests. The retained reference fixture itself is not distributed.

## Validation

Different tests establish different claims:

| Layer | What it checks | Hardware required? |
| --- | --- | ---: |
| Unit and public API tests | Arithmetic, parsers, packets, state machines, persistence, and cross-module invariants | No |
| Offline parity tools | Agreement with retained external reference intermediates | No |
| Live diagnostics | Version, OTP, configuration, D2, and chip ID behavior | Yes |
| Standalone workflows | Capture, enrollment, persistence reload, and verification | Yes |
| libfprint probes | Enrollment and verification through the public libfprint path | Yes |

Ordinary `cargo test` runs are deterministic and do not open the sensor. A
green test run establishes regression behavior on that host; it does not prove
live-device correctness or security. Hardware trials and fixture-based parity
checks are separate.

Four difficult parts of the verification policy are retained as compact
transcriptions of bounded integer control flow graphs containing no calls. Each
records the analyzed reference artifact's SHA-256 and an independent program manifest
hash. Changes to those transcriptions require updated manifests and parity
evidence.

The validation programs and hardware diagnostics are documented in
[tools/README.md](tools/README.md).

## Security-relevant observations

These observations describe the studied implementation. They are not presented
as product-wide vulnerabilities.

### Image session

For each capture, the host generates a 32-byte D2 value and sends the complete
value to the sensor. Bytes 16 through 31 become the AES-128 image key. The
sensor later returns a 5-byte header, 10,560 bytes of AES-128-CBC ciphertext,
and a 4-byte CRC. The CBC IV is zero, and the CRC is calculated over the
decrypted image.

A USB trace containing the D2 command and image response therefore contains
the inputs used by the host to decrypt that capture. The repository does not
yet include a trace-only recovery tool or establish which attacker classes can
obtain those transfers on a deployed system. The CRC detects corruption but
does not establish image origin or freshness.

### Persisted PSK

The proprietary host derives the keys for its mode-1 sealed object from a
static root. The recovered HMAC covers the marker, declared length, and
ciphertext, but not the CBC IV. Modifying the IV can therefore alter the first
decrypted block without invalidating the recorded HMAC.

This property is reproducible offline, but its system impact has not been
established. An attacker would still need to substitute the persisted object,
and the modified plaintext would need to affect a security-sensitive operation.
One captured provisioning flow contained a 32-byte PSK consisting entirely of
zero bytes; that observation is limited to the studied sensor.

## Open research questions

The observations above are established only to the limits stated in this
repository. They motivate, but do not answer, several broader research
questions:

1. **Specification recovery.** Which externally relevant behaviors are
   sufficient to specify a stateful hardware/software interface when no
   authoritative specification exists, and how can stable behavior be
   separated from hidden state, implementation artifacts, and instrumentation
   effects?

2. **Conformance.** What should conformance require from an independent
   implementation when reproducing final enrollment or verification outcomes
   is not sufficient? Relevant dimensions include protocol transitions,
   session and persistent state, failure behavior, recovery, and permitted
   run-to-run variation.

3. **Compatibility and isolation.** Which externally visible behaviors must
   remain compatible while internal trust boundaries are changed? The
   reconstructed path provides a baseline for testing whether privilege,
   shared sensitive state, or trusted code can be reduced without breaking
   device or desktop behavior.

4. **Runtime checking.** Which recovered protocol and state invariants can be
   checked during execution without materially changing the behavior being
   observed, and what coverage, latency, and failure-handling costs do those
   checks introduce?

These are open questions rather than findings of the current implementation.
[RESEARCH.md](RESEARCH.md) defines the corresponding attacker models,
comparison points, prior-work context, and experiments involving trace replay,
endpoint substitution, lifecycle continuity, authority placement, isolation,
and runtime checking.

## Repository map

| Path | Role |
| --- | --- |
| `src/protocol.rs`, `src/transport.rs` | A0 framing, command transactions, and USB behavior |
| `src/firmware*.rs`, `src/bootstrap.rs` | Firmware parsing, authentication, and cold bootstrap |
| `src/chicago_h.rs`, `src/crypto.rs` | Sensor-state recovery, PSK handling, and image-session cryptography |
| `src/image.rs`, `src/preprocess.rs` | Image validation, reconstruction, and preprocessing |
| `src/feature/`, `src/registration/` | Feature extraction, scoring, and geometry |
| `src/enrollment*.rs`, `src/template*.rs` | Enrollment and template persistence |
| `src/verification*.rs` | Gallery matching and verification policy |
| `src/driver.rs` | Capture, enrollment, and verification transactions |
| `src/libfprint*.rs`, `libfprint-bridge/` | Backend-neutral operations and the C ABI |
| `libfprint-overlay/` | Asynchronous libfprint driver and integration probes |
| `tools/` | Offline parity programs and narrow hardware diagnostics |
| `PROJECT_HISTORY.md` | Technical progression from initial device access to the current research baseline |

## Build and test

The crates require Rust 1.85 or newer and the libusb development files.

```bash
# Fedora
sudo dnf install libusb1-devel pkgconf-pkg-config

# Debian or Ubuntu
sudo apt install libusb-1.0-0-dev pkg-config
```

Run the checks as an unprivileged user:

```bash
cargo fmt --all -- --check
cargo check --all-targets --all-features
cargo test --all-targets
cargo clippy --all-targets --all-features -- -D warnings

cargo fmt --manifest-path libfprint-bridge/Cargo.toml -- --check
cargo test --manifest-path libfprint-bridge/Cargo.toml
cargo clippy --manifest-path libfprint-bridge/Cargo.toml \
  --all-targets -- -D warnings
```

## Live-device use

`fprintd` and a standalone process must not own the sensor simultaneously. Do
not run Cargo or a Goodix executable with `sudo`; hardware paths refuse
elevated execution. Install `packaging/70-goodix550a.rules` once, reserve a
dedicated administrative terminal for `fprintd` control, and run sensor
commands from an unprivileged terminal. The complete procedure is in
[tools/README.md](tools/README.md).

```bash
# Capture an algorithm-ready PGM
cargo run --release --bin goodix-info -- capture fingerprint.pgm

# Enroll 12 retained samples
cargo run --release --bin standalone_enroll -- \
  --raw-template gf3258-enrollment.raw \
  --tgla-template gf3258-enrollment.tgla

# Verify a fresh capture
cargo run --release --bin standalone_verify -- \
  --template gf3258-enrollment.tgla --attempts 1
```

`goodix-info bootstrap-live` is the only main CLI operation that transmits
firmware. It accepts only the supported IAP state and exact APP resource.
`bootstrap-check` prepares and authenticates the transfer without sending F0
or F4 firmware data.

For desktop integration, build the Rust bridge and apply the overlay to a clean
libfprint 1.94.100 source tree. See
[libfprint-overlay/README.md](libfprint-overlay/README.md).

## Limitations

* Only USB `27c6:550a`, GF3258 WN2 / GM168SEC, and the listed APP and IAP
  firmware identities are accepted.
* Hardware results currently come from one physical sensor.
* Identify and device-side template storage are not implemented.
* Vendor `GdxEnc` sealing is not reproduced; persistence uses the recovered
  TGLA representation directly.
* Optional verification profile and cache state remain disabled.
* Captures requiring the unresolved vendor top or bottom edge repair are
  rejected.
* External parity fixtures are not distributed. Independent differential
  reproduction requires separately collected reference evidence.
* No presentation attack detection or population-scale FMR/FNMR claim is made.

## Provenance and data handling

Proprietary source code was not available. The Rust and C implementation was
written from stripped binary analysis, USB traces, runtime instrumentation, and
controlled experiments. The finished driver does not load or link the
proprietary Goodix host `.so`.

The public tree excludes fingerprint images, templates, device-specific
secrets, USB captures, memory dumps, vendor binaries, firmware images,
decompiler projects, and disassembly dumps. Experiments use researcher-owned
hardware and biometric samples. Work involving additional participants or
population-level accuracy requires appropriate human-subjects and data-handling
review.

Practical vulnerabilities will be handled through coordinated disclosure before
operational exploit material is published.

## License

Licensed under the GNU Lesser General Public License, version 2.1 or later. See
[LICENSE](LICENSE).