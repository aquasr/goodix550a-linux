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
or device behavior. End to end success was not treated as sufficient evidence of
parity. Reconstructions that produced plausible final behavior but disagreed at an
observable intermediate boundary were revised or rejected. The documentation
distinguishes observed behavior, recovered implementation details, validated
reproductions, inferences, and unresolved questions. Observations that depend on
runtime instrumentation remain separate from behavior confirmed through an
independent trace or hardware trial.
See [REVERSE_ENGINEERING.md](REVERSE_ENGINEERING.md) for the evidence and
provenance rules.

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
One captured provisioning flow contained a 32 byte PSK consisting entirely of
zero bytes; that observation is limited to the studied sensor.

### Host boundary

The reconstructed image, extracted features, enrollment state, persisted
template, and match decision are handled on the host. The relevant boundary is
therefore larger than the USB protocol alone: it also includes libfprint,
fprintd, D-Bus, PAM, and template storage. Retry limits, cancellation,
ownership, and recovery are properties of that composed path.

## Questions raised by the reconstruction

Finishing the host path did not remove the uncertainty that made the reconstruction
difficult. Different internal models sometimes produced the same final result until
an intermediate value or a controlled device transition separated them. Some state
is visible only through instrumentation, and reproducing reference behavior does not
mean every internal choice in the reference implementation should be preserved.

Four questions follow directly from those limits:

1. **Specification recovery.** How can a trustworthy behavioral specification be
   recovered for a stateful hardware and software interface when no authoritative
   specification exists and the reference implementation is observable only through
   its binary and runtime behavior? The problem is to separate stable interface
   behavior from hidden state, implementation artifacts, and effects introduced by
   instrumentation.

2. **Conformance.** What should conformance mean for an independent implementation
   when matching enrollment or verification outcomes is not enough? A useful test
   must cover externally relevant protocol transitions, session and persistent state,
   failure and recovery behavior, and device responses that may legitimately vary
   across runs.

3. **Compatibility and isolation.** Which externally visible behaviors must remain
   compatible, and which internal boundaries can change without breaking the device
   or desktop path? A replacement implementation can test whether required behavior
   is preserved while reducing privilege, shared sensitive state, or the amount of
   code that must be trusted.

4. **Runtime checks.** Can recovered protocol and state invariants be checked during
   execution without materially changing the behavior being checked? The evaluation
   should identify where such checks run, what events trigger them, and what cost
   they add to capture, cancellation, suspend, recovery, and login.

The current repository already supports three direct experiments:

1. Recover an image from a recorded D2 trace and test replay within one session and
   across separate sessions, recording the first state that rejects a substituted
   response.
2. Emulate the expected USB endpoint and test whether device or session identity
   survives re-enumeration, restart, and suspend.
3. Trace one authentication request through libfprint, fprintd, D-Bus, and PAM to
   locate retry, cancellation, and authorization policy.

A failed replay or substitution is still useful if it identifies the component or
state that supplies the missing property. More ambitious runtime checking or host
isolation should come only after this baseline is measured. Without an explicit
attacker model, a comparison point, and measurements of latency and failure behavior,
such a prototype would be implementation work rather than a research result.

The fuller threat models, prior work discussion, and study designs are in
[RESEARCH.md](RESEARCH.md).

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