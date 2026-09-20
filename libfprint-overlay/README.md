# Goodix 27c6:550a libfprint overlay

This directory contains the libfprint integration for the Goodix `27c6:550a`
driver.

The overlay targets a clean libfprint 1.94.100 source tree. libfprint remains the
sole USB owner. The C driver handles libfprint integration and asynchronous
operation dispatch; the Rust bridge retains Goodix protocol, capture, enrollment,
persistence, verification, and host-gallery identification behavior.

For project scope, validation limits, and reverse-engineering provenance, see the
root [README.md](../README.md) and
[REVERSE_ENGINEERING.md](../REVERSE_ENGINEERING.md).

## Integration boundary

```text
application / fprintd
        |
        v
    libfprint
        |
        v
Goodix C driver overlay
        |
        v
Rust C ABI bridge
        |
        v
Goodix Rust core
        |
        v
libfprint-owned GUsbDevice
```

The Rust side does not create a second USB owner.

## Persisted print representation

Enrollment, verification, and identification use the same persisted representation.

The returned `FpPrint` is `FPI_PRINT_RAW`. Its `fpi-data` value is `(uay)` and
contains:

```text
format version 1
TGLA bytes
```

Verification and identification consume this representation directly. The overlay
does not maintain a second template format.

## Enrollment

The driver exposes 12 enrollment stages, matching the recovered
`GeneralSamples` target.

Each retained sample uses a fresh D2 capture session.

Retryable biometric rejection returns `FP_DEVICE_RETRY_GENERAL` and does not
advance the retained-sample count.

After the twelfth accepted sample, Rust:

1. builds the recovered raw enrollment representation;
2. persists it as TGLA;
3. reopens the result with `Gf3258VerificationTemplate::from_tgla()`;
4. reports enrollment completion only if the persisted representation is accepted
   by the verification path.

libfprint enrollment progress follows the retained-sample count reported by Rust.

## Verification

Only the terminal Rust gallery decision crosses the libfprint authentication
boundary:

```text
retryable live capture rejection
    -> FP_DEVICE_RETRY_GENERAL

Gf3258GalleryVerificationDecision::Match
    -> FPI_MATCH_SUCCESS

Gf3258GalleryVerificationDecision::NoMatch
    -> FPI_MATCH_FAIL
```

Intermediate matcher evidence or partial workflow state cannot produce
authentication success by itself.

## Identification

Identification is host-side 1:N matching over a non-empty libfprint gallery.

Before any sensor transaction, the driver validates every gallery `FpPrint`,
including its format version and TGLA payload. A single physical capture is then
evaluated against every accepted TGLA in Rust.

The result mapping is:

```text
retryable live capture rejection
    -> FP_DEVICE_RETRY_GENERAL

one or more gallery matches
    -> highest-scoring match
    -> earlier gallery entry wins an equal-score tie
    -> matched gallery FpPrint + scanned FpPrint

no gallery match
    -> no matched gallery FpPrint + scanned FpPrint
```

The scanned print uses the same versioned `FPI_PRINT_RAW` TGLA representation as
enrollment. Identification does not perform one physical capture per gallery
entry.

The driver has no sensor-resident fingerprint database. An empty libfprint
identification gallery is therefore reported as unsupported rather than treated
as a device-side identification request.

## Public libfprint probes

The `probes/` directory contains small public-API integration programs:

* `capture-probe.c` opens the Goodix device, captures one image through
  `fp_device_capture_sync()`, and checks the expected 80x64 image geometry;
* `enroll-probe.c` enrolls through `fp_device_enroll_sync()`, round-trips the
  returned print through libfprint serialization, writes its TGLA payload, and
  verifies the newly enrolled print;
* `verify-probe.c` reconstructs the driver's versioned raw-print representation
  from an existing TGLA file, round-trips it through libfprint serialization,
  and verifies it through `fp_device_verify_sync()`.

These probes exercise libfprint's public API. They are diagnostics, not an
alternative USB owner or a second driver implementation.

## Applying the overlay

The overlay targets a clean **libfprint 1.94.100** source tree.

First build the Rust bridge:

```bash
cargo build --release --manifest-path libfprint-bridge/Cargo.toml
```

Stage the bridge library, public header, and pkg-config metadata into a
self-contained prefix:

```bash
BRIDGE_STAGE="${TMPDIR:-/tmp}/goodix550a-bridge-stage"

python3 libfprint-bridge/prepare-pkg-config.py \
  --prefix "$BRIDGE_STAGE"
```

Expose that staged package to pkg-config:

```bash
export PKG_CONFIG_PATH="$BRIDGE_STAGE/lib/pkgconfig${PKG_CONFIG_PATH:+:$PKG_CONFIG_PATH}"
```

Then apply the overlay to a clean libfprint source tree:

```bash
python3 libfprint-overlay/apply-overlay.py /path/to/libfprint-1.94.100
```

The staging helper produces a layout like:

```text
goodix550a-bridge-stage/
├── include/
│   └── goodix550a_bridge.h
└── lib/
    ├── libgoodix550a_bridge.so
    └── pkgconfig/
        └── goodix550a-bridge.pc
```

The generated `goodix550a-bridge.pc` is relocatable: it derives its prefix
from the location of the pkg-config file rather than embedding the repository
checkout path.

For release or provenance-sensitive builds, compiler path remapping of the
Rust shared library is still a separate build concern. Staging copies the
already-built artifact; it does not rewrite paths embedded in that binary.

Additional validation procedures are documented in
[`../tools/README.md`](../tools/README.md).

## Not implemented

The overlay does not currently implement:

* device-side template storage or empty-gallery device-side identification;
* a second persistence or template representation.

## Related documentation

* [Root README](../README.md)
* [Reverse-engineering evidence rules](../REVERSE_ENGINEERING.md)
* [Research questions and experimental design](../RESEARCH.md)
* [Validation and live-device procedures](../tools/README.md)