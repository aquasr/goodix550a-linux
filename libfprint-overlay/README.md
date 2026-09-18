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

## Enrollment probe

`enroll-probe.c` exercises the public libfprint API.

It:

1. calls `fp_device_enroll_sync()`;
2. round-trips the returned print through `fp_print_serialize()` and
   `fp_print_deserialize()`;
3. writes the TGLA from the round-tripped print to the requested output path;
4. calls `fp_device_verify_sync()` using that newly enrolled print.

The probe therefore checks that enrollment output survives the public libfprint
serialization path before verification consumes it.

## Applying the overlay

Apply this directory to a clean libfprint 1.94.100 source tree, build the Rust
bridge, then build libfprint with the overlay in place.

Repository-specific preparation and validation steps are documented in this
directory and in [`../tools/README.md`](../tools/README.md).

## Not implemented

The overlay does not currently implement:

* device-side template storage or empty-gallery device-side identification;
* a second persistence or template representation.

## Related documentation

* [Root README](../README.md)
* [Reverse-engineering evidence rules](../REVERSE_ENGINEERING.md)
* [Research questions and experimental design](../RESEARCH.md)
* [Validation and live-device procedures](../tools/README.md)