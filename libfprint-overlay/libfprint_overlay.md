# Goodix 27c6:550a libfprint overlay

This directory contains the libfprint integration for the Goodix `27c6:550a`
driver.

The overlay targets a clean libfprint 1.94.100 source tree. libfprint remains the
sole USB owner. The C driver handles libfprint integration and asynchronous
operation dispatch; the Rust bridge retains Goodix protocol, capture, enrollment,
persistence, and verification behavior.

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

Enrollment and verification use the same persisted representation.

The returned `FpPrint` is `FPI_PRINT_RAW`. Its `fpi-data` value is `(uay)` and
contains:

```text
format version 1
TGLA bytes
```

Verification consumes this representation directly. The overlay does not maintain a
second template format.

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

* identify;
* device-side template storage;
* a second persistence or template representation.

## Related documentation

* [Root README](../README.md)
* [Reverse-engineering evidence rules](../REVERSE_ENGINEERING.md)
* [Research questions and experimental design](../RESEARCH.md)
* [Validation and live-device procedures](../tools/tools.md)