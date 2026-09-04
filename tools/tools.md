# Validation and hardware tools

This directory contains explicit validation programs and live-device diagnostics.
They are not part of the normal driver or application path.

The root [README.md](../README.md) describes the project and its validation layers.
[REVERSE_ENGINEERING.md](../REVERSE_ENGINEERING.md) defines what parity and hardware
results establish. This file covers how the tools are built and run.

## `validation/`

`validation/` contains offline executables used to compare the Rust implementation
with retained reference evidence such as captured fixtures, recovered constants, or
known intermediate outputs.

They do not require a live fingerprint sensor.

Compile the validation tools:

```bash
cargo check --all-targets --features validation-tools
```

Run an individual tool:

```bash
cargo run --features validation-tools --bin feature_bd720_parity -- <args>
```

These executables remain outside the ordinary deterministic test path. They may
depend on external fixtures that are not distributed with the public repository.

Algorithm invariants that can be tested without external evidence belong in the
normal Rust test suite instead.

## `hardware/`

`hardware/` contains live-sensor diagnostics and narrow bootstrap or lifecycle
probes. These executables are compiled only when `hardware-tools` is enabled.

Compile them without opening the sensor:

```bash
cargo check --all-targets --features hardware-tools
```

Build and run a hardware tool as an unprivileged user:

```bash
cargo build --features hardware-tools --bin otp_dump
./target/debug/otp_dump
```

A hardware diagnostic should answer one narrow question. It should not become a
second driver path or duplicate protocol logic that belongs in the library.

## Live-device safety

`fprintd` and a standalone Goodix process must not own the sensor at the same time.

Never run Cargo or a Goodix sensor executable with `sudo`. USB access should come
from the repository udev rule or an equivalent local rule.

Use one dedicated administrative terminal for service control:

1. authenticate in that terminal before beginning sensor testing;
2. use only non-interactive `sudo -n` commands after testing begins;
3. keep every terminal that runs a Goodix executable unprivileged;
4. do not allow a newly opened terminal to prompt for an administrator password
   while the sensor is being exercised.

A typical control-terminal sequence is:

```bash
sudo -v
sudo -n systemctl stop fprintd.service
```

Run the sensor command from a separate unprivileged terminal.

When testing through fprintd or libfprint, return service ownership deliberately
rather than leaving a standalone diagnostic and the daemon competing for the USB
device.

## Development validation gate

A repository-wide development checkpoint should run:

```bash
cargo fmt --all -- --check
cargo check --all-targets
cargo test --all-targets

cargo check --all-targets --features validation-tools
cargo check --all-targets --features hardware-tools

cargo check --all-targets --all-features
cargo clippy --all-targets --all-features -- -D warnings
```

The C ABI bridge has its own Cargo manifest and should be checked separately:

```bash
cargo fmt --manifest-path libfprint-bridge/Cargo.toml -- --check
cargo test --manifest-path libfprint-bridge/Cargo.toml
cargo clippy --manifest-path libfprint-bridge/Cargo.toml \
  --all-targets -- -D warnings
```

Running fixture-based parity programs and live hardware diagnostics remains
explicit. Ordinary `cargo test --all-targets` must stay deterministic and must not
open the sensor.

## Validation fixture root

Tools that consume the shared validation tree resolve it in this order:

1. an explicit root or path argument supported by the tool;
2. `GOODIX_VALIDATION_ROOT`;
3. the repository-relative `../traces/validation` default.

Example:

```bash
GOODIX_VALIDATION_ROOT=/path/to/traces/validation \
  cargo run --features validation-tools --bin feature_orientation_parity
```

Shared fixture readers and writers live in the feature-gated
`goodix_info::validation_support` module. Default builds do not compile that
module.

The public repository does not distribute the external parity fixtures. Independent
reproduction therefore requires separately collected reference evidence.

## Integration tests

Fixture-free cross-module behavior belongs under `tests/`.

These tests exercise the public library from outside the crate and run with the
normal deterministic suite:

```bash
cargo test --all-targets
```

Do not move fixture-dependent vendor comparisons or live USB diagnostics into
integration tests merely to reduce the number of executables. Those checks have
different evidence requirements and remain explicit.

## Tool placement

Use the narrowest location that matches the test:

| Location | Use |
| --- | --- |
| ordinary unit tests | deterministic local invariants |
| `tests/` | deterministic public cross-module behavior |
| `validation/` | fixture-based differential or parity checks |
| `hardware/` | live-device behavior and lifecycle diagnostics |

If a tool no longer depends on external reference evidence or hardware, its logic
should usually move into the deterministic test suite rather than remain as a
standalone program.

## Related documentation

* [Root README](../README.md)
* [Reverse-engineering evidence rules](../REVERSE_ENGINEERING.md)
* [Research questions and experimental design](../RESEARCH.md)
* [libfprint overlay](../libfprint-overlay/libfprint_overlay.md)