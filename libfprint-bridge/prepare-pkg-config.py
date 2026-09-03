#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later

from __future__ import annotations

from pathlib import Path


def main() -> None:
    crate = Path(__file__).resolve().parent
    release = crate / "target" / "release"
    library = release / "libgoodix550a_bridge.so"
    header = crate / "include" / "goodix550a_bridge.h"

    if not library.is_file():
        raise SystemExit(
            f"bridge library does not exist; run cargo build --release first: {library}"
        )
    if not header.is_file():
        raise SystemExit(f"bridge header is missing: {header}")

    pc_dir = release / "pkgconfig"
    pc_dir.mkdir(parents=True, exist_ok=True)
    pc = pc_dir / "goodix550a-bridge.pc"
    pc.write_text(
        "\n".join(
            [
                f"prefix={release}",
                "libdir=${prefix}",
                f"includedir={crate / 'include'}",
                "",
                "Name: goodix550a-bridge",
                "Description: Rust wire-protocol bridge for the Goodix 27c6:550a libfprint driver",
                "Version: 0.1.0",
                "Libs: -L${libdir} -lgoodix550a_bridge",
                "Cflags: -I${includedir}",
                "",
            ]
        )
    )
    print(pc)


if __name__ == "__main__":
    main()
