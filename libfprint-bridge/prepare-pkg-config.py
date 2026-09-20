#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later

from __future__ import annotations

import argparse
import os
import shutil
from pathlib import Path


LIBRARY_NAME = "libgoodix550a_bridge.so"
HEADER_NAME = "goodix550a_bridge.h"
PACKAGE_NAME = "goodix550a-bridge"
PACKAGE_VERSION = "0.1.0"


def main() -> None:
    crate = Path(__file__).resolve().parent

    parser = argparse.ArgumentParser(
        description=(
            "Stage the Goodix libfprint Rust bridge and create a relocatable "
            "pkg-config package"
        )
    )
    parser.add_argument(
        "--prefix",
        type=Path,
        default=crate / "target" / "release" / "stage",
        help=(
            "staging prefix; defaults to "
            "libfprint-bridge/target/release/stage"
        ),
    )
    parser.add_argument(
        "--library",
        type=Path,
        default=crate / "target" / "release" / LIBRARY_NAME,
        help="bridge shared library to stage",
    )
    args = parser.parse_args()

    source_library = args.library.expanduser().resolve()
    source_header = crate / "include" / HEADER_NAME
    prefix = args.prefix.expanduser().resolve()

    if not source_library.is_file():
        raise SystemExit(
            "bridge library does not exist; build it first: "
            f"{source_library}"
        )

    if not source_header.is_file():
        raise SystemExit(f"bridge header is missing: {source_header}")

    lib_dir = prefix / "lib"
    include_dir = prefix / "include"
    pc_dir = lib_dir / "pkgconfig"

    lib_dir.mkdir(parents=True, exist_ok=True)
    include_dir.mkdir(parents=True, exist_ok=True)
    pc_dir.mkdir(parents=True, exist_ok=True)

    staged_library = lib_dir / LIBRARY_NAME
    staged_header = include_dir / HEADER_NAME

    shutil.copy2(source_library, staged_library)
    shutil.copy2(source_header, staged_header)

    os.chmod(staged_library, 0o755)
    os.chmod(staged_header, 0o644)

    pc = pc_dir / f"{PACKAGE_NAME}.pc"
    pc.write_text(
        "\n".join(
            [
                "prefix=${pcfiledir}/../..",
                "libdir=${prefix}/lib",
                "includedir=${prefix}/include",
                "",
                f"Name: {PACKAGE_NAME}",
                (
                    "Description: Rust wire-protocol bridge for the "
                    "Goodix 27c6:550a libfprint driver"
                ),
                f"Version: {PACKAGE_VERSION}",
                "Libs: -L${libdir} -lgoodix550a_bridge",
                "Cflags: -I${includedir}",
                "",
            ]
        )
    )

    print(f"stage: {prefix}")
    print(f"library: {staged_library}")
    print(f"header: {staged_header}")
    print(f"pkg-config: {pc}")
    print(f"PKG_CONFIG_PATH: {pc_dir}")


if __name__ == "__main__":
    main()
