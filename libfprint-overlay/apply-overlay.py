#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later

from __future__ import annotations

import argparse
import shutil
from pathlib import Path

DRIVER = "goodix550a"
MAPPING = "  'goodix550a' :\n  [ 'drivers/goodix550a.c' ],\n"
BRIDGE_DEP_BLOCK = """goodix550a_bridge_deps = []
if 'goodix550a' in drivers
    goodix550a_bridge_deps += [dependency('goodix550a-bridge')]
endif

"""
BRIDGE_DEPS_APPEND = "deps += goodix550a_bridge_deps\n"


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Apply the GF3258 libfprint driver overlay"
    )
    parser.add_argument("libfprint_source", type=Path)
    args = parser.parse_args()

    root = args.libfprint_source.resolve()
    library_meson = root / "libfprint" / "meson.build"
    driver_dest = root / "libfprint" / "drivers" / "goodix550a.c"

    if not (root / "meson.build").is_file() or not library_meson.is_file():
        raise SystemExit(f"not a libfprint source tree: {root}")

    driver_source = Path(__file__).with_name("goodix550a.c")
    shutil.copy2(driver_source, driver_dest)

    library = library_meson.read_text()
    if "'goodix550a' :" not in library:
        anchor = "driver_sources = {\n"
        index = library.find(anchor)
        if index < 0:
            raise SystemExit("cannot find libfprint driver_sources table")
        index += len(anchor)
        library = library[:index] + MAPPING + library[index:]

    if "goodix550a_bridge_deps = []" not in library:
        deps_anchor = "deps = [\n"
        index = library.find(deps_anchor)
        if index < 0:
            raise SystemExit("cannot find libfprint dependency list")
        library = library[:index] + BRIDGE_DEP_BLOCK + library[index:]

    if BRIDGE_DEPS_APPEND not in library:
        deps_start = library.find("deps = [\n")
        deps_end = library.find("] + optional_deps\n", deps_start)
        if deps_start < 0 or deps_end < 0:
            raise SystemExit("cannot find end of libfprint dependency list")
        deps_end += len("] + optional_deps\n")
        library = library[:deps_end] + BRIDGE_DEPS_APPEND + library[deps_end:]

    library_meson.write_text(library)

    print(f"Applied {DRIVER} overlay to {root}")
    print(f"Driver source: {driver_dest}")
    print(
        "The goodix550a-bridge pkg-config dependency is required only when "
        "goodix550a is selected."
    )


if __name__ == "__main__":
    main()
