#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later

from __future__ import annotations

import argparse
import re
import shutil
from pathlib import Path

DRIVER = "goodix550a"

LIBFPRINT_VERSION_PATTERN = re.compile(
    r"^[ \t]*version:[ \t]*'1\.94\.100',[ \t]*$",
    re.MULTILINE,
)

MAPPING = "  'goodix550a' :\n  [ 'drivers/goodix550a.c' ],\n"

BRIDGE_DEP_BLOCK = """goodix550a_bridge_deps = []
if 'goodix550a' in drivers
    goodix550a_bridge_deps += [dependency('goodix550a-bridge')]
endif

"""

BRIDGE_DEPS_APPEND = "deps += goodix550a_bridge_deps\n"

UNSUPPORTED_ID_PATTERN = re.compile(
    r"^[ \t]*\{\s*\.vid\s*=\s*0x27c6\s*,"
    r"\s*\.pid\s*=\s*0x550a\s*,?\s*\},[ \t]*\r?\n",
    re.MULTILINE | re.IGNORECASE,
)

# Catch the same VID:PID inside one C initializer even if upstream reformats
# or reverses the .vid/.pid field order.
UNSUPPORTED_ID_FALLBACK = re.compile(
    r"\{[^{}]*(?:"
    r"0x27c6[^{}]*0x550a|"
    r"0x550a[^{}]*0x27c6"
    r")[^{}]*\}",
    re.IGNORECASE | re.DOTALL,
)


def rewrite_unsupported_device_entry(text: str) -> tuple[str, bool]:
    matches = list(UNSUPPORTED_ID_PATTERN.finditer(text))

    if len(matches) > 1:
        raise SystemExit(
            "found multiple 27c6:550a unsupported-device entries; "
            "refusing an ambiguous edit"
        )

    if len(matches) == 1:
        return UNSUPPORTED_ID_PATTERN.sub("", text, count=1), True

    # No strict match is expected after our overlay has already run.
    # If the VID:PID still exists in an initializer in a form we do not know
    # how to edit exactly, fail rather than silently creating contradictory
    # supported/unsupported metadata.
    if UNSUPPORTED_ID_FALLBACK.search(text):
        raise SystemExit(
            "27c6:550a is still present in fprint-list-udev-hwdb.c "
            "but its initializer format was not recognized"
        )

    return text, False


def rewrite_library_meson(text: str) -> str:
    library = text

    if "'goodix550a' :" in library:
        if MAPPING not in library:
            raise SystemExit(
                "goodix550a already appears in libfprint/meson.build "
                "with an unexpected driver mapping"
            )
    else:
        anchor = "driver_sources = {\n"
        index = library.find(anchor)

        if index < 0:
            raise SystemExit("cannot find libfprint driver_sources table")

        index += len(anchor)
        library = library[:index] + MAPPING + library[index:]

    if "goodix550a_bridge_deps" in library:
        if BRIDGE_DEP_BLOCK not in library:
            raise SystemExit(
                "goodix550a_bridge_deps already appears with an "
                "unexpected dependency block"
            )
    else:
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
        library = (
            library[:deps_end]
            + BRIDGE_DEPS_APPEND
            + library[deps_end:]
        )

    return library


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Apply the GF3258 libfprint driver overlay"
    )
    parser.add_argument("libfprint_source", type=Path)
    args = parser.parse_args()

    root = args.libfprint_source.resolve()

    root_meson = root / "meson.build"
    library_meson = root / "libfprint" / "meson.build"
    unsupported_hwdb = root / "libfprint" / "fprint-list-udev-hwdb.c"
    driver_dest = root / "libfprint" / "drivers" / "goodix550a.c"
    driver_source = Path(__file__).with_name("goodix550a.c")

    if (
        not root_meson.is_file()
        or not library_meson.is_file()
        or not unsupported_hwdb.is_file()
    ):
        raise SystemExit(f"not a supported libfprint source tree: {root}")

    root_text = root_meson.read_text()

    if not LIBFPRINT_VERSION_PATTERN.search(root_text):
        raise SystemExit(
            "this overlay is pinned to libfprint 1.94.100; "
            f"refusing source tree: {root}"
        )

    if not driver_source.is_file():
        raise SystemExit(f"overlay driver source is missing: {driver_source}")

    driver_bytes = driver_source.read_bytes()

    if driver_dest.exists() and driver_dest.read_bytes() != driver_bytes:
        raise SystemExit(
            "refusing to overwrite an existing non-overlay "
            f"goodix550a driver: {driver_dest}"
        )

    # Preflight every text transformation before mutating the target tree.
    original_library = library_meson.read_text()
    new_library = rewrite_library_meson(original_library)

    original_unsupported = unsupported_hwdb.read_text()
    new_unsupported, removed_unsupported = (
        rewrite_unsupported_device_entry(original_unsupported)
    )

    # All structural validation has succeeded. Commit the overlay.
    shutil.copy2(driver_source, driver_dest)

    if new_library != original_library:
        library_meson.write_text(new_library)

    if new_unsupported != original_unsupported:
        unsupported_hwdb.write_text(new_unsupported)

    print(f"Applied {DRIVER} overlay to {root}")
    print(f"Driver source: {driver_dest}")

    if removed_unsupported:
        print(
            "Removed 27c6:550a from libfprint's "
            "known-unsupported device list."
        )
    else:
        print(
            "27c6:550a is already absent from libfprint's "
            "known-unsupported device list."
        )

    print(
        "The goodix550a-bridge pkg-config dependency is required only when "
        "goodix550a is selected."
    )


if __name__ == "__main__":
    main()
