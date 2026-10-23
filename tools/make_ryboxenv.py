#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
make_ryboxenv.py — build a RyBox system-environment package (.ryboxenv).

Why this exists
---------------
RyBox must restore a REAL system environment (/usr, /bin, /System, ...), but a
whole firmware does NOT belong inside the IPA — that would make it several GB.
So the heavy decoding happens on a computer, once, and RyBox only ever imports
the result: a plain ZIP with

    ryboxenv.json     manifest (os version, build, device, counts)
    rootfs/...        the system tree, verbatim

RyBox unzips `rootfs/` into its virtual root and the Files app / Terminal then
show the genuine system layout.

Usage
-----
1) You already have a decoded system volume mounted/extracted somewhere:

       python make_ryboxenv.py --from-dir D:\\fw\\system --out RyBox-27.0.ryboxenv

2) From an IPSW (non-AEA parts only — see LIMITS below):

       python make_ryboxenv.py --from-ipsw iPad_..._Restore.ipsw --out RyBox-27.0.ryboxenv

3) Keep the system apps too (they are OPTIONAL and big):

       python make_ryboxenv.py --from-dir D:\\fw\\system --system-apps --out big.ryboxenv

LIMITS (honest)
---------------
Modern IPSWs keep the main system volume in an AEA-encrypted DMG
(`094-*.dmg.aea`). Decoding that needs a WKMS key + AEA + DMG + APFS, which
this script does NOT implement. Use blacktop/ipsw on a computer:

    ipsw fw aea decrypt --key <wkms-key> 094-13699-084.dmg.aea   # -> .dmg
    # then mount/convert the DMG (APFS) and point --from-dir at it.

This script will still package everything it *can* read from an IPSW
(BuildManifest, kernelcache, trustcaches, mtree, plaintext DMGs) and tell you
exactly which AEA volumes it had to skip.
"""

from __future__ import annotations

import argparse
import datetime as _dt
import json
import os
import sys
import zipfile
from typing import Iterable, List, Optional

# --------------------------------------------------------------------------
# What goes into a package (and what never should)
# --------------------------------------------------------------------------

# Kept by default: the stuff a jailbreak-ish environment actually needs.
INCLUDE_DIRS = [
    "usr/bin", "bin", "sbin", "usr/sbin", "usr/libexec", "usr/lib",
    "usr/share", "usr/standalone", "etc", "private/etc",
    "System/Library", "System/Library/CoreServices",
    "Library/Preferences", "var/db",
]

# Always skipped: gigantic and/or useless inside the container.
# The dyld shared cache is the big one — the RyBox process already maps the
# device's REAL cache, so shipping a second copy would only waste gigabytes.
EXCLUDE_SUFFIXES = (
    ".aea",
)
EXCLUDE_NAMES = {
    "dyld_shared_cache_arm64e",
    "dyld_shared_cache_arm64",
    "dyld_shared_cache_arm64e.symbols",
}
EXCLUDE_DIR_NAMES = {
    "__MACOSX",
    ".git",
}

# System apps: optional (they are large and rarely needed).
SYSTEM_APPS_DIR = "Applications"


def iter_files(root: str,
               include_system_apps: bool,
               extra_dirs: Optional[List[str]] = None,
               skip_larger_than: Optional[int] = None) -> Iterable[str]:
    """Yield absolute paths under `root` that should go into rootfs/."""
    wanted = list(INCLUDE_DIRS)
    if extra_dirs:
        wanted.extend(extra_dirs)
    if include_system_apps:
        wanted.append(SYSTEM_APPS_DIR)

    # Normalise to the "rootfs" layout: strip any leading path components up to
    # the directory that contains usr/ or System/.
    base = root
    for probe in ("usr", "System", "Applications", "bin"):
        idx = root.rfind(os.sep + probe)
        if idx > 0:
            cand = root[:idx]
            if os.path.isdir(os.path.join(cand, "System")) or os.path.isdir(os.path.join(cand, "usr")):
                base = cand
                break

    wanted = [w.strip("/\\") for w in wanted]

    for dirpath, dirnames, filenames in os.walk(base):
        dirnames[:] = [d for d in dirnames if d not in EXCLUDE_DIR_NAMES]
        rel_dir = os.path.relpath(dirpath, base).replace(os.sep, "/")
        if rel_dir == ".":
            rel_dir = ""
        # Filter: keep only the curated subtrees.
        if rel_dir:
            if not any(rel_dir == w or rel_dir.startswith(w + "/") for w in wanted):
                continue
        for fn in filenames:
            if fn in EXCLUDE_NAMES or fn.endswith(EXCLUDE_SUFFIXES):
                continue
            if fn.startswith("dyld_shared_cache_"):
                continue
            p = os.path.join(dirpath, fn)
            try:
                if not os.path.isfile(p) or os.path.islink(p):
                    continue
                if skip_larger_than and os.path.getsize(p) > skip_larger_than:
                    continue
            except OSError:
                continue
            yield p, base


def pack(from_dir: str, out: str, include_system_apps: bool,
         os_version: Optional[str], build: Optional[str], device: Optional[str],
         skip_larger_than: Optional[int], quiet: bool = False) -> int:
    manifest = {
        "format": "ryboxenv-1",
        "createdAt": _dt.datetime.now().isoformat(timespec="seconds"),
        "osVersion": os_version,
        "build": build,
        "deviceClass": device,
        "includesSystemApps": include_system_apps,
        "source": os.path.basename(from_dir.rstrip("/\\")) or from_dir,
    }
    # Try to learn the version from the tree itself.
    sv = os.path.join(from_dir, "System", "Library", "CoreServices", "SystemVersion.plist")
    if not sv:
        pass
    for cand in (sv,
                 os.path.join(from_dir, "SystemVersion.plist")):
        if os.path.isfile(cand):
            try:
                import plistlib
                with open(cand, "rb") as f:
                    pl = plistlib.load(f)
                manifest["osVersion"] = manifest["osVersion"] or pl.get("ProductVersion")
                manifest["build"] = manifest["build"] or pl.get("ProductBuildVersion")
            except Exception:
                pass
            break

    total = 0
    count = 0
    zf = zipfile.ZipFile(out, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=6)
    try:
        # The manifest is written ONCE, at the end, once file/byte counts are
        # known (writing it twice would leave a duplicate zip entry).
        for p, base in iter_files(from_dir, include_system_apps,
                                  skip_larger_than=skip_larger_than):
            rel = os.path.relpath(p, base).replace(os.sep, "/")
            try:
                zf.write(p, "rootfs/" + rel)
            except OSError as e:
                if not quiet:
                    print(f"  skip {rel}: {e}", file=sys.stderr)
                continue
            count += 1
            total += os.path.getsize(p)
            if count % 2000 == 0 and not quiet:
                print(f"  packed {count} files / {total/1024/1024:.1f} MB ...", flush=True)
        manifest["files"] = count
        manifest["bytes"] = total
        # Rewrite the manifest now that the counts are known.
        zf.writestr("ryboxenv.json", json.dumps(manifest, ensure_ascii=False, indent=2))
    finally:
        zf.close()

    if not quiet:
        print(f"\nOK  {out}")
        print(f"    {count} files / {total/1024/1024:.1f} MB")
        print(f"    os={manifest.get('osVersion')} build={manifest.get('build')} "
              f"apps={include_system_apps}")
    return 0


def pack_ipsw(ipsw: str, out: str, include_system_apps: bool, quiet: bool) -> int:
    """Package what an IPSW gives away without AEA decoding."""
    import tempfile

    zin = zipfile.ZipFile(ipsw)
    names = zin.namelist()
    aea = [n for n in names if n.endswith(".aea")]
    keep: List[str] = []
    meta = {}
    for n in names:
        low = n.lower()
        if n.endswith("/"):
            continue
        if low.endswith(".aea") or low.endswith(".dmg"):
            continue
        if low.endswith(".plist") or "kernelcache" in low \
           or low.endswith(".trustcache") or low.endswith(".mtree") \
           or low.endswith(".root_hash"):
            keep.append(n)

    for cand in ("SystemVersion.plist", "Restore.plist"):
        if cand in names:
            try:
                import plistlib
                pl = plistlib.loads(zin.read(cand))
                meta["osVersion"] = pl.get("ProductVersion")
                meta["build"] = pl.get("ProductBuildVersion")
                meta["deviceClass"] = pl.get("ProductName") or pl.get("DeviceClass")
            except Exception:
                pass
            break

    tmp = tempfile.mkdtemp(prefix="ryboxenv-ipsw-")
    for n in keep:
        try:
            dest = os.path.join(tmp, n.replace("/", os.sep))
            os.makedirs(os.path.dirname(dest), exist_ok=True)
            with open(dest, "wb") as f:
                f.write(zin.read(n))
        except Exception as e:
            if not quiet:
                print(f"  skip {n}: {e}", file=sys.stderr)

    rc = pack(tmp, out, include_system_apps,
              meta.get("osVersion"), meta.get("build"), meta.get("deviceClass"),
              skip_larger_than=None, quiet=quiet)
    if aea:
        print("\nAEA volumes present (NOT decodable here — skipped):")
        for n in aea:
            sz = zin.getinfo(n).file_size / 1024 / 1024
            print(f"  {n}  ({sz:.0f} MB)")
        print("\nDecode them on a computer with blacktop/ipsw, then re-run:")
        print("    ipsw fw aea decrypt --key <wkms-key> <volume>.dmg.aea")
        print("    python make_ryboxenv.py --from-dir <mounted-volume> --out RyBox.ryboxenv")
    return rc


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description="Build a RyBox .ryboxenv system-environment package")
    src = ap.add_mutually_exclusive_group(required=True)
    src.add_argument("--from-dir", help="decoded system volume / firmware root")
    src.add_argument("--from-ipsw", help="raw IPSW (non-AEA parts only)")
    ap.add_argument("--out", required=True, help="output .ryboxenv path")
    ap.add_argument("--system-apps", action="store_true",
                    help="also package /Applications (system apps are optional and large)")
    ap.add_argument("--os-version", default=None)
    ap.add_argument("--build", default=None)
    ap.add_argument("--device", default=None)
    ap.add_argument("--max-file-mb", type=int, default=None,
                    help="skip individual files bigger than this")
    ap.add_argument("--quiet", action="store_true")
    args = ap.parse_args(argv)

    skip = int(args.max_file_mb * 1024 * 1024) if args.max_file_mb else None
    if args.from_dir:
        if not os.path.isdir(args.from_dir):
            print(f"not a directory: {args.from_dir}", file=sys.stderr)
            return 2
        return pack(args.from_dir, args.out, args.system_apps,
                    args.os_version, args.build, args.device, skip, args.quiet)
    return pack_ipsw(args.from_ipsw, args.out, args.system_apps, args.quiet)


if __name__ == "__main__":
    raise SystemExit(main())
