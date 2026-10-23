#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
build_ryboxenv.py — one-shot PC pipeline:  IPSW  ->  .ryboxenv

RyBox must restore a REAL system environment, but a whole firmware must never
travel inside the IPA (that would make it gigabytes). So the heavy lifting
happens here, on a computer, once:

    1. ipsw.exe extract --dmg fs   -> pull the AEA volume out of the IPSW
    2. ipsw.exe fw aea  <vol>      -> pure-Go AEA decryption (no key hunting)
    3. 7z x <dmg> -ir!<dirs>       -> 7-Zip reads the APFS straight out of the
                                      decrypted DMG and extracts only what we
                                      want (a full extract is ~15 GB)
    4. make_ryboxenv pack          -> zip: ryboxenv.json + rootfs/...

The result (.ryboxenv) is what RyBox imports in its boot flow.

Tools needed
------------
  * blacktop/ipsw  https://github.com/blacktop/ipsw/releases
        Windows: ipsw_<ver>_windows_x86_64.zip   (NOT the "ipswd" one)
  * 7-Zip 24.08+   https://www.7-zip.org/         (reads APFS)

Both are auto-detected; override with --ipsw-tool / --sevenzip.

Usage
-----
  # full pipeline, straight from the Apple IPSW
  python build_ryboxenv.py --ipsw D:\\fw\\iPad_..._Restore.ipsw \\
                           --out RyBox-iPadOS27.ryboxenv

  # already decrypted? start from the DMG
  python build_ryboxenv.py --from-dmg D:\\RyBoxFirmware\\dec\\094-13699-084.dmg \\
                           --out RyBox-iPadOS27.ryboxenv

  # already extracted? just pack it
  python build_ryboxenv.py --from-dir D:\\RyBoxFirmware\\root --out RyBox.ryboxenv

  # bigger packages
  python build_ryboxenv.py --ipsw ... --profile full      # + frameworks
  python build_ryboxenv.py --ipsw ... --system-apps       # + /Applications
"""

from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from make_ryboxenv import pack  # noqa: E402

# --------------------------------------------------------------------------
# What gets extracted out of the APFS volume
# --------------------------------------------------------------------------

# "core" (default, ~1 GB): binaries, daemons, libs, configs — the stuff a
# jailbreak-ish environment actually runs and reads.
CORE_DIRS = [
    r"bin",
    r"sbin",
    r"usr\bin",
    r"usr\sbin",
    r"usr\libexec",
    r"usr\lib",
    r"usr\share",
    r"etc",
    r"private\etc",
    r"System\Library\LaunchDaemons",
    r"System\Library\CoreServices",
    r"Library\Preferences",
]

# "full": adds the framework trees (several GB — the RyBox process already maps
# the device's real dyld cache, so these are mostly for inspection).
FULL_DIRS = [
    r"System\Library\Frameworks",
    r"System\Library\PrivateFrameworks",
    r"System\Library\PreferenceBundles",
    r"System\Library\TextInput",
    r"usr\standalone",
]

SYSTEM_APPS = r"Applications"


def which(name: str, extra: str | None = None) -> str | None:
    if extra and os.path.isfile(extra):
        return extra
    p = shutil.which(name)
    if p:
        return p
    for cand in (os.path.join(HERE, name), os.path.join(HERE, "tools", name)):
        if os.path.isfile(cand):
            return cand
    for d in (r"D:\RyBoxFirmware\tools", r"C:\Program Files\7-Zip",
              r"C:\Program Files (x86)\7-Zip"):
        cand = os.path.join(d, name)
        if os.path.isfile(cand):
            return cand
    return None


def run(cmd: list[str], quiet: bool = False) -> int:
    if not quiet:
        print("  $", " ".join(f'"{c}"' if " " in c else c for c in cmd), flush=True)
    r = subprocess.run(cmd, capture_output=True, text=True, errors="replace")
    if r.stdout and not quiet:
        for line in r.stdout.splitlines()[-6:]:
            print("   ", line, flush=True)
    if r.returncode != 0 and not quiet:
        print("    [stderr]", r.stderr[-800:], flush=True)
    return r.returncode


def stage_ipsw(ipsw_tool: str, ipsw: str, work: str, cryptex: bool) -> list[str]:
    """Extract the AEA volume(s) from the IPSW and decrypt them."""
    out: list[str] = []
    for kind in (["fs"] + (["sys"] if cryptex else [])):
        d = os.path.join(work, "dmg-" + kind)
        os.makedirs(d, exist_ok=True)
        print(f"[1] extract --dmg {kind} ...", flush=True)
        if run([ipsw_tool, "extract", "--dmg", kind, "-o", d, ipsw]) != 0:
            print(f"    warn: --dmg {kind} failed, skipping", flush=True)
            continue
        for root, _, files in os.walk(d):
            for fn in files:
                if not fn.endswith(".dmg.aea"):
                    continue
                aea = os.path.join(root, fn)
                dec = os.path.join(work, "dec")
                os.makedirs(dec, exist_ok=True)
                print(f"[2] AEA decrypt {fn} ...", flush=True)
                if run([ipsw_tool, "fw", "aea", aea, "-o", dec]) == 0:
                    out.append(os.path.join(dec, fn[:-4]))
                else:
                    print("    warn: decryption failed for", fn, flush=True)
    return out


def stage_7z(sevenzip: str, dmgs: list[str], dest: str, dirs: list[str]) -> int:
    """Extract only the curated directories out of each APFS DMG."""
    os.makedirs(dest, exist_ok=True)
    for dmg in dmgs:
        print(f"[3] 7-Zip extract {os.path.basename(dmg)} ...", flush=True)
        cmd = [sevenzip, "x", dmg, "-o" + dest, "-y"]
        for d in dirs:
            cmd.append(r"-ir!" + d + r"\*")
        if run(cmd) != 0:
            print("    warn: 7z reported an error (partial extract?)", flush=True)
    return sum(len(fs) for _, _, fs in os.walk(dest))


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        description="Build a RyBox .ryboxenv system-environment package from an IPSW")
    src = ap.add_mutually_exclusive_group(required=True)
    src.add_argument("--ipsw", help="Apple IPSW (full pipeline)")
    src.add_argument("--from-dmg", help="already AEA-decrypted DMG")
    src.add_argument("--from-dir", help="already extracted system tree")
    ap.add_argument("--out", required=True, help="output .ryboxenv path")
    ap.add_argument("--profile", choices=["core", "full"], default="core")
    ap.add_argument("--system-apps", action="store_true",
                    help="also package /Applications (big)")
    ap.add_argument("--cryptex", action="store_true",
                    help="also decrypt+merge Cryptex1,SystemOS")
    ap.add_argument("--ipsw-tool", default=None, help="path to ipsw(.exe)")
    ap.add_argument("--sevenzip", default=None, help="path to 7z(.exe)")
    ap.add_argument("--workdir", default=None, help="temp work dir")
    ap.add_argument("--keep-temp", action="store_true")
    ap.add_argument("--quiet", action="store_true")
    args = ap.parse_args(argv)

    dirs = list(CORE_DIRS)
    if args.profile == "full":
        dirs += FULL_DIRS
    if args.system_apps:
        dirs.append(SYSTEM_APPS)

    if args.from_dir:
        return pack(args.from_dir, args.out, args.system_apps,
                    None, None, None, None, args.quiet)

    work = args.workdir or tempfile.mkdtemp(prefix="ryboxenv-")
    keep = args.keep_temp or bool(args.workdir)
    try:
        if args.ipsw:
            ipsw_tool = which("ipsw.exe", args.ipsw_tool) or which("ipsw", args.ipsw_tool)
            if not ipsw_tool:
                print("ERROR: ipsw not found. Pass --ipsw-tool <path> or put "
                      "ipsw.exe in PATH / tools/.", file=sys.stderr)
                return 2
            dmgs = stage_ipsw(ipsw_tool, args.ipsw, work, args.cryptex)
            if not dmgs:
                print("ERROR: no decrypted DMG produced", file=sys.stderr)
                return 3
        else:
            dmgs = [args.from_dmg]

        sevenzip = which("7z.exe", args.sevenzip) or which("7z", args.sevenzip)
        if not sevenzip:
            print("ERROR: 7-Zip not found. Pass --sevenzip <path>.", file=sys.stderr)
            return 2

        root = os.path.join(work, "root")
        n = stage_7z(sevenzip, dmgs, root, dirs)
        print(f"[3] extracted {n} files into {root}", flush=True)

        print("[4] packing .ryboxenv ...", flush=True)
        rc = pack(root, args.out, args.system_apps, None, None, None, None, args.quiet)
        return rc
    finally:
        if not keep:
            print("[5] cleaning temp ...", flush=True)
            shutil.rmtree(work, ignore_errors=True)
        else:
            print(f"[5] kept temp at {work}")


if __name__ == "__main__":
    raise SystemExit(main())
