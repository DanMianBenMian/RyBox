#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
make_jbroot.py — build RyBox's bundled minimal jbroot (ProcursusBootstrap.zip).

Why this exists
---------------
RyBox no longer restores a REAL system image from an IPSW / .ryboxenv. Instead it
ships a small, STANDARD jbroot — the Procursus userspace tree (dpkg, apt, /usr,
/var, package databases) — inside the IPA as `Preinstalled/ProcursusBootstrap.zip`
and unzips it into the virtual root on first launch. That gives Sileo a real
dpkg/apt to drive without the user ever supplying a firmware.

This script builds that zip on a COMPUTER (where the bootstrap is easy to fetch
and decompress), so the IPA only ever carries the finished tree.

Usage
-----
1) You already have a Procursus bootstrap .tar.zst (or a plain .tar) on disk:

       python make_jbroot.py --tarzst bootstrap_*.tar.zst \
           --out ../preinstalled/ProcursusBootstrap.zip

2) Download first, then build (any URL that serves a .tar.zst / .tar):

       python make_jbroot.py --url https://.../bootstrap.tar.zst \
           --out ../preinstalled/ProcursusBootstrap.zip

3) Point at an already-extracted bootstrap directory (must contain usr/ or bin/):

       python make_jbroot.py --from-dir D:\\procursus\\bootstrap \
           --out ../preinstalled/ProcursusBootstrap.zip

Output
------
A FLAT zip: its entries are `usr/...`, `bin/...`, `etc/...`, `var/...` (no
top-level wrapper folder). RyBox extracts it straight into the virtual root, so
"/usr/bin/dpkg" becomes a real file under the jbroot.

Notes
-----
* The bootstrap is userspace-only and device-agnostic (arm64 iOS). Pick the
  iphoneos-arm64 build from your Procursus mirror.
* Executable permission bits are preserved in the zip so /usr/bin/dpkg stays
  runnable after extraction.
"""

import io
import os
import sys
import tarfile
import tempfile
import zipfile

DEFAULT_OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                           os.pardir, "preinstalled", "ProcursusBootstrap.zip")


def log(msg):
    print(msg, flush=True)


def open_tar(path):
    """Open a .tar, or a .tar.zst via the best available decoder."""
    if path.endswith(".zst") or path.endswith(".tar.zst"):
        data = open(path, "rb").read()
        raw = decompress_zstd(data)
        return tarfile.open(fileobj=io.BytesIO(raw), mode="r:*")
    return tarfile.open(path, mode="r:*")


def decompress_zstd(data: bytes) -> bytes:
    # Prefer the python module; fall back to the `zstd`/`tar` CLI if present.
    try:
        import zstandard  # type: ignore
        dctx = zstandard.ZstdDecompressor()
        log("[zstd] using python zstandard")
        # stream_reader().read() works even when the frame has NO embedded
        # content size (ZstdDecompressor.decompress() raises in that case).
        return dctx.stream_reader(io.BytesIO(data)).read()
    except Exception as e:
        log("[zstd] python zstandard unavailable/failed: %s" % e)
    import shutil
    import subprocess
    exe = shutil.which("zstd") or shutil.which("unzstd")
    if exe:
        log("[zstd] using CLI: %s" % exe)
        p = subprocess.run([exe, "-d", "-c"], input=data,
                           stdout=subprocess.PIPE)
        if p.returncode == 0:
            return p.stdout
    raise RuntimeError(
        "无法解压 .zst：请安装 `pip install zstandard` 或系统 `zstd` 后重试")


def extract_to(tar, dest):
    os.makedirs(dest, exist_ok=True)
    tar.extractall(dest)  # permission bits preserved on posix
    log("[extract] -> %s" % dest)


def flatten_single_top(dirpath):
    """If `dirpath` holds exactly one subdir that looks like a bootstrap root,
    move its contents up one level. Returns the directory that holds usr/ or bin/."""
    entries = [e for e in os.listdir(dirpath)
               if not e.startswith(".")]
    if len(entries) == 1:
        only = os.path.join(dirpath, entries[0])
        if os.path.isdir(only) and (
                os.path.isdir(os.path.join(only, "usr")) or
                os.path.isdir(os.path.join(only, "bin"))):
            log("[flatten] 单层目录 %s -> 上移内容" % entries[0])
            for name in os.listdir(only):
                src = os.path.join(only, name)
                dst = os.path.join(dirpath, name)
                if os.path.exists(dst):
                    if os.path.isdir(dst):
                        continue
                    os.remove(dst)
                os.rename(src, dst)
            os.rmdir(only)
    return dirpath


def build_zip(srcdir, out):
    srcdir = flatten_single_top(srcdir)
    if not (os.path.isdir(os.path.join(srcdir, "usr")) or
            os.path.isdir(os.path.join(srcdir, "bin"))):
        log("[warn] 目录里没找到 usr/ 或 bin/，可能不是有效的 bootstrap")
    os.makedirs(os.path.dirname(os.path.abspath(out)), exist_ok=True)
    n = 0
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as z:
        for root, _dirs, files in os.walk(srcdir):
            for f in files:
                full = os.path.join(root, f)
                rel = os.path.relpath(full, srcdir).replace(os.sep, "/")
                # Store unix mode so executables stay executable.
                st = os.stat(full)
                info = zipfile.ZipInfo(rel)
                info.external_attr = (st.st_mode & 0xFFFF) << 16
                with open(full, "rb") as fh:
                    z.writestr(info, fh.read())
                n += 1
    size = os.path.getsize(out)
    log("[zip] 写入 %d 个条目 -> %s (%d bytes)" % (n, out, size))


def main():
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("--tarzst", help="本地 bootstrap .tar / .tar.zst 文件")
    ap.add_argument("--url", help="下载 bootstrap .tar / .tar.zst 的 URL")
    ap.add_argument("--from-dir", help="已解压好的 bootstrap 目录（含 usr/ 或 bin/）")
    ap.add_argument("--out", default=DEFAULT_OUT, help="输出 zip 路径")
    args = ap.parse_args()

    tmp = tempfile.mkdtemp(prefix="make_jbroot_")
    try:
        if args.from_dir:
            src = args.from_dir
        else:
            archive = None
            if args.url:
                import urllib.request
                archive = os.path.join(tmp, "bootstrap.dl")
                log("[dl] %s" % args.url)
                urllib.request.urlretrieve(args.url, archive)
            elif args.tarzst:
                archive = args.tarzst
            else:
                ap.error("必须提供 --tarzst / --url / --from-dir 之一")
            tar = open_tar(archive)
            extract_to(tar, tmp)
            tar.close()
            src = tmp

        build_zip(src, args.out)
    finally:
        import shutil
        shutil.rmtree(tmp, ignore_errors=True)
    log("DONE")


if __name__ == "__main__":
    main()
