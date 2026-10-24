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
A FLAT zip with NO top-level wrapper folder. Modern Procursus bootstraps are
ROOTLESS, so entries look like `var/jb/usr/bin/dpkg`,
`var/jb/var/lib/dpkg/...`, plus a synthesised root-level `bin/sh` / `bin/bash`
/ `usr/bin/env` and the dpkg admindir skeleton (see build_zip_from_tar).
RyBox extracts it straight into the virtual root, which the guest sees as
its "/", so dpkg's compiled-in `/var/jb/...` paths and `#!/bin/sh` scripts
both resolve.

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


def normalize_arc(p):
    """Normalise a tar member / link path to a clean relative zip arcname."""
    p = p.replace("\\", "/")
    while p.startswith("./"):
        p = p[2:]
    p = p.lstrip("/")
    p = os.path.normpath(p).replace(os.sep, "/")
    return "" if p in (".", "") else p


def escapes_root(rel):
    return rel.startswith("../") or rel == ".."


def store(z, arcname, data, execbit):
    info = zipfile.ZipInfo(arcname)
    # NOTE: ZipInfo() defaults compress_type to ZIP_STORED — without this line
    # the jbroot zip ships UNCOMPRESSED (~125 MB instead of ~40 MB).
    info.compress_type = zipfile.ZIP_DEFLATED
    # RyUnzip chmods 0755 when the external attr has any exec bit set, else
    # 0644 — mirror the source mode so /usr/bin/dpkg stays runnable.
    info.external_attr = (0o755 if execbit else 0o644) << 16
    z.writestr(info, data)


def build_zip_from_tar(tar, out):
    """Stream a Procursus bootstrap tar straight into the flat jbroot zip.

    Works on the TAR MEMBER LIST (not an on-disk walk) so symlinks can be
    dereferenced correctly in both flavours the bootstrap uses:
      * relative:  'usr/bin/chsh'            -> 'chpass'
      * absolute:  'var/jb/usr/bin/sh'       -> '/var/jb/usr/bin/dash'
    An on-disk walk would resolve the absolute ones against the HOST root
    (nonexistent on the build machine) and silently drop them — 43 links
    including sh itself. Instead we map an absolute target back into the
    extraction root and copy the TARGET member's bytes + mode.

    Link chains are followed transitively (e.g. bash -> bash5) with a cycle
    guard, because several bootstrap entries are links-to-links.
    """
    members = tar.getmembers()
    reg = {}   # normalised name -> regular-file member
    link = {}  # normalised name -> linkname (sym or hard)
    for m in members:
        name = normalize_arc(m.name)
        if not name:
            continue
        if m.isreg():
            reg[name] = m
        elif m.issym() or m.islnk():
            link[name] = m.linkname

    def resolve_target(start):
        """Follow link chains to the final regular member (None if broken)."""
        cur = start
        seen = set()
        for _ in range(16):
            if cur in reg:
                return reg[cur]
            if cur not in link or cur in seen:
                return None
            seen.add(cur)
            tgt = link[cur]
            cur = (normalize_arc(tgt) if tgt.startswith("/")
                   else normalize_arc(os.path.join(os.path.dirname(cur), tgt)))
            if escapes_root(cur):
                return None
        return None

    os.makedirs(os.path.dirname(os.path.abspath(out)), exist_ok=True)
    n = 0
    skipped = 0
    written = set()
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as z:
        for m in members:
            name = normalize_arc(m.name)
            if not name or m.isdir():
                continue
            if m.issym() or m.islnk():
                tm = resolve_target(name)
                if tm is None:
                    skipped += 1  # broken link -> drop (RyUnzip can't make links)
                    continue
                store(z, name, tar.extractfile(tm).read(),
                      bool(tm.mode & 0o111))
                written.add(name)
                n += 1
            elif m.isreg():
                store(z, name, tar.extractfile(m).read(), bool(m.mode & 0o111))
                written.add(name)
                n += 1
            else:
                skipped += 1  # device nodes, fifos... not in this bootstrap

        # ---- synthesised skeleton (not present in the bootstrap tar) ------
        # 1) dpkg admindir: the bootstrap ships the dpkg/apt binaries and
        #    /etc/apt config, but NOT /var/jb/var/lib/dpkg — on a real device
        #    dpkg creates it on first run. We ship it so dpkg/apt start clean.
        # 2) root-level /bin/sh, /bin/bash, /usr/bin/env: on a real rootless
        #    device these are the SYSTEM binaries; RyBox's virtual root IS the
        #    guest's "/", so without them every "#!/bin/sh" maintainer script
        #    would fail to exec. RyUnzip cannot create symlinks, so these are
        #    plain copies (dereferenced exactly like the tar's own links).
        skeleton_dirs = [
            "var/jb/var/lib/dpkg/",
            "var/jb/var/lib/dpkg/info/",
            "var/jb/var/lib/dpkg/updates/",
            "var/jb/var/lib/apt/lists/",
            "var/jb/var/lib/apt/lists/partial/",
            "var/jb/var/log/",
            "var/jb/var/log/apt/",
            "bin/",
            "usr/",
            "usr/bin/",
        ]
        skeleton_files = [
            ("var/jb/var/lib/dpkg/status", b""),   # no packages installed yet
            ("var/jb/var/lib/dpkg/available", b""),
        ]
        copies = [
            ("bin/sh",   "var/jb/usr/bin/dash"),
            ("bin/bash", "var/jb/bin/bash"),
            ("usr/bin/env", "var/jb/usr/bin/env"),
        ]
        for d in skeleton_dirs:
            if any(w == d.rstrip("/") or w.startswith(d) for w in written):
                continue
            info = zipfile.ZipInfo(d)
            info.external_attr = (0o040755) << 16  # S_IFDIR | 0755
            z.writestr(info, b"")
            n += 1
        for path, data in skeleton_files:
            if path in written:
                continue
            store(z, path, data, False)
            written.add(path)
            n += 1
        for dst, src in copies:
            if dst in written:
                continue
            tm = resolve_target(src)
            if tm is None:
                log("[warn] skeleton copy source missing: %s" % src)
                continue
            store(z, dst, tar.extractfile(tm).read(), bool(tm.mode & 0o111))
            written.add(dst)
            n += 1
    size = os.path.getsize(out)
    log("[zip] wrote %d entries (skipped %d broken/special) -> %s (%d bytes)"
        % (n, skipped, out, size))


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


def build_zip_from_dir(srcdir, out):
    """--from-dir variant: walk an already-extracted tree, dereferencing
    symlinks the same way (absolute targets map back into srcdir)."""
    srcdir = flatten_single_top(srcdir)
    looks_valid = (os.path.isdir(os.path.join(srcdir, "var", "jb")) or
                   os.path.isdir(os.path.join(srcdir, "usr")) or
                   os.path.isdir(os.path.join(srcdir, "bin")))
    if not looks_valid:
        log("[warn] dir has no var/jb, usr/ or bin/ — may not be a bootstrap")
    os.makedirs(os.path.dirname(os.path.abspath(out)), exist_ok=True)
    n = 0
    skipped = 0
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as z:
        for root, _dirs, files in os.walk(srcdir):
            for f in files:
                full = os.path.join(root, f)
                rel = os.path.relpath(full, srcdir).replace(os.sep, "/")
                if os.path.islink(full):
                    tgt = os.readlink(full)
                    if tgt.startswith("/"):
                        cand = normalize_arc(tgt)
                    else:
                        cand = normalize_arc(
                            os.path.join(os.path.dirname(rel), tgt))
                    if escapes_root(cand):
                        skipped += 1
                        continue
                    full = os.path.join(srcdir, cand)
                if not os.path.isfile(full):
                    skipped += 1
                    continue
                st = os.stat(full)
                execbit = bool(st.st_mode & 0o111)
                with open(full, "rb") as fh:
                    store(z, rel, fh.read(), execbit)
                n += 1
    size = os.path.getsize(out)
    log("[zip] wrote %d entries (skipped %d broken/special) -> %s (%d bytes)"
        % (n, skipped, out, size))


def main():
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("--tarzst", help="本地 bootstrap .tar / .tar.zst 文件")
    ap.add_argument("--url", help="下载 bootstrap .tar / .tar.zst 的 URL")
    ap.add_argument("--from-dir", help="已解压好的 bootstrap 目录（含 usr/ 或 bin/）")
    ap.add_argument("--out", default=DEFAULT_OUT, help="输出 zip 路径")
    args = ap.parse_args()

    if args.from_dir:
        build_zip_from_dir(args.from_dir, args.out)
        log("DONE")
        return

    archive = None
    tmp = tempfile.mkdtemp(prefix="make_jbroot_")
    try:
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
        build_zip_from_tar(tar, args.out)
        tar.close()
    finally:
        import shutil
        shutil.rmtree(tmp, ignore_errors=True)
    log("DONE")


if __name__ == "__main__":
    main()
