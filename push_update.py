#!/usr/bin/env python3
# 本地源码 -> GitHub (REST Contents API)。用法: GITHUB_PAT=xxx python3 push_update.py
# 脚本放在 ContainerApp/ 目录下运行（repo 根 = 本目录内容）。
import base64, glob, json, os, sys, urllib.request, urllib.error

REPO = "DanMianBenMian/RyBox"
BRANCH = "main"
API = f"https://api.github.com/repos/{REPO}/contents"

# 固定配置文件（相对 repo 根，即本脚本所在目录）
FIXED = [
    "project.yml",
    "ContainerApp/Info.plist",
    "ContainerApp/ContainerApp.entitlements",
    ".github/workflows/ota-build.yml",
    # 预装的真 Sileo IPA（二进制，base64 推送）
    "preinstalled/Sileo.ipa",
    # 内置最小 jbroot（Procursus bootstrap，可选，缺失时 CI 仍通过）
    "preinstalled/ProcursusBootstrap.zip",
    # PC 端系统环境打包工具（生成 .ryboxenv，避免把固件塞进 IPA）
    "tools/make_ryboxenv.py",
    "tools/build_ryboxenv.py",
    # PC 端 jbroot 打包工具（生成 ProcursusBootstrap.zip）
    "tools/make_jbroot.py",
]

def discover():
    files = list(FIXED)
    for f in sorted(glob.glob("ContainerApp/Sources/**/*", recursive=True)):
        if os.path.isfile(f):
            # Windows glob returns backslash separators. The GitHub Contents API
            # treats '\' as a literal filename char (not a path sep), so pushing a
            # backslash path silently creates a junk sibling file and leaves the
            # real forward-slash file untouched — exactly the "build has none of my
            # changes" trap. Normalize to '/' like the explicit-args branch does.
            files.append(f.replace("\\", "/"))
    return files

FILES = discover()

def api_req(url, data=None, method="GET"):
    pat = os.environ.get("GITHUB_PAT") or os.environ.get("GH_TOKEN")
    if not pat:
        sys.exit("ERROR: set GITHUB_PAT env var")
    headers = {"Authorization": f"Bearer {pat}",
               "Accept": "application/vnd.github+json"}
    if data is not None:
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req) as r:
            return r.read().decode("utf-8", "replace"), r.status
    except urllib.error.HTTPError as e:
        return e.read().decode("utf-8", "replace"), e.code

def put_file(path, content: bytes):
    url = f"{API}/{path}"
    _, status = api_req(url)
    sha = None
    if status == 200:
        body, _ = api_req(url)
        try:
            sha = json.loads(body)["sha"]
        except Exception:
            sha = None
    payload = {"message": f"update {path}",
               "content": base64.b64encode(content).decode("ascii"),
               "branch": BRANCH}
    if sha:
        payload["sha"] = sha
    body, st = api_req(url, data=json.dumps(payload).encode("utf-8"), method="PUT")
    ok = st in (200, 201)
    print(f"[{'OK' if ok else 'FAIL'} {st}] {path}")
    if not ok:
        print("   ", body[:400])
    return ok

def main():
    root = os.path.dirname(os.path.abspath(__file__))
    # Passing explicit paths pushes ONLY those files. Every commit the Contents
    # API makes triggers `on: push`, so a full sweep literally queues ~45 builds
    # — which is how the macOS runner pool ends up jammed.
    only = [a for a in sys.argv[1:] if not a.startswith("-")]
    files = [f.replace("\\", "/") for f in only] if only else FILES
    print(f"repo root: {root}")
    print(f"files to push ({len(files)}):")
    for f in files:
        print("   ", f)
    all_ok = True
    for f in files:
        local = os.path.join(root, f)
        if not os.path.exists(local):
            print(f"[SKIP missing] {f}")
            continue
        with open(local, "rb") as fh:   # 二进制安全（png/ipa 原样推送）
            all_ok &= put_file(f, fh.read())
    print("DONE" if all_ok else "SOME FAILED")

if __name__ == "__main__":
    main()
