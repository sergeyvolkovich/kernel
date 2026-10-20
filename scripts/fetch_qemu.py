#!/usr/bin/env python3
"""Fetch qemu-system-x86 + ovmf (Debian trixie) as .deb, extract into a prefix.

No root needed: uses dpkg-deb -x. Host-installed deps (per dpkg status db)
are skipped. Deps not on host are downloaded recursively.
"""
import gzip
import json
import os
import subprocess
import sys
import urllib.request

DIST = "http://deb.debian.org/debian"
SUITE = "trixie"
ARCH = "amd64"
ROOT = "/home/z/my-project/tools/qroot"
WORK = "/home/z/my-project/tools/qwork"
WANT = ["qemu-system-x86", "ovmf"]


def http(url):
    with urllib.request.urlopen(url, timeout=60) as r:
        return r.read()


def load_packages():
    """Return {name: {Version, Filename, Depends}} from the suite index."""
    cache = os.path.join(WORK, "Packages.json")
    if os.path.exists(cache):
        with open(cache) as f:
            return json.load(f)
    raw = http(f"{DIST}/dists/{SUITE}/main/binary-{ARCH}/Packages.gz")
    txt = gzip.decompress(raw).decode("utf-8", "replace")
    pkgs = {}
    cur = {}
    for line in txt.splitlines():
        if not line.strip():
            if cur.get("Package"):
                pkgs[cur["Package"]] = {
                    "Version": cur.get("Version", ""),
                    "Filename": cur.get("Filename", ""),
                    "Depends": cur.get("Depends", ""),
                }
            cur = {}
            continue
        if ": " in line:
            k, v = line.split(": ", 1)
            cur[k.strip()] = v.strip()
    if cur.get("Package"):
        pkgs[cur["Package"]] = {
            "Version": cur.get("Version", ""),
            "Filename": cur.get("Filename", ""),
            "Depends": cur.get("Depends", ""),
        }
    os.makedirs(WORK, exist_ok=True)
    with open(cache, "w") as f:
        json.dump(pkgs, f)
    return pkgs


def installed_pkgs():
    """Names of packages installed on host (dpkg status db, read-only)."""
    out = subprocess.run(["dpkg-query", "-W", "-f=${Package}\\n"],
                         capture_output=True, text=True)
    return set(out.stdout.split())


def first_term(dep):
    """First alternative name of a Depends term, version spec stripped."""
    name = dep.split("|")[0].split("(")[0].strip()
    return name


def resolve(pkgs, host, want):
    """BFS over runtime deps, skipping host-installed packages."""
    need, queue, seen = {}, list(want), set(want)
    while queue:
        name = queue.pop(0)
        if name in host or name in need:
            continue
        if name not in pkgs:
            print(f"  !! unknown package (skip): {name}")
            continue
        need[name] = pkgs[name]
        for term in pkgs[name]["Depends"].split(","):
            term = term.strip()
            if not term:
                continue
            dep = first_term(term)
            if dep not in seen:
                seen.add(dep)
                queue.append(dep)
    return need


def main():
    os.makedirs(ROOT, exist_ok=True)
    os.makedirs(WORK, exist_ok=True)
    pkgs = load_packages()
    host = installed_pkgs()
    need = resolve(pkgs, host, WANT)
    # Also pull seabios/ipxe (qemu searches for them at runtime)
    for extra in ("seabios", "ipxe-qemu"):
        if extra not in need and extra in pkgs and extra not in host:
            need[extra] = pkgs[extra]
    print(f"need {len(need)} debs:")
    for name, meta in sorted(need.items()):
        url = f"{DIST}/{meta['Filename']}"
        out = os.path.join(WORK, os.path.basename(meta["Filename"]))
        if not os.path.exists(out):
            print(f"  get {name} {meta['Version']}")
            data = http(url)
            with open(out, "wb") as f:
                f.write(data)
        else:
            print(f"  have {name} (cached)")
        subprocess.run(["dpkg-deb", "-x", out, ROOT], check=True)
    print("extracted to", ROOT)


if __name__ == "__main__":
    sys.exit(main())
