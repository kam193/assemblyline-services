#!/usr/bin/env python3
"""Install the pinned Opengrep binary or update the pin in opengrep.lock.json.

opengrep.py install [--dest DIR]                     download and verify the pinned binary
opengrep.py update [--cooldown-days N] [--version V]  pin the newest release older than N days
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import sys
import tempfile
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path

REPO = "opengrep/opengrep"
LOCK = Path(__file__).resolve().parent.parent / "opengrep.lock.json"
ASSETS = {
    "x86_64": "opengrep_manylinux_x86",
    "aarch64": "opengrep_manylinux_aarch64",
}


def fetch(url: str) -> urllib.request.addinfourl:
    headers = {"User-Agent": "opengrep-pin"}
    if url.startswith("https://api.github.com/") and (token := os.environ.get("GITHUB_TOKEN")):
        headers["Authorization"] = f"Bearer {token}"
    return urllib.request.urlopen(urllib.request.Request(url, headers=headers), timeout=60)


def download(url: str, target: Path) -> str:
    sha = hashlib.sha256()
    with fetch(url) as response, target.open("wb") as out:
        while chunk := response.read(1 << 20):
            sha.update(chunk)
            out.write(chunk)
    return sha.hexdigest()


def file_sha256(path: Path) -> str:
    with path.open("rb") as f:
        return hashlib.file_digest(f, "sha256").hexdigest()


@dataclass
class Lock:
    version: str
    assets: dict[str, str]

    @classmethod
    def load(cls) -> Lock:
        return cls(**json.loads(LOCK.read_text()))

    def save(self) -> None:
        LOCK.write_text(json.dumps(self.__dict__, indent=2) + "\n")

    def url(self, asset: str) -> str:
        return f"https://github.com/{REPO}/releases/download/{self.version}/{asset}"

    def install(self, dest: Path) -> None:
        machine = platform.machine()
        if platform.system() != "Linux" or machine not in ASSETS:
            raise SystemExit(f"no pinned Opengrep asset for {platform.system()} {machine}")
        asset = ASSETS[machine]
        expected = self.assets[asset]
        binary = dest / "opengrep"
        if binary.exists() and file_sha256(binary) == expected:
            print(f"{binary} already at {self.version}")
            return
        dest.mkdir(parents=True, exist_ok=True)
        with tempfile.NamedTemporaryFile(dir=dest, delete=False) as tmp:
            partial = Path(tmp.name)
        try:
            actual = download(self.url(asset), partial)
            if actual != expected:
                raise SystemExit(f"SHA256 mismatch for {asset}: expected {expected}, got {actual}")
            partial.chmod(0o755)
            partial.replace(binary)
        finally:
            partial.unlink(missing_ok=True)
        print(f"installed Opengrep {self.version} to {binary}")


def select_release(version: str | None, cooldown_days: int, pinned: str | None) -> dict | None:
    api = f"https://api.github.com/repos/{REPO}/releases"
    if version:
        with fetch(f"{api}/tags/{version}") as response:
            return json.load(response)
    cutoff = datetime.now(timezone.utc) - timedelta(days=cooldown_days)
    with fetch(f"{api}?per_page=50") as response:
        releases = json.load(response)
    for release in releases:
        if release["tag_name"] == pinned:
            return None
        published = datetime.fromisoformat(release["published_at"])
        if not release["draft"] and not release["prerelease"] and published <= cutoff:
            return release
    raise SystemExit(f"no release older than {cooldown_days} days")


def update(version: str | None, cooldown_days: int) -> None:
    pinned = Lock.load().version if LOCK.exists() else None
    release = select_release(version, cooldown_days, pinned)
    if release is None or release["tag_name"] == pinned:
        print(f"already pinned to {pinned}")
        return
    tag = release["tag_name"]
    digests = {a["name"]: a.get("digest") for a in release["assets"]}
    lock = Lock(tag, {})
    with tempfile.TemporaryDirectory(dir=LOCK.parent) as tmp:
        for asset in ASSETS.values():
            sha = download(lock.url(asset), Path(tmp) / asset)
            if digests.get(asset) not in (None, f"sha256:{sha}"):
                raise SystemExit(f"{asset}: downloaded {sha}, release lists {digests[asset]}")
            lock.assets[asset] = sha
    lock.save()
    print(f"pinned Opengrep {tag} (published {release['published_at']})")


def main() -> None:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawTextHelpFormatter
    )
    commands = parser.add_subparsers(dest="command", required=True)
    install_parser = commands.add_parser("install")
    install_parser.add_argument("--dest", type=Path, default=Path.home() / ".local" / "bin")
    update_parser = commands.add_parser("update")
    update_parser.add_argument("--cooldown-days", type=int, default=7)
    update_parser.add_argument("--version", help="pin this tag, skipping the cooldown")
    args = parser.parse_args()
    if args.command == "install":
        Lock.load().install(args.dest)
    else:
        update(args.version, args.cooldown_days)


if __name__ == "__main__":
    sys.exit(main())
