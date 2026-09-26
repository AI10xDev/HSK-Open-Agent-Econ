"""Download and install the official HSKChain testnet faucet.

The faucet ships as a JavaScript single-page app rather than a binary release,
so "installing" it means: fetch the deployed bundle, verify and record what we
got, then extract the API contract our Python client needs. Running this is
idempotent and re-running it refreshes the pin file.

Usage::

    python -m hskfaucet.installer            # download + install
    python -m hskfaucet.installer --check    # verify the existing install
"""

from __future__ import annotations

import argparse
import hashlib
import json
import logging
import re
import sys
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from pathlib import Path

import requests

from .client import DEFAULT_API_URL, DEFAULT_RECAPTCHA_SITE_KEY
from .hmac_auth import BROWSER_USER_AGENT
from .network import HSK_TESTNET

log = logging.getLogger(__name__)

FAUCET_WEB_URL = HSK_TESTNET.faucet_url  # https://faucet.hsk.xyz/faucet
INSTALL_DIR = Path(__file__).resolve().parent / "vendor"

#: Artifacts we pull down. ``envs.js`` and ``config.js`` are small config shims
#: loaded before the app; the hashed bundle carries the signing logic.
WANTED_ARTIFACTS = ("envs.js", "config.js")
BUNDLE_RE = re.compile(r'src="(/js/main\.[A-Za-z0-9_-]+\.js)"')

#: Endpoint we expect to find in the bundle, as a sanity check on the download.
DRIP_ENDPOINT = "/api/faucet/drip"
QUERY_ENDPOINT = "/api/faucet/query"


@dataclass
class Artifact:
    """One downloaded file plus its digest."""

    path: str
    bytes: int
    sha256: str

    @property
    def short(self) -> str:
        return f"{self.path} ({self.bytes} B, sha256:{self.sha256[:12]})"


@dataclass
class InstallManifest:
    """What ``installer`` wrote to ``vendor/install-manifest.json``."""

    installed_at: str
    faucet_web_url: str
    faucet_api_url: str
    network: dict
    artifacts: list[Artifact]
    endpoints: dict
    recaptcha_site_key: str
    hmac_username: str

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def load(cls, path: Path) -> "InstallManifest":
        raw = json.loads(path.read_text())
        return cls(
            installed_at=raw["installed_at"],
            faucet_web_url=raw["faucet_web_url"],
            faucet_api_url=raw["faucet_api_url"],
            network=raw["network"],
            artifacts=[Artifact(**a) for a in raw["artifacts"]],
            endpoints=raw["endpoints"],
            recaptcha_site_key=raw["recaptcha_site_key"],
            hmac_username=raw["hmac_username"],
        )


def _get(url: str, timeout: float = 60.0) -> requests.Response:
    response = requests.get(
        url,
        timeout=timeout,
        headers={"User-Agent": BROWSER_USER_AGENT, "Accept": "*/*"},
    )
    response.raise_for_status()
    return response


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _save(directory: Path, name: str, data: bytes) -> Artifact:
    # The app bundle lives under /js/, so nested paths must be created too.
    target = directory / name
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(data)
    return Artifact(path=name, bytes=len(data), sha256=_sha256(data))


def _parse_envs(text: str) -> dict[str, str]:
    """Pull the ``window.__envs = {...}`` literal out of ``envs.js``."""
    out: dict[str, str] = {}
    for key, value in re.findall(r"(\w+)\s*:\s*\"([^\"]*)\"", text):
        out[key] = value
    return out


def install(directory: Path | None = None, timeout: float = 60.0) -> InstallManifest:
    """Download the faucet app, record its digests, and write a manifest."""
    directory = Path(directory) if directory else INSTALL_DIR
    origin = FAUCET_WEB_URL.rsplit("/faucet", 1)[0]

    log.info("downloading faucet from %s", FAUCET_WEB_URL)
    page = _get(FAUCET_WEB_URL, timeout).text

    artifacts: list[Artifact] = []
    for name in WANTED_ARTIFACTS:
        response = _get(f"{origin}/{name}", timeout)
        artifacts.append(_save(directory, name, response.content))

    match = BUNDLE_RE.search(page)
    if not match:
        raise RuntimeError(
            f"could not find the faucet app bundle in the HTML at {FAUCET_WEB_URL}"
        )
    bundle_path = match.group(1)
    bundle = _get(f"{origin}{bundle_path}", timeout)
    artifacts.append(_save(directory, bundle_path.lstrip("/"), bundle.content))

    bundle_text = bundle.text
    for endpoint in (DRIP_ENDPOINT, QUERY_ENDPOINT):
        if endpoint not in bundle_text:
            raise RuntimeError(
                f"downloaded bundle does not contain {endpoint}; refusing to "
                "install an unexpected faucet build"
            )

    envs = _parse_envs((directory / "envs.js").read_text())
    api_url = envs.get("VITE_FAUCET_API_URL", DEFAULT_API_URL)
    site_key = envs.get("VITE_RECAPTCHA_SITE_KEY_V2", DEFAULT_RECAPTCHA_SITE_KEY)
    hmac_username = envs.get("VITE_HMAC_USERNAME", "faucet")

    manifest = InstallManifest(
        installed_at=datetime.now(timezone.utc).isoformat(timespec="seconds"),
        faucet_web_url=FAUCET_WEB_URL,
        faucet_api_url=api_url,
        network=HSK_TESTNET.to_dict(),
        artifacts=artifacts,
        endpoints={"drip": DRIP_ENDPOINT, "query": QUERY_ENDPOINT},
        recaptcha_site_key=site_key,
        hmac_username=hmac_username,
    )

    directory.mkdir(parents=True, exist_ok=True)
    (directory / "install-manifest.json").write_text(
        json.dumps(manifest.to_dict(), indent=2) + "\n"
    )

    for artifact in artifacts:
        log.info("installed %s", artifact.short)
    log.info("faucet API: %s", api_url)
    log.info("manifest: %s", directory / "install-manifest.json")
    return manifest


def check(directory: Path | None = None, quiet: bool = False) -> bool:
    """Re-hash the installed artifacts and confirm they still match the manifest."""
    directory = Path(directory) if directory else INSTALL_DIR
    out = (lambda *a, **k: None) if quiet else print
    manifest_path = directory / "install-manifest.json"
    if not manifest_path.exists():
        out(f"not installed: {manifest_path} is missing")
        return False

    manifest = InstallManifest.load(manifest_path)
    ok = True
    for artifact in manifest.artifacts:
        target = directory / artifact.path
        if not target.exists():
            out(f"MISSING  {artifact.path}")
            ok = False
            continue
        digest = _sha256(target.read_bytes())
        if digest != artifact.sha256:
            out(f"MODIFIED {artifact.path} (expected {artifact.sha256[:12]})")
            ok = False
        else:
            out(f"ok       {artifact.short}")

    out(f"\ninstalled at : {manifest.installed_at}")
    out(f"web app      : {manifest.faucet_web_url}")
    out(f"api          : {manifest.faucet_api_url}")
    out(f"chain id     : {manifest.network['chain_id']} ({manifest.network['name']})")
    out(f"reCAPTCHA key: {manifest.recaptcha_site_key}")
    out("endpoints    : " + ", ".join(f"{k}={v}" for k, v in manifest.endpoints.items()))
    return ok


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m hskfaucet.installer",
        description="Download and install the HSKChain testnet faucet.",
    )
    parser.add_argument(
        "--check", action="store_true", help="verify the existing install instead"
    )
    parser.add_argument("--dir", type=Path, default=None, help="install directory")
    args = parser.parse_args(argv)

    logging.basicConfig(level=logging.INFO, format="%(levelname)-7s %(message)s")

    if args.check:
        return 0 if check(args.dir) else 1

    manifest = install(args.dir)
    print()
    print("HSKChain testnet faucet installed.")
    print(f"  web app    : {manifest.faucet_web_url}")
    print(f"  api        : {manifest.faucet_api_url}")
    print(f"  chain id   : {manifest.network['chain_id']}")
    print(f"  artifacts  : {len(manifest.artifacts)}")
    for artifact in manifest.artifacts:
        print(f"    - {artifact.short}")
    print()
    print("To claim testnet HSK you still need a reCAPTCHA v2 token, which only a")
    print(f"human can obtain at {manifest.faucet_web_url}.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
