#!/usr/bin/env python3
"""Produce a bounded public Privanta status document from synthetic endpoints."""

from __future__ import annotations

import argparse
import base64
import binascii
import dataclasses
import datetime as dt
import json
import pathlib
import re
import ssl
import subprocess
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Callable, Mapping, Protocol


MAXIMUM_RESPONSE_BYTES = 1024 * 1024
IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,31}$")


class StatusProbeError(RuntimeError):
    """The status probe input or a cryptographic assertion is invalid."""


@dataclasses.dataclass(frozen=True)
class FetchResponse:
    body: bytes
    headers: Mapping[str, str]
    duration_seconds: float


class Fetcher(Protocol):
    def fetch(self, url: str, maximum_bytes: int = MAXIMUM_RESPONSE_BYTES) -> FetchResponse: ...


def _https(raw: str) -> None:
    try:
        parsed = urllib.parse.urlparse(raw)
        port = parsed.port
    except ValueError as error:
        raise StatusProbeError("status endpoint is invalid") from error
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or port not in {None, 443}
        or parsed.fragment
    ):
        raise StatusProbeError("status endpoint must use standard HTTPS")


class _HTTPSRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request: Any, fp: Any, code: int, message: str, headers: Any, new_url: str) -> Any:
        _https(new_url)
        return super().redirect_request(request, fp, code, message, headers, new_url)


class HTTPSFetcher:
    def __init__(self) -> None:
        self.opener = urllib.request.build_opener(
            urllib.request.HTTPSHandler(context=ssl.create_default_context()),
            _HTTPSRedirectHandler(),
        )

    def fetch(self, url: str, maximum_bytes: int = MAXIMUM_RESPONSE_BYTES) -> FetchResponse:
        _https(url)
        if not 1 <= maximum_bytes <= MAXIMUM_RESPONSE_BYTES:
            raise StatusProbeError("status response bound is invalid")
        request = urllib.request.Request(
            url,
            method="GET",
            headers={"User-Agent": "Privanta-Public-Status/1", "Accept": "application/json"},
        )
        started = time.monotonic()
        try:
            with self.opener.open(request, timeout=15) as response:
                _https(response.geturl())
                if response.status != 200:
                    raise StatusProbeError("status endpoint did not return HTTP 200")
                length = response.headers.get("Content-Length")
                if length is not None and (not length.isdigit() or int(length) > maximum_bytes):
                    raise StatusProbeError("status endpoint exceeds its declared bound")
                body = response.read(maximum_bytes + 1)
                if len(body) > maximum_bytes:
                    raise StatusProbeError("status endpoint exceeds its bound")
                headers = {key.lower(): value.strip() for key, value in response.headers.items()}
        except (OSError, urllib.error.URLError, urllib.error.HTTPError) as error:
            raise StatusProbeError("status HTTPS request failed") from error
        return FetchResponse(body=body, headers=headers, duration_seconds=time.monotonic() - started)


def _read_json(response: FetchResponse, name: str) -> dict[str, Any]:
    try:
        value = json.loads(response.body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise StatusProbeError(f"{name} is not bounded JSON") from error
    if not isinstance(value, dict):
        raise StatusProbeError(f"{name} is not a JSON object")
    return value


def _utc_time(raw: object, name: str) -> dt.datetime:
    if not isinstance(raw, str):
        raise StatusProbeError(f"{name} timestamp is invalid")
    try:
        parsed = dt.datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError as error:
        raise StatusProbeError(f"{name} timestamp is invalid") from error
    if parsed.tzinfo is None:
        raise StatusProbeError(f"{name} timestamp is invalid")
    return parsed.astimezone(dt.timezone.utc)


def verify_ed25519(payload: bytes, signature: bytes, public_key: pathlib.Path) -> bool:
    if not public_key.is_file() or public_key.is_symlink() or public_key.stat().st_size > 64 * 1024:
        raise StatusProbeError("status trust key is absent or unsafe")
    try:
        document = json.loads(signature.decode("utf-8"))
        raw_signature = base64.b64decode(document["signature"], validate=True)
    except (UnicodeDecodeError, json.JSONDecodeError, KeyError, TypeError, ValueError, binascii.Error):
        return False
    if document.get("algorithm") != "ed25519" or len(raw_signature) != 64:
        return False
    with tempfile.TemporaryDirectory(prefix="privanta-status-signature-") as raw:
        directory = pathlib.Path(raw)
        payload_path = directory / "payload"
        signature_path = directory / "signature"
        payload_path.write_bytes(payload)
        signature_path.write_bytes(raw_signature)
        try:
            completed = subprocess.run(
                [
                    "openssl",
                    "pkeyutl",
                    "-verify",
                    "-rawin",
                    "-pubin",
                    "-inkey",
                    str(public_key),
                    "-in",
                    str(payload_path),
                    "-sigfile",
                    str(signature_path),
                ],
                check=False,
                capture_output=True,
                timeout=10,
            )
        except (OSError, subprocess.TimeoutExpired):
            return False
    return completed.returncode == 0


def _latency_bucket(seconds: float) -> str:
    if seconds < 0.25:
        return "under_250ms"
    if seconds < 1:
        return "250ms_1s"
    if seconds < 3:
        return "1s_3s"
    return "over_3s"


def _component(identifier: str, name: str, status: str, detail: str, durations: list[float]) -> dict[str, Any]:
    return {
        "id": identifier,
        "name": name,
        "status": status,
        "detail": detail,
        "latency_bucket": _latency_bucket(max(durations)) if durations else "unavailable",
    }


def _validate_config(config: Mapping[str, Any], directory: pathlib.Path) -> dict[str, Any]:
    required = {"schema_version", "api", "bootstrap", "releases", "data_plane"}
    if set(config) != required or config.get("schema_version") != 2:
        raise StatusProbeError("status probe config is incomplete or unexpected")
    api = config.get("api")
    bootstrap = config.get("bootstrap")
    releases = config.get("releases")
    data_plane = config.get("data_plane")
    if not isinstance(api, dict) or set(api) != {"origin", "expected_egress_class"}:
        raise StatusProbeError("status API config is invalid")
    _https(api["origin"])
    if api["expected_egress_class"] not in {"ru", "external"}:
        raise StatusProbeError("status API egress class is invalid")
    if not isinstance(data_plane, dict) or set(data_plane) != {
        "url",
        "minimum_available_entry_paths",
    }:
        raise StatusProbeError("status Data Plane config is invalid")
    _https(data_plane["url"])
    minimum_available = data_plane["minimum_available_entry_paths"]
    if not isinstance(minimum_available, int) or not 1 <= minimum_available <= 32:
        raise StatusProbeError("status Data Plane minimum is invalid")
    for group, minimum in ((bootstrap, 3), (releases, 1)):
        if not isinstance(group, dict) or set(group) != {"root_public_key", "endpoints"}:
            raise StatusProbeError("status signed-endpoint config is invalid")
        key = directory / group["root_public_key"]
        if not key.is_file() or key.is_symlink():
            raise StatusProbeError("status root public key is absent or unsafe")
        endpoints = group["endpoints"]
        if not isinstance(endpoints, list) or len(endpoints) < minimum:
            raise StatusProbeError("status signed-endpoint set is incomplete")
        identifiers: list[str] = []
        for endpoint in endpoints:
            if not isinstance(endpoint, dict) or set(endpoint) != {"id", "url"}:
                raise StatusProbeError("status signed endpoint is invalid")
            if not isinstance(endpoint["id"], str) or IDENTIFIER.fullmatch(endpoint["id"]) is None:
                raise StatusProbeError("status endpoint ID is invalid")
            _https(endpoint["url"])
            identifiers.append(endpoint["id"])
        if len(identifiers) != len(set(identifiers)):
            raise StatusProbeError("status endpoint IDs are duplicated")
    return dict(config)


def _data_plane_component(
    config: Mapping[str, Any],
    client: Fetcher,
    checked_at: dt.datetime,
    snapshot_path: pathlib.Path | None,
) -> dict[str, Any]:
    durations: list[float] = []
    try:
        if snapshot_path is None:
            response = client.fetch(config["data_plane"]["url"], 64 * 1024)
            durations.append(response.duration_seconds)
        else:
            if (
                not snapshot_path.is_file()
                or snapshot_path.is_symlink()
                or snapshot_path.stat().st_size > 64 * 1024
            ):
                raise StatusProbeError("local Data Plane snapshot is absent or unsafe")
            response = FetchResponse(snapshot_path.read_bytes(), {}, 0)
        document = _read_json(response, "Data Plane snapshot")
        expected_keys = {
            "schema_version",
            "generated_at",
            "max_age_seconds",
            "status",
            "source_authentication",
            "telemetry_verified",
            "expected_entry_paths",
            "fresh_entry_paths",
            "available_entry_paths",
            "redundant_entry_paths",
        }
        if set(document) != expected_keys or document.get("schema_version") != 1:
            raise StatusProbeError("Data Plane snapshot contract is invalid")
        if document.get("source_authentication") != "tls_basic_per_node":
            raise StatusProbeError("Data Plane source is not authenticated")
        if not isinstance(document.get("telemetry_verified"), bool):
            raise StatusProbeError("Data Plane verification state is invalid")
        maximum_age = document.get("max_age_seconds")
        if not isinstance(maximum_age, int) or not 300 <= maximum_age <= 1800:
            raise StatusProbeError("Data Plane snapshot freshness is invalid")
        generated_at = _utc_time(document.get("generated_at"), "Data Plane snapshot")
        age = (checked_at - generated_at).total_seconds()
        if age < -300 or age > maximum_age:
            raise StatusProbeError("Data Plane snapshot is stale")
        counts = [
            document.get("expected_entry_paths"),
            document.get("fresh_entry_paths"),
            document.get("available_entry_paths"),
            document.get("redundant_entry_paths"),
        ]
        if any(isinstance(value, bool) or not isinstance(value, int) for value in counts):
            raise StatusProbeError("Data Plane path counts are invalid")
        expected, fresh, available, redundant = counts
        if not (1 <= expected <= 32 and 0 <= redundant <= available <= fresh <= expected):
            raise StatusProbeError("Data Plane path counts are invalid")
        minimum_available = config["data_plane"]["minimum_available_entry_paths"]
        if minimum_available > expected:
            raise StatusProbeError("Data Plane path policy is invalid")
        status = document.get("status")
        operational = (
            document["telemetry_verified"]
            and fresh == expected
            and available == expected
            and redundant == expected
        )
        degraded = (
            document["telemetry_verified"]
            and available >= minimum_available
            and not operational
        )
        outage = not document["telemetry_verified"] or available < minimum_available
        if (
            status not in {"operational", "degraded", "outage"}
            or (status == "operational") != operational
            or (status == "degraded") != degraded
            or (status == "outage") != outage
        ):
            raise StatusProbeError("Data Plane status is inconsistent")
        detail = f"{available} of {expected} authenticated entry paths available"
        if status != "outage" and redundant < expected:
            detail += f"; {redundant} retain full relay redundancy"
        return _component("vpn-data-plane", "VPN network", status, detail, durations)
    except (OSError, StatusProbeError):
        return _component(
            "vpn-data-plane",
            "VPN network",
            "outage",
            "Authenticated Data Plane telemetry is unavailable or stale",
            durations,
        )


def run_probe(
    config_path: pathlib.Path,
    *,
    fetcher: Fetcher | None = None,
    signature_verifier: Callable[[bytes, bytes, pathlib.Path], bool] = verify_ed25519,
    now: dt.datetime | None = None,
    data_plane_snapshot_path: pathlib.Path | None = None,
) -> dict[str, Any]:
    try:
        config_raw = json.loads(config_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise StatusProbeError("status probe config is invalid JSON") from error
    if not isinstance(config_raw, dict):
        raise StatusProbeError("status probe config must be an object")
    config = _validate_config(config_raw, config_path.parent)
    client = fetcher or HTTPSFetcher()
    checked_at = (now or dt.datetime.now(dt.timezone.utc)).astimezone(dt.timezone.utc)
    components: list[dict[str, Any]] = []

    data_plane = _data_plane_component(config, client, checked_at, data_plane_snapshot_path)
    components.append(data_plane)

    api_durations: list[float] = []
    api_ok = True
    try:
        origin = config["api"]["origin"].rstrip("/")
        for name, expected in (("live", "ok"), ("ready", "ready")):
            response = client.fetch(f"{origin}/health/{name}", 64 * 1024)
            api_durations.append(response.duration_seconds)
            api_ok = api_ok and _read_json(response, f"API {name}").get("status") == expected
        response = client.fetch(f"{origin}/v1/client/canary", 64 * 1024)
        api_durations.append(response.duration_seconds)
        payload = _read_json(response, "API canary")
        expected_egress = config["api"]["expected_egress_class"]
        api_ok = api_ok and (
            payload.get("schema_version") == 1
            and payload.get("status") == "ok"
            and payload.get("ip_family") in {"ipv4", "ipv6"}
            and payload.get("egress_class") == expected_egress
            and response.headers.get("x-privanta-canary") == "ok"
            and response.headers.get("x-privanta-egress") == expected_egress
        )
    except StatusProbeError:
        api_ok = False
    components.append(
        _component(
            "control-api",
            "Control API",
            "operational" if api_ok else "outage",
            "Public API and payload canary verified" if api_ok else "Public API payload verification failed",
            api_durations,
        )
    )

    bootstrap_success = 0
    bootstrap_durations: list[float] = []
    bootstrap_payloads: list[bytes] = []
    bootstrap_signatures: list[bytes] = []
    bootstrap_key = config_path.parent / config["bootstrap"]["root_public_key"]
    for endpoint in config["bootstrap"]["endpoints"]:
        try:
            base = endpoint["url"].rstrip("/")
            manifest = client.fetch(f"{base}/v1/bootstrap")
            signature = client.fetch(f"{base}/v1/bootstrap.sig", 64 * 1024)
            bootstrap_durations.append(manifest.duration_seconds + signature.duration_seconds)
            document = _read_json(manifest, "bootstrap")
            if (
                document.get("schema_version") == 1
                and isinstance(document.get("revision"), int)
                and isinstance(document.get("expires_at"), str)
                and signature_verifier(manifest.body, signature.body, bootstrap_key)
            ):
                bootstrap_success += 1
                bootstrap_payloads.append(manifest.body)
                bootstrap_signatures.append(signature.body)
        except StatusProbeError:
            continue
    bootstrap_count = len(config["bootstrap"]["endpoints"])
    bootstrap_identical = (
        len(bootstrap_payloads) == bootstrap_count
        and len(set(bootstrap_payloads)) == 1
        and len(set(bootstrap_signatures)) == 1
    )
    bootstrap_status = "operational" if bootstrap_success == bootstrap_count and bootstrap_identical else (
        "degraded" if bootstrap_success > 0 else "outage"
    )
    components.append(
        _component(
            "configuration",
            "Configuration channels",
            bootstrap_status,
            f"{bootstrap_success} of {bootstrap_count} signed channels verified",
            bootstrap_durations,
        )
    )

    release_success = 0
    release_durations: list[float] = []
    release_key = config_path.parent / config["releases"]["root_public_key"]
    for endpoint in config["releases"]["endpoints"]:
        try:
            manifest = client.fetch(endpoint["url"])
            signature = client.fetch(f"{endpoint['url']}.sig", 64 * 1024)
            release_durations.append(manifest.duration_seconds + signature.duration_seconds)
            document = _read_json(manifest, "release manifest")
            artifacts = document.get("artifacts")
            if (
                document.get("schema_version") == 1
                and isinstance(document.get("revision"), int)
                and isinstance(artifacts, list)
                and artifacts
                and all(
                    isinstance(item, dict)
                    and isinstance(item.get("url"), str)
                    and item["url"].startswith("https://")
                    and re.fullmatch(r"[0-9a-f]{64}", str(item.get("sha256", ""))) is not None
                    for item in artifacts
                )
                and signature_verifier(manifest.body, signature.body, release_key)
            ):
                release_success += 1
        except StatusProbeError:
            continue
    release_count = len(config["releases"]["endpoints"])
    release_status = "operational" if release_success == release_count else (
        "degraded" if release_success > 0 else "outage"
    )
    components.append(
        _component(
            "application-updates",
            "Application updates",
            release_status,
            f"{release_success} of {release_count} signed manifests verified",
            release_durations,
        )
    )

    states = {component["status"] for component in components}
    if not api_ok or data_plane["status"] == "outage":
        overall = "major_outage"
    elif states == {"operational"}:
        overall = "operational"
    else:
        overall = "degraded"
    return {
        "schema_version": 2,
        "overall_status": overall,
        "generated_at": checked_at.isoformat().replace("+00:00", "Z"),
        "max_age_seconds": 900,
        "components": components,
        "data_plane_note": "VPN availability is derived from authenticated, freshness-checked synthetic entry-path telemetry. Customer traffic is not inspected.",
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", type=pathlib.Path, required=True)
    parser.add_argument("--output", type=pathlib.Path, required=True)
    parser.add_argument("--data-plane-snapshot", type=pathlib.Path)
    arguments = parser.parse_args()
    try:
        report = run_probe(
            arguments.config,
            data_plane_snapshot_path=arguments.data_plane_snapshot,
        )
        arguments.output.parent.mkdir(parents=True, exist_ok=True)
        arguments.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    except (OSError, ValueError, StatusProbeError) as error:
        print(f"status probe failed safely: {error}")
        return 1
    print(f"status probe generated: {report['overall_status']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
