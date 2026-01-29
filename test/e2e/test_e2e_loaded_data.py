from __future__ import annotations

from typing import TYPE_CHECKING, Any

import httpx

from config import AppConfig

if TYPE_CHECKING:
    from syrupy.assertion import SnapshotAssertion


def _fetch_payload(path: str) -> Any:
    isim_urls = AppConfig.get().isim_urls
    with httpx.Client(base_url=isim_urls.rest_url, timeout=60.0) as client:
        response = client.get(path)
        response.raise_for_status()
        try:
            return response.json()
        except ValueError:
            return response.text


def test_e2e_asset_info_snapshot(snapshot: SnapshotAssertion) -> None:
    """
    Snapshot the asset info endpoint (Nmap + EASM results).

    Update snapshots intentionally via:
      E2E_API_SNAPSHOT=1 poetry run pytest test/e2e/test_api_snapshots.py --snapshot-update
    """
    payload = _fetch_payload("/asset_info")
    assert payload == snapshot(name="asset_info")


def test_e2e_cves_snapshot(snapshot: SnapshotAssertion) -> None:
    """
    Snapshot the CVE/Nuclei/component endpoint.

    Update snapshots intentionally via:
      E2E_API_SNAPSHOT=1 poetry run pytest test/e2e/test_api_snapshots.py --snapshot-update
    """
    payload = _fetch_payload("/cves")
    assert payload == snapshot(name="cves")

