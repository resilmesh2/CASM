from __future__ import annotations

from typing import TYPE_CHECKING, Any

import httpx

from config import AppConfig
from pathlib import Path
if TYPE_CHECKING:
    from syrupy.assertion import SnapshotAssertion


class TestE2ELoadedData:
    def _rest_request(self, path: str) -> Any:
        isim_urls = AppConfig.get().isim_urls
        with httpx.Client(base_url=isim_urls.rest_url, timeout=60.0) as client:
            response = client.get(path)
            response.raise_for_status()
            try:
                return response.json()
            except ValueError:
                return response.text

    def _graphql_request(self, payload: dict[str, str]) -> Any:
        isim_urls = AppConfig.get().isim_urls
        with httpx.Client(base_url=isim_urls.graphql_url, timeout=60.0) as client:
            response = client.post("", json=payload)
            try:
                return response.json()
            except ValueError:
                return response.text

    def test_e2e_nmap_snapshot(self, snapshot: SnapshotAssertion) -> None:
        """
        Snapshot the asset info endpoint (Nmap + EASM results).

        Update snapshots intentionally via:
          E2E_API_SNAPSHOT=1 poetry run pytest test/e2e/test_api_snapshots.py --snapshot-update
        """
        payload = self._rest_request("/asset_info")
        assert payload == snapshot(name="asset_info")


    def test_e2e_easm_snapshot(self, snapshot: SnapshotAssertion) -> None:
        """
        Snapshot the CVE/Nuclei/component endpoint.

        Update snapshots intentionally via:
          E2E_API_SNAPSHOT=1 poetry run pytest test/e2e/test_api_snapshots.py --snapshot-update
        """
        payload = self._rest_request("/asset_info")
        assert payload == snapshot(name="asset_info")


    def test_e2e_cve_connector_snapshot(self, snapshot: SnapshotAssertion) -> None:
        """
        Snapshot the CVE/Nuclei/component endpoint.

        Update snapshots intentionally via:
          E2E_API_SNAPSHOT=1 poetry run pytest test/e2e/test_api_snapshots.py --snapshot-update
        """
        payload = self._rest_request("/cves")
        assert payload == snapshot(name="cves")

    def test_e2e_nuclei_snapshot(self, snapshot: SnapshotAssertion) -> None:
        """
        Snapshot the CVE/Nuclei/component endpoint.

        Update snapshots intentionally via:
          E2E_API_SNAPSHOT=1 poetry run pytest test/e2e/test_api_snapshots.py --snapshot-update
        """
        vulns_query_path = (Path(__file__).parent / "assets" / "get_vulnerabilities.graphql").read_text(encoding="utf-8")
        payload = {
            "query": vulns_query_path,
        }
        payload = self._graphql_request(payload)
        assert payload == snapshot(name="asset_info")

