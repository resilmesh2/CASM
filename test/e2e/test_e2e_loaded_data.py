from __future__ import annotations

import json
from pathlib import Path
from typing import TYPE_CHECKING, Any

import httpx

from config import AppConfig

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

    def _graphql_request(self, query: str) -> Any:
        isim_urls = AppConfig.get().isim_urls

        payload = {
            "query": query,
        }

        with httpx.Client(base_url=isim_urls.graphql_url, timeout=60.0) as client:
            response = client.post("", json=payload)
            try:
                return response.json()
            except ValueError:
                return response.text

    def _canon_json(self, value: Any) -> str:
        return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)

    def normalize_for_snapshot(self, value: Any) -> Any:
        """
        Key-agnostic normalization:
        - dicts: keys sorted
        - lists: elements normalized, then sorted by canonical JSON of each element
        This makes snapshots stable when list order is nondeterministic.
        """
        if isinstance(value, dict):
            return {k: self.normalize_for_snapshot(v) for k, v in sorted(value.items())}

        if isinstance(value, list):
            normalized = [self.normalize_for_snapshot(v) for v in value]
            return sorted(normalized, key=self._canon_json)

        return value

    def test_e2e_nmap_snapshot(self, snapshot: SnapshotAssertion) -> None:
        """
        Snapshot the asset info endpoint (Nmap + EASM results).

        Update snapshots intentionally via:
          E2E_API_SNAPSHOT=1 poetry run pytest test/e2e/test_api_snapshots.py --snapshot-update
        """
        hosts_query = (Path(__file__).parent / "assets" / "get_hosts.graphql").read_text(encoding="utf-8")

        payload = self._graphql_request(hosts_query)
        assert self.normalize_for_snapshot(payload) == snapshot(name="nmap")

    def test_e2e_easm_snapshot(self, snapshot: SnapshotAssertion) -> None:
        """
        Snapshot the CVE/Nuclei/component endpoint.

        Update snapshots intentionally via:
          E2E_API_SNAPSHOT=1 poetry run pytest test/e2e/test_api_snapshots.py --snapshot-update
        """
        nodes_query = (Path(__file__).parent / "assets" / "get_nodes.graphql").read_text(encoding="utf-8")

        payload = self._graphql_request(nodes_query)
        assert self.normalize_for_snapshot(payload) == snapshot(name="easm")

    def test_e2e_cve_connector_snapshot(self, snapshot: SnapshotAssertion) -> None:
        """
        Snapshot the CVE/Nuclei/component endpoint.

        Update snapshots intentionally via:
          E2E_API_SNAPSHOT=1 poetry run pytest test/e2e/test_api_snapshots.py --snapshot-update
        """
        cves_query = (Path(__file__).parent / "assets" / "get_cves.graphql").read_text(encoding="utf-8")

        payload = self._graphql_request(cves_query)
        assert self.normalize_for_snapshot(payload) == snapshot(name="cve_connector")

    def test_e2e_nuclei_snapshot(self, snapshot: SnapshotAssertion) -> None:
        """
        Snapshot the CVE/Nuclei/component endpoint.

        Update snapshots intentionally via:
          E2E_API_SNAPSHOT=1 poetry run pytest test/e2e/test_api_snapshots.py --snapshot-update
        """
        vulns_query = (Path(__file__).parent / "assets" / "get_vulnerabilities.graphql").read_text(encoding="utf-8")

        payload = self._graphql_request(vulns_query)
        assert self.normalize_for_snapshot(payload) == snapshot(name="nuclei")
