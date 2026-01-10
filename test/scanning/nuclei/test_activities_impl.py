# ruff: noqa: SLF001
# pyright: reportPrivateUsage=false

import json
from pathlib import Path
from typing import Any
from unittest.mock import Mock

import pytest
from pytest_mock import MockerFixture
from syrupy.assertion import SnapshotAssertion

from temporal.nuclei import activities_impl, dtos, exceptions


@pytest.fixture
def network_services_response() -> str:
    path = Path(__file__).parent / "assets" / "network_services_response.json"
    return path.read_text()


@pytest.fixture
def mock_http_cves_path(tmp_path: Path, mocker: MockerFixture) -> Path:
    path = tmp_path / "http" / "cves"
    mocker.patch(
        "temporal.nuclei.activities_impl.HTTP_CVE_TEMPLATES_PATH",
        path,
    )

    return path


@pytest.fixture
def mock_network_cves_path(tmp_path: Path, mocker: MockerFixture) -> Path:
    path = tmp_path / "network" / "cves"
    mocker.patch(
        "temporal.nuclei.activities_impl.NETWORK_CVE_TEMPLATES_PATH",
        path,
    )

    return path


class TestSearchNucleiTemplates:
    """Tests for search_nuclei_templates function."""

    def test_search_http_service_with_existing_template(
        self, mock_http_cves_path: Path, mock_network_cves_path: Path
    ) -> None:
        """Test searching for HTTP service CVE template that exists."""
        http_cve_path = mock_http_cves_path / "2021"
        http_cve_path.mkdir(parents=True)
        template_file = http_cve_path / "CVE-2021-12345.yaml"
        template_file.write_text("mock template")

        mock_network_cves_path.mkdir(parents=True)

        result = activities_impl.search_nuclei_templates("CVE-2021-12345", "http")

        assert len(result) == 1
        assert str(template_file) in result

    def test_search_non_http_service_with_existing_template(self, mock_network_cves_path: Path) -> None:
        """Test searching for non-HTTP service CVE template that exists."""
        network_cve_path = mock_network_cves_path / "2020"
        network_cve_path.mkdir(parents=True)
        template_file = network_cve_path / "CVE-2020-99999.yaml"
        template_file.write_text("mock template")

        result = activities_impl.search_nuclei_templates("CVE-2020-99999", "ssh")

        assert len(result) == 1
        assert str(template_file) in result

    def test_search_with_no_matching_template(self, mock_http_cves_path: Path, mock_network_cves_path: Path) -> None:
        """Test searching for CVE with no matching template."""
        mock_http_cves_path.mkdir(parents=True)
        mock_network_cves_path.mkdir(parents=True)

        result = activities_impl.search_nuclei_templates("CVE-2022-99999", "http")

        assert len(result) == 0

    def test_search_raises_error_when_templates_not_found(self, mocker: MockerFixture) -> None:
        """Test that NucleiTemplatesNotFoundError is raised when template directory doesn't exist."""
        mocker.patch("temporal.nuclei.activities_impl.HTTP_CVE_TEMPLATES_PATH", Path("/nonexistent/path"))
        mocker.patch("temporal.nuclei.activities_impl.NETWORK_CVE_TEMPLATES_PATH", Path("/nonexistent/path2"))

        with pytest.raises(exceptions.NucleiTemplatesNotFoundError):
            activities_impl.search_nuclei_templates("CVE-2021-12345", "http")

    def test_search_fallback_to_directory_iteration(self, mock_network_cves_path: Path) -> None:
        """Test that search falls back to iterating directories when direct lookup fails."""
        network_cve_path = mock_network_cves_path / "2019"
        network_cve_path.mkdir(parents=True)
        template_file = network_cve_path / "CVE-2021-12345.yaml"
        template_file.write_text("mock template")

        result = activities_impl.search_nuclei_templates("CVE-2021-12345", "ssh")

        assert len(result) == 1
        assert str(template_file) in result

    def test_search_http_checks_both_paths(self, mock_http_cves_path: Path, mock_network_cves_path: Path) -> None:
        """Test that HTTP service searches both http/cves and network/cves paths."""
        http_cve_path = mock_http_cves_path / "2021"
        http_cve_path.mkdir(parents=True)
        http_template = http_cve_path / "CVE-2021-11111.yaml"
        http_template.write_text("http template")

        network_cve_path = mock_network_cves_path / "2021"
        network_cve_path.mkdir(parents=True)

        result = activities_impl.search_nuclei_templates("CVE-2021-11111", "http")

        # Should find the template from http path
        assert len(result) == 1
        assert str(http_template) in result


class TestParseDataForNucleiScan:
    """Tests for parse_data_for_nuclei_scan function."""

    def _sort_services_with_nuclei_templates(self, input_dict: dict[str, dict[str, Any]]) -> dict[str, dict[str, Any]]:
        return {
            key: {**value, "cves": sorted(value.get("cves", [])) if "cves" in value else []}
            for key, value in sorted(input_dict.items())
        }

    def test_parse_valid_service_data(
        self, network_services_response: str, mocker: MockerFixture, snapshot: SnapshotAssertion
    ) -> None:
        """Test parsing valid network service data with CVEs."""
        mock_valkey = Mock()
        mock_valkey.get.return_value = network_services_response
        mock_valkey.set = Mock()

        mock_search = mocker.patch("temporal.nuclei.activities_impl.search_nuclei_templates")
        mock_search.return_value = ["/path/to/template.yaml"]
        result_uuid = activities_impl.parse_data_for_nuclei_scan(mock_valkey, "test-uuid")

        mock_valkey.get.assert_called_once_with("test-uuid")
        assert mock_valkey.set.called
        assert result_uuid.startswith("services_with_nuclei_templates-")

        # Verify the stored data
        stored_data = json.loads(mock_valkey.set.call_args[0][1])

        # Sort the dictionary by keys and sort CVE lists within each service
        stable_data = self._sort_services_with_nuclei_templates(stored_data)

        assert stable_data == snapshot

    def test_parse_service_data_with_no_domain_name(self, mocker: MockerFixture, snapshot: SnapshotAssertion) -> None:
        """Test parsing service data when domain name is not available, uses IP."""
        service_data = {  # pyright: ignore
            "data": {
                "hosts": [
                    {
                        "node": {"ips": [{"address": "10.0.0.5", "domain_names": []}]},
                        "network_services": [
                            {
                                "service": "ssh",
                                "port": 22,
                                "protocol": "tcp",
                                "software_versions": [{"vulnerabilities": [{"cve": {"cve_id": "CVE-2020-99999"}}]}],
                            }
                        ],
                    }
                ]
            }
        }

        mock_valkey = Mock()
        mock_valkey.get.return_value = json.dumps(service_data)
        mock_valkey.set = Mock()

        mocker.patch("temporal.nuclei.activities_impl.search_nuclei_templates", return_value=[])
        activities_impl.parse_data_for_nuclei_scan(mock_valkey, "test-uuid")

        stored_data = json.loads(mock_valkey.set.call_args[0][1])
        assert stored_data == snapshot

    def test_parse_handles_missing_node(self, mocker: MockerFixture, snapshot: SnapshotAssertion) -> None:
        """Test parsing when host has no node information."""
        service_data = {
            "data": {
                "hosts": [
                    {
                        "node": None,
                        "network_services": [
                            {
                                "service": "http",
                                "port": 80,
                                "protocol": "tcp",
                                "software_versions": [{"vulnerabilities": [{"cve": {"cve_id": "CVE-2021-12345"}}]}],
                            }
                        ],
                    }
                ]
            }
        }

        mock_valkey = Mock()
        mock_valkey.get.return_value = json.dumps(service_data)
        mock_valkey.set = Mock()

        mocker.patch("temporal.nuclei.activities_impl.search_nuclei_templates", return_value=[])
        activities_impl.parse_data_for_nuclei_scan(mock_valkey, "test-uuid")

        stored_data = json.loads(mock_valkey.set.call_args[0][1])
        assert stored_data == snapshot


class TestDetermineCveStatusFromNucleiScanResults:
    """Tests for _determine_cve_status_from_nuclei_scan_results function."""

    def test_confirmed_vulnerability_found(self) -> None:
        """Test that CVE is marked as confirmed when found in scan results."""
        stdout = json.dumps(
            {
                "info": {
                    "classification": {"cve-id": ["CVE-2021-12345"]},
                    "name": "Test Vulnerability",
                }
            }
        )

        service_data = dtos.ServiceTemplateData(
            target="example.com",
            ip_address="192.168.1.1",
            port=80,
            service="http",
            protocol="tcp",
            cves=["CVE-2021-12345"],
            templates=["/path/template.yaml"],
        )

        cve_status: dict[str, str] = {}
        activities_impl._determine_cve_status_from_nuclei_scan_results(stdout, service_data, cve_status)

        assert cve_status["CVE-2021-12345"] == activities_impl.VulnerabilityStatus.CONFIRMED.value

    def test_unconfirmed_vulnerability_not_found_in_results(self) -> None:
        """Test that CVE remains unconfirmed when not found in scan results."""
        stdout = json.dumps(
            {
                "info": {
                    "classification": {"cve-id": ["CVE-2021-99999"]},  # Different CVE
                    "name": "Other Vulnerability",
                }
            }
        )

        service_data = dtos.ServiceTemplateData(
            target="example.com",
            ip_address="192.168.1.1",
            port=80,
            service="http",
            protocol="tcp",
            cves=["CVE-2021-12345"],
            templates=["/path/template.yaml"],
        )

        cve_status: dict[str, str] = {}
        activities_impl._determine_cve_status_from_nuclei_scan_results(stdout, service_data, cve_status)

        assert cve_status["CVE-2021-12345"] == activities_impl.VulnerabilityStatus.UNCONFIRMED.value

    def test_multiple_cves_in_scan_results(self) -> None:
        """Test handling multiple CVEs in a single scan result."""
        results = [
            json.dumps(
                {"info": {"classification": {"cve-id": ["CVE-2021-11111", "CVE-2021-22222"]}, "name": "Multi CVE"}}
            ),
            json.dumps({"info": {"classification": {"cve-id": ["CVE-2021-33333"]}, "name": "Single CVE"}}),
        ]
        stdout = "\n".join(results)

        service_data = dtos.ServiceTemplateData(
            target="example.com",
            ip_address="192.168.1.1",
            port=80,
            service="http",
            protocol="tcp",
            cves=["CVE-2021-11111", "CVE-2021-22222", "CVE-2021-33333", "CVE-2021-44444"],
            templates=[],
        )

        cve_status: dict[str, str] = {}
        activities_impl._determine_cve_status_from_nuclei_scan_results(stdout, service_data, cve_status)

        assert cve_status["CVE-2021-11111"] == activities_impl.VulnerabilityStatus.CONFIRMED.value
        assert cve_status["CVE-2021-22222"] == activities_impl.VulnerabilityStatus.CONFIRMED.value
        assert cve_status["CVE-2021-33333"] == activities_impl.VulnerabilityStatus.CONFIRMED.value
        assert cve_status["CVE-2021-44444"] == activities_impl.VulnerabilityStatus.UNCONFIRMED.value

    def test_case_insensitive_cve_matching(self) -> None:
        """Test that CVE matching is case-insensitive."""
        stdout = json.dumps({"info": {"classification": {"cve-id": ["cve-2021-12345"]}, "name": "Test"}})

        service_data = dtos.ServiceTemplateData(
            target="example.com",
            ip_address="192.168.1.1",
            port=80,
            service="http",
            protocol="tcp",
            cves=["CVE-2021-12345"],  # Uppercase in service data
            templates=[],
        )

        cve_status: dict[str, str] = {}
        activities_impl._determine_cve_status_from_nuclei_scan_results(stdout, service_data, cve_status)

        assert cve_status["CVE-2021-12345"] == activities_impl.VulnerabilityStatus.CONFIRMED.value

    def test_handles_invalid_json_lines(self) -> None:
        """Test that invalid JSON lines are gracefully handled."""
        stdout = "invalid json line\n" + json.dumps(
            {"info": {"classification": {"cve-id": ["CVE-2021-12345"]}, "name": "Valid"}}
        )

        service_data = dtos.ServiceTemplateData(
            target="example.com",
            ip_address="192.168.1.1",
            port=80,
            service="http",
            protocol="tcp",
            cves=["CVE-2021-12345"],
            templates=[],
        )

        cve_status: dict[str, str] = {}
        activities_impl._determine_cve_status_from_nuclei_scan_results(stdout, service_data, cve_status)

        # Should still process the valid line
        assert cve_status["CVE-2021-12345"] == activities_impl.VulnerabilityStatus.CONFIRMED.value

    def test_handles_empty_stdout(self) -> None:
        """Test handling of empty scan output."""
        stdout = ""

        service_data = dtos.ServiceTemplateData(
            target="example.com",
            ip_address="192.168.1.1",
            port=80,
            service="http",
            protocol="tcp",
            cves=["CVE-2021-12345"],
            templates=[],
        )

        cve_status: dict[str, str] = {}
        activities_impl._determine_cve_status_from_nuclei_scan_results(stdout, service_data, cve_status)

        assert cve_status["CVE-2021-12345"] == activities_impl.VulnerabilityStatus.UNCONFIRMED.value

    def test_handles_results_without_classification(self) -> None:
        """Test handling results that don't have classification field."""
        stdout = json.dumps({"info": {"name": "Test", "severity": "high"}})

        service_data = dtos.ServiceTemplateData(
            target="example.com",
            ip_address="192.168.1.1",
            port=80,
            service="http",
            protocol="tcp",
            cves=["CVE-2021-12345"],
            templates=[],
        )

        cve_status: dict[str, str] = {}
        activities_impl._determine_cve_status_from_nuclei_scan_results(stdout, service_data, cve_status)

        assert cve_status["CVE-2021-12345"] == activities_impl.VulnerabilityStatus.UNCONFIRMED.value

    def test_preserves_existing_cve_status(self) -> None:
        """Test that existing CVE status is preserved when not in service data."""
        stdout = json.dumps({"info": {"classification": {"cve-id": ["CVE-2021-12345"]}, "name": "Test"}})

        service_data = dtos.ServiceTemplateData(
            target="example.com",
            ip_address="192.168.1.1",
            port=80,
            service="http",
            protocol="tcp",
            cves=["CVE-2021-12345"],
            templates=[],
        )

        cve_status = {"CVE-2021-99999": activities_impl.VulnerabilityStatus.CONFIRMED.value}
        activities_impl._determine_cve_status_from_nuclei_scan_results(stdout, service_data, cve_status)

        # Existing status should be preserved
        assert cve_status["CVE-2021-99999"] == activities_impl.VulnerabilityStatus.CONFIRMED.value
        assert cve_status["CVE-2021-12345"] == activities_impl.VulnerabilityStatus.CONFIRMED.value
