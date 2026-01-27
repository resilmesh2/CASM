# ruff: noqa: SLF001
# pyright: reportPrivateUsage=false

from unittest.mock import AsyncMock, MagicMock

import httpx
import pytest
from pytest_mock import MockerFixture
from syrupy.assertion import SnapshotAssertion

from temporal.easm import activities_impl
from temporal.lib import exceptions


@pytest.mark.anyio
class TestRunHttpx:
    async def test_run_httpx_success(self, mocker: MockerFixture) -> None:
        mock_redis = MagicMock()
        mock_redis.get.return_value = "example.com\ntest.com"
        mocker.patch("temporal.lib.redis_handler.get_redis", return_value=mock_redis)

        mock_run_command = mocker.patch("temporal.lib.util.run_command_with_output", new_callable=AsyncMock)
        mock_run_command.return_value = ('{"input": "example.com", "host": "1.2.3.4"}\n', "", 0)

        result = await activities_impl.run_httpx("input_uuid", "/usr/bin/httpx")

        assert result.startswith("httpx-")
        mock_redis.get.assert_called_once_with("input_uuid")
        mock_run_command.assert_called_once()
        mock_redis.set.assert_called_once_with(result, '{"input": "example.com", "host": "1.2.3.4"}\n')

    async def test_run_httpx_failure(self, mocker: MockerFixture) -> None:
        mock_redis = MagicMock()
        mock_redis.get.return_value = "example.com"
        mocker.patch("temporal.lib.redis_handler.get_redis", return_value=mock_redis)

        mock_run_command = mocker.patch("temporal.lib.util.run_command_with_output", new_callable=AsyncMock)
        mock_run_command.return_value = ("", "error", 1)

        with pytest.raises(exceptions.EnumerationToolError):
            await activities_impl.run_httpx("input_uuid", "/usr/bin/httpx")

        mock_redis.close.assert_called_once()


class TestParseHttpxOutput:
    def test_parse_httpx_output_success(self, mocker: MockerFixture, snapshot: SnapshotAssertion) -> None:
        mock_redis = MagicMock()
        httpx_jsonl = (
            '{"input": "example.com", "host": "1.2.3.4", "port": 443, "scheme": "https", "tech": ["nginx:1.24"]}\n'
            '{"input": "test.com", "host": "5.6.7.8", "failed": true}'
        )
        mock_redis.get.return_value = httpx_jsonl
        mocker.patch("temporal.lib.redis_handler.get_redis", return_value=mock_redis)

        mock_determine = mocker.patch(
            "temporal.easm.activities_impl.determine_software_versions",
            return_value=[{"name": "nginx:1.24", "version": "cpe:2.3:a:nginx:nginx:1.24:*:*:*:*:*:*:*"}],
        )

        results = activities_impl.parse_httpx_output("httpx_uuid")

        assert len(results) == 1
        res = results[0]
        assert res.domain_name == "example.com"
        assert res.ip == "1.2.3.4"
        assert res.port == 443
        assert res.protocol == "https"
        assert res.software_versions == snapshot
        mock_determine.assert_called_once_with(["nginx:1.24"])


class TestFetchFingerprints:
    def test_fetch_fingerprints_success(self, mocker: MockerFixture) -> None:
        mock_response = MagicMock()
        mock_response.json.return_value = {"apps": {"nginx": {"cpe": "cpe:2.3:a:nginx:nginx"}}}
        mock_response.raise_for_status = MagicMock()

        mock_client = MagicMock()
        mock_client.get.return_value = mock_response
        mock_client.__enter__.return_value = mock_client

        mocker.patch("httpx.Client", return_value=mock_client)

        result = activities_impl.fetch_fingerprints()

        assert result == {"apps": {"nginx": {"cpe": "cpe:2.3:a:nginx:nginx"}}}
        mock_client.get.assert_called_once_with(activities_impl.WAPPALYZERGO_FINGERPRINTS_URL)

    def test_fetch_fingerprints_error(self, mocker: MockerFixture) -> None:
        mock_client = MagicMock()
        mock_client.get.side_effect = httpx.HTTPError("error")
        mock_client.__enter__.return_value = mock_client

        mocker.patch("httpx.Client", return_value=mock_client)

        with pytest.raises(httpx.HTTPError):
            activities_impl.fetch_fingerprints()


class TestHelperFunctions:
    @pytest.mark.parametrize(
        "token, expected",
        [
            ("nginx:1.24", ("nginx", "1.24")),
            ("Apache:httpd 2.4", ("Apache", "httpd 2.4")),
            ("WordPress", ("WordPress", None)),
            ("  spaces : 1.0  ", ("spaces", "1.0")),
        ],
    )
    def test_split_name_version(self, token: str, expected: tuple[str, str | None]) -> None:
        assert activities_impl._split_name_version(token) == expected

    @pytest.mark.parametrize(
        "cpe, expected",
        [
            ("cpe:2.3:a:nginx:nginx:1.24", ("nginx", "nginx")),
            ("cpe:/a:apache:http_server:2.4", ("apache", "http_server")),
            ("invalid", None),
            ("cpe:2.3:o:microsoft:windows", None),  # Part 'o' is not 'a'
            ("cpe:2.3:a:vendor", None),  # Too short
        ],
    )
    def test_parse_vendor_product_from_cpe(self, cpe: str, expected: tuple[str, str] | None) -> None:
        assert activities_impl._parse_vendor_product_from_cpe(cpe) == expected

    def test_make_cpe23_app(self) -> None:
        assert (
            activities_impl._make_cpe23_app("nginx", "nginx", "1.24")
            == "cpe:2.3:a:nginx:nginx:1.24:*:*:*:*:*:*:*"
        )
        assert (
            activities_impl._make_cpe23_app("vendor", "prod", None)
            == "cpe:2.3:a:vendor:prod:*:*:*:*:*:*:*:*"
        )


class TestDetermineSoftwareVersions:
    def test_determine_software_versions_empty(self) -> None:
        assert activities_impl.determine_software_versions([]) == []

    def test_determine_software_versions_success(
        self, mocker: MockerFixture, snapshot: SnapshotAssertion
    ) -> None:
        fingerprints = {
            "apps": {
                "nginx": {"cpe": "cpe:2.3:a:nginx:nginx"},
                "Apache": {"cpe": "cpe:/a:apache:http_server"},
            }
        }
        mocker.patch("temporal.easm.activities_impl.fetch_fingerprints", return_value=fingerprints)

        techs = ["nginx:1.24", "Apache:2.4", "UnknownTech:1.0"]
        results = activities_impl.determine_software_versions(techs)

        assert len(results) == 2
        assert results == snapshot

    def test_determine_software_versions_deduplication(
        self, mocker: MockerFixture, snapshot: SnapshotAssertion
    ) -> None:
        fingerprints = {"apps": {"nginx": {"cpe": "cpe:2.3:a:nginx:nginx"}}}
        mocker.patch("temporal.easm.activities_impl.fetch_fingerprints", return_value=fingerprints)

        techs = ["nginx:1.24", "nginx:1.24"]
        results = activities_impl.determine_software_versions(techs)

        assert len(results) == 1
        assert results == snapshot