# ruff: noqa: SLF001
# pyright: reportPrivateUsage=false

from unittest.mock import AsyncMock, MagicMock

import pytest
from pytest_mock import MockerFixture

from temporal.easm.passive_enumeration import activities_impl
from temporal.lib import exceptions


@pytest.mark.anyio
class TestRunSubfinder:
    async def test_run_subfinder_success(self, mocker: MockerFixture) -> None:
        mock_redis = MagicMock()
        mocker.patch("temporal.lib.redis_handler.get_redis", return_value=mock_redis)

        mock_run_command = mocker.patch("temporal.lib.util.run_command_with_output", new_callable=AsyncMock)
        mock_run_command.return_value = ("sub1.example.com\nsub2.example.com", "", 0)

        result = await activities_impl.run_subfinder(["example.com"])

        assert len(result) == 32  # hex uuid length
        mock_run_command.assert_called_once()
        mock_redis.set.assert_called_once_with(result, "sub1.example.com\nsub2.example.com")

    async def test_run_subfinder_failure(self, mocker: MockerFixture) -> None:
        mock_run_command = mocker.patch("temporal.lib.util.run_command_with_output", new_callable=AsyncMock)
        mock_run_command.return_value = ("", "error", 1)

        with pytest.raises(exceptions.EnumerationToolError):
            await activities_impl.run_subfinder(["example.com"])


@pytest.mark.anyio
class TestRunAmass:
    async def test_run_amass_success(self, mocker: MockerFixture) -> None:
        mock_redis = MagicMock()
        mocker.patch("temporal.lib.redis_handler.get_redis", return_value=mock_redis)

        mock_run_command = mocker.patch("temporal.lib.util.run_command_with_output", new_callable=AsyncMock)
        mock_run_command.return_value = ("sub3.example.com\nsub4.example.com", "", 0)

        result = await activities_impl.run_amass(["example.com"])

        assert len(result) == 32  # hex uuid length
        mock_run_command.assert_called_once()
        mock_redis.set.assert_called_once_with(result, "sub3.example.com\nsub4.example.com")

    async def test_run_amass_failure(self, mocker: MockerFixture) -> None:
        mock_run_command = mocker.patch("temporal.lib.util.run_command_with_output", new_callable=AsyncMock)
        mock_run_command.return_value = ("", "error", 1)

        with pytest.raises(exceptions.EnumerationToolError):
            await activities_impl.run_amass(["example.com"])


@pytest.mark.anyio
class TestGetUniqueSubdomains:
    async def test_get_unique_subdomains_success(self, mocker: MockerFixture) -> None:
        mock_redis = MagicMock()
        mock_redis.get.side_effect = ["sub1.example.com\nsub2.example.com", "sub2.example.com\nsub3.example.com"]
        mocker.patch("temporal.lib.redis_handler.get_redis", return_value=mock_redis)

        result = await activities_impl.get_unique_subdomains(["uuid1", "uuid2"])

        assert result.startswith("unique_subdomains-")
        mock_redis.set.assert_called_once()
        set_call_args = mock_redis.set.call_args[0]
        assert set_call_args[0] == result
        # The order of domains in the result might vary because of set()
        saved_domains = set(set_call_args[1].splitlines())
        assert saved_domains == {"sub1.example.com", "sub2.example.com", "sub3.example.com"}

    async def test_get_unique_subdomains_no_results(self, mocker: MockerFixture) -> None:
        mock_redis = MagicMock()
        mock_redis.get.return_value = ""
        mocker.patch("temporal.lib.redis_handler.get_redis", return_value=mock_redis)

        with pytest.raises(exceptions.NoDomainsFoundError):
            await activities_impl.get_unique_subdomains(["uuid1"])

        mock_redis.close.assert_called_once()
