# ruff: noqa: SLF001
# pyright: reportPrivateUsage=false

from unittest.mock import AsyncMock, MagicMock

import pytest
from pytest_mock import MockerFixture

from temporal.easm.active_enumeration import activities_impl
from temporal.lib import exceptions


@pytest.mark.anyio
class TestRunDnsxBruteforce:
    async def test_run_dnsx_bruteforce_success(self, mocker: MockerFixture) -> None:
        mock_redis = MagicMock()
        mock_redis.get.return_value = "example.com"
        mocker.patch("temporal.lib.redis_handler.get_redis", return_value=mock_redis)

        mock_run_command = mocker.patch("temporal.lib.util.run_command_with_output", new_callable=AsyncMock)
        mock_run_command.return_value = ("sub.example.com\n", "", 0)

        mocker.patch("temporal.lib.util.get_unique_subdomains", return_value="sub.example.com")

        result = await activities_impl.run_dnsx_bruteforce("passive_uuid", "wordlist.txt", "10")

        assert result.startswith("dnsx-bruteforce-")
        mock_redis.get.assert_called_once_with("passive_uuid")
        mock_run_command.assert_called_once()
        mock_redis.set.assert_called_once_with(result, "sub.example.com")
        mock_redis.close.assert_called_once()

    async def test_run_dnsx_bruteforce_failure(self, mocker: MockerFixture) -> None:
        mock_redis = MagicMock()
        mock_redis.get.return_value = "example.com"
        mocker.patch("temporal.lib.redis_handler.get_redis", return_value=mock_redis)

        mock_run_command = mocker.patch("temporal.lib.util.run_command_with_output", new_callable=AsyncMock)
        mock_run_command.return_value = ("", "error", 1)

        with pytest.raises(exceptions.EnumerationToolError):
            await activities_impl.run_dnsx_bruteforce("passive_uuid", "wordlist.txt", "10")

        mock_redis.close.assert_called_once()

    async def test_run_dnsx_bruteforce_no_results(self, mocker: MockerFixture) -> None:
        mock_redis = MagicMock()
        mock_redis.get.return_value = "example.com"
        mocker.patch("temporal.lib.redis_handler.get_redis", return_value=mock_redis)

        mock_run_command = mocker.patch("temporal.lib.util.run_command_with_output", new_callable=AsyncMock)
        mock_run_command.return_value = ("", "", 0)

        with pytest.raises(exceptions.NoDomainsFoundError):
            await activities_impl.run_dnsx_bruteforce("passive_uuid", "wordlist.txt", "10")

        mock_redis.close.assert_called_once()


@pytest.mark.anyio
class TestRunAlterx:
    async def test_run_alterx_success(self, mocker: MockerFixture) -> None:
        mock_redis = MagicMock()
        mock_redis.get.return_value = "example.com"
        mocker.patch("temporal.lib.redis_handler.get_redis", return_value=mock_redis)

        mock_process = AsyncMock()
        mock_process.wait.return_value = 0
        mocker.patch("asyncio.create_subprocess_exec", return_value=mock_process)

        mock_named_temp = mocker.patch("tempfile.NamedTemporaryFile")
        mock_domains_file = MagicMock()
        mock_alterx_output = MagicMock()
        # Mocking the context manager __enter__
        mock_named_temp.return_value.__enter__.side_effect = [mock_domains_file, mock_alterx_output]

        mock_alterx_output.read.return_value = "permuted.example.com"

        result = await activities_impl.run_alterx("domains_uuid")

        assert result.startswith("alterx-")
        mock_redis.get.assert_called_once_with("domains_uuid")
        mock_redis.set.assert_called_once_with(result, "permuted.example.com")
        mock_redis.close.assert_called_once()

    async def test_run_alterx_failure(self, mocker: MockerFixture) -> None:
        mock_redis = MagicMock()
        mock_redis.get.return_value = "example.com"
        mocker.patch("temporal.lib.redis_handler.get_redis", return_value=mock_redis)

        mock_process = AsyncMock()
        mock_process.wait.return_value = 1
        mocker.patch("asyncio.create_subprocess_exec", return_value=mock_process)

        mocker.patch("tempfile.NamedTemporaryFile")

        with pytest.raises(exceptions.EnumerationToolError):
            await activities_impl.run_alterx("domains_uuid")

        mock_redis.close.assert_called_once()


@pytest.mark.anyio
class TestRunDnsxResolver:
    async def test_run_dnsx_resolver_success(self, mocker: MockerFixture) -> None:
        mock_redis = MagicMock()
        mock_redis.get.return_value = "sub.example.com"
        mocker.patch("temporal.lib.redis_handler.get_redis", return_value=mock_redis)

        mock_run_command = mocker.patch("temporal.lib.util.run_command_with_output", new_callable=AsyncMock)
        mock_run_command.return_value = ("sub.example.com\n", "", 0)

        mocker.patch("temporal.lib.util.get_unique_subdomains", return_value="sub.example.com")

        result = await activities_impl.run_dnsx_resolver("domains_uuid")

        assert result.startswith("dnsx-resolver-")
        mock_redis.get.assert_called_once_with("domains_uuid")
        mock_redis.set.assert_called_once_with(result, "sub.example.com")
        mock_redis.close.assert_called_once()

    async def test_run_dnsx_resolver_failure(self, mocker: MockerFixture) -> None:
        mock_redis = MagicMock()
        mock_redis.get.return_value = "sub.example.com"
        mocker.patch("temporal.lib.redis_handler.get_redis", return_value=mock_redis)

        mock_run_command = mocker.patch("temporal.lib.util.run_command_with_output", new_callable=AsyncMock)
        mock_run_command.return_value = ("", "error", 1)

        with pytest.raises(exceptions.EnumerationToolError):
            await activities_impl.run_dnsx_resolver("domains_uuid")

        mock_redis.close.assert_called_once()

    async def test_run_dnsx_resolver_no_results(self, mocker: MockerFixture) -> None:
        mock_redis = MagicMock()
        mock_redis.get.return_value = "sub.example.com"
        mocker.patch("temporal.lib.redis_handler.get_redis", return_value=mock_redis)

        mock_run_command = mocker.patch("temporal.lib.util.run_command_with_output", new_callable=AsyncMock)
        mock_run_command.return_value = ("", "", 0)

        with pytest.raises(exceptions.NoDomainsFoundError):
            await activities_impl.run_dnsx_resolver("domains_uuid")

        mock_redis.close.assert_called_once()
