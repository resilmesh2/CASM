from collections.abc import Awaitable, Callable, Sequence
from typing import Any

import httpx
from temporalio import activity

from config import EasmScannerConfig, ISIMConfig, RedisConfig
from temporal.easm import activities_impl
from temporal.lib.util import validate_input_domain


class EasmActivities:
    def __init__(self, redis_config: RedisConfig, isim_config: ISIMConfig) -> None:
        self.isim_config = isim_config
        self.redis_config = redis_config

    @activity.defn
    async def validate_input(self, input_: dict[str, Any]) -> EasmScannerConfig:
        """
        Validate and normalize the incoming EASM scanner configuration.

        This activity constructs an EasmScannerConfig from the provided mapping
        and verifies that all domains are syntactically valid.

        :param input_: Mapping with fields expected by EasmScannerConfig
                        (e.g., domains, httpx_path, complete, etc.).
        :return: A validated EasmScannerConfig instance.
        :raises ValueError: If any provided domain is invalid.
        """
        obj_input = EasmScannerConfig(**input_)
        if not all(map(validate_input_domain, obj_input.domains)):
            raise ValueError("Invalid targets!")
        return obj_input

    @activity.defn
    async def run_httpx(self, domains_to_probe_uuid: str, httpx_path: str) -> str:
        """
        Run httpx against a list of domains stored in Redis.

        The list of domains is read from Redis under the given UUID and passed to
        the external httpx binary. The httpx JSONL output is stored back in
        Redis and the UUID key for that output is returned.

        :param domains_to_probe_uuid: Redis key where newline-separated domains are stored.
        :param httpx_path: Absolute or relative path to the httpx executable.
        :return: Redis UUID key where httpx JSONL output is stored.
        :raises temporal.lib.exceptions.EnumerationToolError: If the httpx command fails.
        """
        return await activities_impl.run_httpx(domains_to_probe_uuid, httpx_path, self.redis_config)

    @activity.defn
    async def parse_result_and_send_to_api(self, active_httpx_result_uuid: str) -> str:
        """
        Parse httpx JSONL output from Redis and forward results to the ISIM API.

        This activity converts each parsed entry to a dictionary payload expected
        by the ISIM endpoint and sends the list in a single POST request.

        :param active_httpx_result_uuid: Redis key from which to load httpx JSONL output.
        :return: The response body returned by the ISIM API.
        """
        parsed_httpx = activities_impl.parse_httpx_output(active_httpx_result_uuid, self.redis_config)
        payload = [item.to_dict() for item in parsed_httpx]
        headers = {"Content-Type": "application/json"}

        async with httpx.AsyncClient() as conn:
            return (await conn.post(f"{self.isim_config.url}/easm", json=payload, headers=headers)).text

    def get_activities(self) -> Sequence[Callable[..., Awaitable[Any]]]:
        return [self.run_httpx, self.parse_result_and_send_to_api, self.validate_input]
