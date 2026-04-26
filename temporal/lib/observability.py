from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import Any

import structlog

_configured = False


def _parse_bool(value: str | None) -> bool | None:
    if value is None:
        return None
    normalized = value.strip().lower()
    if normalized in {"1", "true", "yes", "on"}:
        return True
    if normalized in {"0", "false", "no", "off"}:
        return False
    return None


def _should_use_json_logs(json_logs: bool | None) -> bool:
    if json_logs is not None:
        return json_logs

    env_value = _parse_bool(os.getenv("LOG_JSON"))
    if env_value is not None:
        return env_value

    return Path("/.dockerenv").exists()


def _resolve_log_level(level: str | None) -> int:
    candidate = level or os.getenv("LOG_LEVEL") or "INFO"
    resolved = logging.getLevelName(candidate.upper())
    return resolved if isinstance(resolved, int) else logging.INFO


def _add_service_name(service: str) -> structlog.types.Processor:
    def processor(_logger: Any, _method_name: str, event_dict: structlog.types.EventDict) -> structlog.types.EventDict:
        event_dict.setdefault("service", service)
        return event_dict

    return processor


def configure_logging(service: str, level: str | None = None, json_logs: bool | None = None) -> None:
    global _configured

    if _configured:
        return

    log_level = _resolve_log_level(level)
    renderer: structlog.types.Processor = (
        structlog.processors.JSONRenderer() if _should_use_json_logs(json_logs) else structlog.dev.ConsoleRenderer()
    )

    shared_processors: list[structlog.types.Processor] = [
        structlog.contextvars.merge_contextvars,
        _add_service_name(service),
        structlog.stdlib.add_logger_name,
        structlog.stdlib.add_log_level,
        structlog.stdlib.PositionalArgumentsFormatter(),
        structlog.processors.TimeStamper(fmt="iso", utc=True),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
    ]

    formatter = structlog.stdlib.ProcessorFormatter(
        foreign_pre_chain=shared_processors,
        processors=[
            structlog.stdlib.ProcessorFormatter.remove_processors_meta,
            renderer,
        ],
    )

    handler = logging.StreamHandler()
    handler.setFormatter(formatter)

    root_logger = logging.getLogger()
    root_logger.handlers.clear()
    root_logger.addHandler(handler)
    root_logger.setLevel(log_level)

    structlog.configure(
        processors=[
            *shared_processors,
            structlog.stdlib.ProcessorFormatter.wrap_for_formatter,
        ],
        logger_factory=structlog.stdlib.LoggerFactory(),
        wrapper_class=structlog.stdlib.BoundLogger,
        cache_logger_on_first_use=True,
    )

    _configured = True
