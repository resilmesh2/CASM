from __future__ import annotations

import logging.config
from typing import Any

import structlog

from config import AppConfig, LogFormatter, LoggingConfig

_configured = False


def _add_service_name(service: str) -> structlog.types.Processor:
    def processor(_logger: Any, _method_name: str, event_dict: structlog.types.EventDict) -> structlog.types.EventDict:
        event_dict.setdefault("service", service)
        return event_dict

    return processor


def _resolve_logging_config(logging_config: LoggingConfig | None) -> LoggingConfig:
    return logging_config if logging_config is not None else AppConfig.get().logging


def _build_shared_processors(service: str, *, verbose_origin: bool) -> list[structlog.types.Processor]:
    shared_processors: list[structlog.types.Processor] = [
        structlog.contextvars.merge_contextvars,
        _add_service_name(service),
        structlog.stdlib.add_logger_name,
        structlog.stdlib.add_log_level,
        structlog.stdlib.PositionalArgumentsFormatter(),
        structlog.processors.TimeStamper(fmt="iso", utc=True),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.UnicodeDecoder(encoding="utf-8"),
        structlog.processors.format_exc_info,
    ]

    if verbose_origin:
        shared_processors.append(structlog.processors.CallsiteParameterAdder())

    return shared_processors


def _build_renderer(formatter: LogFormatter, *, pretty_print_exceptions: bool) -> structlog.types.Processor:
    if formatter == "json":
        return structlog.processors.JSONRenderer()

    if formatter == "key_value":
        return structlog.processors.LogfmtRenderer(sort_keys=True)

    exception_formatter = (
        structlog.dev.rich_traceback if pretty_print_exceptions else structlog.dev.plain_traceback
    )
    return structlog.dev.ConsoleRenderer(
        colors=formatter == "colored",
        exception_formatter=exception_formatter,
    )


def configure_logging(service: str, logging_config: LoggingConfig | None = None) -> None:
    global _configured

    if _configured:
        return

    resolved_logging_config = _resolve_logging_config(logging_config)
    shared_processors = _build_shared_processors(service, verbose_origin=resolved_logging_config.verbose_origin)
    renderer = _build_renderer(
        resolved_logging_config.formatter_const,
        pretty_print_exceptions=resolved_logging_config.pretty_print_exceptions,
    )

    logging.config.dictConfig(
        {
            "version": 1,
            "disable_existing_loggers": False,
            "formatters": {
                "default": {
                    "()": structlog.stdlib.ProcessorFormatter,
                    "processors": [
                        structlog.stdlib.ProcessorFormatter.remove_processors_meta,
                        renderer,
                    ],
                    "foreign_pre_chain": shared_processors,
                }
            },
            "handlers": {
                "default": {
                    "class": "logging.StreamHandler",
                    "formatter": "default",
                    "stream": "ext://sys.stdout",
                    "level": resolved_logging_config.level_const,
                }
            },
            "root": {
                "handlers": ["default"],
                "level": resolved_logging_config.level_const,
            },
        }
    )

    structlog.configure(
        processors=[
            structlog.stdlib.filter_by_level,
            *shared_processors,
            structlog.stdlib.ProcessorFormatter.wrap_for_formatter,
        ],
        logger_factory=structlog.stdlib.LoggerFactory(),
        wrapper_class=structlog.make_filtering_bound_logger(resolved_logging_config.level_const),
        cache_logger_on_first_use=True,
    )

    _configured = True
