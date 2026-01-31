from __future__ import annotations

import inspect
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path
from types import ModuleType
from typing import TypeVar

import pytest

T = TypeVar("T", bound=Callable[..., object])


@dataclass(frozen=True, slots=True)
class PytestTarget:
    nodeid: str


def _module_to_file(module: ModuleType) -> Path:
    module_file = getattr(module, "__file__", None)
    if not module_file:
        raise ValueError(f"Cannot locate file for module {module.__name__!r}.")
    return Path(module_file).resolve()


def _callable_to_nodeid(test: Callable[..., object]) -> PytestTarget:
    func = test.__func__ if inspect.ismethod(test) else test

    module = inspect.getmodule(func)
    if module is None:
        raise ValueError("Cannot resolve module for the given callable.")

    file_path = _module_to_file(module)

    qualname = getattr(func, "__qualname__", "")
    name = getattr(func, "__name__", "")
    if not name:
        raise ValueError("Callable has no __name__.")

    tail = qualname or name
    if "<locals>" in tail:
        raise ValueError("Locally defined callables cannot be targeted by pytest nodeid.")

    node_tail = "::".join(tail.split("."))
    return PytestTarget(nodeid=f"{file_path}::{node_tail}")


def run_test_callable(
    test: Callable[..., object],
    *,
    update_snapshots: bool = False,
    extra_args: Sequence[str] = (),
) -> int:
    """
    Run pytest targeting exactly the given test callable.

    - update_snapshots=True adds the common snapshot update flags.
    - extra_args are passed verbatim to pytest.
    """
    target = _callable_to_nodeid(test)

    args: list[str] = [target.nodeid]

    if update_snapshots:
        # Covers common snapshot plugins
        args.extend(
            [
                "--snapshot-update",  # pytest-snapshot
                "--snapshot-update-all",  # syrupy (ignored if unsupported)
            ]
        )

    args.extend(extra_args)
    return pytest.main(args)
