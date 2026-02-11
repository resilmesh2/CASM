from __future__ import annotations

import inspect
import subprocess
import sys
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


@dataclass(frozen=True, slots=True)
class TestRunResult:
    name: str
    returncode: int

    @property
    def ok(self) -> bool:
        return self.returncode == 0


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
        args.append("--snapshot-update")

    args.extend(extra_args)
    return pytest.main(args)


def run_test_callable_subprocess(
    test: Callable[..., object],
    *,
    update_snapshots: bool = False,
    extra_args: Sequence[str] = (),
    name: str | None = None,
) -> TestRunResult:
    target = _callable_to_nodeid(test)

    cmd: list[str] = [sys.executable, "-m", "pytest", target.nodeid]
    if update_snapshots:
        cmd.append("--snapshot-update")
    cmd.extend(extra_args)

    completed = subprocess.run(cmd, check=False)
    return TestRunResult(name=name or target.nodeid, returncode=int(completed.returncode))


def finish(results: Sequence[TestRunResult]) -> None:
    failed = [result for result in results if not result.ok]
    if failed:
        print("\nE2E TEST SUMMARY (FAILED)")
        for result in failed:
            print(f"- {result.name} (exit={result.returncode})")
        raise SystemExit(1)
    print("\nALL E2E TESTS PASSED")
