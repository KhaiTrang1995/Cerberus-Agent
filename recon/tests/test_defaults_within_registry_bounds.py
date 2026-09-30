"""
Every default the recon orchestrator's /defaults emits stays inside its registry bound.

The MCP preset apply resets every field a preset does not name to these
defaults, and it judges what it writes against the registry. A default outside
its own bound would therefore refuse EVERY apply, and the fix would be a code
change on a live system. This catches the drift where it starts: a default moved
in a Python settings module while the bound in recon_settings/registry.yaml did
not (or the reverse).

The orchestrator's /defaults is DEFAULT_SETTINGS named through the registry, plus
the GVM and GitHub-hunt scanner defaults. Its image does not carry the recon code
(that is mounted at run time), so this runs in the recon image against the same
sources. The agent's half is agentic/tests/test_defaults_within_registry_bounds.py.

Run: python -m pytest recon/tests/test_defaults_within_registry_bounds.py -v
"""
from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest

from recon import settings_registry as reg
from recon.project_settings import DEFAULT_SETTINGS

REPO = Path(__file__).resolve().parents[2]


def _problem(column: str, value) -> str | None:
    """The registry's bound or value set, applied to one default. None when it fits."""
    spec = reg.field(column)
    if spec is None or value is None:
        return None
    bounds = spec.get("bounds")
    values = spec.get("values")
    if bounds and isinstance(value, (int, float)) and not isinstance(value, bool):
        if not bounds["min"] <= value <= bounds["max"]:
            return f"{value!r} is outside {bounds['min']}..{bounds['max']}"
    if values:
        items = value if isinstance(value, list) else [value]
        bad = [v for v in items if v not in values]
        if bad:
            return f"{bad!r} is not one of {values}"
    return None


def _camel(snake: str) -> str:
    parts = snake.lower().split("_")
    return parts[0] + "".join(p.title() for p in parts[1:])


def _scanner_defaults(relative: str, attr: str) -> dict:
    path = REPO / relative
    if not path.exists():
        pytest.skip(f"{relative} is not in this checkout")
    spec = importlib.util.spec_from_file_location(f"_defaults_{attr.lower()}", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return getattr(module, attr)


@pytest.fixture(autouse=True)
def _fresh_registry():
    reg.load_registry.cache_clear()
    yield
    reg.load_registry.cache_clear()


def test_every_recon_default_fits_its_bound():
    column_for = {key: entry["column"] for key, entry in reg.by_runtime_key().items()}
    problems = []
    for key, value in DEFAULT_SETTINGS.items():
        column = column_for.get(key)
        if column is None:
            continue
        problem = _problem(column, value)
        if problem:
            problems.append(f"{key} -> {column}: {problem}")
    assert problems == [], "recon defaults outside their registry bound: " + "; ".join(problems)


def test_the_gvm_defaults_fit_their_bounds():
    # The orchestrator names these gvm_<KEY> in camelCase, e.g. SCAN_TARGETS -> gvmScanTargets.
    defaults = _scanner_defaults("scanners/gvm_scan/project_settings.py", "DEFAULT_GVM_SETTINGS")
    problems = [
        f"{key}: {problem}"
        for key, value in defaults.items()
        if (problem := _problem(_camel(f"gvm_{key}"), value))
    ]
    assert problems == []


def test_the_github_hunt_defaults_fit_their_bounds():
    defaults = _scanner_defaults("scanners/github_secret_hunt/project_settings.py", "DEFAULT_GITHUB_SETTINGS")
    problems = [
        f"{key}: {problem}"
        for key, value in defaults.items()
        if (problem := _problem(_camel(key), value))
    ]
    assert problems == []


def test_the_check_itself_catches_a_default_out_of_bounds():
    # Guards the guard: a helper that never fails would pass every test above.
    bounded = next(c for c, e in reg.fields().items() if e.get("bounds") and e.get("type") == "int")
    assert _problem(bounded, reg.field(bounded)["bounds"]["max"] + 1) is not None
    assert _problem("gvmScanTargets", "everything") is not None
    assert _problem("gvmScanTargets", "both") is None
