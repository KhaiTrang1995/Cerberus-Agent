"""
Every default the agent's /defaults emits stays inside its registry bound.

The MCP preset apply resets every field a preset does not name to the running
backends' defaults, and it judges what it writes against the registry. A
default outside its own bound would refuse EVERY apply, so this is where a
default moved in project_settings.py without its bound (or the reverse) is
caught. The recon half is recon/tests/test_defaults_within_registry_bounds.py.

The real endpoint is called, so its own naming (agentXxx, the unprefixed HYDRA_
and FIRETEAM_ families) is what is checked, not a copy of it.
"""
from __future__ import annotations

import asyncio
import sys
from contextlib import asynccontextmanager
from pathlib import Path
from unittest.mock import patch

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))


@pytest.fixture(scope="module")
def defaults():
    @asynccontextmanager
    async def fake_lifespan(_app):
        yield

    with patch("api.lifespan", fake_lifespan):
        import api as api_module
    return asyncio.run(api_module.get_defaults())


def _problem(spec: dict, value) -> str | None:
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


def test_the_endpoint_emits_registry_columns(defaults):
    from recon_settings.loader import field

    known = [k for k in defaults if field(k) is not None]
    # Most of what it emits is a real column; an empty intersection would mean
    # the naming broke and the check below passed vacuously.
    assert len(known) > 20


def test_every_agent_default_fits_its_bound(defaults):
    from recon_settings.loader import field

    problems = []
    for column, value in defaults.items():
        spec = field(column)
        if spec is None or value is None:
            continue
        problem = _problem(spec, value)
        if problem:
            problems.append(f"{column}: {problem}")
    assert problems == [], "agent defaults outside their registry bound: " + "; ".join(problems)
