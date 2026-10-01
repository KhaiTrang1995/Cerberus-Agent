"""Contract between the agent's Jev extension catalog and recon's validator.

The agent and recon run in different images, so they share no module: the agent
ranks a fixed list of file extensions and recon re-validates whatever comes back
with its own regex (`EXT_REGEX`, a dot plus 1-8 of a-z0-9). An entry the agent
can choose but recon rejects is dropped without an error, so the catalog would
silently be smaller than it says.

recon's package cannot be imported from the agent image (its helpers need
dnspython, which only the recon image has), so the consumer's own constant is
read out of its source file in the mounted repo and compiled here. It is never
re-typed in this test: a copy could drift and keep passing.

Runs inside the agent container.
"""
from __future__ import annotations

import ast
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import jev_hooks  # noqa: E402

RECON_FFUF = Path(__file__).resolve().parents[2] / "recon" / "helpers" / "ai_planner" / "ffuf_extensions.py"


def _recon_ext_regex() -> re.Pattern:
    tree = ast.parse(RECON_FFUF.read_text())
    for node in tree.body:
        if (isinstance(node, ast.Assign) and any(isinstance(t, ast.Name) and t.id == "EXT_REGEX" for t in node.targets)
                and isinstance(node.value, ast.Call) and node.value.args
                and isinstance(node.value.args[0], ast.Constant) and isinstance(node.value.args[0].value, str)):
            return re.compile(node.value.args[0].value)
    raise AssertionError(
        f"EXT_REGEX = re.compile('<pattern>') not found in {RECON_FFUF}: the consumer's validator moved, "
        "so this contract no longer checks anything")


def test_every_catalog_extension_passes_the_recon_validator():
    regex = _recon_ext_regex()
    dropped = [e for e in jev_hooks.FFUF_JEV_CATALOG if not regex.match(e)]
    assert dropped == [], f"recon's EXT_REGEX would silently drop: {dropped}"
