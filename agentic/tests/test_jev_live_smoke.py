"""LIVE smoke: the TypeSafe API still answers the way jev_client expects.

Everything else about Jev is tested against mocks written from the docs and one
live capture. This is the only check that notices TypeSafe changing under us (a
status code, a field, the pinned model id), and a drifted API would otherwise
just make every hook fall back to its static list with nothing saying why.

Needs a real key in the environment, so it self-skips without one and is in the
live tier by its filename, never in the unit gate. It makes three calls and
spends about 270 input tokens (a hundredth of a cent).

  TYPESAFE_AI=<key> ./agentic/run_tests.sh live    (or any runner that passes the variable in)

The key is only ever sent by jev_client; nothing here prints it.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import jev_client  # noqa: E402
from jev_client import JevError  # noqa: E402

KEY = os.environ.get("TYPESAFE_AI", "").strip()

pytestmark = pytest.mark.skipif(
    not KEY, reason="TYPESAFE_AI is not set: no live TypeSafe key to test with")

# Well-formed but not a real key, so it reaches TypeSafe and is rejected there
# (a malformed key would be refused locally and prove nothing about the API).
BAD_KEY = "apikey_" + "0" * 36 + "_" + "f" * 64


async def test_models_listing_answers_200_and_names_the_model_family():
    models = await jev_client.list_models(KEY)
    assert isinstance(models, list) and models
    assert "jev-latest" in models


async def test_a_noul_ping_on_the_pinned_model_returns_a_valid_answer():
    question = {"ping": {"type": "noul", "instructions": "Is this a ping?"}}
    result = await jev_client.system_one(KEY, jev_client.JEV_MODEL, "ping", question)
    assert result["model"] == jev_client.JEV_MODEL
    noul = result["answers"]["ping"]["noul"]
    assert 0.0 <= noul <= 1.0


async def test_a_rejected_key_is_jev_auth():
    with pytest.raises(JevError) as err:
        await jev_client.list_models(BAD_KEY)
    assert err.value.error_type == "jev_auth"
