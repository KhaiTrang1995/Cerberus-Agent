"""Partial-recon STATUS_DEGRADED plumbing (partial_recon_modules/helpers.py, §7.4).

A root that ran but had some coverage cut (a breaker opened, every OSINT provider
was refused) is 'degraded': it still counts as a root that ran (exit 0) and is
listed with its reason. The OSINT `_one_root` functions return STATUS_OK
regardless, so `_run_one_root` reads the coverage accumulator to detect it.
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from recon.helpers import circuit_breaker as cb
from recon.partial_recon_modules import helpers as h
from recon.partial_recon_modules.helpers import (
    STATUS_DEGRADED,
    STATUS_OK,
    STATUS_NO_RESULTS,
    run_exit_code,
    run_per_root,
)


def test_a_degraded_root_still_means_something_ran():
    assert run_exit_code({"a.test": STATUS_DEGRADED}) == 0
    assert run_exit_code({"a.test": STATUS_DEGRADED, "b.test": "failed: X"}) == 0


def test_only_failures_mean_nothing_ran():
    assert run_exit_code({"a.test": "failed: X"}) == 1


def test_a_root_that_records_a_coverage_gap_is_degraded():
    cb.reset_registry()

    def fn(root):
        # An OSINT-style root that "succeeds" but records a provider skip.
        cb.note_degraded("osint", sources=["shodan"], reason="key refused")
        return STATUS_OK

    got = run_per_root(["a.test"], fn, "OSINT")
    assert got == {"a.test": STATUS_DEGRADED}
    assert run_exit_code(got) == 0


def test_a_clean_root_stays_ok():
    cb.reset_registry()
    got = run_per_root(["a.test"], lambda root: STATUS_OK, "OSINT")
    assert got == {"a.test": STATUS_OK}


def test_an_explicit_no_results_is_preserved_over_degraded():
    cb.reset_registry()
    got = run_per_root(["a.test"], lambda root: STATUS_NO_RESULTS, "OSINT")
    assert got == {"a.test": STATUS_NO_RESULTS}
