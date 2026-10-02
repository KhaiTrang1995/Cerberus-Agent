"""MITRE CVE year files: fetched when missing, refreshed when stale, written atomically.

update_database only fetched a CVE-<year>.jsonl that did not exist, and returned
early whenever the TTL marker was fresh. The marker covers resources and
CWE/CAPEC metadata only, so:
  - a year a run's CVEs needed but the DB never had stayed missing for the TTL;
  - the current year's file, which upstream appends to daily, was never
    refreshed, so recent CVEs silently got no CWE/CAPEC.

Every test points MITRE_DATABASE_PATH at a tmp dir and mocks requests.get; the
real downloader never runs and the tracked data files are never touched.
"""

from __future__ import annotations

import os
import sys
import time
from datetime import datetime, timedelta
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from recon.main_recon_modules import add_mitre  # noqa: E402

YEAR = datetime.now().year
OLD = YEAR - 3
TTL_H = 24


def _settings(tmp_path):
    return {"MITRE_DATABASE_PATH": str(tmp_path / "mitre_db"), "MITRE_CACHE_TTL_HOURS": TTL_H}


def _db(tmp_path, *, marker_age_h, years=(), year_age_h=0):
    db = tmp_path / "mitre_db"
    (db / "database").mkdir(parents=True)
    (db / "resources").mkdir(parents=True)
    for res in add_mitre.RESOURCE_FILES:
        (db / res).write_text("{}")
    (db / ".last_update").write_text((datetime.now() - timedelta(hours=marker_age_h)).isoformat())
    for y in years:
        f = db / "database" / f"CVE-{y}.jsonl"
        f.write_text('{"CVE-%d-0001": {"CWE": ["79"]}}\n' % y)
        ts = time.time() - year_age_h * 3600
        os.utime(f, (ts, ts))
    return db


def _ok(content=b'{"CVE-X": {}}\n'):
    resp = MagicMock()
    resp.content = content
    resp.raise_for_status.return_value = None
    return resp


def _update(tmp_path, cve_ids, get=None):
    """Run update_database with the network and the metadata parsers mocked."""
    get = get or MagicMock(return_value=_ok())
    with patch.object(add_mitre.requests, "get", get), \
         patch.object(add_mitre, "download_cwe_metadata", return_value=True) as cwe, \
         patch.object(add_mitre, "download_capec_metadata", return_value=True) as capec:
        ok = add_mitre.update_database(cve_ids, settings=_settings(tmp_path))
    return ok, [c.args[0] for c in get.call_args_list], cwe, capec


def _year_urls(urls):
    """The year files requested, once each: a year is tried as the upstream
    .jsonl.gz, then the plain .jsonl, and both name the same CVE-<year>.jsonl."""
    return sorted({u.rsplit("/", 1)[-1].removesuffix(".gz") for u in urls if "/database/" in u})


# --------------------------------------------------------------------------- #
# Normal path: within TTL, every needed year present -> no network at all
# --------------------------------------------------------------------------- #
def test_fresh_db_with_all_needed_years_makes_no_network_call(tmp_path):
    _db(tmp_path, marker_age_h=1, years=(OLD, YEAR), year_age_h=500)
    ok, urls, cwe, capec = _update(tmp_path, [f"CVE-{OLD}-1234", f"CVE-{YEAR}-5678"])
    assert ok is True
    assert urls == []
    cwe.assert_not_called()
    capec.assert_not_called()


def test_fresh_db_without_cve_ids_makes_no_network_call(tmp_path):
    _db(tmp_path, marker_age_h=1)          # no year files at all
    ok, urls, _, _ = _update(tmp_path, [])
    assert ok is True and urls == []


# --------------------------------------------------------------------------- #
# (a) a missing needed year is fetched even within the TTL
# --------------------------------------------------------------------------- #
def test_fresh_db_fetches_a_missing_needed_year(tmp_path):
    db = _db(tmp_path, marker_age_h=1, years=(OLD,))
    ok, urls, cwe, _ = _update(tmp_path, [f"CVE-{OLD}-1234", f"CVE-{YEAR}-5678"])
    assert ok is True
    assert _year_urls(urls) == [f"CVE-{YEAR}.jsonl"]      # only the missing one
    assert all("/database/" in u for u in urls)            # no resource refresh
    cwe.assert_not_called()
    assert (db / "database" / f"CVE-{YEAR}.jsonl").read_bytes() == b'{"CVE-X": {}}\n'


# --------------------------------------------------------------------------- #
# (b) on a TTL refresh, needed years older than the TTL are re-downloaded
# --------------------------------------------------------------------------- #
def test_ttl_refresh_redownloads_stale_needed_years_only(tmp_path):
    db = _db(tmp_path, marker_age_h=TTL_H + 1, years=(OLD, YEAR, YEAR - 1), year_age_h=TTL_H + 5)
    ok, urls, _, _ = _update(tmp_path, [f"CVE-{YEAR}-5678", f"CVE-{OLD}-1"])
    assert ok is True
    # YEAR-1 is stale too, but no CVE needs it: bounded to the needed years.
    assert _year_urls(urls) == sorted([f"CVE-{OLD}.jsonl", f"CVE-{YEAR}.jsonl"])
    assert (db / "database" / f"CVE-{YEAR}.jsonl").read_bytes() == b'{"CVE-X": {}}\n'


def test_ttl_refresh_keeps_year_files_younger_than_the_ttl(tmp_path):
    _db(tmp_path, marker_age_h=TTL_H + 1, years=(YEAR,), year_age_h=1)
    _, urls, _, _ = _update(tmp_path, [f"CVE-{YEAR}-5678"])
    assert _year_urls(urls) == []
    # resources still refresh on the TTL, as before
    assert sum("/resources/" in u for u in urls) == len(add_mitre.RESOURCE_FILES)


def test_ttl_refresh_without_cve_ids_only_fills_missing_years_in_the_window(tmp_path):
    # Nothing is about to be enriched, so stale years are not re-fetched; only
    # the default window's gaps are filled, as before.
    window = list(range(YEAR - 10, YEAR + 1))
    present = [YEAR - 11] + window[:-2]
    _db(tmp_path, marker_age_h=TTL_H + 1, years=present, year_age_h=TTL_H + 5)
    _, urls, _, _ = _update(tmp_path, [])
    assert _year_urls(urls) == sorted(f"CVE-{y}.jsonl" for y in window[-2:])


def test_malformed_cve_ids_never_raise(tmp_path):
    _db(tmp_path, marker_age_h=1, years=(YEAR,))
    ok, urls, _, _ = _update(tmp_path, [None, "", "garbage", 42, f"CVE-{YEAR}-1"])
    assert ok is True and urls == []


# --------------------------------------------------------------------------- #
# Atomic writes: a failed download never leaves a truncated file
# --------------------------------------------------------------------------- #
def test_http_error_leaves_the_existing_year_file_intact(tmp_path):
    db = _db(tmp_path, marker_age_h=TTL_H + 1, years=(YEAR,), year_age_h=TTL_H + 5)
    target = db / "database" / f"CVE-{YEAR}.jsonl"
    before = target.read_bytes()
    bad = MagicMock()
    bad.raise_for_status.side_effect = RuntimeError("503")
    get = MagicMock(side_effect=lambda url, **kw: bad if "/database/" in url else _ok())
    _, urls, _, _ = _update(tmp_path, [f"CVE-{YEAR}-1"], get=get)
    assert _year_urls(urls) == [f"CVE-{YEAR}.jsonl"]          # it was attempted
    assert target.read_bytes() == before


def test_a_write_that_dies_midway_does_not_truncate_the_year_file(tmp_path):
    db = _db(tmp_path, marker_age_h=TTL_H + 1, years=(YEAR,), year_age_h=TTL_H + 5)
    target = db / "database" / f"CVE-{YEAR}.jsonl"
    before = target.read_bytes()
    real_write = Path.write_bytes

    def dies_midway(self, data):
        if "CVE-" not in self.name:          # resources write normally
            return real_write(self, data)
        real_write(self, data[: len(data) // 2])
        raise OSError("No space left on device")

    payload = (b'{"CVE-%d-9999": {"CWE": ["89"]}}\n' % YEAR) * 50
    with patch.object(Path, "write_bytes", dies_midway):
        _, urls, _, _ = _update(tmp_path, [f"CVE-{YEAR}-1"],
                                get=MagicMock(return_value=_ok(payload)))
    assert _year_urls(urls) == [f"CVE-{YEAR}.jsonl"]          # it was attempted
    assert target.read_bytes() == before
    assert [p.name for p in (db / "database").iterdir()] == [target.name]   # no temp left


def test_download_file_that_dies_midway_keeps_the_previous_file(tmp_path):
    dest = tmp_path / "CVE-2020.jsonl"
    dest.write_bytes(b"complete previous copy\n")
    real_write = Path.write_bytes

    def dies_midway(self, data):
        real_write(self, data[: len(data) // 2])
        raise OSError("No space left on device")

    with patch.object(add_mitre.requests, "get", MagicMock(return_value=_ok(b"x" * 1000))), \
         patch.object(Path, "write_bytes", dies_midway):
        assert add_mitre.download_file("https://example.test/CVE-2020.jsonl", dest) is False
    assert dest.read_bytes() == b"complete previous copy\n"
    assert [p.name for p in tmp_path.iterdir()] == [dest.name]


def test_atomic_write_replaces_content_and_keeps_mode(tmp_path):
    dest = tmp_path / "f.jsonl"
    dest.write_bytes(b"old")
    os.chmod(dest, 0o640)
    add_mitre._atomic_write_bytes(dest, b"new")
    assert dest.read_bytes() == b"new"
    assert (dest.stat().st_mode & 0o777) == 0o640
    assert [p.name for p in tmp_path.iterdir()] == ["f.jsonl"]


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-v"]))
