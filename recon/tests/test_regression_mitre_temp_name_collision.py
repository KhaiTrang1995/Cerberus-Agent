"""Regression: MITRE downloads from two scan containers shared one temp file.

_atomic_write_bytes named its temp `.{name}.{pid}.tmp`. pid is 1 in every scan
container and mitre_db lives in the bind-mounted recon/ checkout, so two
concurrent scans wrote the SAME temp file: one could install the other's
half-written copy, and the other's os.replace then failed on a temp that was
already gone. The temp name is now unique per write.

Everything runs in pytest's tmp_path; the tracked data files are never touched.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path
from unittest.mock import patch

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from recon.main_recon_modules import add_mitre  # noqa: E402

FIRST, SECOND = b"A" * 4096, b"B" * 4096


def _two_containers_interleaved(dest: Path):
    """Container 1 writes its temp; container 2's whole write lands before
    container 1's os.replace. Both run as pid 1."""
    real_replace = os.replace
    calls = []

    def replace(src, dst):
        calls.append(Path(src).name)
        if len(calls) == 1:
            add_mitre._atomic_write_bytes(dest, SECOND)
        return real_replace(src, dst)

    with patch.object(add_mitre.os, "getpid", return_value=1), \
         patch.object(add_mitre.os, "replace", side_effect=replace):
        add_mitre._atomic_write_bytes(dest, FIRST)
    return calls


def test_regression_mitre_temp_name_collision(tmp_path):
    dest = tmp_path / "CVE-2024.jsonl"
    dest.write_bytes(b"old")

    temp_names = _two_containers_interleaved(dest)

    assert len(temp_names) == 2 and temp_names[0] != temp_names[1]
    # The last os.replace wins, and it installs a complete copy.
    assert dest.read_bytes() == FIRST
    assert sorted(p.name for p in tmp_path.iterdir()) == ["CVE-2024.jsonl"]


def test_temp_file_stays_a_hidden_sibling_and_mode_is_kept(tmp_path):
    dest = tmp_path / "cwe_db.json"
    dest.write_bytes(b"{}")
    os.chmod(dest, 0o640)
    seen = []
    real_replace = os.replace

    def replace(src, dst):
        seen.append(Path(src))
        return real_replace(src, dst)

    with patch.object(add_mitre.os, "replace", side_effect=replace):
        add_mitre._atomic_write_bytes(dest, b'{"x": 1}')
    [tmp] = seen
    assert tmp.parent == dest.parent
    assert tmp.name.startswith(".cwe_db.json.") and tmp.name.endswith(".tmp")
    assert dest.read_bytes() == b'{"x": 1}'
    assert dest.stat().st_mode & 0o7777 == 0o640
