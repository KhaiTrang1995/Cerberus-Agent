"""A failed `docker pull` must not drop a tool whose image is already on the host.

Found in an end-to-end scan: the host's DNS dropped for a moment while recon set
up its tools, every `docker pull` failed, and Katana and Hakrawler were skipped
("Image/setup unavailable") although both images were sitting in the local store.
The scan then ran with no crawler at all. Naabu and httpx already checked the
local store first; these helpers did not.

The pull is still attempted first, so a moving tag such as :latest stays current
whenever the registry is reachable.
"""
from __future__ import annotations

from unittest import mock

import pytest

from recon.helpers import docker_helpers as dh
from recon.helpers.resource_enum import (gau_helpers, hakrawler_helpers, katana_helpers,
                                         zap_ajax_spider_helpers)

IMAGE = "example/tool:latest"


def _proc(returncode=0, stdout="", stderr=""):
    return mock.Mock(returncode=returncode, stdout=stdout, stderr=stderr)


def _docker(pull: mock.Mock, local_ids: str = ""):
    """A fake `subprocess.run`: `pull` answers `docker pull`, the store holds `local_ids`."""
    def run(cmd, **_kw):
        if cmd[:2] == ["docker", "pull"]:
            return pull(cmd)
        if cmd[:2] == ["docker", "images"]:
            return _proc(stdout=local_ids)
        raise AssertionError(f"unexpected command {cmd}")
    return run


DNS_DOWN = _proc(1, stderr="Error response from daemon: dial tcp: lookup registry-1.docker.io: Temporary failure in name resolution\n")


def test_a_successful_pull_is_enough():
    pull = mock.Mock(return_value=_proc(0))
    with mock.patch.object(dh.subprocess, "run", side_effect=_docker(pull)):
        assert dh.pull_image_or_use_local(IMAGE, "Tool") is True
    pull.assert_called_once()


def test_a_failed_pull_uses_the_image_already_on_the_host(capsys):
    with mock.patch.object(dh.subprocess, "run", side_effect=_docker(mock.Mock(return_value=DNS_DOWN), "sha256:abc\n")):
        assert dh.pull_image_or_use_local(IMAGE, "Tool") is True
    out = capsys.readouterr().out
    assert "[!][Tool] Pull failed" in out and "name resolution" in out and "already on this host" in out


def test_a_failed_pull_with_no_local_copy_is_unavailable():
    with mock.patch.object(dh.subprocess, "run", side_effect=_docker(mock.Mock(return_value=DNS_DOWN), "")):
        assert dh.pull_image_or_use_local(IMAGE, "Tool") is False


def test_a_pull_that_raises_or_times_out_also_falls_back_to_the_local_copy():
    def run(cmd, **_kw):
        if cmd[:2] == ["docker", "pull"]:
            raise dh.subprocess.TimeoutExpired(cmd, 300)
        return _proc(stdout="sha256:abc\n")
    with mock.patch.object(dh.subprocess, "run", side_effect=run):
        assert dh.pull_image_or_use_local(IMAGE, "Tool") is True


def test_the_helper_never_raises_even_when_the_store_check_fails():
    def run(cmd, **_kw):
        raise OSError("docker is gone")
    with mock.patch.object(dh.subprocess, "run", side_effect=run):
        assert dh.pull_image_or_use_local(IMAGE, "Tool") is False


def test_the_platform_flag_reaches_the_pull():
    pull = mock.Mock(return_value=_proc(0))
    with mock.patch.object(dh.subprocess, "run", side_effect=_docker(pull)):
        dh.pull_image_or_use_local(IMAGE, "GAU", platform="linux/amd64")
    assert pull.call_args.args[0] == ["docker", "pull", "--platform", "linux/amd64", IMAGE]


# Every caller, not just the helper: each one used to carry its own copy of the
# bare pull, so fixing the helper alone would leave the others behind.
CALLERS = [
    ("katana", katana_helpers.pull_katana_docker_image),
    ("hakrawler", hakrawler_helpers.pull_hakrawler_docker_image),
    ("gau", gau_helpers.pull_gau_docker_image),
    ("zap", zap_ajax_spider_helpers.pull_zap_ajax_docker_image),
    ("nuclei", dh.pull_nuclei_docker_image),
    ("docker-katana", dh.pull_katana_docker_image),
]


@pytest.mark.parametrize("name,fn", CALLERS, ids=[c[0] for c in CALLERS])
def test_every_pull_helper_survives_a_pull_failure_when_the_image_is_local(name, fn):
    with mock.patch.object(dh.subprocess, "run", side_effect=_docker(mock.Mock(return_value=DNS_DOWN), "sha256:abc\n")):
        assert fn(IMAGE) is True


@pytest.mark.parametrize("name,fn", CALLERS, ids=[c[0] for c in CALLERS])
def test_every_pull_helper_still_reports_a_missing_image(name, fn):
    with mock.patch.object(dh.subprocess, "run", side_effect=_docker(mock.Mock(return_value=DNS_DOWN), "")):
        assert fn(IMAGE) is False


def test_the_pull_helpers_no_longer_carry_their_own_bare_pull():
    """Guard against the pattern coming back: only the shared helper runs `docker pull`."""
    import inspect
    for _, fn in CALLERS:
        assert '"docker", "pull"' not in inspect.getsource(fn), fn.__name__
