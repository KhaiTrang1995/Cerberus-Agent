"""The real tools, run by their real helpers against an empty local site, must not be
recorded as failures.

tool_health decides from exit codes and stderr, and a routine line a tool prints on a
healthy run that is not in its list would turn every genuine empty result into a
coverage gap (and, for the crawlers, keep jsluice secrets out of the prune for ever).
Only the real binaries can show what they print, so this runs them.

Integration tier. Needs the recon image (ffuf, arjun) and, for Katana and Hakrawler,
a usable docker daemon reachable from the test with host networking:

    docker run --rm --net=host -v /var/run/docker.sock:/var/run/docker.sock \\
      -v /tmp/redamon:/tmp/redamon -v "$PWD:/repo" -w /repo/recon \\
      -e PYTHONPATH=/repo/recon:/repo --entrypoint python redamon-recon \\
      -m pytest tests/test_tool_health_binaries_integration.py

Each part skips itself when its binary or the daemon is missing.
"""
from __future__ import annotations

import http.server
import shutil
import subprocess
import threading

import pytest

from recon.helpers.resource_enum import tool_health as th

EMPTY_PAGE = b"<!doctype html><html><head><title>Empty</title></head><body>nothing here</body></html>"


class _Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path in ("/", "/index.html"):
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(EMPTY_PAGE)))
            self.end_headers()
            self.wfile.write(EMPTY_PAGE)
        else:
            self.send_response(404)
            self.send_header("Content-Length", "0")
            self.end_headers()

    do_POST = do_GET

    def log_message(self, *a):
        pass


@pytest.fixture(scope="module")
def site():
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{srv.server_address[1]}"
    srv.shutdown()


@pytest.fixture(autouse=True)
def _empty_queue():
    th.drain()
    yield
    th.drain()


def _docker_usable() -> bool:
    if not shutil.which("docker"):
        return False
    try:
        return subprocess.run(["docker", "info"], capture_output=True, timeout=15).returncode == 0
    except Exception:  # noqa: BLE001
        return False


def _recorded_failures(tool: str):
    return [r for r in th.drain() if r.tool == tool]


def test_ffuf_finding_nothing_is_not_a_failure(site, tmp_path):
    if not shutil.which("ffuf"):
        pytest.skip("ffuf binary not available")
    from recon.helpers.resource_enum import ffuf_helpers as ff
    words = tmp_path / "words.txt"
    words.write_text("alpha\nbeta\ngamma\n")
    results, _ = ff._fuzz_single_target(0, f"{site}/FUZZ", str(tmp_path), str(words), 2, 5, 30, 10,
                                        [200], [], "", [], False, 1, False, [], False, {"127.0.0.1"})
    assert results == []
    assert _recorded_failures("ffuf") == []


def test_arjun_finding_no_parameters_is_not_a_failure(site):
    if not shutil.which("arjun"):
        pytest.skip("arjun binary not available")
    from recon.helpers.resource_enum import arjun_helpers as aj
    params, _ = aj._run_arjun_single_method([f"{site}/"], "GET", 2, 5, 120, 250, 50,
                                            False, False, False, [], {"127.0.0.1"})
    assert params == []
    assert _recorded_failures("arjun") == []


def test_hakrawler_on_a_page_with_no_links_is_not_a_failure(site):
    if not _docker_usable():
        pytest.skip("no usable docker daemon for the Hakrawler image")
    from recon.helpers.resource_enum import hakrawler_helpers as hk
    health = {"failed": 0}
    urls, _, _ = hk._crawl_single_url(f"{site}/", "jauderho/hakrawler:latest", 1, 2, 10,
                                      False, True, {"127.0.0.1"}, [], [], set(), threading.Lock(),
                                      100, health)
    assert health["failed"] == 0, _recorded_failures("hakrawler")
    assert _recorded_failures("hakrawler") == []


def test_katana_on_a_page_with_no_links_is_not_a_failure(site):
    if not _docker_usable():
        pytest.skip("no usable docker daemon for the Katana image")
    from recon.helpers.resource_enum import katana_helpers as kt
    _, meta = kt.run_katana_crawler(
        target_urls=[f"{site}/"], docker_image="projectdiscovery/katana:latest", depth=1,
        max_urls=50, rate_limit=10, timeout=20, js_crawl=False, params_only=False,
        allowed_hosts={"127.0.0.1"}, custom_headers=[], exclude_patterns=[])
    assert meta.get("failed") is False
    assert _recorded_failures("katana") == []
