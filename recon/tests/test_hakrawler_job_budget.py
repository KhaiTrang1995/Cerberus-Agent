"""
REGRESSION: the full pipeline waited on Hakrawler with a PER-URL timeout.

resource_enum waited `HAKRAWLER_TIMEOUT * 2 + 120` seconds (180 by default) for
the whole crawler, which works through every seed a few at a time. On a
3000-seed target the wait expired after three minutes and raised a
TimeoutError whose message is empty, so the log read a bare
"[!][ResourceEnum] hakrawler failed: ". The URLs were then discarded, while the
`with ThreadPoolExecutor` block still blocked in shutdown until the crawl
finished hours later: all of the time, none of the output.

These tests pin the three halves of the fix:
  - the budget is sized from the seeds and the parallelism,
  - the per-URL bound it multiplies is enforced even when hakrawler goes silent,
  - run_resource_enum waits that long, and says what is missing when it cannot.

No Docker, no network: every external call is mocked.
"""

import concurrent.futures as cf
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from unittest import mock

PROJECT_ROOT = Path(__file__).parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from recon.helpers.resource_enum.hakrawler_helpers import (  # noqa: E402
    hakrawler_job_budget,
    per_url_budget,
    run_hakrawler_crawler,
)
import recon.main_recon_modules.resource_enum as resource_enum  # noqa: E402

SEEDS = [f"https://h{i}.example.test" for i in range(3166)]


# ===========================================================================
# The budget
# ===========================================================================

def test_per_url_budget_is_the_bound_the_crawler_enforces():
    assert per_url_budget(30) == 120


def test_budget_covers_every_seed_in_rounds_of_parallelism():
    # 3166 seeds, 5 at a time = 634 rounds of at most 120s each.
    assert hakrawler_job_budget(SEEDS, 30, 5) == 634 * 120


def test_budget_for_a_large_run_is_far_above_the_old_per_url_wait():
    old_wait = 30 * 2 + 120
    assert hakrawler_job_budget(SEEDS, 30, 5) > 100 * old_wait


def test_fewer_seeds_than_workers_is_one_round():
    assert hakrawler_job_budget(SEEDS[:3], 30, 5) == per_url_budget(30)


def test_no_crawlable_seed_means_no_budget():
    assert hakrawler_job_budget([], 30, 5) == 0
    assert hakrawler_job_budget(["ftp://h.example.test", "h.example.test"], 30, 5) == 0


def test_only_http_seeds_count():
    seeds = ["ftp://a.example.test", "https://b.example.test", "http://c.example.test"]
    assert hakrawler_job_budget(seeds, 30, 1) == 2 * per_url_budget(30)


def test_a_non_positive_parallelism_does_not_divide_by_zero():
    assert hakrawler_job_budget(SEEDS[:4], 30, 0) == 4 * per_url_budget(30)
    assert hakrawler_job_budget(SEEDS[:4], 30, -3) == 4 * per_url_budget(30)


def test_budget_counts_exactly_the_seeds_the_crawler_runs():
    """The budget and the runner filter seeds through the same function.

    If they drifted, a seed the runner crawls but the budget does not count
    would reopen the gap this file exists for.
    """
    seeds = ["https://a.example.test", "ftp://b.example.test", "http://c.example.test", "d.example.test"]
    launched = []

    def fake_popen(cmd, **kwargs):
        proc = mock.MagicMock()
        proc.stdin.write.side_effect = lambda line: launched.append(line.strip())
        proc.stdout.readline.return_value = ""
        proc.poll.return_value = 0
        return proc

    with mock.patch("subprocess.Popen", side_effect=fake_popen):
        run_hakrawler_crawler(
            target_urls=seeds, docker_image="jauderho/hakrawler:latest", depth=2,
            threads=5, timeout=30, max_urls=500, include_subs=False, insecure=True,
            allowed_hosts={"a.example.test", "c.example.test"}, custom_headers=[],
            exclude_patterns=[], parallelism=1,
        )

    assert sorted(launched) == ["http://c.example.test", "https://a.example.test"]
    assert hakrawler_job_budget(seeds, 30, 1) == len(launched) * per_url_budget(30)


# ===========================================================================
# The per-URL bound holds when hakrawler is silent
# ===========================================================================

def _silent_process(killed: threading.Event):
    """A hakrawler that never writes a line: readline() blocks until killed."""
    proc = mock.MagicMock()

    def readline():
        killed.wait(timeout=10)
        return ""

    proc.stdout.readline.side_effect = readline
    proc.poll.side_effect = lambda: 0 if killed.is_set() else None
    proc.kill.side_effect = killed.set
    return proc


def test_a_silent_hakrawler_is_killed_at_the_per_url_budget(capsys):
    """The old bound was a check inside the read loop, so a silent process
    blocked readline() forever and the check never ran.
    """
    killed = threading.Event()
    done = threading.Event()

    def crawl():
        run_hakrawler_crawler(
            target_urls=["https://slow.example.test"], docker_image="jauderho/hakrawler:latest",
            depth=2, threads=5, timeout=30, max_urls=500, include_subs=False, insecure=True,
            allowed_hosts={"slow.example.test"}, custom_headers=[], exclude_patterns=[],
            parallelism=1,
        )
        done.set()

    with mock.patch("subprocess.Popen", return_value=_silent_process(killed)), \
         mock.patch("recon.helpers.resource_enum.hakrawler_helpers.per_url_budget", return_value=0.2):
        worker = threading.Thread(target=crawl, daemon=True)
        started = time.time()
        worker.start()
        try:
            finished = done.wait(timeout=5)
        finally:
            killed.set()  # never leave the fake blocking, whatever happened
            worker.join(timeout=5)

    assert finished, "the crawler was not stopped at its per-URL budget"
    assert time.time() - started < 5
    assert "[!][Hakrawler] Overall timeout for https://slow.example.test" in capsys.readouterr().out


def test_a_fast_hakrawler_is_not_killed_by_the_watchdog(capsys):
    proc = mock.MagicMock()
    proc.stdout.readline.side_effect = ["https://fast.example.test/a\n", ""]
    proc.poll.return_value = 0

    with mock.patch("subprocess.Popen", return_value=proc), \
         mock.patch("recon.helpers.resource_enum.hakrawler_helpers.per_url_budget", return_value=0.2):
        urls, _ = run_hakrawler_crawler(
            target_urls=["https://fast.example.test"], docker_image="jauderho/hakrawler:latest",
            depth=2, threads=5, timeout=30, max_urls=500, include_subs=False, insecure=True,
            allowed_hosts={"fast.example.test"}, custom_headers=[], exclude_patterns=[],
            parallelism=1,
        )
        time.sleep(0.4)  # past the budget: a watchdog left running would fire now

    assert urls == ["https://fast.example.test/a"]
    proc.kill.assert_not_called()
    assert "Overall timeout" not in capsys.readouterr().out


# ===========================================================================
# run_resource_enum waits for the whole crawl
# ===========================================================================

SETTINGS = {
    "KATANA_ENABLED": False,
    "HAKRAWLER_ENABLED": True,
    "HAKRAWLER_TIMEOUT": 30,
    "HAKRAWLER_PARALLELISM": 5,
    "GAU_ENABLED": False,
    "PARAMSPIDER_ENABLED": False,
    "KITERUNNER_ENABLED": False,
    "JSLUICE_ENABLED": False,
    "FFUF_ENABLED": False,
    "ARJUN_ENABLED": False,
    "ZAP_AJAX_SPIDER_ENABLED": False,
    "RESOURCE_ENUM_AI_CLASSIFIER_ENABLED": False,
}

FOUND = "https://h1.example.test/login"


def fake_hakrawler(*args, **kwargs):
    return [FOUND], {"external_domains": []}


def _recording_executor(waits: dict, time_out: bool = False):
    """A real executor whose futures record the wait the caller applies.

    With `time_out`, the crawler's wait raises exactly what an expired
    Future.result() raises, without the test having to wait for it.
    """
    class Recording(ThreadPoolExecutor):
        def submit(self, fn, *args, **kwargs):
            future = super().submit(fn, *args, **kwargs)
            real_result = future.result

            def result(timeout=None):
                waits[fn] = timeout
                if time_out and fn is fake_hakrawler:
                    real_result()  # let the worker finish before "timing out"
                    raise cf.TimeoutError()
                return real_result(timeout)

            future.result = result
            return future

    return Recording


def _run(waits: dict, time_out: bool = False) -> dict:
    hosts = {s.split("//", 1)[1] for s in SEEDS}
    with mock.patch.object(resource_enum, "ThreadPoolExecutor", _recording_executor(waits, time_out)), \
         mock.patch.object(resource_enum, "run_hakrawler_crawler", fake_hakrawler), \
         mock.patch.object(resource_enum, "pull_hakrawler_docker_image"), \
         mock.patch.object(resource_enum, "is_docker_installed", return_value=True), \
         mock.patch.object(resource_enum, "is_docker_running", return_value=True), \
         mock.patch.object(resource_enum, "extract_targets_from_recon", return_value=(set(), hosts, {})), \
         mock.patch.object(resource_enum, "build_target_urls", return_value=list(SEEDS)):
        return resource_enum.run_resource_enum({"domain": "example.test"}, settings=dict(SETTINGS))


def test_the_wait_on_hakrawler_is_sized_from_every_seed():
    waits = {}
    _run(waits)
    assert fake_hakrawler in waits, "run_resource_enum never waited on the crawler"
    assert waits[fake_hakrawler] >= hakrawler_job_budget(SEEDS, 30, 5)
    assert waits[fake_hakrawler] > 30 * 2 + 120


def test_the_crawled_urls_reach_the_result():
    recon_data = _run({})
    meta = recon_data["resource_enum"]["scan_metadata"]
    assert meta["hakrawler_urls_found"] == 1


def test_a_timed_out_wait_names_the_error_and_the_gap(capsys):
    recon_data = _run({}, time_out=True)
    out = capsys.readouterr().out
    line = next(l for l in out.splitlines() if "[!][ResourceEnum] hakrawler failed" in l)
    assert "TimeoutError" in line
    assert "WITHOUT its URLs" in line
    assert "hakrawler failed: \n" not in out + "\n"
    # The scan carries on; it just has nothing from the crawler.
    assert recon_data["resource_enum"]["scan_metadata"]["hakrawler_urls_found"] == 0
