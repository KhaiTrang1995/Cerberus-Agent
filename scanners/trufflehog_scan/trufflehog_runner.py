"""TruffleHog runner — builds commands from the source registry and parses JSONL.

One runner instance is one *run*: one project, one source, one output file. Two
sources scanning the same project at the same time are two containers, two
runners and two output files; nothing here is shared between them.

The runner never writes to Neo4j. It is the dirty half of the dirty/clean split
(12.3): it parses attacker-controlled bytes with one credential and no other
secret in reach, and hands the orchestrator a JSON file. Graph ingest is a
separate, clean step.
"""

from __future__ import annotations

import json
import os
import subprocess
import tempfile
import time
import urllib.error
import urllib.request
from datetime import datetime
from pathlib import Path
from typing import Optional

try:  # container path
    from trufflehog_scan import findings as fnd
    from trufflehog_scan import sources as reg
    from trufflehog_scan.job_config import JobConfig
except ImportError:  # standalone / test path
    import findings as fnd
    import sources as reg
    from job_config import JobConfig

#: Docker Hub tag listing, used only when "Scan all tags" is on. 100 per page is
#: the API's max; the runner stops at `maxImages` regardless.
_DOCKERHUB_TAGS_URL = "https://hub.docker.com/v2/repositories/{name}/tags?page_size=100"
_DEFAULT_MAX_IMAGES = 25


class TrufflehogRunner:
    """Runs the TruffleHog binary for one source and collects findings."""

    def __init__(self, job: JobConfig, binary: str = "trufflehog", env: Optional[dict] = None):
        self.job = job
        self.binary = binary
        self.env = os.environ if env is None else env
        self.source = reg.get_source(job.source)

        self.output_file = job.output_file
        self.output_dir = Path(self.output_file).parent
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.run_dir = Path(job.run_dir)

        self.target = reg.describe_target(self.source.id, job.config)

        self.stats = {
            "total_findings": 0,
            "verified_findings": 0,
            "unverified_findings": 0,
            "assets_scanned": 0,
            # Kept alongside assets_scanned for one release so existing report
            # queries that read repositories_scanned keep working (6.3).
            "repositories_scanned": 0,
            "validated": 0,
            "unvalidated": 0,
            "verify_error": 0,
            "unverified": 0,
            "detector_types": {},
            "unknown_metadata_keys": [],
        }

        self.findings: list[dict] = []
        self._seen_assets: set[str] = set()
        self._seen_dedup: set[str] = set()
        self._start_time = ""
        self._start_epoch = time.time()
        self._exit_codes: list[int] = []
        # TruffleHog reports a failed scan as a JSON record on STDOUT, in the
        # same stream as the findings. Parsed and dropped, it left an errored run
        # with no reason attached — and the container is auto-removed, so the log
        # is gone too. Kept here and published on the artifact.
        self._scan_errors: list[str] = []

    # -- command construction -------------------------------------------------

    def _log(self, message: str) -> None:
        """Every line the container prints goes through redaction.

        The credential is in env and can reach a log line through a composed
        clone URL where no ``--token=`` prefix precedes it, so redaction is
        value-based, not flag-based.
        """
        print(reg.redact(message, self.env), flush=True)

    def build_commands(self) -> list[list[str]]:
        """One argv per TruffleHog invocation.

        Normally a single command. Docker is the exception: "Scan all tags" and
        "Scan all architectures" are *our* expansion, not a TruffleHog flag —
        ``remote.Image()`` resolves one platform per reference — so each resolved
        digest becomes its own invocation.
        """
        cfg = dict(self.job.config or {})
        if self.source.id == "docker":
            expanded = self._expand_docker_images(cfg)
            if expanded is not None:
                cfg["images"] = expanded
        return [reg.build_command(
            self.source.id, cfg, self.job.common, self.run_dir,
            env=self.env, binary=self.binary,
        )]

    def _max_images(self) -> int:
        raw = (self.job.config or {}).get("maxImages")
        try:
            value = int(raw)
        except (TypeError, ValueError):
            return _DEFAULT_MAX_IMAGES
        return value if value > 0 else _DEFAULT_MAX_IMAGES

    def _expand_docker_images(self, cfg: dict) -> Optional[list[str]]:
        """Expand each image reference to per-tag / per-architecture digests.

        Every expansion multiplies the pull count directly, and Docker Hub allows
        only 10 anonymous pulls per hour per IP, so this is off by default and
        hard-capped by ``maxImages``. Fail-soft: a listing error leaves the
        original reference in place rather than aborting the scan.
        """
        scan_all_tags = str(cfg.get("scanAllTags") or "").lower() in ("1", "true", "yes", "on") or cfg.get("scanAllTags") is True
        scan_all_arch = str(cfg.get("scanAllArchitectures") or "").lower() in ("1", "true", "yes", "on") or cfg.get("scanAllArchitectures") is True
        if not (scan_all_tags or scan_all_arch):
            return None

        images = reg.as_list(cfg.get("images"))
        if not images:
            return None

        cap = self._max_images()
        out: list[str] = []
        for ref in images:
            if len(out) >= cap:
                break
            name = ref.split("@")[0].split(":")[0]
            digests = self._list_dockerhub_digests(name, scan_all_arch)
            if not digests:
                out.append(ref)
                continue
            for d in digests:
                if len(out) >= cap:
                    break
                out.append(f"{name}@{d}")

        if len(out) >= cap:
            self._log(f"[!] Image expansion capped at {cap} references (Max images)")
        return out

    def _list_dockerhub_digests(self, name: str, all_architectures: bool) -> list[str]:
        """Manifest digests for a Docker Hub repository, one page (100 tags)."""
        repo = name if "/" in name else f"library/{name}"
        if repo.count("/") > 1 or "." in repo.split("/")[0]:
            # Not Docker Hub (ghcr.io/..., registry.example.com/...); no listing API.
            return []
        url = _DOCKERHUB_TAGS_URL.format(name=repo)
        try:
            request = urllib.request.Request(url, headers={"Accept": "application/json"})
            token = (self.env.get(reg.CRED_DOCKER.env) or "").strip()
            if token:
                request.add_header("Authorization", f"Bearer {token}")
            with urllib.request.urlopen(request, timeout=30) as response:
                payload = json.loads(response.read().decode())
        except (urllib.error.URLError, OSError, ValueError, json.JSONDecodeError) as exc:
            self._log(f"[~] Could not list tags for {repo}: {exc}")
            return []

        digests: list[str] = []
        for result in payload.get("results", []):
            if all_architectures:
                for image in result.get("images") or []:
                    d = image.get("digest")
                    if d and d not in digests:
                        digests.append(d)
            d = result.get("digest")
            if d and d not in digests:
                digests.append(d)
        return digests

    # -- parsing --------------------------------------------------------------

    def _on_unknown_meta(self, key: str) -> None:
        if key not in self.stats["unknown_metadata_keys"]:
            self.stats["unknown_metadata_keys"].append(key)
            self._log(
                f"[!] Unrecognised TruffleHog metadata key '{key}' — findings are kept "
                f"with asset='unknown:{key}'. The source registry needs an entry for it."
            )

    def _parse_finding(self, result: dict) -> Optional[dict]:
        try:
            finding = fnd.normalise(
                result,
                self.source.id,
                verification_enabled=self.job.verification_enabled,
                on_unknown=self._on_unknown_meta,
                default_asset=self.target,
            )
        except Exception as exc:
            self._log(f"[!] Error parsing finding: {exc}")
            return None

        if not finding["detector_name"]:
            return None

        key = fnd.dedup_key(
            self.source.id, finding["asset"], finding["location"],
            finding["line"], finding["detector_name"],
        )
        if key in self._seen_dedup:
            return None
        self._seen_dedup.add(key)

        self.stats["total_findings"] += 1
        status = finding["validation_status"]
        self.stats[status] = self.stats.get(status, 0) + 1
        if finding["verified"]:
            self.stats["verified_findings"] += 1
        else:
            self.stats["unverified_findings"] += 1

        detector = finding["detector_name"]
        self.stats["detector_types"][detector] = self.stats["detector_types"].get(detector, 0) + 1

        asset = finding["asset"]
        if asset and asset not in self._seen_assets:
            self._seen_assets.add(asset)
            self.stats["assets_scanned"] = len(self._seen_assets)
            self.stats["repositories_scanned"] = len(self._seen_assets)

        return finding

    # -- execution ------------------------------------------------------------

    def _run_command(self, cmd: list[str]) -> None:
        self._log(f"[*] Running: {reg.safe_command(cmd, self.env)}")

        try:
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1,
                cwd=str(self.run_dir) if self.run_dir.exists() else None,
            )
        except FileNotFoundError:
            self._log(f"[!] ERROR: {self.binary} binary not found")
            raise

        for line in process.stdout:
            line = line.strip()
            if not line:
                continue
            try:
                result = json.loads(line)
            except json.JSONDecodeError:
                self._log(f"[~] {line}")
                continue
            if not isinstance(result, dict):
                continue
            if result.get("level") == "error":
                self._record_scan_error(result)
                continue
            finding = self._parse_finding(result)
            if finding:
                self.findings.append(finding)
                self._log(
                    f"[+] Found: {finding['detector_name']} [{finding['validation_status']}] "
                    f"in {finding['location'] or '(no location)'} ({finding['asset']})"
                )
                self._save_incremental()

        process.wait()
        self._exit_codes.append(process.returncode)

        stderr_output = process.stderr.read()
        if stderr_output:
            for err_line in stderr_output.strip().split("\n"):
                err_line = err_line.strip()
                if not err_line:
                    continue
                # TruffleHog logs structured records here, error ones included.
                # Parsed, they give the operator a sentence; unparsed they give a
                # JSON blob, and dropped they give nothing at all.
                record = None
                if err_line.startswith("{"):
                    try:
                        record = json.loads(err_line)
                    except json.JSONDecodeError:
                        record = None
                if isinstance(record, dict) and record.get("level") == "error":
                    self._record_scan_error(record)
                    continue
                self._log(f"[~] {err_line}")

        if process.returncode != 0:
            self._log(f"[!] TruffleHog exited with code {process.returncode}")
            if not self._scan_errors and stderr_output:
                # Nothing structured anywhere: keep the tail of stderr so the run
                # still says something more useful than "it failed".
                tail = stderr_output.strip().splitlines()[-1][:400]
                self._scan_errors.append(reg.redact(tail, self.env))

    def _record_scan_error(self, record: dict) -> None:
        """Keep a TruffleHog error record, redacted, for the artifact.

        Redaction matters more here than in a finding: the message frequently
        quotes the target, and for git that is a URI the credential was spliced
        into.
        """
        msg = str(record.get("msg") or "").strip()
        err = str(record.get("error") or "").strip()
        text = f"{msg}: {err}" if msg and err else (err or msg)
        if not text:
            return
        text = reg.redact(text, self.env)[:600]
        if text not in self._scan_errors:
            self._scan_errors.append(text)
        self._log(f"[!] {text}")

    def _save_incremental(self) -> None:
        """Atomic temp-file rename, so the orchestrator never reads a half file."""
        try:
            fd, tmp_path = tempfile.mkstemp(dir=str(self.output_dir), suffix=".tmp")
            with os.fdopen(fd, "w") as fh:
                json.dump(self._build_output(), fh, indent=2, default=str)
            os.replace(tmp_path, self.output_file)
            os.chmod(self.output_file, 0o644)
        except Exception as exc:
            self._log(f"[!] Error saving incremental results: {exc}")

    def _build_output(self, status: str = "in_progress",
                      incomplete_reason: Optional[str] = None) -> dict:
        return {
            "source": self.source.id,
            "source_label": self.source.label,
            "asset_label": self.source.asset_label,
            "asset_kind": self.source.asset_kind,
            "run_id": self.job.run_id or self.source.id,
            "target": self.target,
            "verification_enabled": self.job.verification_enabled,
            "scan_start_time": self._start_time,
            "scan_end_time": datetime.now().isoformat(),
            "duration_seconds": round(time.time() - self._start_epoch, 2),
            "status": status,
            # Present ONLY on a failed run, so a consumer can treat its presence
            # as the signal. Gated on the status too: a multi-command source can
            # have one invocation fail and still complete, and emitting `error`
            # there would make a successful scan look failed.
            **({"error": "; ".join(self._scan_errors)}
               if self._scan_errors and status == "error" else {}),
            # Present ONLY on a completed run although part of the target was
            # never scanned (an invocation exited non-zero). The status stays
            # `completed` for the UI and the orchestrator; the graph write reads
            # this to keep the findings of what was skipped instead of clearing
            # and pruning them.
            **({"incomplete": True, "incomplete_reason": incomplete_reason}
               if incomplete_reason and status == "completed" else {}),
            "statistics": dict(self.stats),
            "findings": self.findings,
        }

    def run(self) -> list[dict]:
        self._start_time = datetime.now().isoformat()
        self._start_epoch = time.time()
        self.run_dir.mkdir(parents=True, exist_ok=True)

        errors = reg.validate_config(self.source.id, self.job.config)
        if errors:
            for err in errors:
                self._log(f"[!] {err}")
            self._write_final("error")
            raise ValueError("; ".join(errors))

        commands = self.build_commands()
        self._log(f"[*] Source: {self.source.label} ({self.source.id})")
        self._log(f"[*] Target: {self.target or '(none)'}")
        self._log(f"[*] Verification: {'on' if self.job.verification_enabled else 'OFF (nothing is checked)'}")

        # Write the envelope up front so a container that dies before the first
        # finding still leaves a readable artifact for the ingest step.
        self._save_incremental()

        for i, cmd in enumerate(commands, 1):
            if len(commands) > 1:
                self._log(f"\n[*] Invocation {i}/{len(commands)}")
            self._run_command(cmd)

        # A non-zero exit with zero findings is a failed scan, not a clean one;
        # recording it as `completed` would tell the operator "no secrets here".
        failed = all(code != 0 for code in self._exit_codes) if self._exit_codes else True
        status = "error" if failed and not self.findings else "completed"
        self._write_final(status, self._incomplete_reason() if status == "completed" else None)
        return self.findings

    def _incomplete_reason(self) -> Optional[str]:
        """Why a completed run did not scan all of its target, or None if it did.

        Every invocation runs with --fail-on-scan-errors, so a non-zero exit
        means some of the target was not scanned: one of several Docker images
        failed to pull, one of an org's repositories failed to clone. Findings
        from the rest make the run `completed`, but it cannot say the skipped
        part is clean.
        """
        codes = [code for code in self._exit_codes if code != 0]
        if not codes:
            return None
        if self._scan_errors:
            return "; ".join(self._scan_errors)
        return f"TruffleHog exited with code {', '.join(str(c) for c in codes)}"

    def _write_final(self, status: str, incomplete_reason: Optional[str] = None) -> None:
        output = self._build_output(status, incomplete_reason)
        with open(self.output_file, "w") as fh:
            json.dump(output, fh, indent=2, default=str)
        try:
            os.chmod(self.output_file, 0o644)
        except OSError:
            pass
        self._log(f"\n[+] Results saved to {self.output_file} (status={status})")
        if "incomplete" in output:
            self._log("[!] Part of the target was not scanned; its earlier findings "
                      "are kept, not pruned")

    def save_results(self) -> str:
        return self.output_file
