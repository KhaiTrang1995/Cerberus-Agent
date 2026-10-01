#!/usr/bin/env python3
"""I5 — the agent log redaction filter scrubs token shapes; the LLM-provider test
returns a generic error body (no raw SDK string).

Run in the agent image: python3 tests/test_log_redaction.py
"""
import logging
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import logging_config as lc  # noqa: E402

PASS = 0
FAIL = 0


def check(desc, cond):
    global PASS, FAIL
    if cond:
        PASS += 1; print(f"  PASS {desc}")
    else:
        FAIL += 1; print(f"  FAIL {desc}")


def main():
    # test_log_redaction_filter — each token shape is scrubbed.
    cases = {
        "github PAT": "cloning with ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 now",
        "fine-grained": "token github_pat_11ABCDE0123456789_abcdefghijklmnopqrstuvwxyz here",
        "openai": "key sk-abcdefghijklmnopqrstuvwxyz0123 used",
        "bearer header": "Authorization: Bearer supersecrettoken123456",
        "inline url": "clone https://x-access-token:ghp_SECRETTOKEN12345678901234@github.com/o/r",
        "aws akid": "id AKIAIOSFODNN7EXAMPLE seen",
        "typesafe jev": "key apikey_" + "0f" * 18 + "_" + "a1" * 32 + " used",
    }
    for name, text in cases.items():
        red = lc._redact_text(text)
        # the sensitive core must be gone; a redaction marker present.
        check(f"redacts {name}", "[REDACTED]" in red)

    # specific: the exact PAT value must not survive.
    secret = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    check("PAT value removed", secret not in lc._redact_text(f"boom {secret} boom"))
    jev_key = "apikey_" + "0f" * 18 + "_" + "a1" * 32
    check("TypeSafe key value removed", jev_key not in lc._redact_text(f"key={jev_key}, x"))

    # RedactingFilter applied through a real handler record.
    rec = logging.LogRecord("t", logging.INFO, __file__, 1,
                            "argfmt %s", ("Bearer leakedtoken1234567890",), None)
    lc._REDACTING_FILTER.filter(rec)
    check("filter scrubs args", "[REDACTED]" in (rec.args[0] if rec.args else ""))

    # normal (non-secret) message is unchanged.
    check("normal message untouched", lc._redact_text("scan of example.com complete") == "scan of example.com complete")

    # test_llm_provider_test_generic_error — the endpoint returns a generic body.
    api_src = open(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "api.py")).read()
    # find the provider-test except block
    idx = api_src.find("LLM provider test failed")
    block = api_src[idx:idx + 400]
    check("provider-test error is generic (no str(e) in body)",
          "Provider test failed" in block and 'content={"success": False, "error": str(e)}' not in block)

    print()
    print(f"RESULT: PASS={PASS} FAIL={FAIL}")
    return 0 if FAIL == 0 else 1


def test_log_redaction():
    """pytest entrypoint: run the script-style checks; main() returns
    non-zero on any failed check (bucket-1 runner-compat conversion)."""
    assert main() == 0


if __name__ == "__main__":
    sys.exit(main())
