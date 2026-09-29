"""Every TruffleHog credential must appear in all THREE hardcoded key lists.

The webapp enumerates API-key fields in three separate places, and a field
missing from any one of them fails differently and silently:

  * `ALLOWED_KEY_FIELDS` (apiKeysTemplate.ts) — dropped on import, so offline key
    entry appears to work and the scan stays blocked on a key the operator
    believes they set;
  * the GET mask block (settings/route.ts) — the raw secret is returned to
    anyone who can open the settings page;
  * the PUT persist array (settings/route.ts) — the form accepts the value and
    never stores it.

Plus the Prisma column itself, without which none of the three do anything.
Driven from the source registry, so adding source 15 fails here until every
layer is wired.
"""

import re
import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "scanners"))

from trufflehog_scan import sources as reg  # noqa: E402

TEMPLATE = REPO_ROOT / "webapp" / "src" / "lib" / "apiKeysTemplate.ts"
SETTINGS_ROUTE = REPO_ROOT / "webapp" / "src" / "app" / "api" / "users" / "[id]" / "settings" / "route.ts"
SCHEMA = REPO_ROOT / "webapp" / "prisma" / "schema.prisma"
TS_REGISTRY = REPO_ROOT / "webapp" / "src" / "lib" / "trufflehogSources.ts"

CREDENTIAL_FIELDS = sorted({c.settings_key for c in reg.ALL_CREDENTIALS})


def section(text: str, start: str, end: str) -> str:
    return text[text.index(start):text.index(end, text.index(start))]


class TestCredentialFieldWiring(unittest.TestCase):
    def setUp(self):
        self.template = TEMPLATE.read_text()
        self.route = SETTINGS_ROUTE.read_text()
        self.schema = SCHEMA.read_text()

    def test_there_are_the_expected_number_of_credentials(self):
        # 19 flat per-user keys (5.2). A change here is a deliberate decision,
        # not a typo.
        self.assertEqual(len(CREDENTIAL_FIELDS), 19)

    def test_every_credential_is_a_prisma_user_settings_column(self):
        user_settings = section(self.schema, "model UserSettings {", "\n}")
        for field in CREDENTIAL_FIELDS:
            self.assertIn(f"{field} ", user_settings, f"{field} is not a UserSettings column")

    def test_no_credential_is_a_project_column(self):
        """Project rows are spread verbatim into project.json inside the
        downloadable export zip, with no field allowlist. A token there leaks."""
        project = section(self.schema, "model Project {", "\n}")
        for field in CREDENTIAL_FIELDS:
            self.assertNotIn(field, project, f"{field} is on Project and would leak with the export")

    def test_no_credential_is_on_the_scan_profile(self):
        profile = section(self.schema, "model TrufflehogScanProfile {", "\n}")
        for field in CREDENTIAL_FIELDS:
            self.assertNotIn(field, profile)

    def test_every_credential_is_in_the_import_export_template(self):
        allowed = section(self.template, "const ALLOWED_KEY_FIELDS = [", "] as const")
        for field in CREDENTIAL_FIELDS:
            self.assertIn(f"'{field}'", allowed, f"{field} would be dropped on import")

    def test_every_credential_is_masked_on_read(self):
        # One list masks the GET and the PUT response alike.
        secret_fields = section(self.route, "const SECRET_FIELDS = [", "] as const")
        for field in CREDENTIAL_FIELDS:
            self.assertIn(
                f"'{field}'", secret_fields,
                f"{field} is returned unmasked by GET /api/users/[id]/settings",
            )
        self.assertIn("settings = maskSecrets(settings)", self.route)
        self.assertIn("...maskSecrets(settings), rotationConfigs", self.route)

    def test_every_credential_is_persisted_on_write(self):
        fields_array = section(self.route, "const fields = [", "] as const")
        for field in CREDENTIAL_FIELDS:
            self.assertIn(f"'{field}'", fields_array, f"{field} is accepted but never saved")

    def test_the_masked_round_trip_guard_covers_them(self):
        """A masked value read back and re-submitted must keep the stored secret,
        not overwrite it with bullets. The guard is shared by every field in the
        persist array, so being in that array IS the coverage."""
        self.assertIn("startsWith('••••')", self.route)
        fields_array = section(self.route, "const fields = [", "] as const")
        for field in CREDENTIAL_FIELDS:
            self.assertIn(f"'{field}'", fields_array)

    def test_the_ts_registry_names_the_same_columns(self):
        ts = TS_REGISTRY.read_text()
        ts_keys = sorted(set(re.findall(r"settingsKey: '(\w+)'", ts)))
        self.assertEqual(ts_keys, CREDENTIAL_FIELDS)

    def test_the_github_secret_hunt_token_stays_separate(self):
        """Three github.com PATs, one per consumer: Secret Hunt, Supply Chain
        and the Secret Multiscanner. A scope change to one cannot silently
        widen another, and revoking one leaves the others scanning."""
        self.assertNotIn("githubAccessToken", CREDENTIAL_FIELDS)
        self.assertNotIn("supplyChainGithubToken", CREDENTIAL_FIELDS)
        self.assertIn("trufflehogGithubToken", CREDENTIAL_FIELDS)


if __name__ == "__main__":
    unittest.main()
