"""HTTP Request Smuggling (desync) built-in attack skill.

Verifies the `http_request_smuggling` class is wired end-to-end and, importantly,
that it stays a GENERAL methodology with NO benchmark-specific content (fairness:
the agent must discover the target itself; the skill only supplies standard
technique).

This test is the regression guard for the unblock: unlike the pre-unblock version
it IMPORTS `state`, so the A1/A2/A3 gaps (KNOWN_ATTACK_PATHS + the two hardcoded
classification render loops) can no longer ship green. The class is fail-closed
OFF by default (raw-socket execute_code bypasses the egress/tool guardrails), so
every render test that needs the workflow enables the skill in the settings
context first.

Run with: python -m pytest tests/test_http_smuggling_skill.py -v
"""

from __future__ import annotations

import os
import sys
import unittest
from unittest.mock import MagicMock, patch

_agentic_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _agentic_dir)


# --- Stub heavy LangChain/LangGraph deps so `state` imports outside Docker too
#     (copied verbatim from test_xxe_skill.py; Docker-safe in-container).
class FakeAIMessage:
    def __init__(self, content="", **kwargs):
        self.content = content
        self.type = "ai"


class FakeHumanMessage:
    def __init__(self, content="", **kwargs):
        self.content = content
        self.type = "human"


def _fake_add_messages(left, right):
    return (left or []) + right


_stub_modules = [
    'langchain_core', 'langchain_core.tools', 'langchain_core.messages',
    'langchain_core.language_models', 'langchain_core.runnables',
    'langchain_mcp_adapters', 'langchain_mcp_adapters.client', 'langchain_neo4j',
    'langgraph', 'langgraph.graph', 'langgraph.graph.message',
    'langgraph.graph.state', 'langgraph.checkpoint', 'langgraph.checkpoint.memory',
    'langchain_openai', 'langchain_openai.chat_models',
    'langchain_openai.chat_models.azure', 'langchain_openai.chat_models.base',
    'langchain_anthropic', 'langchain_core.language_models.chat_models',
    'langchain_core.callbacks', 'langchain_core.outputs',
]
for _mod in _stub_modules:
    if _mod not in sys.modules:
        sys.modules[_mod] = MagicMock()
sys.modules['langchain_core.messages'].AIMessage = FakeAIMessage
sys.modules['langchain_core.messages'].HumanMessage = FakeHumanMessage
sys.modules['langgraph.graph.message'].add_messages = _fake_add_messages

import project_settings as ps  # noqa: E402
from prompts import (  # noqa: E402
    build_builtin_skill_workflow, HTTP_SMUGGLING_TOOLS, HTTP_SMUGGLING_ZERO_CL_STEP,
    HTTP_SMUGGLING_EXPECT_STEP, HTTP_SMUGGLING_MUTATION_FUZZING_STEP,
)
from prompts.base import build_attack_path_behavior  # noqa: E402
from prompts.classification import (  # noqa: E402
    build_skill_menu, build_classification_prompt,
    _BUILTIN_SKILL_MAP, _CLASSIFICATION_INSTRUCTIONS,
)
from state import (  # noqa: E402
    KNOWN_ATTACK_PATHS, is_valid_attack_path_value, SkillSwitchDecision,
    evaluate_skill_switch,
)

CLS = "http_request_smuggling"


class TestHrsStateSchema(unittest.TestCase):
    """A1: the Pydantic allow-list. Missing this ABORTS the run on switch_skill."""

    def test_in_known_attack_paths(self):
        self.assertIn(CLS, KNOWN_ATTACK_PATHS)

    def test_is_valid_attack_path_value(self):
        self.assertTrue(is_valid_attack_path_value(CLS))

    def test_skill_switch_decision_constructs_without_raising(self):
        # The exact path that terminates the run today (correction #3): a
        # SkillSwitchDecision to an unknown id fails Pydantic validation and
        # invalidates the whole decision object.
        self.assertEqual(SkillSwitchDecision(to_skill=CLS).to_skill, CLS)

    def test_unclassified_still_a_valid_fallback_format(self):
        self.assertTrue(is_valid_attack_path_value("http_request_smuggling-unclassified"))


class TestHrsClassificationWiring(unittest.TestCase):
    def test_in_builtin_skill_map(self):
        self.assertIn(CLS, _BUILTIN_SKILL_MAP)
        section, letter, sid = _BUILTIN_SKILL_MAP[CLS]
        self.assertEqual(sid, CLS)
        self.assertTrue(section.strip())

    def test_classification_instructions_present(self):
        self.assertIn(CLS, _CLASSIFICATION_INSTRUCTIONS)
        crit = _CLASSIFICATION_INSTRUCTIONS[CLS]
        for token in ("Transfer-Encoding", "Content-Length", "proxy"):
            self.assertIn(token, crit, token)

    def test_skill_menu_lists_and_classifies_hrs(self):
        menu = build_skill_menu({CLS}, [])
        self.assertIn(f"### {CLS}", menu)
        self.assertIn(f"- **{CLS}**", menu)

    def test_menu_boundary_distinguishes_neighbors(self):
        section, _, _ = _BUILTIN_SKILL_MAP[CLS]
        # must disambiguate from single-server injection / URL-fetch classes
        for token in ("SQLi", "SSRF"):
            self.assertIn(token, section, token)

    def test_full_classification_prompt_renders_hrs(self):
        # A2/A3 guard: the two hardcoded render loops must include the id.
        # build_skill_menu asserting it is NOT enough (it uses a different list).
        enabled = {"cve_exploit", "sql_injection", "xss", "ssrf", "rce",
                   "path_traversal", "access_control", CLS, "xxe"}
        with patch("prompts.classification.get_enabled_builtin_skills", return_value=set(enabled)), \
             patch("prompts.classification.get_enabled_user_skills", return_value=[]), \
             patch("prompts.classification.get_setting", return_value=False):
            prompt = build_classification_prompt("Test the fronted endpoint for a desync")
        self.assertIn(f"### {CLS}", prompt)      # step-1 section rendered (A2)
        self.assertIn(f"- **{CLS}**", prompt)    # step-2 criteria rendered (A3)
        self.assertIn(f'"{CLS}"', prompt)        # in the valid_types JSON schema


class TestHrsListConsistency(unittest.TestCase):
    """Behavioral guard for the three function-local ordered id lists that must
    stay in sync with _BUILTIN_SKILL_MAP (the drift that half-wired this skill)."""

    def test_classification_prompt_renders_every_builtin(self):
        enabled = set(_BUILTIN_SKILL_MAP.keys())
        with patch("prompts.classification.get_enabled_builtin_skills", return_value=set(enabled)), \
             patch("prompts.classification.get_enabled_user_skills", return_value=[]), \
             patch("prompts.classification.get_setting", return_value=False):
            prompt = build_classification_prompt("hack it")
        for sid in _BUILTIN_SKILL_MAP:
            self.assertIn(f"### {sid}", prompt, f"section missing for {sid}")
            self.assertIn(f"- **{sid}**", prompt, f"criteria missing for {sid}")

    def test_skill_menu_renders_every_builtin(self):
        menu = build_skill_menu(set(_BUILTIN_SKILL_MAP.keys()), [])
        for sid in _BUILTIN_SKILL_MAP:
            self.assertIn(f"### {sid}", menu, f"section missing for {sid}")
            self.assertIn(f"- **{sid}**", menu, f"criteria missing for {sid}")


class TestHrsInjection(unittest.TestCase):
    def test_workflow_builds_with_key_steps(self):
        # Fail-closed default OFF -> must enable in the settings context first.
        with patch("project_settings.get_enabled_builtin_skills", return_value={CLS}):
            wf = build_builtin_skill_workflow(CLS, {"execute_code", "execute_curl", "kali_shell"})
        blob = "\n".join(wf)
        self.assertTrue(wf)
        for token in ("SMUGGLING", "CL.TE", "TE.CL", "desync", "Transfer-Encoding"):
            self.assertIn(token, blob, token)

    def test_workflow_requires_execute_code(self):
        # smuggling needs raw byte control -> gated on execute_code
        with patch("project_settings.get_enabled_builtin_skills", return_value={CLS}):
            self.assertEqual(build_builtin_skill_workflow(CLS, {"execute_curl"}), [])

    def test_workflow_empty_when_skill_disabled(self):
        # The fail-closed default: no settings-context enable -> not injected.
        with patch("project_settings.get_enabled_builtin_skills", return_value={"xss"}):
            self.assertEqual(
                build_builtin_skill_workflow(CLS, {"execute_code"}), [])


class TestHrsZeroClStep(unittest.TestCase):
    """Class 2: the CL.0 / 0.CL sub-section (X4 wiring + content)."""

    def test_step_injected_with_tools_when_enabled(self):
        # Fail-closed default OFF -> enable in the settings context first.
        with patch("project_settings.get_enabled_builtin_skills", return_value={CLS}):
            wf = build_builtin_skill_workflow(CLS, {"execute_code"})
        blob = "\n".join(wf)
        self.assertIn(HTTP_SMUGGLING_ZERO_CL_STEP, wf)
        # rides the same execute_code branch as the base workflow
        self.assertIn("MANDATORY HTTP REQUEST SMUGGLING WORKFLOW", blob)
        self.assertIn("CL.0", blob)

    def test_step_absent_without_execute_code(self):
        with patch("project_settings.get_enabled_builtin_skills", return_value={CLS}):
            self.assertEqual(build_builtin_skill_workflow(CLS, {"execute_curl"}), [])

    def test_zero_cl_content(self):
        s = HTTP_SMUGGLING_ZERO_CL_STEP
        # case-sensitive: the class labels
        for token in ("0.CL", "CL.0", "Content-Length"):
            self.assertIn(token, s, token)
        # the paused-oracle detection primitive + the "no TE header" premise
        low = s.lower()
        for token in ("paused", "pause before sending", "connection-state",
                      "read timeout", "no such header"):
            self.assertIn(token, low, token)

    def test_candidate_endpoint_heuristic(self):
        s = HTTP_SMUGGLING_ZERO_CL_STEP.lower()
        for token in ("favicon", "robots.txt", "redirect", "health", "options"):
            self.assertIn(token, s, token)

    def test_pipelining_guard_shared(self):
        # the separate-connection guard must be present here too (sharper for 0.CL)
        self.assertIn("SEPARATE", HTTP_SMUGGLING_ZERO_CL_STEP)
        self.assertIn("pipelining", HTTP_SMUGGLING_ZERO_CL_STEP)

    def test_no_em_dash_no_braces(self):
        self.assertNotIn("—", HTTP_SMUGGLING_ZERO_CL_STEP)
        self.assertEqual(HTTP_SMUGGLING_ZERO_CL_STEP.count("{"), 0)
        self.assertEqual(HTTP_SMUGGLING_ZERO_CL_STEP.count("}"), 0)

    def test_full_system_prompt_includes_zero_cl(self):
        from prompts import get_phase_tools
        with patch("project_settings.get_enabled_builtin_skills", return_value={CLS}):
            sysprompt = get_phase_tools(phase="exploitation", attack_path_type=CLS)
        self.assertIn("CL.0 / 0.CL DESYNC", sysprompt)


class TestHrsExpectAndFuzzingStep(unittest.TestCase):
    """Class 5: the Expect/100-continue + byte-mutation fuzzing steps (X4 + content)."""

    def test_both_steps_injected_when_enabled(self):
        with patch("project_settings.get_enabled_builtin_skills", return_value={CLS}):
            wf = build_builtin_skill_workflow(CLS, {"execute_code"})
        self.assertIn(HTTP_SMUGGLING_EXPECT_STEP, wf)
        self.assertIn(HTTP_SMUGGLING_MUTATION_FUZZING_STEP, wf)

    def test_expect_content(self):
        s = HTTP_SMUGGLING_EXPECT_STEP
        for token in ("Expect: 100-continue", "0.CL"):
            self.assertIn(token, s, token)
        low = s.lower()
        # must reuse the CL.0 oracle, not build a new one
        self.assertIn("do not build a second oracle", low)
        self.assertIn("separate connection", low)

    def test_fuzzing_content(self):
        s = HTTP_SMUGGLING_MUTATION_FUZZING_STEP
        low = s.lower()
        for token in ("mutate one byte", "baseline", "stateless", "chunk",
                      "per-mutation socket", "separate", "uuid"):
            self.assertIn(token, low, token)
        # must point back to Step 2's obfuscation list rather than restating it
        self.assertIn("step 2", low)

    def test_no_em_dash_no_braces(self):
        for s in (HTTP_SMUGGLING_EXPECT_STEP, HTTP_SMUGGLING_MUTATION_FUZZING_STEP):
            self.assertNotIn("—", s)
            self.assertEqual(s.count("{"), 0)
            self.assertEqual(s.count("}"), 0)

    def test_full_system_prompt_includes_both(self):
        from prompts import get_phase_tools
        with patch("project_settings.get_enabled_builtin_skills", return_value={CLS}):
            sysprompt = get_phase_tools(phase="exploitation", attack_path_type=CLS)
        self.assertIn("EXPECT / 100-CONTINUE DESYNC", sysprompt)
        self.assertIn("BYTE-MUTATION FUZZING", sysprompt)


class TestHrsNoUninstalledTools(unittest.TestCase):
    """Every tool the skill NAMES AS RUNNABLE must exist. Guards against telling the
    agent to run a binary the kali-sandbox image does not have (the proxy_brain
    'smuggler' lesson)."""

    ALL_STEPS = "\n".join([
        HTTP_SMUGGLING_TOOLS, HTTP_SMUGGLING_ZERO_CL_STEP,
        HTTP_SMUGGLING_EXPECT_STEP, HTTP_SMUGGLING_MUTATION_FUZZING_STEP,
    ])

    def test_registry_tools_only(self):
        import re as _re
        from prompts.tool_registry import TOOL_REGISTRY
        referenced = set(_re.findall(
            r"\b(query_graph|kali_shell|metasploit_console|execute_[a-z_]+|"
            r"proxy_[a-z_]+|fs_[a-z_]+|job_[a-z_]+)\b", self.ALL_STEPS))
        bad = sorted(t for t in referenced if t not in TOOL_REGISTRY)
        self.assertEqual(bad, [], f"skill references non-registry tools: {bad}")

    def test_no_uninstalled_binary_named(self):
        low = self.ALL_STEPS.lower()
        # tools that live in Burp / external repos and are NOT in the kali image;
        # the skill must teach the raw-socket path instead of naming these.
        for banned in ("smuggler", "http2smugl", "h2csmuggler", "turbo intruder",
                       "turbointruder", "t-reqs", "treqs", "nghttp2", "param miner"):
            self.assertNotIn(banned, low, f"names an uninstalled tool: {banned}")


class TestHrsDisabledSwitchIsGraceful(unittest.TestCase):
    """Fail-closed OFF must be a graceful reject in evaluate_skill_switch, NOT the
    A1 Pydantic run-abort. Distinguishes the two failure modes."""

    def test_switch_to_disabled_is_rejected_not_aborted(self):
        outcome, resolved = evaluate_skill_switch(
            CLS, current_skill="recon-unclassified",
            enabled_builtins={"xss", "ssrf"}, enabled_user_ids=set())
        self.assertEqual(outcome, "rejected")
        self.assertIsNone(resolved)

    def test_switch_to_enabled_is_accepted(self):
        outcome, resolved = evaluate_skill_switch(
            CLS, current_skill="recon-unclassified",
            enabled_builtins={CLS, "xss"}, enabled_user_ids=set())
        self.assertEqual(outcome, "switched")
        self.assertEqual(resolved, CLS)


class TestHrsProjectSettings(unittest.TestCase):
    def test_disabled_by_default_fail_closed(self):
        # Fail-closed: raw-socket execute_code bypasses check_egress, the capture
        # proxy AND the is_hard_blocked tool guardrail; operators opt in per project.
        self.assertIs(
            ps.DEFAULT_AGENT_SETTINGS["ATTACK_SKILL_CONFIG"]["builtIn"][CLS], False)


class TestHrsBehaviorBlurb(unittest.TestCase):
    def test_behavior_blurb_present(self):
        self.assertIn("raw socket", build_attack_path_behavior(CLS))


class TestHrsContentCoverage(unittest.TestCase):
    def test_tooling_steers_to_raw_sockets(self):
        self.assertIn("execute_code", HTTP_SMUGGLING_TOOLS)
        self.assertIn("raw socket", HTTP_SMUGGLING_TOOLS)

    def test_core_technique_tokens(self):
        for token in ("CL.TE", "TE.CL", "TE.TE", "Transfer-Encoding",
                      "Content-Length", "chunked"):
            self.assertIn(token, HTTP_SMUGGLING_TOOLS, token)

    def test_pipelining_false_positive_guard_present(self):
        # E1: the single most important correctness fix. A "desync" proved only
        # on a reused connection is pipelining, not a desync.
        blob = HTTP_SMUGGLING_TOOLS
        self.assertIn("SEPARATE connection", blob)
        self.assertIn("pipelining", blob)

    def test_timing_is_screening_only(self):
        # E2: timing must be demoted to a screening signal with a negative-result
        # caveat (mitigations mask the classic timing signal).
        low = HTTP_SMUGGLING_TOOLS.lower()
        self.assertIn("screening", low)
        self.assertIn("mask", low)


class TestHrsFairnessAndStyle(unittest.TestCase):
    """The skill must be GENERAL: no target/benchmark-specific hints, no em dashes."""

    def test_no_em_dash_in_workflow(self):
        self.assertNotIn("—", HTTP_SMUGGLING_TOOLS)
        self.assertNotIn("—", _BUILTIN_SKILL_MAP[CLS][0])
        self.assertNotIn("—", build_attack_path_behavior(CLS))

    def test_no_format_braces(self):
        # HTTP_SMUGGLING_TOOLS is injected verbatim (no .format).
        self.assertEqual(HTTP_SMUGGLING_TOOLS.count("{"), 0)
        self.assertEqual(HTTP_SMUGGLING_TOOLS.count("}"), 0)

    def test_no_benchmark_specific_leak(self):
        blob = (HTTP_SMUGGLING_TOOLS + _CLASSIFICATION_INSTRUCTIONS[CLS]
                + build_attack_path_behavior(CLS)).lower()
        for leak in ("mitmproxy", "haproxy", "lab-", "xben", "/devices", "/admin_panel",
                     "hrs_admin_router", "flag{"):
            self.assertNotIn(leak, blob, f"benchmark-specific leak: {leak}")


class TestHrsSystemPromptSmoke(unittest.TestCase):
    """End-to-end: the real system-prompt assembler (get_phase_tools) must inject
    the smuggling workflow when the class is active AND enabled, and only then."""

    def test_exploitation_hrs_injects_workflow(self):
        from prompts import get_phase_tools
        with patch("project_settings.get_enabled_builtin_skills", return_value={CLS}):
            sysprompt = get_phase_tools(phase="exploitation", attack_path_type=CLS)
        self.assertIn("MANDATORY HTTP REQUEST SMUGGLING WORKFLOW", sysprompt)

    def test_other_class_does_not_inject_hrs(self):
        from prompts import get_phase_tools
        with patch("project_settings.get_enabled_builtin_skills", return_value={CLS, "xss"}):
            sysprompt = get_phase_tools(phase="exploitation", attack_path_type="xss")
        self.assertNotIn("MANDATORY HTTP REQUEST SMUGGLING WORKFLOW", sysprompt)


class TestHrsFrontendArtifacts(unittest.TestCase):
    """Smoke checks against the webapp source (layers 6-9): the wiring that does
    not crash the agent but silently breaks the UI badge / toggle / tooltip /
    suggestions. Requires the repo checkout (webapp/ sibling of agentic/)."""

    REPO_ROOT = os.path.dirname(_agentic_dir)

    def _read(self, rel):
        with open(os.path.join(self.REPO_ROOT, rel), encoding="utf-8") as f:
            return f.read()

    def test_prisma_default_includes_hrs_false(self):
        body = self._read("webapp/prisma/schema.prisma")
        # fail-closed: present as a strict has-key AND set false
        self.assertIn('\\"http_request_smuggling\\":false', body)

    def test_attack_skills_section_lists_hrs(self):
        body = self._read(
            "webapp/src/components/projects/ProjectForm/sections/AttackSkillsSection.tsx")
        self.assertIn("id: 'http_request_smuggling'", body)
        self.assertIn("http_request_smuggling: false", body)  # DEFAULT_CONFIG fallback

    def test_drawer_tooltip_api_lists_hrs(self):
        body = self._read(
            "webapp/src/app/api/users/[id]/attack-skills/available/route.ts")
        self.assertIn("id: 'http_request_smuggling'", body)

    def test_phase_config_has_badge(self):
        body = self._read(
            "webapp/src/app/graph/components/AIAssistantDrawer/phaseConfig.ts")
        self.assertIn("http_request_smuggling: {", body)
        self.assertIn("'DESYNC'", body)

    def test_suggestion_data_has_block(self):
        body = self._read(
            "webapp/src/app/graph/components/AIAssistantDrawer/suggestionData.ts")
        self.assertIn("id: 'http_request_smuggling'", body)
        self.assertIn("HTTP Request Smuggling / Desync", body)


class TestHrsToolRegistryAlignment(unittest.TestCase):
    """Every tool the skill names must be a REAL registry tool."""

    import re as _re

    def _referenced_tools(self):
        return set(self._re.findall(
            r"\b(query_graph|kali_shell|metasploit_console|execute_[a-z_]+|"
            r"proxy_[a-z_]+|fs_[a-z_]+|job_[a-z_]+)\b", HTTP_SMUGGLING_TOOLS))

    def test_all_referenced_tools_are_real_registry_keys(self):
        from prompts.tool_registry import TOOL_REGISTRY
        bad = sorted(t for t in self._referenced_tools() if t not in TOOL_REGISTRY)
        self.assertEqual(bad, [], f"skill references non-registry tools: {bad}")


if __name__ == "__main__":
    unittest.main(verbosity=2)
