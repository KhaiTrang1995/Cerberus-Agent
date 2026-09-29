"""Finding triage: AI verdicts, and the mute / unmute suppression state.

Two separate things live here, and keeping them separate is the point:

- A **verdict** (`triage_status` and friends) is the classifier's opinion. It
  ranks a finding and never hides it, and the AI can write nothing else.
- A **mute** is a decision to suppress a finding as noise. It adds the
  `:Muted` label, which makes the node invisible to every agent query and every
  analytics, report and graph read.

Three things mute:

- a person, in the UI (`muted_by` is their user id);
- a project's node-filter rule (`muted_by` starts with `rule:`; see
  `graph_db/mixins/node_filter_mixin.py`);
- an external agent over MCP, and only through `mute_findings_delegated`,
  holding an operator's access token with the opt-in `triage:mute`
  permission. `muted_by` stays that operator's id, because the token carries
  their authority, and the mute is always stamped `muted_channel = 'mcp'` and
  `muted_token = <token prefix>` so it is never read as a person's judgement.

RedAmon's own AI never mutes: `apply_triage_scores` -- the one path a triage
run writes through -- cannot set `:Muted` no matter what the model returns, so
a prompt injection in scanner output (`raw_response`, `evidence`) can at worst
mislabel a verdict a human can overrule. What bounds an EXTERNAL agent is
enforced in `mute_findings_delegated` and in the webapp: it never touches an
existing mute, never hides a proven finding or one a person brought back, and
is capped per call and per day.

See `docs/readmes/GRAPH.SCHEMA.md` for the label's schema contract, and
`graph_db/tenant_filter.py` for how invisibility is enforced.
"""

#: Labels a finding can be muted on. Asset and reference nodes (IP, Port,
#: Domain, Endpoint, CVE, ...) are deliberately absent: they are context, and
#: muting one would orphan the real findings hanging off it.
#:
#: Used as a Cypher label expression, so a node id that belongs to anything else
#: matches nothing and the write is a no-op. That is the fail-closed direction:
#: a caller cannot mute an asset by guessing its id.
#:
#: Keep in sync with MUTEABLE in `webapp/src/lib/muteEnforcement.test.ts`.
MUTEABLE_LABELS = (
    "Vulnerability",
    "JsReconFinding",
    "Secret",
    "MultiscannerFinding",
    "GithubSecret",
    "GithubSensitiveFile",
    "MalPackageFinding",
    "ExploitGvm",
)

_MUTEABLE = "|".join(MUTEABLE_LABELS)

#: Findings are keyed on `id`, except MalPackageFinding, whose uniqueness
#: constraint is on `finding_id` (`graph_db/schema.py`). Matching either keeps
#: one call site for all eight labels.
#:
#: This is the stored `id` PROPERTY and never Neo4j's elementId: import and
#: version-activate do DETACH DELETE and recreate, so elementId changes under a
#: node that is otherwise the same finding.
_BY_ID = "(n.id = $node_id OR n.finding_id = $node_id)"

#: Neo4j's internal id, projected for DISPLAY only: the Node ID column the
#: tables show and the `WHERE id(n) = <id>` an external agent passes to MCP
#: `query_graph`. It is never a key: rows stay keyed on the stored `id`
#: property, for the reason `_BY_ID` gives. A string, so it never reaches JS as
#: a lossy float.
#:
#: Read from the tail of `elementId(n)` ("4:<db-uuid>:<id>" on Neo4j 5), the
#: same value as `id(n)`: `id()` makes 5.26 send a DEPRECATION notification,
#: which the Python driver logs as a WARNING on every board load.
_NODE_ID = "last(split(elementId(n), ':'))"

#: The functional label of a muted node. A muted finding is dual-labelled and
#: Neo4j does not order labels, so `labels(n)[0]` may be 'Muted' and would
#: mis-type the row. Everything reporting "what kind of finding is this" uses
#: this instead.
_FUNCTIONAL_LABEL = "[l IN labels(n) WHERE l <> 'Muted'][0]"

#: A mute written by a node-filter rule rather than a person. Rule mutes carry
#: `muted_by = 'rule:<kind>/<rule id>'`; a person's mute carries their user id,
#: which can never start with `rule:`.
RULE_MUTE_PREFIX = "rule:"
_RULE_MUTED = f"coalesce(n.muted_by, '') STARTS WITH '{RULE_MUTE_PREFIX}'"

#: How a mute ARRIVED, recorded beside `muted_by` (who it is attributed to).
#: Absent for a person in the UI and for a rule; `mcp` for an external agent on
#: an operator's token. Every unmute removes both properties and every other
#: mute clears them, so a later mute can never inherit an old token's stamp.
MCP_MUTE_CHANNEL = "mcp"
_MCP_MUTED = f"coalesce(n.muted_channel, '') = '{MCP_MUTE_CHANNEL}'"
_MUTE_PROVENANCE = "n.muted_channel, n.muted_token"
_MUTE_PROPS = f"n.muted, n.muted_at, n.muted_by, n.muted_reason, {_MUTE_PROVENANCE}"

#: Who a mute is by, three-valued. A rule wins over the channel: a rule write
#: clears the channel, so both can only hold on a hand-edited node.
_MUTED_VIA = (f"CASE WHEN {_RULE_MUTED} THEN 'rule' "
              f"WHEN {_MCP_MUTED} THEN 'mcp' ELSE 'person' END")

#: The host a finding is about, from the fields the writers actually use.
_HOST = "coalesce(n.triage_host, n.host, n.hostname, n.target_hostname, '')"

#: Upper bound on one batch unmute. The Muted Nodes table selects at most a page
#: (50), so this only bounds a hand-crafted request.
MAX_UNMUTE_BATCH = 500

#: Upper bound on one delegated (MCP) mute. The webapp caps it too; this is the
#: bound a master-key caller that skipped the webapp still hits.
MAX_DELEGATED_MUTE_BATCH = 25

#: The evidence that makes a finding un-hideable by an agent: a confirmed
#: verdict, a stored proof, or a chain finding that confirms it. The Mute Rules
#: guards minus `g_human`: a person calling it noise is a reason TO mute.
_PROVEN = """(coalesce(n.triage_status, '') = 'confirmed' OR n.triage_proof IS NOT NULL
              OR EXISTS { MATCH (:ChainFinding)-[:CONFIRMS]->(n) })"""


def _graph_id_session(driver):
    """A session that does not log `id()`'s DEPRECATION notification.

    `id(n) IN $gids` is the only form Neo4j plans as a NodeByIdSeek; matching
    on the elementId tail scans the tenant. Imported here, not at module level,
    because the recon image bakes graph_db too and must not fail to import it.
    """
    try:
        from neo4j import NotificationDisabledClassification
    except ImportError:  # pragma: no cover - an older driver logs the warning
        return driver.session()
    return driver.session(notifications_disabled_classifications=[
        NotificationDisabledClassification.DEPRECATION])


def _clean_graph_ids(graph_ids, cap: int) -> list:
    """Digits only, as ints, de-duplicated. Anything else is dropped, never cast."""
    out = set()
    for g in graph_ids or []:
        text = str(g).strip()
        if text.isascii() and text.isdigit() and len(text) <= 18:
            out.add(int(text))
    return sorted(out)[:cap]

#: Worst-first ordering, so a capped list keeps the findings that matter. An
#: unknown or missing severity sorts last rather than being treated as critical.
_SEVERITY_RANK = """CASE toLower(coalesce(n.severity, ''))
             WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2
             WHEN 'low' THEN 3 WHEN 'info' THEN 4 ELSE 5 END"""

#: Verdict + priority properties the triage phase owns. Listed once so the write
#: and the unmute cleanup cannot drift apart.
TRIAGE_PROPS = (
    "triage_status",
    "triage_confidence",
    "triage_reason",
    "triage_source",
    "triage_cluster_id",
    "triaged_at",
    # Prioritisation (deterministic scorer). triage_priority_score is THE sort
    # key: higher = more urgent. Deliberately no inverted "priority number".
    "triage_priority_score",
    "triage_signals",
    # Score model v3. The score is one number, but an operator who cannot see
    # WHY it ranked there has no way to disagree with it, so the whole
    # derivation is stored beside it.
    "triage_state",           # open | fixed | gone | inactive | false_positive
    "triage_tier",            # T1 | T2 | T3 | T4
    "triage_tier_rule",       # the rule that placed it in that tier
    "triage_factors",         # JSON: C, L, I, R with the evidence for each
    "triage_math_score",      # the score before any AI correction
    "triage_risk",            # C x L x I x R, before the tier is folded in
    "triage_host",            # the host the model resolved, deterministically
    "triage_group_key",       # one problem, one fix (replaces triage_cluster_id)
    "triage_detector",        # which detector fired, so Real/False clicks teach it
    "triage_run_id",          # drives "new since the last triage"
    "triage_model_version",
    "triage_intel_date",
    # The AI review (Step C).
    "triage_ai_verdict",      # real | doubtful | false_positive | unclear | not_reviewed
    "triage_ai_corrections",  # JSON
    "triage_ai_quote",        # verified: a substring of the evidence we sent
    "triage_ai_model",
    "triage_ai_at",
    "triage_fix_lever",
    "triage_evidence_hash",   # the review cache key
    # X9: the chain findings that proved this, so the proof survives an
    # activation that drops the bridge edges but keeps the chain nodes.
    "triage_proof",
)

#: `needs_verification` is gone. The old classifier answered it for almost
#: everything, because it was the safe-looking answer and nothing punished it,
#: so it stopped meaning anything. The review's equivalent is `unclear`, which
#: is recorded as an AI verdict and deliberately changes NOTHING about the rank.
VALID_TRIAGE_STATUS = ("confirmed", "likely_noise", "unreviewed")

#: What `triage_state` may hold. Anything else is refused rather than stored,
#: because the board's sections are driven by this and an unknown value would
#: silently drop a finding out of every section.
VALID_TRIAGE_STATE = ("open", "fixed", "gone", "inactive", "false_positive")

#: What the AI review may conclude.
VALID_AI_VERDICT = ("real", "doubtful", "false_positive", "unclear", "not_reviewed")

#: The board's four sections, in the order they are always shown.
SECTION_RANKED = 0
SECTION_NOT_TRIAGED = 1
SECTION_FALSE_POSITIVE = 2
SECTION_RESOLVED = 3


class TriageMixin:
    """Mute/unmute and AI-verdict writes for finding nodes."""

    def mute_finding(self, user_id: str, project_id: str, node_id: str,
                     muted_by: str = "", reason: str = "") -> dict:
        """Suppress one finding as noise.

        Adds `:Muted` ALONGSIDE the finding's own label rather than replacing it.
        That is what makes unmute lossless and what lets a re-scan keep the mute:
        recon re-runs `MERGE (v:Vulnerability {id, user_id, project_id})`, which
        still matches a `:Vulnerability:Muted` node, refreshes its scan
        properties and leaves the suppression intact. Relabelling would make that
        MERGE miss and create a second, un-muted duplicate.

        Idempotent, and it never overwrites: an already-muted finding is left
        exactly as it was -- whoever muted it, when and why -- and returns
        muted=True with already=True. Re-muting from a stale row would
        otherwise re-attribute a rule's or an agent's mute to this person.

        A fresh mute clears `muted_channel`/`muted_token`: a person's mute
        carries neither, and a leftover from an older build must not make it
        read as an agent's.

        The node's write lock is taken BEFORE `n:Muted` is read, as in
        `set_human_verdict`, so a mute committing in between is seen.

        Returns {"muted": bool, "already": bool, "label": str|None}.
        `muted=False` means nothing matched: a wrong id, another tenant's id,
        or an asset node, all of which are indistinguishable to the caller on
        purpose.
        """
        query = f"""
        MATCH (n:{_MUTEABLE})
        WHERE {_BY_ID} AND n.user_id = $user_id AND n.project_id = $project_id
        SET n._mute_lock = true
        REMOVE n._mute_lock
        WITH n, n:Muted AS already
        FOREACH (_ IN CASE WHEN already THEN [] ELSE [1] END |
            SET n:Muted,
                n.muted = true,
                n.muted_at = datetime(),
                n.muted_by = $muted_by,
                n.muted_reason = $reason
            REMOVE {_MUTE_PROVENANCE})
        RETURN {_FUNCTIONAL_LABEL} AS label, already
        """
        with self.driver.session() as session:
            record = session.run(
                query,
                node_id=node_id, user_id=user_id, project_id=project_id,
                muted_by=muted_by or user_id, reason=str(reason or "")[:500],
            ).single()

        if record is None:
            return {"muted": False, "label": None}
        return {"muted": True, "already": bool(record.get("already")),
                "label": record["label"]}

    def mute_findings_delegated(self, user_id: str, project_id: str,
                                keys=None, graph_ids=None, exempt_pairs=None,
                                muted_by: str = "", reason: str = "",
                                token_prefix: str = "") -> dict:
        """Mute findings on behalf of an external agent (MCP `mute_findings`).

        Everything that bounds an agent is decided here, per node, under the
        node's write lock and in the same statement as the write, so nothing
        read beforehand can go stale:

        - an already-muted node is NEVER touched (`already_muted`), whoever
          muted it: a rule, a person, or another token;
        - a proven finding is refused (`proven`), see `_PROVEN`;
        - a finding a person brought back, i.e. one with a Mute Rules
          exemption, is refused (`kept_visible`). The exemptions live in
          Postgres, so the caller passes them as `[label, key]` pairs.

        A mute that does land is stamped `muted_channel = 'mcp'` and
        `muted_token = token_prefix`, with `muted_by` the token owner.

        `graph_ids` (Neo4j internal ids, as the tables show them) are resolved
        to finding keys first, inside the tenant. One that is not a finding is
        `not_a_finding` and muted by nothing. A key can match more than one
        node (`_BY_ID` spans eight labels), so EVERY matched row is reported.

        Returns {"items": [{ref, key, label, node_id, name, severity, outcome,
        was_via}], "not_found": [ref]}. `outcome` is muted | already_muted |
        proven | kept_visible | not_a_finding.
        """
        clean_keys = sorted({str(k) for k in (keys or []) if k})[:MAX_DELEGATED_MUTE_BATCH]
        gids = _clean_graph_ids(graph_ids, MAX_DELEGATED_MUTE_BATCH)
        pairs = [[str(p[0]), str(p[1])] for p in (exempt_pairs or [])
                 if isinstance(p, (list, tuple)) and len(p) == 2]

        items: list = []
        not_found: list = []
        # Which ref each key came from, so a result names what the caller sent.
        ref_of: dict = {k: k for k in clean_keys}

        if gids:
            resolve = """
            MATCH (n) WHERE id(n) IN $gids
              AND n.user_id = $user_id AND n.project_id = $project_id
            RETURN id(n) AS gid,
                   [l IN labels(n) WHERE l <> 'Muted'] AS labels,
                   n.id AS id, n.finding_id AS finding_id
            """
            with _graph_id_session(self.driver) as session:
                found = {int(r["gid"]): dict(r) for r in session.run(
                    resolve, gids=gids, user_id=user_id, project_id=project_id)}
            for gid in gids:
                row = found.get(gid)
                if row is None:
                    not_found.append(str(gid))
                    continue
                labels = row.get("labels") or []
                label = next((l for l in labels if l in MUTEABLE_LABELS), None)
                if label is None:
                    items.append({"ref": str(gid), "key": None,
                                  "label": labels[0] if labels else None,
                                  "node_id": str(gid), "name": "", "severity": "",
                                  "outcome": "not_a_finding", "was_via": None})
                    continue
                key = row.get("finding_id") if label == "MalPackageFinding" else row.get("id")
                key = key or row.get("id") or row.get("finding_id")
                if not key:
                    not_found.append(str(gid))
                    continue
                ref_of.setdefault(str(key), str(gid))

        mute_keys = sorted(ref_of)[:MAX_DELEGATED_MUTE_BATCH]
        if not mute_keys:
            return {"items": items, "not_found": not_found}

        query = f"""
        UNWIND $keys AS key
        MATCH (n:{_MUTEABLE})
        WHERE n.user_id = $user_id AND n.project_id = $project_id
          AND (n.id = key OR n.finding_id = key)
        SET n._mute_lock = true
        REMOVE n._mute_lock
        WITH key, n, {_FUNCTIONAL_LABEL} AS label
        WITH key, n, label, n:Muted AS already,
             {_PROVEN} AS proven,
             any(p IN $exempt_pairs WHERE p[0] = label
                 AND (p[1] = n.id OR p[1] = n.finding_id)) AS kept_visible,
             {_MUTED_VIA} AS was_via
        FOREACH (_ IN CASE WHEN already OR proven OR kept_visible THEN [] ELSE [1] END |
            SET n:Muted,
                n.muted = true,
                n.muted_at = datetime(),
                n.muted_by = $muted_by,
                n.muted_reason = $reason,
                n.muted_channel = '{MCP_MUTE_CHANNEL}',
                n.muted_token = $token_prefix)
        RETURN key, label, {_NODE_ID} AS node_id,
               coalesce(n.name, n.title, n.detector_name, n.secret_type, n.type, '') AS name,
               coalesce(n.severity, '') AS severity,
               CASE WHEN already THEN 'already_muted' WHEN proven THEN 'proven'
                    WHEN kept_visible THEN 'kept_visible' ELSE 'muted' END AS outcome,
               CASE WHEN already THEN was_via ELSE NULL END AS was_via
        """
        with self.driver.session() as session:
            rows = [dict(r) for r in session.run(
                query, keys=mute_keys, exempt_pairs=pairs,
                user_id=user_id, project_id=project_id,
                muted_by=muted_by or user_id, reason=str(reason or "")[:500],
                token_prefix=str(token_prefix or "")[:40])]

        matched = set()
        for r in rows:
            matched.add(r["key"])
            items.append({"ref": ref_of.get(r["key"], r["key"]), **r})
        not_found.extend(ref_of[k] for k in mute_keys if k not in matched)
        return {"items": items, "not_found": not_found}

    def resolve_muted(self, user_id: str, project_id: str, keys=None, graph_ids=None,
                      include_rule_mutes: bool = False) -> dict:
        """What an unmute of these refs WOULD do. Reads only; writes nothing.

        MCP `unmute_findings` records the Mute Rules exemptions BEFORE the
        graph write, so a lost response cannot leave a finding unmuted with no
        exemption, and it needs the (label, key) pairs to do that. This is where
        they come from.

        A rule mute is `skipped_rule_mute` unless `include_rule_mutes`: its
        unmute becomes a standing exception to that rule. A ref that is not a
        muted finding in this tenant is `not_found`.
        """
        clean_keys = sorted({str(k) for k in (keys or []) if k})[:MAX_UNMUTE_BATCH]
        gids = _clean_graph_ids(graph_ids, MAX_UNMUTE_BATCH)
        columns = f"""{_FUNCTIONAL_LABEL} AS label, {_NODE_ID} AS node_id,
               coalesce(n.muted_by, '') AS muted_by, {_MUTED_VIA} AS was_via"""
        rows: list = []
        if clean_keys:
            with self.driver.session() as session:
                rows += [{**dict(r), "ref": r["key"]} for r in session.run(f"""
        MATCH (n:Muted)
        WHERE n.user_id = $user_id AND n.project_id = $project_id
          AND (n.id IN $keys OR n.finding_id IN $keys)
        RETURN CASE WHEN n.id IN $keys THEN n.id ELSE n.finding_id END AS key,
               {columns}
        """, keys=clean_keys, user_id=user_id, project_id=project_id)]
        if gids:
            with _graph_id_session(self.driver) as session:
                rows += [{**dict(r), "ref": str(r["gid"])} for r in session.run(f"""
        MATCH (n:Muted)
        WHERE id(n) IN $gids AND n.user_id = $user_id AND n.project_id = $project_id
        RETURN id(n) AS gid,
               CASE WHEN n:MalPackageFinding THEN n.finding_id
                    ELSE coalesce(n.id, n.finding_id) END AS key,
               {columns}
        """, gids=gids, user_id=user_id, project_id=project_id)]

        to_unmute, skipped, seen, found_refs = [], [], set(), set()
        for r in rows:
            found_refs.add(r["ref"])
            if not r.get("key"):
                continue
            ident = (r["label"], r["key"])
            if ident in seen:
                continue
            seen.add(ident)
            item = {"ref": r["ref"], "key": r["key"], "label": r["label"],
                    "node_id": r.get("node_id"), "muted_by": r.get("muted_by") or "",
                    "was_via": r.get("was_via")}
            if r.get("was_via") == "rule" and not include_rule_mutes:
                skipped.append(item)
            else:
                to_unmute.append(item)
        refs = clean_keys + [str(g) for g in gids]
        return {"to_unmute": to_unmute, "skipped_rule_mute": skipped,
                "not_found": [ref for ref in refs if ref not in found_refs]}

    def unmute_finding(self, user_id: str, project_id: str, node_id: str) -> dict:
        """Restore a suppressed finding.

        Removes the label and the muted properties and touches nothing else, so
        the finding comes back with every relationship and scan property it had.
        Idempotent.

        Note this deliberately does NOT clear the triage verdict: unmuting is
        "show me this again", not "forget what we concluded about it".
        """
        query = f"""
        MATCH (n:Muted)
        WHERE {_BY_ID} AND n.user_id = $user_id AND n.project_id = $project_id
        REMOVE n:Muted, {_MUTE_PROPS}
        RETURN {_FUNCTIONAL_LABEL} AS label
        """
        with self.driver.session() as session:
            record = session.run(
                query, node_id=node_id, user_id=user_id, project_id=project_id
            ).single()

        if record is None:
            return {"unmuted": False, "label": None}
        return {"unmuted": True, "label": record["label"]}

    @staticmethod
    def _muted_filter(label=None, muted_via=None, rule=None, search=None,
                      live_rules=None, token=None) -> tuple[str, dict]:
        """The WHERE clauses and parameters shared by the Muted list and its count.

        Built once so a page and the total it is "N of" can never disagree on
        what they filter. `label` is interpolated as a label expression, so it is
        accepted only from MUTEABLE_LABELS; anything else is ignored rather than
        interpolated. Every other value travels as a parameter.

        `muted_via` is three-valued: `person` is a person in the UI only, `mcp`
        is an external agent on a person's token, `rule` a Mute Rule.
        """
        clauses, params = [], {}
        if label in MUTEABLE_LABELS:
            clauses.append(f"n:{label}")
        if muted_via == "person":
            clauses.append(f"NOT {_RULE_MUTED} AND NOT {_MCP_MUTED}")
        elif muted_via == "mcp":
            clauses.append(f"NOT {_RULE_MUTED} AND {_MCP_MUTED}")
        elif muted_via == "rule":
            clauses.append(_RULE_MUTED)
        elif muted_via == "deleted_rule":
            # "Deleted" is relative to the rule document, which lives in
            # Postgres, so the caller names the rules that still exist.
            clauses.append(f"{_RULE_MUTED} AND NOT n.muted_by IN $live_rules")
            params["live_rules"] = [str(r) for r in (live_rules or [])][:2000]
        if rule:
            clauses.append("n.muted_by = $rule")
            params["rule"] = str(rule)[:200]
        if token:
            clauses.append("n.muted_token = $token")
            params["token"] = str(token)[:40]
        if search:
            # An all-digit search is also an exact Node ID, the value a person
            # copies from any table. Exact, so "12" does not match node 3120.
            node_id = f" OR {_NODE_ID} = $search_raw" if str(search).strip().isdigit() else ""
            clauses.append(
                "(toLower(coalesce(n.name, n.title, n.detector_name, n.secret_type, n.type, '')) CONTAINS $search"
                " OR toLower(coalesce(n.id, n.finding_id, '')) CONTAINS $search"
                f" OR toLower({_HOST}) CONTAINS $search"
                f" OR toLower(coalesce(n.muted_reason, '')) CONTAINS $search{node_id})")
            params["search"] = str(search).strip().lower()[:200]
            if node_id:
                params["search_raw"] = str(search).strip()[:20]
        where = "".join(f"\n          AND {c}" for c in clauses)
        return where, params

    def list_muted(self, user_id: str, project_id: str,
                   limit: int | None = None, offset: int | None = None,
                   label: str | None = None, muted_via: str | None = None,
                   rule: str | None = None, search: str | None = None,
                   order: str | None = None, live_rules=None,
                   token: str | None = None) -> list:
        """Every suppressed finding in the project, one page at a time.

        The ONLY query in the codebase that deliberately matches `:Muted`. It is
        reachable exclusively from the webapp's Muted Nodes endpoint and the MCP
        muted-findings tool over the internal API; the agent cannot reach it,
        and `scope_query` refuses any agent query that so much as names the label.

        With no arguments it returns every row, newest mute first, as it always
        did. A page is `offset`/`limit`; `count_muted` with the same filters is
        the total that page is "N of".

        `order='person_first'` puts an operator's own mutes ahead of rule mutes.
        A capped reader (MCP, 2,000 rows) uses it so a bulk rule apply cannot
        push the mutes that ARE a person's judgement out of its window.

        Sorted on `datetime(toString(n.muted_at))`, not `n.muted_at`: a version
        activation or an import restores timestamps as ISO strings, and Cypher
        orders every string after every datetime, so restored mutes would sort
        as a block regardless of when they happened.
        """
        where, params = self._muted_filter(label, muted_via, rule, search, live_rules, token)
        first = f"CASE WHEN {_RULE_MUTED} THEN 1 ELSE 0 END, " if order == "person_first" else ""
        page = ""
        if offset:
            page += "\n        SKIP $offset"
            params["offset"] = max(0, int(offset))
        if limit:
            page += "\n        LIMIT $limit"
            params["limit"] = max(1, int(limit))
        query = f"""
        MATCH (n:Muted)
        WHERE n.user_id = $user_id AND n.project_id = $project_id{where}
        RETURN coalesce(n.id, n.finding_id)        AS id,
               {_NODE_ID}                          AS node_id,
               {_FUNCTIONAL_LABEL}                 AS label,
               coalesce(n.name, n.title, n.detector_name, n.secret_type, n.type, '') AS name,
               coalesce(n.severity, '')            AS severity,
               coalesce(n.source, '')              AS source,
               {_HOST}                             AS host,
               toString(n.muted_at)                AS muted_at,
               coalesce(n.muted_by, '')            AS muted_by,
               {_MUTED_VIA} AS muted_via,
               coalesce(n.muted_channel, '')       AS muted_channel,
               coalesce(n.muted_token, '')         AS muted_token,
               coalesce(n.muted_reason, '')        AS muted_reason,
               toString(n.stale_since)             AS stale_since,
               coalesce(n.triage_status, 'unreviewed') AS triage_status,
               n.triage_reason                     AS triage_reason
        ORDER BY {first}datetime(toString(n.muted_at)) DESC, coalesce(n.id, n.finding_id){page}
        """
        params.update(user_id=user_id, project_id=project_id)
        with self.driver.session() as session:
            return [dict(r) for r in session.run(query, **params)]

    def count_muted(self, user_id: str, project_id: str,
                    label: str | None = None, muted_via: str | None = None,
                    rule: str | None = None, search: str | None = None,
                    live_rules=None, token: str | None = None) -> int:
        """How many muted findings match the same filters as `list_muted`."""
        where, params = self._muted_filter(label, muted_via, rule, search, live_rules, token)
        query = f"""
        MATCH (n:Muted)
        WHERE n.user_id = $user_id AND n.project_id = $project_id{where}
        RETURN count(n) AS total
        """
        params.update(user_id=user_id, project_id=project_id)
        with self.driver.session() as session:
            record = session.run(query, **params).single()
        return int(record["total"]) if record else 0

    def muted_facets(self, user_id: str, project_id: str) -> dict:
        """Counts per functional label, per `muted_by` rule and per MCP token.

        Per-rule counts are also the review surface for rule drift: a rule that
        hides thousands of findings, or none, is visible here without paging.
        People are collapsed into one bucket; the Kind and Rule menus do not
        name individual operators. Agent (MCP) mutes are counted apart from
        people's, and per token prefix, so one token's mutes can be reviewed
        and reverted together.
        """
        query = f"""
        MATCH (n:Muted)
        WHERE n.user_id = $user_id AND n.project_id = $project_id
        WITH {_FUNCTIONAL_LABEL} AS label,
             {_MUTED_VIA} AS via,
             CASE WHEN {_RULE_MUTED} THEN n.muted_by ELSE '' END AS rule,
             CASE WHEN {_RULE_MUTED} THEN coalesce(n.muted_reason, '') ELSE '' END AS reason,
             CASE WHEN {_RULE_MUTED} THEN '' ELSE coalesce(n.muted_token, '') END AS token
        RETURN label, via, rule, token, head(collect(reason)) AS reason, count(*) AS c
        """
        labels: dict = {}
        rules: dict = {}
        tokens: dict = {}
        person = 0
        mcp = 0
        total = 0
        with self.driver.session() as session:
            for r in session.run(query, user_id=user_id, project_id=project_id):
                c = int(r["c"] or 0)
                total += c
                labels[r["label"]] = labels.get(r["label"], 0) + c
                if r["rule"]:
                    entry = rules.setdefault(r["rule"], {"count": 0, "reason": r["reason"] or ""})
                    entry["count"] += c
                elif r.get("via") == "mcp":
                    mcp += c
                    token = r.get("token") or ""
                    if token:
                        tokens[token] = tokens.get(token, 0) + c
                else:
                    person += c
        return {
            "total": total,
            "by_person": person,
            "by_mcp": mcp,
            "labels": labels,
            "rules": [{"muted_by": k, **v} for k, v in sorted(rules.items())],
            "tokens": [{"token": k, "count": v}
                       for k, v in sorted(tokens.items(), key=lambda kv: (-kv[1], kv[0]))],
        }

    def unmute_findings(self, user_id: str, project_id: str, keys,
                        skip_rule_mutes: bool = False) -> dict:
        """Unmute several findings in one write, whoever muted them.

        Returns what was actually unmuted, as `{key, label, muted_by, was_via}`
        rows: the caller records an exemption per row (so no rule mutes it
        again) and the audit names what each one had been muted by. A key that
        matched nothing is absent from the result, never reported as done.

        `skip_rule_mutes` leaves a rule's mute in place and reports it under
        `skipped`: an MCP caller may release a rule mute only when it asked to
        explicitly. The rule check is read under the node's write lock. The
        default is the UI's behaviour, which unmutes whatever it is given.
        """
        clean = sorted({str(k) for k in (keys or []) if k})[:MAX_UNMUTE_BATCH]
        if not clean:
            return {"unmuted": 0, "items": [], "skipped": []}
        # One pass over the muted nodes with IN, not a pass per key: an OR on two
        # properties is served by no index, and rule mutes make the set large.
        query = f"""
        MATCH (n:Muted)
        WHERE n.user_id = $user_id AND n.project_id = $project_id
          AND (n.id IN $keys OR n.finding_id IN $keys)
        SET n._mute_lock = true
        REMOVE n._mute_lock
        WITH n, CASE WHEN n.id IN $keys THEN n.id ELSE n.finding_id END AS key,
             coalesce(n.muted_by, '') AS was, {_MUTED_VIA} AS was_via
        WITH n, key, was, was_via, ($skip_rule_mutes AND was_via = 'rule') AS skipped
        FOREACH (_ IN CASE WHEN skipped THEN [] ELSE [1] END |
            REMOVE n:Muted, {_MUTE_PROPS})
        RETURN key, {_FUNCTIONAL_LABEL} AS label, was AS muted_by, was_via, skipped
        """
        with self.driver.session() as session:
            rows = [dict(r) for r in session.run(
                query, keys=clean, user_id=user_id, project_id=project_id,
                skip_rule_mutes=bool(skip_rule_mutes))]
        items = [{k: r.get(k) for k in ("key", "label", "muted_by", "was_via")}
                 for r in rows if not r.get("skipped")]
        skipped = [{k: r.get(k) for k in ("key", "label", "muted_by")}
                   for r in rows if r.get("skipped")]
        return {"unmuted": len(items), "items": items, "skipped": skipped}

    def list_triage_findings(self, user_id: str, project_id: str, limit: int = 2000) -> list:
        """Every finding in triage scope that is NOT muted, for the Priority Board.

        THE ORDERING CONTRACT. The board has four sections, always in this order,
        and the server decides which one each finding is in so the client cannot
        disagree with it:

          0 Ranked            open, carries a triage_run_id, sorted by score
          1 Not triaged yet   open, never scored, sorted by severity
          2 Likely false pos  the AI or a human called it noise
          3 Resolved          fixed, gone or inactive

        Within a section the key is (score DESC, severity, id), with the id as a
        stable final tiebreak so two runs over an unchanged graph produce exactly
        the same order.

        A capped list keeps the top N, because the score is a near-total order;
        `count_triage_findings` gives the caller the real total so the table can
        say "showing N of M" rather than presenting a truncated list as the whole
        picture.
        """
        query = f"""
        MATCH (n:{_MUTEABLE})
        WHERE n.user_id = $user_id AND n.project_id = $project_id
          AND NOT n:Muted
        OPTIONAL MATCH (parent)-[:HAS_VULNERABILITY|FOUND_AT|HAS_SECRET|HAS_FINDING]-(n)
        WITH n, head(collect(parent)) AS parent
        WITH n, parent,
             coalesce(n.triage_state, 'open') AS state,
             coalesce(n.triage_status, 'unreviewed') AS status
        WITH n, parent, state, status,
             CASE
               WHEN state IN ['fixed', 'gone', 'inactive'] THEN {SECTION_RESOLVED}
               WHEN state = 'false_positive' OR status = 'likely_noise'
                 THEN {SECTION_FALSE_POSITIVE}
               WHEN coalesce(n.triage_run_id, '') = '' THEN {SECTION_NOT_TRIAGED}
               ELSE {SECTION_RANKED}
             END AS section
        RETURN coalesce(n.id, n.finding_id)        AS id,
               {_NODE_ID}                          AS node_id,
               // NOT labels(n)[0]: a muted finding is dual-labelled and Neo4j
               // does not order labels, so that could return 'Muted' and
               // mis-type the row (X14).
               {_FUNCTIONAL_LABEL}                 AS label,
               coalesce(n.name, n.detector_name, n.secret_type, n.type, '') AS name,
               coalesce(n.severity, '')            AS severity,
               coalesce(n.source, '')              AS source,
               coalesce(n.matched_at, n.url, n.endpoint, '') AS location,
               // The host the model actually used, not a non-deterministic pick
               // from whichever parent Neo4j returned first (R5).
               coalesce(n.triage_host, parent.name, parent.address, parent.url, '') AS host,
               section                             AS section,
               state                               AS triage_state,
               status                              AS triage_status,
               n.triage_confidence                 AS triage_confidence,
               n.triage_reason                     AS triage_reason,
               coalesce(n.triage_source, '')       AS triage_source,
               coalesce(n.triage_tier, '')         AS triage_tier,
               coalesce(n.triage_tier_rule, '')    AS triage_tier_rule,
               n.triage_factors                    AS triage_factors,
               n.triage_math_score                 AS triage_math_score,
               n.triage_risk                       AS triage_risk,
               n.triage_priority_score             AS triage_priority_score,
               coalesce(n.triage_signals, [])      AS triage_signals,
               coalesce(n.triage_group_key, n.triage_cluster_id, '') AS triage_group_key,
               coalesce(n.triage_run_id, '')       AS triage_run_id,
               coalesce(n.triage_ai_verdict, '')   AS triage_ai_verdict,
               n.triage_ai_corrections             AS triage_ai_corrections,
               n.triage_ai_quote                   AS triage_ai_quote,
               coalesce(n.triage_ai_model, '')     AS triage_ai_model,
               toString(n.triage_ai_at)            AS triage_ai_at,
               coalesce(n.triage_fix_lever, '')    AS triage_fix_lever,
               n.triage_proof                      AS triage_proof,
               toString(n.triaged_at)              AS triaged_at,
               toString(n.updated_at)              AS updated_at
        ORDER BY section,
                 coalesce(n.triage_priority_score, -1) DESC,
                 {_SEVERITY_RANK},
                 coalesce(n.id, n.finding_id)
        LIMIT $limit
        """
        with self.driver.session() as session:
            return [dict(r) for r in session.run(
                query, user_id=user_id, project_id=project_id, limit=limit)]

    def triage_preflight(self, user_id: str, project_id: str) -> dict:
        """What the confirmation dialog needs to tell the operator, in one read.

        Counts only, never finding text: this crosses two services to reach a
        browser, and a dialog does not need to name anything.
        """
        query = f"""
        MATCH (n:{_MUTEABLE})
        WHERE n.user_id = $user_id AND n.project_id = $project_id
          AND NOT n:Muted
        WITH n,
             coalesce(n.triage_state, 'open') AS state,
             coalesce(n.triage_run_id, '') AS run_id
        RETURN count(n) AS in_scope,
               count(CASE WHEN run_id = '' THEN 1 END) AS never_triaged,
               count(CASE WHEN state = 'open' THEN 1 END) AS open_findings,
               max(toString(n.triaged_at)) AS last_triaged_at,
               // What the review would actually cost: facts and advisories are
               // skipped, and they are the bulk of a real project.
               count(CASE WHEN run_id = ''
                            AND coalesce(n.source, '') <> 'security_check'
                            AND coalesce(n.source, '') <> 'osv'
                            AND state = 'open'
                          THEN 1 END) AS reviewable
        """
        with self.driver.session() as session:
            record = session.run(
                query, user_id=user_id, project_id=project_id).single()
        if not record:
            return {"in_scope": 0, "never_triaged": 0, "open_findings": 0,
                    "reviewable": 0, "last_triaged_at": None}
        return {
            "in_scope": int(record["in_scope"] or 0),
            "never_triaged": int(record["never_triaged"] or 0),
            "open_findings": int(record["open_findings"] or 0),
            "reviewable": int(record["reviewable"] or 0),
            "last_triaged_at": record["last_triaged_at"],
        }

    def count_triage_findings(self, user_id: str, project_id: str) -> int:
        """How many findings are in triage scope, ignoring the display cap.

        The Triage table is capped, so this is what lets the UI say "showing N
        of M" instead of presenting a truncated list as the whole picture.
        """
        query = f"""
        MATCH (n:{_MUTEABLE})
        WHERE n.user_id = $user_id AND n.project_id = $project_id
          AND NOT n:Muted
        RETURN count(n) AS total
        """
        with self.driver.session() as session:
            record = session.run(
                query, user_id=user_id, project_id=project_id).single()
        return int(record["total"]) if record else 0

    def apply_triage_scores(self, user_id: str, project_id: str, rows: list,
                            guard_updated_at: bool = True) -> dict:
        """Publish a triage run's results onto the findings. Step E, and the
        only step that writes.

        `rows` carry the whole derivation, not just a number: state, the four
        factors with the evidence behind each, the tier and the rule that chose
        it, the resolved host, the group key, the run id, and the AI's verdict
        where one was produced. An operator who cannot see why a finding ranked
        where it did has no way to disagree with it.

        Three rules are enforced HERE, in Cypher, rather than trusted to the
        caller:

        1. **A human's verdict is theirs.** Facts, factors and the score always
           update, because those are measurements and staleness helps nobody.
           `triage_status`, `triage_reason` and `triage_confidence` on a
           human-owned finding are never touched, and `triage_source` stays
           'human' (C14).
        2. **Nothing is muted here.** There is no `SET n:Muted` in this method
           and there never must be: a run produces verdicts, and only a person
           suppresses a finding.
        3. **A node a scan changed mid-run is skipped.** Steps A to D read the
           graph minutes before this writes. If a scanner re-ingested a finding
           in between, its facts are no longer the ones that were scored, so the
           row is left alone and counted as `skipped_changed`; the next run
           picks it up. Triage never sets `updated_at` itself (only
           `triaged_at`), so this compares against scanner writes only.

        Returns counts, never finding text.
        """
        clean = []
        for r in rows or []:
            node_id = (r or {}).get("id")
            if not node_id:
                continue
            clean.append(self._clean_publish_row(r))

        if not clean:
            return {"updated": 0, "skipped_human": 0, "skipped_changed": 0,
                    "rejected": len(rows or [])}

        # `seen_updated_at` is the node's updated_at as Step A read it. A row
        # that never carried one (a caller that does not track it) opts out of
        # the guard rather than being skipped for ever.
        query = f"""
        UNWIND $rows AS row
        MATCH (n:{_MUTEABLE})
        WHERE (n.id = row.id OR n.finding_id = row.id)
          AND n.user_id = $user_id AND n.project_id = $project_id
        WITH n, row,
             // coalesce, or a never-triaged node (triage_source NULL) makes
             // `NOT isHuman` NULL and the verdict is silently never written.
             coalesce(n.triage_source, '') = 'human' AS isHuman,
             (NOT $guard
              OR row.seen_updated_at IS NULL
              OR toString(n.updated_at) = row.seen_updated_at) AS unchanged
        FOREACH (_ IN CASE WHEN unchanged THEN [1] ELSE [] END |
          // Measurements: always written, human-owned or not (C14).
          SET n.triage_priority_score = row.score,
              n.triage_math_score     = row.math_score,
              n.triage_risk           = row.risk,
              n.triage_signals        = row.signals,
              n.triage_state          = row.state,
              n.triage_tier           = row.tier,
              n.triage_tier_rule      = row.tier_rule,
              n.triage_factors        = row.factors,
              n.triage_host           = row.host,
              n.triage_group_key      = row.group_key,
              n.triage_detector       = row.detector,
              n.triage_run_id         = row.run_id,
              n.triage_model_version  = row.model_version,
              n.triaged_at            = datetime()
        )
        FOREACH (_ IN CASE WHEN unchanged AND row.proof IS NOT NULL THEN [1] ELSE [] END |
          SET n.triage_proof = row.proof)
        FOREACH (_ IN CASE WHEN unchanged AND row.intel_date IS NOT NULL THEN [1] ELSE [] END |
          SET n.triage_intel_date = row.intel_date)
        FOREACH (_ IN CASE WHEN unchanged AND row.evidence_hash IS NOT NULL THEN [1] ELSE [] END |
          SET n.triage_evidence_hash = row.evidence_hash)
        FOREACH (_ IN CASE WHEN unchanged AND row.fix_lever IS NOT NULL THEN [1] ELSE [] END |
          SET n.triage_fix_lever = row.fix_lever)
        // The AI review and the verdict it implies: never over a human.
        FOREACH (_ IN CASE WHEN unchanged AND NOT isHuman AND row.ai_verdict IS NOT NULL
                           THEN [1] ELSE [] END |
          SET n.triage_ai_verdict     = row.ai_verdict,
              n.triage_ai_corrections = row.ai_corrections,
              n.triage_ai_quote       = row.ai_quote,
              n.triage_ai_model       = row.ai_model,
              n.triage_ai_at          = datetime()
        )
        FOREACH (_ IN CASE WHEN unchanged AND NOT isHuman AND row.status IS NOT NULL
                           THEN [1] ELSE [] END |
          SET n.triage_status     = row.status,
              n.triage_confidence = row.confidence,
              n.triage_source     = 'ai'
        )
        FOREACH (_ IN CASE WHEN unchanged AND NOT isHuman AND row.reason IS NOT NULL
                           THEN [1] ELSE [] END |
          SET n.triage_reason = row.reason)
        RETURN count(CASE WHEN NOT unchanged THEN 1 END) AS skipped_changed,
               count(CASE WHEN unchanged AND isHuman THEN 1 END) AS skipped_human,
               count(CASE WHEN unchanged THEN 1 END) AS updated
        """
        with self.driver.session() as session:
            record = session.run(
                query, rows=clean, user_id=user_id, project_id=project_id,
                guard=bool(guard_updated_at),
            ).single()

        return {
            "updated": (record["updated"] if record else 0) or 0,
            "skipped_human": (record["skipped_human"] if record else 0) or 0,
            "skipped_changed": (record["skipped_changed"] if record else 0) or 0,
            "rejected": len(rows or []) - len(clean),
        }

    @staticmethod
    def _clean_publish_row(r: dict) -> dict:
        """Coerce one publish row, refusing anything outside its enum.

        Everything here either came from the pure score model or passed the
        review's quote check, but this is the last gate before the graph, so an
        out-of-range number or an invented state is dropped rather than stored.
        """
        import json as _json

        def _float(value, default=0.0):
            try:
                return float(value)
            except (TypeError, ValueError):
                return default

        def _text(value, cap):
            text = str(value or "").strip()
            return text[:cap] or None

        def _json_text(value, cap=8000):
            if value is None:
                return None
            if isinstance(value, str):
                return value[:cap]
            try:
                return _json.dumps(value, default=str)[:cap]
            except (TypeError, ValueError):
                return None

        status = r.get("status")
        if status not in VALID_TRIAGE_STATUS:
            status = None
        confidence = r.get("confidence")
        try:
            confidence = None if confidence is None else max(0.0, min(1.0, float(confidence)))
        except (TypeError, ValueError):
            confidence = None

        state = r.get("state")
        if state not in VALID_TRIAGE_STATE:
            state = "open"
        tier = r.get("tier") if r.get("tier") in ("T1", "T2", "T3", "T4") else "T4"
        ai_verdict = r.get("ai_verdict")
        if ai_verdict not in VALID_AI_VERDICT:
            ai_verdict = None

        signals = r.get("signals") or []
        if not isinstance(signals, list):
            signals = [str(signals)]

        return {
            "id": str(r.get("id")),
            "score": max(0.0, min(100.0, _float(r.get("score")))),
            "math_score": max(0.0, min(100.0, _float(r.get("math_score", r.get("score"))))),
            # The raw risk, kept separate from the score so the project-level
            # roll-up can combine findings properly instead of averaging a
            # number that already has the tier folded into it.
            "risk": max(0.0, min(1.0, _float(r.get("risk")))),
            "signals": [str(x)[:120] for x in signals][:30],
            "state": state,
            "tier": tier,
            "tier_rule": _text(r.get("tier_rule"), 200) or "",
            "factors": _json_text(r.get("factors")) or "{}",
            "host": _text(r.get("host"), 300) or "",
            "group_key": _text(r.get("group_key"), 200) or "",
            "detector": _text(r.get("detector"), 200) or "",
            "run_id": _text(r.get("run_id"), 60) or "",
            "model_version": _text(r.get("model_version"), 40) or "",
            "intel_date": _text(r.get("intel_date"), 40),
            "proof": _json_text(r.get("proof"), 4000),
            "evidence_hash": _text(r.get("evidence_hash"), 80),
            "fix_lever": _text(r.get("fix_lever"), 120),
            "status": status,
            "confidence": confidence,
            "reason": _text(r.get("reason"), 500),
            "ai_verdict": ai_verdict,
            "ai_corrections": _json_text(r.get("ai_corrections"), 4000),
            "ai_quote": _text(r.get("ai_quote"), 1000),
            "ai_model": _text(r.get("ai_model"), 120) or "",
            "seen_updated_at": _text(r.get("seen_updated_at"), 60),
        }

    def set_human_verdict(self, user_id: str, project_id: str, node_id: str,
                          status: str, reason: str = "",
                          channel: str = "", verdict_by: str = "",
                          refuse_muted: bool = False) -> dict:
        """Record an operator's own verdict, which the AI may not later overwrite.

        Stamping `triage_source = 'human'` is what makes the skip in
        `apply_triage_scores` fire on the next run: facts and factors keep
        updating, but the verdict stays theirs.

        A verdict delegated through an access token is STILL `'human'`, and
        writing a third value there would be actively wrong. It is the closed
        two-value set four other behaviours branch on: the ingest-then-prune
        keep predicate keeps an operator mute OR `coalesce(n.triage_source,'') = 'human'`,
        so a third value makes the finding prune-eligible and a re-scan DELETES
        it; the publish guard re-reads the same equality, so a later AI run
        overwrites the verdict; `finding_state` tests
        `triage_source in ("human","ai")`, so `likely_noise` stops meaning
        false-positive; and the board renders anything else as "Not reviewed".

        So the VALUE stays `human` and the CHANNEL is recorded separately.
        `verdict_by` mirrors `muted_by`: without it the node recorded only who
        the verdict was not.

        `refuse_muted` is for a delegated caller. Any `human` verdict is a
        Mute Rules guard, so on a rule-muted finding it releases the mute at
        the next apply or sweep: a verdict would be an unmute by another name.
        An MCP caller unmutes only through `unmute_findings`, which needs its
        own opt-in permission and an explicit flag for a rule mute, so the
        verdict permission alone can never release one.

        The node's write lock is taken BEFORE `n:Muted` is read, the same idiom
        as `_lock` in graph_db/node_filters/cypher.py. Under read committed a
        label read without it can see "not muted", then wait on a mute's lock
        and write the verdict onto the node that mute just committed.
        """
        if status not in VALID_TRIAGE_STATUS:
            return {"updated": False, "reason": f"invalid status {status!r}"}

        query = f"""
        MATCH (n:{_MUTEABLE})
        WHERE {_BY_ID} AND n.user_id = $user_id AND n.project_id = $project_id
        SET n._verdict_lock = true
        REMOVE n._verdict_lock
        WITH n, ($refuse_muted AND n:Muted) AS refused
        FOREACH (_ IN CASE WHEN refused THEN [] ELSE [1] END |
            SET n.triage_status = $status,
                n.triage_reason = $reason,
                n.triage_source = 'human',
                n.triage_verdict_channel = $channel,
                n.triage_verdict_by = $verdict_by,
                n.triage_confidence = 1.0,
                n.triaged_at = datetime())
        RETURN {_FUNCTIONAL_LABEL} AS label, refused
        """
        with self.driver.session() as session:
            record = session.run(
                query, node_id=node_id, user_id=user_id, project_id=project_id,
                status=status, reason=str(reason or "")[:500],
                channel=str(channel or "app")[:32],
                # Defaults to the tenant, which is who a UI verdict is by.
                verdict_by=str(verdict_by or user_id)[:128],
                refuse_muted=bool(refuse_muted),
            ).single()

        if record is None:
            return {"updated": False, "label": None}
        if record.get("refused"):
            return {"updated": False, "reason": "muted", "label": record["label"]}
        return {"updated": True, "label": record["label"]}
