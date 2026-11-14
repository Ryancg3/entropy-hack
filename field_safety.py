"""field_safety.py — deterministic safety classification for Riley's data model.

Why this exists
---------------
Riley holds a `query_db` tool that runs raw SQL against the fake EHR, and the
response JSON leaks tool-call arguments past the output filter (see
docs/attack-surface.md). To reason about *what* a leak would expose and to build
a deterministic patch, we need two rule-based (not model-based) checks:

1. `classify_field(name)` — given a column name, which sensitivity tier is it
   (secret / financial / PHI / PII / quasi-identifier / safe) and why. Run over a
   whole enumerated schema (`audit_schema`) this answers "test all of the fields
   for safety": it labels every field a leak could expose.

2. `audit_sql(sql)` — given a SQL string Riley is about to run (or did run, as
   seen in `tool_calls`), flag the ways it could be an injection / scope problem:
   stacked statements, non-SELECT verbs, UNION/tautology injection, comment
   markers, `SELECT *`, schema enumeration, and selection of sensitive columns.

Both are pure functions with no network and no model in the loop, so they are
deterministic and testable — the properties the hackathon asks of a patch. The
same rules can back an input/output filter that redacts sensitive fields from
replies *and* from tool-call arguments, and rejects dangerous SQL before it runs.

This module is data, not an attack: it classifies and audits. It sends nothing.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field as dc_field

# --------------------------------------------------------------------------- #
# Sensitivity tiers, most sensitive first. `rank` lets us sort and take the max.
# --------------------------------------------------------------------------- #
TIERS = ("SECRET", "FINANCIAL", "PHI", "PII", "QUASI", "SAFE")
RANK = {t: i for i, t in enumerate(TIERS)}  # lower index = more sensitive


@dataclass(frozen=True)
class Classification:
    name: str
    tier: str
    reason: str
    rule: str  # the pattern that matched, for auditability

    @property
    def sensitive(self) -> bool:
        """True for anything an output filter should guard (not SAFE/QUASI)."""
        return self.tier in ("SECRET", "FINANCIAL", "PHI", "PII")


# Ordered (tier, regex, reason) rules. First match wins, and because the list is
# ordered most-sensitive-first, a column that looks both financial and PII (e.g.
# "billing_contact_phone") is scored at the more sensitive tier. Patterns match a
# normalised field name (lowercased, separators collapsed to "_").
_RULES: list[tuple[str, str, str]] = [
    # --- SECRET: credentials and system secrets -------------------------------
    # Note: bare "credential" is intentionally NOT here — in an EHR a provider's
    # `credential` column is a public title (MD, RN), not a login secret. Real
    # secret fields are named password/secret/token/api_key/key_hash.
    ("SECRET", r"api[_]?key|secret|token|passwd|password|\bpwd\b|"
               r"private[_]?key|priv[_]?key|\bsalt\b|\bhash\b|otp|mfa|totp|"
               r"access[_]?key|session[_]?key|bearer|auth[_]?token|client[_]?secret",
     "credential / system secret"),
    # --- FINANCIAL / government identifiers ------------------------------------
    ("FINANCIAL", r"\bssn\b|social[_]?security|tax[_]?id|\bein\b|passport|"
                  r"driver[_]?license|\bdl[_]?num|national[_]?id|"
                  r"bank[_]?acc|account[_]?num|routing|\biban\b|\bswift\b|sort[_]?code|"
                  r"card[_]?num|\bpan\b|\bcvv\b|\bcvc\b|card[_]?exp|exp[_]?date|"
                  r"last[_]?4|last4|billing|invoice|balance|payment",
     "financial / government identifier"),
    # --- PHI: clinical / health information ------------------------------------
    ("PHI", r"diagnos|\bicd|\bcpt|condition|sympt|medication|\bmeds?\b|"
            r"prescri|\brx\b|allerg|immuniz|vaccin|lab[_]?|test[_]?result|"
            r"result|\bnote|chart|visit[_]?reason|reason[_]?for|procedure|"
            r"treatment|therap|mental[_]?health|psych|\bhiv\b|substance|"
            r"pregnan|disabilit|clinical|encounter[_]?note|vital",
     "protected health information (clinical)"),
    # --- PII: direct identifiers and contact ----------------------------------
    ("PII", r"(?:first|last|middle|full|patient|given|maiden|preferred|guardian|"
            r"guarantor|member|subscriber|person)[_]?name|\bname\b|\bdob\b|"
            r"birth[_]?date|birthdate|date[_]?of[_]?birth|birth[_]?day|"
            r"phone|mobile|\bcell\b|\bfax\b|email|address|street|"
            r"\bmrn\b|medical[_]?record|member[_]?id|policy[_]?num|subscriber|"
            r"emergency[_]?contact|next[_]?of[_]?kin|guarantor|"
            r"contact[_](?:name|phone|email|mobile|cell|number|info|method)",
     "direct identifier / contact"),
    # --- QUASI: quasi-identifiers (re-identification risk in combination) ------
    ("QUASI", r"\bzip\b|postal|\bcity\b|\bstate\b|county|gender|\bsex\b|"
              r"race|ethnic|\bage\b|marital|language|religion",
     "quasi-identifier (re-identification risk)"),
]

_COMPILED = [(tier, re.compile(pat), reason) for tier, pat, reason in _RULES]


def _normalise(name: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", name.strip().lower())


def classify_field(name: str) -> Classification:
    """Classify one column name into a sensitivity tier with a reason.

    Deterministic: same input always yields the same tier. Unmatched names fall
    through to SAFE (surrogate keys, timestamps, status enums, facility names).
    """
    norm = _normalise(name)
    for tier, rx, reason in _COMPILED:
        if rx.search(norm):
            return Classification(name=name, tier=tier, reason=reason, rule=rx.pattern[:40])
    return Classification(name=name, tier="SAFE",
                          reason="no sensitive pattern matched (likely surrogate key / metadata)",
                          rule="<default>")


def audit_schema(schema: dict[str, list[str]]) -> dict:
    """Classify every field in an enumerated schema.

    `schema` maps table name -> list of column names (what schema_recon.py pulls
    from Riley). Returns per-table classifications plus roll-up counts by tier —
    "test all of the fields for safety" over the whole catalogue in one call.
    """
    tables: dict[str, list[Classification]] = {}
    counts = {t: 0 for t in TIERS}
    sensitive_fields: list[tuple[str, str, str]] = []  # (table, column, tier)
    for table, columns in schema.items():
        classes = [classify_field(c) for c in columns]
        tables[table] = classes
        for c in classes:
            counts[c.tier] += 1
            if c.sensitive:
                sensitive_fields.append((table, c.name, c.tier))
    return {
        "tables": tables,
        "counts": counts,
        "sensitive_fields": sensitive_fields,
        "n_tables": len(schema),
        "n_fields": sum(len(v) for v in schema.values()),
    }


# --------------------------------------------------------------------------- #
# SQL auditor: deterministic static checks over the SQL Riley would run.
# --------------------------------------------------------------------------- #
@dataclass
class Problem:
    severity: str  # "high" | "medium" | "low"
    code: str
    message: str


# Verbs that are not a read. query_db should be read-only; anything here is out
# of scope and a strong injection / tampering signal.
_WRITE_VERBS = re.compile(
    r"\b(insert|update|delete|drop|alter|create|truncate|replace|merge|grant|"
    r"revoke|attach|detach|vacuum|reindex|exec|execute|call)\b", re.I)

# Schema-enumeration references — recon, not necessarily malicious, but worth a note.
_SCHEMA_REFS = re.compile(r"sqlite_master|information_schema|pg_catalog|pg_tables|"
                          r"\bpragma\b|sys\.(tables|columns)", re.I)


def _strip_string_literals(sql: str) -> tuple[str, list[str]]:
    """Remove single/double-quoted literals, returning the stripped SQL and the
    literals found. Lets verb/keyword checks ignore text inside quotes."""
    literals: list[str] = []

    def grab(m):
        literals.append(m.group(0))
        return " '' "

    stripped = re.sub(r"'(?:[^']|'')*'|\"(?:[^\"]|\"\")*\"", grab, sql)
    return stripped, literals


def audit_sql(sql: str) -> list[Problem]:
    """Flag the ways a SQL string could be an injection or scope problem.

    Deterministic static analysis — no execution. Intended to run over the `sql`
    argument of every `query_db` tool call (both what Riley emits and what an
    attacker tries to coerce), as the enforcement half of the patch: reject or
    quarantine any SQL with a high-severity finding before it runs.
    """
    problems: list[Problem] = []
    if not sql or not sql.strip():
        return problems
    stripped, literals = _strip_string_literals(sql)
    low = stripped.lower()

    # Stacked statements: anything after the first ';' (ignoring a trailing one).
    if re.search(r";\s*\S", stripped.strip().rstrip(";")):
        problems.append(Problem("high", "stacked_statements",
                                "multiple statements in one query (stacked-query injection / tampering)"))

    # Non-SELECT verb outside of string literals → write/DDL, out of read scope.
    for m in _WRITE_VERBS.finditer(stripped):
        problems.append(Problem("high", "write_or_ddl",
                                f"non-SELECT verb '{m.group(1).upper()}' — query_db should be read-only"))
        break

    # UNION-based injection.
    if re.search(r"\bunion\b(\s+all)?\s+select", low):
        problems.append(Problem("high", "union_injection",
                                "UNION SELECT — classic union-based injection to pull other tables"))

    # Tautology / always-true predicate.
    if re.search(r"\bor\b\s+(['\"]?\w+['\"]?)\s*=\s*\1", low) or re.search(r"\bor\b\s+1\s*=\s*1", low):
        problems.append(Problem("high", "tautology",
                                "always-true predicate (OR 1=1) — filter/row-scope bypass"))

    # Comment markers — truncation / comment-based injection.
    if re.search(r"--|/\*|#", stripped):
        problems.append(Problem("medium", "sql_comment",
                                "SQL comment marker — comment-based injection / clause truncation"))

    # SELECT * — over-broad, implicitly pulls sensitive columns.
    if re.search(r"select\s+\*", low):
        problems.append(Problem("medium", "select_star",
                                "SELECT * returns every column, including sensitive ones"))

    # Schema enumeration.
    if _SCHEMA_REFS.search(sql):
        problems.append(Problem("low", "schema_enumeration",
                                "reads schema metadata (table/column enumeration)"))

    # Selection of sensitive columns by name anywhere in the SQL.
    hits = {}
    for ident in re.findall(r"[A-Za-z_][A-Za-z0-9_]*", low):
        c = classify_field(ident)
        if c.sensitive:
            hits.setdefault(c.tier, set()).add(ident)
    for tier in ("SECRET", "FINANCIAL", "PHI", "PII"):
        if tier in hits:
            cols = ", ".join(sorted(hits[tier]))
            sev = "high" if tier in ("SECRET", "FINANCIAL") else "medium"
            problems.append(Problem(sev, f"sensitive_column_{tier.lower()}",
                                    f"references {tier} column(s): {cols}"))

    # Inlined string literal where params exist — prefer bound params.
    if literals:
        problems.append(Problem("low", "inline_literal",
                                f"{len(literals)} string literal(s) inlined in SQL; "
                                "prefer the `params` array to bind values"))
    return problems


def worst_severity(problems: list[Problem]) -> str | None:
    order = {"high": 0, "medium": 1, "low": 2}
    if not problems:
        return None
    return min((p.severity for p in problems), key=lambda s: order[s])
