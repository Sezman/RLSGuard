"""Tests for SARIF output (GitHub code scanning integration)."""

import json
from pathlib import Path

import pytest

from rlsguard.engine import run_scan
from rlsguard.scanner.reporter import render_sarif

FIXTURES = Path(__file__).parent.parent / "fixtures"

# Fixtures chosen to collectively exercise every rule that can fire, so the
# rule-help assertions below cover the full emitted rule set.
_ALL_RULE_FIXTURES = [
    "table-without-rls",          # SUPA-RLS-001
    "rls-without-policies",       # SUPA-RLS-002
    "unrestricted-select-policy",  # SUPA-RLS-003
    "update-missing-with-check",  # SUPA-RLS-004
    "ownership-not-protected",    # SUPA-RLS-005
    "unsafe-security-definer",    # SUPA-FUNC-001
    "unsafe-storage-policy",      # SUPA-STORAGE-001
    "frontend-service-role-key",  # SUPA-KEY-001
]


def _all_rules(explain: bool = False) -> list[dict]:
    """Driver rules across every fixture that produces a finding."""
    rules: dict[str, dict] = {}
    for fixture in _ALL_RULE_FIXTURES:
        result = run_scan(FIXTURES / fixture, explain=explain)
        doc = json.loads(render_sarif(result))
        for rule in doc["runs"][0]["tool"]["driver"]["rules"]:
            rules[rule["id"]] = rule
    return list(rules.values())


def test_sarif_is_valid_and_maps_levels():
    result = run_scan(FIXTURES / "frontend-service-role-key")
    doc = json.loads(render_sarif(result))

    assert doc["version"] == "2.1.0"
    run = doc["runs"][0]
    assert run["tool"]["driver"]["name"] == "RLSGuard"

    # The critical secret finding maps to SARIF level "error".
    res = next(r for r in run["results"] if r["ruleId"] == "SUPA-KEY-001")
    assert res["level"] == "error"
    loc = res["locations"][0]["physicalLocation"]
    assert loc["artifactLocation"]["uri"] == "src/supabaseClient.ts"
    assert loc["region"]["startLine"] >= 1

    # Every result references a rule defined in the driver.
    rule_ids = {r["id"] for r in run["tool"]["driver"]["rules"]}
    assert {r["ruleId"] for r in run["results"]} <= rule_ids


def test_sarif_level_mapping_for_low_severity():
    # A low-severity finding maps to SARIF "note".
    result = run_scan(FIXTURES / "update-missing-with-check")
    doc = json.loads(render_sarif(result))
    res = next(
        r for r in doc["runs"][0]["results"] if r["ruleId"] == "SUPA-RLS-004"
    )
    assert res["level"] == "note"
    assert res["properties"]["severity"] == "low"


def test_every_emitted_rule_has_full_help_and_official_reference():
    rules = _all_rules()
    assert rules  # sanity: fixtures produced findings

    for rule in rules:
        rid = rule["id"]
        # Descriptions populated so GitHub never shows "No rule help available."
        assert rule["shortDescription"]["text"].strip(), rid
        assert rule["fullDescription"]["text"].strip(), rid

        help_ = rule["help"]
        assert help_["text"].strip(), f"{rid} missing help text"
        assert help_["markdown"].strip(), f"{rid} missing help markdown"

        # helpUri points somewhere; references carry at least one official cite.
        assert rule["helpUri"].startswith("http"), rid
        refs = rule["properties"]["references"]
        assert any(r["official"] for r in refs), f"{rid} has no official reference"
        assert all("supabase.com" in r["url"] for r in refs if r["official"]), rid


def test_rule_help_contains_general_remediation_and_safe_example():
    # The rule panel (not the result message) carries the general guidance:
    # a remediation section, a safe-code example, and Supabase citations.
    result = run_scan(FIXTURES / "table-without-rls")
    doc = json.loads(render_sarif(result))
    rule = next(
        r for r in doc["runs"][0]["tool"]["driver"]["rules"]
        if r["id"] == "SUPA-RLS-001"
    )
    markdown = rule["help"]["markdown"]
    assert "How to fix it" in markdown
    assert "Safe example" in markdown
    assert "enable row level security" in markdown.lower()
    assert "supabase.com" in markdown


def test_result_message_stays_finding_specific():
    # The result message names the offending table; the rule help does not.
    result = run_scan(FIXTURES / "table-without-rls")
    doc = json.loads(render_sarif(result))
    res = next(
        r for r in doc["runs"][0]["results"] if r["ruleId"] == "SUPA-RLS-001"
    )
    msg = res["message"]["text"]
    assert "RLS disabled" in msg
    # Detected evidence is preserved verbatim in result properties.
    assert res["properties"]["evidence"]


def test_explain_enriches_help_and_results_without_changing_decisions():
    fixture = FIXTURES / "table-without-rls"
    plain = json.loads(render_sarif(run_scan(fixture, explain=False)))
    explained = json.loads(render_sarif(run_scan(fixture, explain=True)))

    def decisions(doc):
        return sorted(
            (
                r["ruleId"],
                r["level"],
                r["properties"]["severity"],
                r["properties"]["confidence"],
                r["properties"]["evidence"],
            )
            for r in doc["runs"][0]["results"]
        )

    # The LLM/RAG layer must not move any decision field or detected evidence.
    assert decisions(plain) == decisions(explained)

    # Enrichment is additive: the RAG citations surface in the result and the
    # rule reference list still leads with the official Supabase citation.
    res = next(
        r for r in explained["runs"][0]["results"] if r["ruleId"] == "SUPA-RLS-001"
    )
    assert res["properties"]["citations"]
    rule = next(
        r for r in explained["runs"][0]["tool"]["driver"]["rules"]
        if r["id"] == "SUPA-RLS-001"
    )
    assert any(ref["official"] for ref in rule["properties"]["references"])


def test_explained_rules_still_pass_help_contract():
    # The full-help + official-reference contract holds under --explain too.
    for rule in _all_rules(explain=True):
        assert rule["help"]["text"].strip(), rule["id"]
        assert rule["help"]["markdown"].strip(), rule["id"]
        assert any(
            r["official"] for r in rule["properties"]["references"]
        ), rule["id"]


@pytest.mark.parametrize(
    "rule_id",
    [
        "SUPA-RLS-001", "SUPA-RLS-002", "SUPA-RLS-003", "SUPA-RLS-004",
        "SUPA-RLS-005", "SUPA-FUNC-001", "SUPA-STORAGE-001", "SUPA-KEY-001",
    ],
)
def test_registry_entry_is_complete(rule_id):
    from rlsguard.rules.rule_help import RULE_HELP

    help_ = RULE_HELP[rule_id]
    assert help_.help_text().strip()
    assert help_.help_markdown().strip()
    assert help_.safe_example.strip()
    assert help_.official_references()
