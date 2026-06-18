"""Render scan results as human-readable text (Rich), JSON, or SARIF."""

from __future__ import annotations

import json
from dataclasses import replace

from rich.console import Console
from rich.panel import Panel
from rich.text import Text

from rlsguard import __version__
from rlsguard.engine import ScanResult
from rlsguard.models.finding import Finding
from rlsguard.rules.rule_help import Reference, get_rule_help

_SEVERITY_STYLE = {
    "critical": "bold white on red",
    "high": "bold red",
    "medium": "yellow",
    "low": "cyan",
    "info": "dim",
}


def render_text(result: ScanResult, console: Console) -> None:
    """Print a Rich report of the scan to ``console``."""
    findings = result.findings

    if not findings:
        console.print("[bold green]No findings.[/] Scanned "
                      f"{result.files_scanned} file(s).")
        _print_warnings(result, console)
        return

    for f in findings:
        style = _SEVERITY_STYLE.get(f.severity, "white")
        header = Text()
        header.append(f"{f.rule_id} - {f.severity.upper()}", style=style)
        body = Text()
        body.append(f"{f.title}\n\n", style="bold")
        if f.file:
            loc = f.file + (f":{f.line}" if f.line is not None else "")
            body.append("Location:\n", style="bold")
            body.append(f"{loc}\n\n")
        if f.evidence:
            body.append("Evidence:\n", style="bold")
            body.append(f"{f.evidence}\n\n")
        if f.explanation:
            body.append("Why this matters:\n", style="bold")
            body.append(f"{f.explanation}\n\n")
        if f.generated_explanation:
            body.append("In plain terms (AI-generated):\n", style="bold")
            body.append(f"{f.generated_explanation}\n\n")
        if f.remediation:
            body.append("Suggested remediation:\n", style="bold")
            body.append(f"{f.remediation}\n\n")
        if f.citations:
            body.append("Learn more:\n", style="bold")
            for c in f.citations:
                body.append(f"- {c.title}\n  {c.url}\n")
            body.append("\n")
        body.append(f"Confidence: {f.confidence.capitalize()}")
        console.print(Panel(body, title=header, title_align="left", border_style=style))

    console.print(_summary_line(result))
    _print_warnings(result, console)


def _summary_line(result: ScanResult) -> Text:
    counts: dict[str, int] = {}
    for f in result.findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1
    total = len(result.findings)
    parts = [f"{counts[s]} {s}" for s in ("critical", "high", "medium", "low", "info") if s in counts]
    return Text(f"\n{total} finding(s): " + ", ".join(parts), style="bold")


def _print_warnings(result: ScanResult, console: Console) -> None:
    for w in result.warnings:
        console.print(f"[dim]warning: {w}[/]")


def render_json(result: ScanResult) -> str:
    """Serialize the scan result to a JSON string."""
    payload = {
        "files_scanned": result.files_scanned,
        "summary": _severity_counts(result),
        "findings": [f.model_dump() for f in result.findings],
        "warnings": result.warnings,
    }
    return json.dumps(payload, indent=2)


def _severity_counts(result: ScanResult) -> dict[str, int]:
    counts: dict[str, int] = {}
    for f in result.findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1
    return counts


# SARIF level expected by GitHub code scanning, plus a numeric security-severity
# (CVSS-like) used to bucket findings in the Security tab.
_SARIF_LEVEL = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "info": "note",
}
_SECURITY_SCORE = {
    "critical": "9.5",
    "high": "8.0",
    "medium": "5.0",
    "low": "3.0",
    "info": "1.0",
}
_INFO_URI = "https://github.com/Sezman/RLSGuard"


def _merged_references(base, findings: list[Finding]) -> list[Reference]:
    """Official rule references, augmented by any RAG citations (--explain).

    The deterministic registry supplies the baseline official Supabase
    citations. When ``--explain`` enriched the findings, their retrieved
    citations are merged in (deduplicated by URL) so the rule panel reflects the
    same sources the result message cites — but the LLM cannot remove or replace
    the official references that anchor the rule.
    """
    references = list(base.references)
    seen = {r.url for r in references}
    for f in findings:
        for c in f.citations:
            if c.url and c.url not in seen:
                seen.add(c.url)
                references.append(Reference(c.title or c.url, c.url))
    return references


def _rule_definition(rule_id: str, findings: list[Finding]) -> dict:
    """Build the SARIF reportingDescriptor (rule) for ``rule_id``.

    All help content here is general and finding-independent, so GitHub renders
    a full rule panel instead of "No rule help available." Severity bucketing
    uses the (deterministic) severity of the rule's findings.
    """
    base = get_rule_help(
        rule_id,
        fallback_references=findings[0].references if findings else None,
    )
    references = _merged_references(base, findings)
    # Re-render help with the (possibly RAG-augmented) reference set.
    help_ = replace(base, references=tuple(references))
    official = [r for r in references if r.official]
    help_uri = (official[0].url if official else references[0].url) if references else _INFO_URI
    # Worst severity seen for this rule drives the security-severity bucket.
    severity = max(findings, key=lambda f: f.severity_rank).severity

    return {
        "id": rule_id,
        "name": help_.name,
        "shortDescription": {"text": help_.short_description},
        "fullDescription": {"text": help_.full_description},
        "help": {"text": help_.help_text(), "markdown": help_.help_markdown()},
        "helpUri": help_uri,
        "properties": {
            "security-severity": _SECURITY_SCORE[severity],
            "references": [
                {"title": r.title, "url": r.url, "official": r.official}
                for r in references
            ],
        },
    }


def _result_message(f: Finding) -> str:
    """Finding-specific result message, enriched by --explain when present.

    The deterministic title/explanation always lead. When the RAG layer attached
    a generated explanation it is appended as additional context — it never
    replaces the detected evidence or any decision field.
    """
    text = f"{f.title}\n\n{f.explanation}".strip()
    if f.generated_explanation:
        text += f"\n\nIn plain terms (AI-generated):\n{f.generated_explanation}"
    return text


def render_sarif(result: ScanResult) -> str:
    """Serialize findings to SARIF 2.1.0 for GitHub code scanning."""
    findings_by_rule: dict[str, list[Finding]] = {}
    for f in result.findings:
        findings_by_rule.setdefault(f.rule_id, []).append(f)

    rules = [
        _rule_definition(rule_id, findings)
        for rule_id, findings in findings_by_rule.items()
    ]

    results: list[dict] = []
    for f in result.findings:
        # ruleId, level, severity, confidence and evidence come *only* from the
        # deterministic finding — the LLM may enrich prose but never these.
        result_entry: dict = {
            "ruleId": f.rule_id,
            "level": _SARIF_LEVEL[f.severity],
            "message": {"text": _result_message(f)},
            "properties": {
                "severity": f.severity,
                "confidence": f.confidence,
                "evidence": f.evidence,
            },
        }
        if f.citations:
            result_entry["properties"]["citations"] = [
                {"title": c.title, "url": c.url} for c in f.citations
            ]
        if f.file:
            location: dict = {
                "physicalLocation": {"artifactLocation": {"uri": f.file}}
            }
            if f.line is not None:
                location["physicalLocation"]["region"] = {"startLine": f.line}
            result_entry["locations"] = [location]
        results.append(result_entry)

    sarif = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "RLSGuard",
                        "informationUri": _INFO_URI,
                        "version": __version__,
                        "rules": rules,
                    }
                },
                "results": results,
            }
        ],
    }
    return json.dumps(sarif, indent=2)
