"""Typer CLI entrypoint: ``rlsguard scan PATH``."""

from __future__ import annotations

import json as _json
from enum import Enum
from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table

from rlsguard.engine import run_scan
from rlsguard.models.finding import SEVERITY_ORDER
from rlsguard.scanner.project_detector import InvalidProjectError
from rlsguard.scanner.reporter import render_json, render_sarif, render_text

app = typer.Typer(
    add_completion=False,
    help="Static security scanner for Supabase projects.",
)


class OutputFormat(str, Enum):
    text = "text"
    json = "json"
    sarif = "sarif"


class Threshold(str, Enum):
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"


# Exit codes (per spec): 0 = clean, 1 = findings at/above threshold, 2 = error.
EXIT_OK = 0
EXIT_FINDINGS = 1
EXIT_ERROR = 2


@app.callback()
def _main() -> None:
    """RLSGuard — static security scanner for Supabase projects."""
    # Presence of a callback keeps ``scan`` as an explicit subcommand
    # (otherwise Typer collapses the single command into the root).


@app.command()
def scan(
    path: str = typer.Argument(..., help="Path to the project to scan."),
    format: OutputFormat = typer.Option(
        OutputFormat.text, "--format", help="Output format."
    ),
    fail_on: Threshold = typer.Option(
        Threshold.high, "--fail-on", help="Minimum severity that fails the scan."
    ),
    explain: bool = typer.Option(
        False,
        "--explain",
        help="Attach Supabase doc citations to findings (and an AI explanation "
        "if ANTHROPIC_API_KEY is set).",
    ),
    output: str = typer.Option(
        None,
        "--output",
        "-o",
        help="Write the report to a file instead of stdout (json/sarif formats).",
    ),
) -> None:
    """Scan a Supabase project for likely security misconfigurations."""
    # stderr console so machine output on stdout stays clean and pipeable.
    err = Console(stderr=True)

    try:
        result = run_scan(path, explain=explain)
    except InvalidProjectError as exc:
        err.print(f"[bold red]error:[/] {exc}")
        raise typer.Exit(EXIT_ERROR)
    except Exception as exc:  # unexpected scanner failure
        err.print(f"[bold red]scanner error:[/] {exc}")
        raise typer.Exit(EXIT_ERROR)

    if format is OutputFormat.json:
        rendered = render_json(result)
    elif format is OutputFormat.sarif:
        rendered = render_sarif(result)
    else:
        rendered = None

    if output:
        if rendered is None:
            err.print("[bold red]error:[/] --output requires --format json or sarif")
            raise typer.Exit(EXIT_ERROR)
        Path(output).write_text(rendered, encoding="utf-8")
        err.print(f"[dim]wrote {format.value} report to {output}[/]")
    elif rendered is not None:
        typer.echo(rendered)
    else:
        render_text(result, Console())

    threshold = SEVERITY_ORDER[fail_on.value]
    has_failing = any(f.severity_rank >= threshold for f in result.findings)
    raise typer.Exit(EXIT_FINDINGS if has_failing else EXIT_OK)


@app.command(name="rag-eval")
def rag_eval(
    k: int = typer.Option(2, "--k", help="Retrieve the top-k docs per query."),
    as_json: bool = typer.Option(
        False, "--json", help="Emit the metrics as JSON instead of a table."
    ),
    verbose: bool = typer.Option(
        False, "--verbose", "-v", help="Show per-query retrieval results."
    ),
) -> None:
    """Evaluate retrieval quality against the labeled query set.

    Reports hit rate, recall@k, precision@k and MRR so changes to the corpus or
    the ranking can be measured rather than guessed at.
    """
    from rlsguard.rag.evaluate import evaluate

    report = evaluate(k=k)
    console = Console()

    if as_json:
        typer.echo(_json.dumps(report.summary(), indent=2))
        raise typer.Exit(EXIT_OK)

    table = Table(title=f"RAG retrieval evaluation (k={report.k}, n={report.n})")
    table.add_column("Metric")
    table.add_column("Value", justify="right")
    table.add_row("Hit rate", f"{report.hit_rate:.3f}")
    table.add_row(f"Recall@{report.k}", f"{report.mean_recall:.3f}")
    table.add_row(f"Precision@{report.k}", f"{report.mean_precision:.3f}")
    table.add_row("MRR", f"{report.mrr:.3f}")
    console.print(table)

    if verbose:
        detail = Table(title="Per-query results")
        detail.add_column("Query id")
        detail.add_column("Hit", justify="center")
        detail.add_column("RR", justify="right")
        detail.add_column("Retrieved (top-k)")
        for r in report.results:
            detail.add_row(
                r.case.id,
                "[green]yes[/]" if r.hit else "[red]no[/]",
                f"{r.reciprocal_rank:.2f}",
                ", ".join(r.retrieved),
            )
        console.print(detail)

    raise typer.Exit(EXIT_OK)


if __name__ == "__main__":
    app()
