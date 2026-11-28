"""ThreatLens command-line interface."""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path

import typer
from rich.console import Console
from rich.markdown import Markdown
from rich.panel import Panel
from rich.table import Table

from . import ai, report
from .core import Cache, Config, Http, Report, Resolver, __version__
from .enrich import run_enrichment
from .ioc import classify, extract
from .recon import run_recon
from .typosquat import run_typosquat

app = typer.Typer(
    add_completion=False,
    no_args_is_help=True,
    help="AI-assisted OSINT for defenders: domain recon, IOC enrichment, typosquat monitoring.",
)
console = Console()
COLORS = {"critical": "magenta", "high": "red", "medium": "dark_orange", "low": "yellow", "info": "cyan"}

Summary = typer.Option(False, "--summary", "-s", help="Write an analyst summary with a local Ollama model")
Out = typer.Option(None, "--out", "-o", help="Save report: .md, .json or .html")
NoCache = typer.Option(False, "--no-cache", help="Bypass the local response cache")


def _show(rep: Report) -> None:
    t = Table(title=f"{rep.kind.upper()} · {rep.target}", show_lines=False, header_style="bold")
    t.add_column("Severity")
    t.add_column("Finding")
    t.add_column("Detail", overflow="fold", max_width=70)
    for f in rep.sorted_findings():
        t.add_row(f"[{COLORS[f.severity]}]{f.severity.upper()}[/]", f.title, f.detail)
    console.print(t if rep.findings else "[green]No findings.[/]")
    if rep.summary:
        console.print(
            Panel(Markdown(rep.summary), title=f"Analyst summary ({rep.summary_source})", border_style="cyan")
        )
    for e in rep.errors:
        console.print(f"[dim]note: {e}[/]")


async def _collect(kind: str, target, summary: bool, no_cache: bool, **kw) -> Report:
    cfg = Config.from_env()
    cache = Cache(None if no_cache else cfg.cache_path, cfg.cache_ttl)
    async with Http(cfg, cache) as http:
        res = Resolver()
        with console.status(f"Running {kind}..."):
            if kind == "recon":
                rep = await run_recon(target, http, res, **kw)
            elif kind == "ioc":
                rep = await run_enrichment(target, http, res, cfg)
            else:
                rep = await run_typosquat(target, http, res, **kw)
        if summary:
            with console.status(f"Summarising with {cfg.ollama_model} ..."):
                await ai.summarise(rep, cfg)
    return rep


def _run(kind: str, target, summary: bool, out: Path | None, no_cache: bool, **kw) -> None:
    rep = asyncio.run(_collect(kind, target, summary, no_cache, **kw))
    _show(rep)
    if out:
        render = {".json": report.to_json, ".html": report.to_html}.get(out.suffix.lower(), report.to_markdown)
        out.write_text(render(rep), encoding="utf-8")
        console.print(f"[green]Saved {out}[/]")


@app.command()
def recon(
    domain: str,
    summary: bool = Summary,
    out: Path = Out,
    no_cache: bool = NoCache,
    max_subdomains: int = typer.Option(200, help="Max CT-log hostnames to resolve"),
):
    """Passive recon of a domain you are authorised to assess."""
    _run("recon", domain, summary, out, no_cache, max_subdomains=max_subdomains)


@app.command()
def ioc(
    indicators: list[str] = typer.Argument(None, help="IPs, domains, URLs or hashes (defanged OK)"),
    file: Path = typer.Option(None, "--file", "-f", help="Extract indicators from a text file ('-' = stdin)"),
    summary: bool = Summary,
    out: Path = Out,
    no_cache: bool = NoCache,
):
    """Enrich indicators of compromise across threat-intel sources."""
    items = []
    for raw in indicators or []:
        i = classify(raw)
        if i:
            items.append(i)
        else:
            console.print(f"[yellow]skipping unrecognised indicator: {raw}[/]")
    if file:
        text = sys.stdin.read() if str(file) == "-" else file.read_text(encoding="utf-8", errors="replace")
        items += [i for i in extract(text) if i not in items]
    if not items:
        raise typer.BadParameter("no indicators given")
    _run("ioc", items, summary, out, no_cache)


@app.command()
def typosquat(
    domain: str,
    summary: bool = Summary,
    out: Path = Out,
    no_cache: bool = NoCache,
    tlds: str = typer.Option(None, help="Comma-separated TLDs for TLD-swap (default: common set)"),
    limit: int = typer.Option(600, help="Max permutations to check"),
):
    """Find registered look-alike domains of a brand."""
    _run("typosquat", domain, summary, out, no_cache, tlds=tlds.split(",") if tlds else None, limit=limit)


@app.command()
def version():
    """Show version."""
    console.print(f"ThreatLens {__version__}")


if __name__ == "__main__":
    app()
