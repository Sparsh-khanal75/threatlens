"""Markdown and JSON report rendering."""

from __future__ import annotations

import json

from .core import Report, __version__

ICON = {"critical": "🟣", "high": "🔴", "medium": "🟠", "low": "🟡", "info": "🔵"}


def to_json(rep: Report) -> str:
    return json.dumps(rep.to_dict(), indent=2, default=str)


def to_markdown(rep: Report) -> str:
    out = [
        f"# ThreatLens {rep.kind} report: `{rep.target}`",
        "",
        f"*Generated {rep.generated_at} by ThreatLens {__version__}*",
        "",
    ]
    if rep.summary:
        out += ["## Analyst summary", f"*Source: {rep.summary_source}*", "", rep.summary, ""]
    out += ["## Findings", ""]
    if rep.findings:
        out += ["| Severity | Finding | Detail | Source |", "|---|---|---|---|"]
        for f in rep.sorted_findings():
            detail = f.detail.replace("|", "\\|").replace("\n", " ")
            out.append(f"| {ICON[f.severity]} {f.severity} | {f.title} | {detail} | {f.source} |")
    else:
        out.append("No findings.")
    out.append("")
    out += _details(rep)
    if rep.errors:
        out += ["## Collection notes", ""] + [f"- {e}" for e in rep.errors] + [""]
    return "\n".join(out)


def _details(rep: Report) -> list[str]:
    d = rep.data
    out: list[str] = []
    if rep.kind == "recon":
        r = d.get("rdap")
        out += (
            ["## Registration", "", "Registration data unavailable.", ""]
            if not r
            else [
                "## Registration",
                "",
                f"- Registrar: {r.get('registrar')}",
                f"- Created: {r.get('created')} ({r.get('age_days', '?')} days ago)",
                f"- Expires: {r.get('expires')}",
                f"- Name servers: {', '.join(r.get('nameservers', []))}",
                "",
            ]
        )
        dns_ = d.get("dns", {})
        out += ["## DNS", ""] + [f"- **{k}**: {', '.join(v) if v else '—'}" for k, v in dns_.items()] + [""]
        em = d.get("email")
        if em:
            spf, dmarc = em.get("spf", {}), em.get("dmarc")
            out += [
                "## Email security",
                "",
                f"- SPF: `{spf.get('record', 'missing')}`",
                f"- DMARC: `{dmarc.get('record', 'missing')}`" if dmarc else "- DMARC: not checked (lookup failed)",
                "- DKIM selectors found: "
                + (", ".join(em.get("dkim_selectors_found", [])) or "none of the common ones"),
                "",
            ]
        s = d.get("subdomains", {})
        out += [
            "## Attack surface (certificate transparency)",
            "",
            f"{s.get('from_ct_logs', 0)} hostnames in CT logs, {s.get('live', 0)} resolve.",
            "",
        ]
        live = [h for h in s.get("hosts", []) if h["a"] or h["cname"]][:40]
        if live:
            out += ["| Host | A | CNAME |", "|---|---|---|"]
            out += [f"| {h['name']} | {', '.join(h['a'][:3])} | {', '.join(h['cname'])} |" for h in live] + [""]
    elif rep.kind == "ioc":
        out += ["## Indicators", "", "| Verdict | Score | Type | Indicator | Evidence |", "|---|---|---|---|---|"]
        for r in d.get("results", []):
            ev = "; ".join(f"{e['provider']}: {e['status']}" for e in r["evidence"] if e["status"] != "skipped")
            out.append(f"| **{r['verdict']}** | {r['score']} | {r['type']} | `{r['defanged']}` | {ev} |")
        if d.get("providers_without_keys"):
            out += ["", f"*Not queried (no API key): {', '.join(d['providers_without_keys'])}*"]
        out.append("")
    elif rep.kind == "typosquat":
        out += [
            "## Registered look-alikes",
            "",
            f"{d.get('generated')} permutations generated, {d.get('registered')} registered.",
            "",
            "| Risk | Domain | Technique | MX | A | Age (days) |",
            "|---|---|---|---|---|---|",
        ]
        for c in d.get("candidates", [])[:60]:
            out.append(
                f"| {c['risk']} | `{c['domain']}` | {c['technique']} | {'yes' if c['mx'] else '—'} | "
                f"{', '.join(c['a'][:2]) or '—'} | {c['age_days'] if c['age_days'] is not None else '?'} |"
            )
        out.append("")
    return out
