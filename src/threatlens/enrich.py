"""IOC enrichment across free threat-intelligence sources, with an explainable combined verdict."""

from __future__ import annotations

import asyncio
import base64
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any

from .core import Http, Report, Resolver
from .ioc import IOC, classify, defang, registered_domain

VT = "https://www.virustotal.com/api/v3"
ABUSEIPDB = "https://api.abuseipdb.com/api/v2/check"
URLHAUS = "https://urlhaus-api.abuse.ch/v1"
THREATFOX = "https://threatfox-api.abuse.ch/api/v1/"
INTERNETDB = "https://internetdb.shodan.io"
RISKY_SHODAN_TAGS = {"c2", "malware", "compromised", "botnet", "scanner", "tor", "proxy", "honeypot"}


@dataclass
class Evidence:
    provider: str
    status: str  # malicious | suspicious | clean | no_data | skipped | error
    reason: str = ""
    details: dict[str, Any] = field(default_factory=dict)


# --------------------------------------------------------------------------- #
# Providers - each returns an Evidence and never raises
# --------------------------------------------------------------------------- #
async def virustotal(http: Http, ioc: IOC, key: str | None) -> Evidence:
    if not key:
        return Evidence("virustotal", "skipped", "set VT_API_KEY")
    path = {
        "ipv4": "ip_addresses",
        "ipv6": "ip_addresses",
        "domain": "domains",
        "md5": "files",
        "sha1": "files",
        "sha256": "files",
    }.get(ioc.type)
    ident = ioc.value
    if ioc.type == "url":
        path, ident = "urls", base64.urlsafe_b64encode(ioc.value.encode()).decode().rstrip("=")
    data = await http.json("GET", f"{VT}/{path}/{ident}", headers={"x-apikey": key})
    if not data:
        return Evidence("virustotal", "no_data", "not in VirusTotal")
    attrs = data.get("data", {}).get("attributes", {})
    stats = attrs.get("last_analysis_stats", {})
    mal, sus = stats.get("malicious", 0), stats.get("suspicious", 0)
    total = sum(stats.values()) or 0
    details = {"malicious": mal, "suspicious": sus, "engines": total, "reputation": attrs.get("reputation")}
    if ioc.type in ("md5", "sha1", "sha256"):
        details["name"] = attrs.get("meaningful_name")
        details["type"] = attrs.get("type_description")
    reason = f"{mal}/{total} engines malicious, {sus} suspicious"
    if mal >= 3:
        return Evidence("virustotal", "malicious", reason, details)
    if mal + sus >= 1:
        return Evidence("virustotal", "suspicious", reason, details)
    return Evidence("virustotal", "clean", reason, details)


async def abuseipdb(http: Http, ioc: IOC, key: str | None) -> Evidence:
    if ioc.type not in ("ipv4", "ipv6"):
        return Evidence("abuseipdb", "skipped", "IPs only")
    if not key:
        return Evidence("abuseipdb", "skipped", "set ABUSEIPDB_API_KEY")
    data = await http.json(
        "GET",
        ABUSEIPDB,
        params={"ipAddress": ioc.value, "maxAgeInDays": 90},
        headers={"Key": key, "Accept": "application/json"},
    )
    d = (data or {}).get("data", {})
    score, reports = d.get("abuseConfidenceScore", 0), d.get("totalReports", 0)
    details = {
        k: d.get(k)
        for k in ("abuseConfidenceScore", "totalReports", "countryCode", "isp", "usageType", "isTor", "lastReportedAt")
    }
    reason = f"abuse confidence {score}%, {reports} reports in 90 days"
    status = "malicious" if score >= 75 else "suspicious" if score >= 25 else "clean"
    return Evidence("abuseipdb", status, reason, details)


async def urlhaus(http: Http, ioc: IOC, key: str | None) -> Evidence:
    if not key:
        return Evidence("urlhaus", "skipped", "set ABUSECH_AUTH_KEY")
    if ioc.type == "url":
        endpoint, form = "url/", {"url": ioc.value}
    elif ioc.type in ("domain", "ipv4"):
        endpoint, form = "host/", {"host": ioc.value}
    elif ioc.type in ("md5", "sha256"):
        endpoint, form = "payload/", {f"{ioc.type}_hash": ioc.value}
    else:
        return Evidence("urlhaus", "skipped", f"{ioc.type} not supported")
    data = await http.json("POST", f"{URLHAUS}/{endpoint}", data=form, headers={"Auth-Key": key}) or {}
    if data.get("query_status") != "ok":
        return Evidence("urlhaus", "no_data", "not listed")
    if ioc.type == "url":
        d = {"threat": data.get("threat"), "url_status": data.get("url_status"), "tags": data.get("tags")}
        return Evidence("urlhaus", "malicious", f"listed: {d['threat']} ({d['url_status']})", d)
    if endpoint == "payload/":
        d = {
            "signature": data.get("signature"),
            "file_type": data.get("file_type"),
            "first_seen": data.get("firstseen"),
            "url_count": data.get("url_count"),
        }
        return Evidence("urlhaus", "malicious", f"known payload: {d['signature'] or d['file_type']}", d)
    urls = data.get("urls", [])
    online = sum(1 for u in urls if u.get("url_status") == "online")
    d = {
        "url_count": data.get("url_count", len(urls)),
        "online": online,
        "blacklists": data.get("blacklists"),
        "sample_threats": sorted({u.get("threat") for u in urls if u.get("threat")}),
    }
    return Evidence("urlhaus", "malicious", f"hosted {d['url_count']} malware URLs ({online} online)", d)


async def threatfox(http: Http, ioc: IOC, key: str | None) -> Evidence:
    if not key:
        return Evidence("threatfox", "skipped", "set ABUSECH_AUTH_KEY")
    if ioc.type in ("md5", "sha256"):
        body = {"query": "search_hash", "hash": ioc.value}
    elif ioc.type in ("ipv4", "domain", "url"):
        body = {"query": "search_ioc", "search_term": ioc.value, "exact_match": True}
    else:
        return Evidence("threatfox", "skipped", f"{ioc.type} not supported")
    data = await http.json("POST", THREATFOX, json=body, headers={"Auth-Key": key}) or {}
    rows = data.get("data") if data.get("query_status") == "ok" else None
    if not rows or not isinstance(rows, list):
        return Evidence("threatfox", "no_data", "not listed")
    families = sorted({r.get("malware_printable") for r in rows if r.get("malware_printable")})
    d = {
        "matches": len(rows),
        "malware": families,
        "threat_type": rows[0].get("threat_type"),
        "confidence": max(int(r.get("confidence_level") or 0) for r in rows),
        "first_seen": rows[0].get("first_seen"),
    }
    return Evidence("threatfox", "malicious", f"IOC for {', '.join(families) or 'malware'} ({d['threat_type']})", d)


async def internetdb(http: Http, ioc: IOC) -> Evidence:
    if ioc.type != "ipv4":
        return Evidence("shodan-internetdb", "skipped", "IPv4 only")
    data = await http.json("GET", f"{INTERNETDB}/{ioc.value}")
    if not data:
        return Evidence("shodan-internetdb", "no_data", "no scan data")
    tags, vulns, ports = data.get("tags", []), data.get("vulns", []), data.get("ports", [])
    d = {
        "ports": ports,
        "tags": tags,
        "vulns": vulns[:20],
        "vuln_count": len(vulns),
        "hostnames": data.get("hostnames", []),
    }
    risky = sorted(RISKY_SHODAN_TAGS & {t.lower() for t in tags})
    reason = f"open ports {ports[:10]}; tags {tags}; {len(vulns)} known CVEs"
    if risky:
        return Evidence("shodan-internetdb", "suspicious", f"tagged {risky}; " + reason, d)
    return Evidence("shodan-internetdb", "clean", reason, d)


async def domain_context(http: Http, res: Resolver, ioc: IOC, now: datetime) -> Evidence:
    """Keyless: does the domain resolve, and how old is it? (RDAP)"""
    host = ioc.value if ioc.type == "domain" else ioc.value.split("://", 1)[-1].split("/")[0].split(":")[0]
    if classify(host) is None or classify(host).type != "domain":
        return Evidence("rdap+dns", "skipped", "no domain")
    reg = registered_domain(host)
    a, rdap = await asyncio.gather(res.query(host, "A"), http.json("GET", f"https://rdap.org/domain/{reg}"))
    created = None
    for e in (rdap or {}).get("events", []):
        if e.get("eventAction") == "registration":
            created = e.get("eventDate")
    d = {"registered_domain": reg, "resolves_to": a, "created": created}
    if created:
        dt = datetime.fromisoformat(created.replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        d["age_days"] = (now - dt).days
        if d["age_days"] < 30:
            return Evidence("rdap+dns", "suspicious", f"domain only {d['age_days']} days old", d)
    if rdap is None:
        return Evidence("rdap+dns", "no_data", "no RDAP record (unregistered or unsupported TLD)", d)
    return Evidence("rdap+dns", "clean", f"registered {d.get('age_days', '?')} days ago; resolves: {bool(a)}", d)


async def ip_context(http: Http, ioc: IOC) -> Evidence:
    if ioc.type not in ("ipv4", "ipv6"):
        return Evidence("rdap-ip", "skipped", "IPs only")
    data = await http.json("GET", f"https://rdap.org/ip/{ioc.value}")
    if not data:
        return Evidence("rdap-ip", "no_data", "")
    d = {
        "network": data.get("name"),
        "country": data.get("country"),
        "range": f"{data.get('startAddress')} - {data.get('endAddress')}",
    }
    return Evidence("rdap-ip", "clean", f"network {d['network']} ({d['country']})", d)


# --------------------------------------------------------------------------- #
# Orchestration
# --------------------------------------------------------------------------- #
VERDICT_RANK = {"malicious": 3, "suspicious": 2, "clean": 1, "unknown": 0}


def combine(evidence: list[Evidence]) -> tuple[str, int]:
    """Verdict + 0-100 risk score. Two independent malicious sources = high confidence."""
    mal = [e for e in evidence if e.status == "malicious"]
    sus = [e for e in evidence if e.status == "suspicious"]
    checked = [e for e in evidence if e.status in ("malicious", "suspicious", "clean", "no_data")]
    score = min(100, 45 * len(mal) + 15 * len(sus))
    if mal:
        return "malicious", max(score, 70)
    if sus:
        return "suspicious", max(score, 30)
    if any(e.status == "clean" for e in checked):
        return "clean", 0
    return "unknown", 0


async def enrich_one(ioc: IOC, http: Http, res: Resolver, cfg, now: datetime | None = None) -> dict[str, Any]:
    now = now or datetime.now(timezone.utc)
    tasks = [
        virustotal(http, ioc, cfg.virustotal_key),
        abuseipdb(http, ioc, cfg.abuseipdb_key),
        urlhaus(http, ioc, cfg.abusech_key),
        threatfox(http, ioc, cfg.abusech_key),
        internetdb(http, ioc),
        ip_context(http, ioc),
    ]
    if ioc.type in ("domain", "url"):
        tasks.append(domain_context(http, res, ioc, now))
    names = ["virustotal", "abuseipdb", "urlhaus", "threatfox", "shodan-internetdb", "rdap-ip", "rdap+dns"]
    results = await asyncio.gather(*tasks, return_exceptions=True)
    evidence = []
    for name, r in zip(names, results, strict=False):
        if isinstance(r, Exception):
            evidence.append(Evidence(name, "error", f"{type(r).__name__}: {r}"[:150]))
        elif r.status != "skipped" or r.reason.startswith("set "):
            evidence.append(r)
    verdict, score = combine(evidence)
    return {
        "ioc": ioc.value,
        "type": ioc.type,
        "defanged": defang(ioc.value),
        "verdict": verdict,
        "score": score,
        "evidence": [asdict(e) for e in evidence],
    }


async def run_enrichment(iocs: list[IOC], http: Http, res: Resolver, cfg, now: datetime | None = None) -> Report:
    rep = Report("ioc", f"{len(iocs)} indicator(s)")
    sem = asyncio.Semaphore(5)

    async def guarded(i: IOC):
        async with sem:
            return await enrich_one(i, http, res, cfg, now)

    results = await asyncio.gather(*(guarded(i) for i in iocs))
    results.sort(key=lambda r: (-VERDICT_RANK[r["verdict"]], -r["score"]))
    rep.data["results"] = results
    skipped = sorted({e["provider"] for r in results for e in r["evidence"] if e["status"] == "skipped"})
    if skipped:
        rep.data["providers_without_keys"] = skipped
    for r in results:
        why = "; ".join(
            f"{e['provider']}: {e['reason']}" for e in r["evidence"] if e["status"] in ("malicious", "suspicious")
        )
        if r["verdict"] == "malicious":
            rep.add(
                "critical" if r["score"] >= 90 else "high",
                f"{r['type']} {r['defanged']} is malicious",
                why,
                "enrichment",
            )
        elif r["verdict"] == "suspicious":
            rep.add("medium", f"{r['type']} {r['defanged']} is suspicious", why, "enrichment")
        elif r["verdict"] == "unknown":
            failed = sum(1 for e in r["evidence"] if e["status"] == "error")
            note = f" {failed} lookup(s) failed - check network/API keys." if failed else ""
            rep.add(
                "info",
                f"{r['type']} {r['defanged']}: no data",
                "No provider returned information." + note,
                "enrichment",
            )
    return rep
