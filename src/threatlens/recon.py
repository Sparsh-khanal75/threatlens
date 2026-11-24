"""Passive domain reconnaissance: RDAP, DNS, certificate transparency, email and web security posture.

Everything here is passive or low-touch (public registries, DNS, one HTTPS request to the
apex). No port scanning, no subdomain brute-forcing.
"""

from __future__ import annotations

import asyncio
import re
import ssl
from collections.abc import Awaitable, Callable
from datetime import datetime, timezone
from typing import Any

from .core import DNSFailure, Http, Report, Resolver

UTC = timezone.utc

SENSITIVE_WORDS = (
    "dev",
    "staging",
    "stage",
    "test",
    "uat",
    "qa",
    "admin",
    "vpn",
    "jenkins",
    "git",
    "gitlab",
    "jira",
    "old",
    "backup",
    "internal",
    "intranet",
    "beta",
    "debug",
    "grafana",
    "kibana",
    "phpmyadmin",
    "sso",
    "remote",
    "citrix",
    "owa",
    "exchange",
)
# CNAME targets where a deleted resource can be claimed by anyone (subdomain takeover)
TAKEOVER_SUFFIXES = (
    "s3.amazonaws.com",
    ".s3-website",
    "azurewebsites.net",
    "cloudapp.net",
    "trafficmanager.net",
    "herokuapp.com",
    "herokudns.com",
    "github.io",
    "netlify.app",
    "pantheonsite.io",
    "ghost.io",
    "surge.sh",
    "bitbucket.io",
    "readthedocs.io",
    "wordpress.com",
    "fly.dev",
    "azureedge.net",
    "blob.core.windows.net",
    "elasticbeanstalk.com",
    "myshopify.com",
)
DKIM_SELECTORS = ("default", "google", "selector1", "selector2", "k1", "mail", "dkim", "s1", "s2", "mandrill")
SECURITY_HEADERS = {
    "strict-transport-security": ("medium", "HSTS not set - browsers may be downgraded to HTTP"),
    "content-security-policy": ("low", "No Content-Security-Policy - weaker protection against XSS"),
    "x-content-type-options": ("low", "X-Content-Type-Options missing - MIME sniffing allowed"),
    "referrer-policy": ("low", "Referrer-Policy missing - full URLs may leak to third parties"),
}


def _days_between(iso: str | None, now: datetime) -> int | None:
    if not iso:
        return None
    try:
        dt = datetime.fromisoformat(iso.replace("Z", "+00:00"))
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    return (dt - now).days


# --------------------------------------------------------------------------- #
# Collectors
# --------------------------------------------------------------------------- #
async def rdap_domain(http: Http, domain: str) -> dict[str, Any] | None:
    data = await http.json("GET", f"https://rdap.org/domain/{domain}")
    if not data:
        return None
    events = {e.get("eventAction"): e.get("eventDate") for e in data.get("events", [])}
    registrar = None
    for ent in data.get("entities", []):
        if "registrar" in ent.get("roles", []):
            for item in (ent.get("vcardArray") or [None, []])[1]:
                if item and item[0] == "fn":
                    registrar = item[3]
    return {
        "registrar": registrar,
        "created": events.get("registration"),
        "updated": events.get("last changed"),
        "expires": events.get("expiration"),
        "nameservers": sorted(ns.get("ldhName", "").lower() for ns in data.get("nameservers", [])),
        "status": data.get("status", []),
    }


async def crtsh_subdomains(http: Http, domain: str) -> list[str]:
    """Hostnames seen in public certificate-transparency logs."""
    data = await http.json("GET", "https://crt.sh/", params={"q": f"%.{domain}", "output": "json"})
    names = set()
    for row in data or []:
        for n in str(row.get("name_value", "")).splitlines():
            n = n.strip().lower().lstrip("*.")
            if n == domain or n.endswith("." + domain):
                names.add(n)
    return sorted(names)


async def dns_profile(res: Resolver, domain: str) -> dict[str, list[str]]:
    rtypes = ("A", "AAAA", "MX", "NS", "TXT", "CAA")
    results = await asyncio.gather(*(res.query(domain, t) for t in rtypes))
    return dict(zip(rtypes, results, strict=True))


async def resolve_subdomains(res: Resolver, names: list[str], limit: int = 200) -> list[dict[str, Any]]:
    sem = asyncio.Semaphore(25)

    async def one(name: str) -> dict[str, Any]:
        async with sem:
            try:
                a, cname = await asyncio.gather(res.query(name, "A"), res.query(name, "CNAME"))
                target_ok = bool(a)
                if cname and not a:
                    target_ok = bool(await res.query(cname[0], "A"))
            except DNSFailure:
                return {"name": name, "a": [], "cname": [], "cname_target_resolves": None, "dns_error": True}
            return {"name": name, "a": a, "cname": cname, "cname_target_resolves": target_ok}

    return list(await asyncio.gather(*(one(n) for n in names[:limit])))


async def http_headers(http: Http, domain: str) -> dict[str, Any] | None:
    try:
        resp = await http.request("GET", f"https://{domain}/", cache=False)
    except Exception as e:  # noqa: BLE001 - network errors are reported, not fatal
        return {"error": type(e).__name__}
    return {
        "status": resp.status_code,
        "final_url": str(resp.url),
        "headers": {k.lower(): v for k, v in resp.headers.items()},
    }


async def tls_certificate(domain: str, port: int = 443, timeout: float = 8.0) -> dict[str, Any] | None:
    ctx = ssl.create_default_context()
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(domain, port, ssl=ctx), timeout)
    except (OSError, asyncio.TimeoutError, ssl.SSLError) as e:
        return {"error": f"{type(e).__name__}: {e}"[:200]}
    cert = writer.get_extra_info("peercert") or {}
    writer.close()
    not_after = cert.get("notAfter")
    expires = (
        datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=UTC).isoformat() if not_after else None
    )
    issuer = dict(x[0] for x in cert.get("issuer", ())).get("organizationName")
    return {"issuer": issuer, "expires": expires}


# --------------------------------------------------------------------------- #
# Analysis
# --------------------------------------------------------------------------- #
def analyse_spf(txt: list[str], rep: Report) -> dict[str, Any]:
    spf = [t for t in txt if t.lower().startswith("v=spf1")]
    if not spf:
        rep.add("high", "No SPF record", "Anyone can send mail claiming to be from this domain.", "dns")
        return {"present": False}
    if len(spf) > 1:
        rep.add("medium", "Multiple SPF records", "RFC 7208 makes this a permerror - SPF effectively fails.", "dns")
    rec = spf[0]
    m = re.search(r"([+~?-]?)all\b", rec)
    qual = (m.group(1) or "+") if m else None
    lookups = len(re.findall(r"\b(include:|a\b|a:|mx\b|mx:|ptr|exists:|redirect=)", rec))
    if qual == "+":
        rep.add(
            "critical", "SPF ends in +all", "Every server on the internet is authorised to send as this domain.", "dns"
        )
    elif qual == "?":
        rep.add("medium", "SPF neutral (?all)", "Unauthorised senders are not rejected.", "dns")
    elif qual == "~":
        rep.add("low", "SPF softfail (~all)", "Unauthorised mail is only marked, not rejected; rely on DMARC.", "dns")
    elif qual is None:
        rep.add("medium", "SPF has no 'all' mechanism", "Unmatched senders get a neutral result.", "dns")
    if lookups > 10:
        rep.add(
            "medium", f"SPF needs {lookups} DNS lookups", "Over the limit of 10 - receivers return permerror.", "dns"
        )
    return {"present": True, "record": rec, "all": qual, "lookups": lookups}


def analyse_dmarc(records: list[str], rep: Report) -> dict[str, Any]:
    dmarc = [t for t in records if t.lower().startswith("v=dmarc1")]
    if not dmarc:
        rep.add("high", "No DMARC record", "Spoofed mail using this exact domain will usually be delivered.", "dns")
        return {"present": False}
    tags = dict(kv.strip().split("=", 1) for kv in dmarc[0].split(";") if "=" in kv)
    tags = {k.strip().lower(): v.strip() for k, v in tags.items()}
    policy = tags.get("p", "none").lower()
    if policy == "none":
        rep.add("medium", "DMARC policy is p=none", "Monitoring only - spoofed mail is not blocked.", "dns")
    pct = int(tags.get("pct", "100")) if tags.get("pct", "100").isdigit() else 100
    if policy != "none" and pct < 100:
        rep.add("low", f"DMARC applies to only {pct}% of mail", "", "dns")
    if "rua" not in tags:
        rep.add("low", "DMARC has no rua reporting address", "You won't see who is sending as you.", "dns")
    return {"present": True, "record": dmarc[0], "policy": policy, "pct": pct, "rua": tags.get("rua")}


async def run_recon(
    domain: str,
    http: Http,
    res: Resolver,
    *,
    now: datetime | None = None,
    tls_fn: Callable[[str], Awaitable[dict | None]] = tls_certificate,
    max_subdomains: int = 200,
) -> Report:
    domain = domain.lower().strip().rstrip(".")
    now = now or datetime.now(UTC)
    rep = Report("recon", domain)

    async def safe(name: str, coro):
        try:
            return await coro
        except Exception as e:  # noqa: BLE001
            rep.errors.append(f"{name}: {type(e).__name__}: {e}"[:200])
            return None

    rdap, dnsp, subs, dmarc_txt, web, tls = await asyncio.gather(
        safe("rdap", rdap_domain(http, domain)),
        safe("dns", dns_profile(res, domain)),
        safe("crt.sh", crtsh_subdomains(http, domain)),
        safe("dmarc", res.query(f"_dmarc.{domain}", "TXT")),
        safe("https", http_headers(http, domain)),
        safe("tls", tls_fn(domain)),
    )
    rep.data.update(rdap=rdap, dns=dnsp or {})

    # Registration
    if rdap:
        age = _days_between(rdap.get("created"), now)
        if age is not None:
            rdap["age_days"] = -age
            if -age < 30:
                rep.add(
                    "high",
                    f"Domain registered {-age} days ago",
                    "Newly registered domains are common in phishing.",
                    "rdap",
                )
        left = _days_between(rdap.get("expires"), now)
        if left is not None and left < 30:
            rep.add(
                "medium", f"Domain expires in {left} days", "Lapsed domains can be re-registered by attackers.", "rdap"
            )

    # Email security (only when DNS answered - an outage must not look like a missing record)
    if dnsp is None:
        rep.errors.append("DNS lookups failed - email and DNS checks skipped")
    elif not any(dnsp.get(t) for t in ("NS", "A", "AAAA", "MX", "TXT")):
        rep.add("info", "Domain has no DNS records", "Not registered, not delegated, or DNS is unreachable.", "dns")
    else:
        rep.data["email"] = {"spf": analyse_spf(dnsp.get("TXT", []), rep)}
        if dmarc_txt is not None:
            rep.data["email"]["dmarc"] = analyse_dmarc(dmarc_txt, rep)
        if not dnsp.get("MX"):
            rep.add("info", "No MX records", "Domain does not receive mail.", "dns")
        try:
            dkim = await asyncio.gather(*(res.query(f"{s}._domainkey.{domain}", "TXT") for s in DKIM_SELECTORS))
            found = [s for s, r in zip(DKIM_SELECTORS, dkim, strict=True) if any("p=" in t for t in r)]
        except DNSFailure:
            found = []
        rep.data["email"]["dkim_selectors_found"] = found
        if dnsp.get("MX") and not found:
            rep.add(
                "info", "No DKIM key at common selectors", "Inconclusive - providers use custom selector names.", "dns"
            )
        if not dnsp.get("CAA"):
            rep.add("low", "No CAA record", "Any certificate authority may issue certificates for this domain.", "dns")

    # Web
    if web and "headers" in web:
        hdrs = web["headers"]
        for h, (sev, msg) in SECURITY_HEADERS.items():
            if h not in hdrs:
                rep.add(sev, msg, source="https")
        if "x-frame-options" not in hdrs and "frame-ancestors" not in hdrs.get("content-security-policy", ""):
            rep.add(
                "low", "No clickjacking protection", "Neither X-Frame-Options nor CSP frame-ancestors set.", "https"
            )
        server = hdrs.get("server", "") + " " + hdrs.get("x-powered-by", "")
        if re.search(r"\d+\.\d+", server):
            rep.add("low", "Server version disclosed", server.strip()[:80], "https")
        rep.data["web"] = {
            "status": web["status"],
            "final_url": web["final_url"],
            "security_headers": {h: h in hdrs for h in SECURITY_HEADERS},
        }
    elif web:
        rep.data["web"] = web
    if tls and tls.get("expires"):
        left = _days_between(tls["expires"], now)
        rep.data["tls"] = {**tls, "days_left": left}
        if left is not None and left < 0:
            rep.add("critical", "TLS certificate expired", tls["expires"], "tls")
        elif left is not None and left < 14:
            rep.add("high", f"TLS certificate expires in {left} days", tls["expires"], "tls")
        elif left is not None and left < 30:
            rep.add("medium", f"TLS certificate expires in {left} days", tls["expires"], "tls")
    elif tls:
        rep.data["tls"] = tls

    # Attack surface from certificate transparency
    subs = subs or []
    resolved = await resolve_subdomains(res, subs, max_subdomains) if subs else []
    live = [r for r in resolved if r["a"] or r["cname"]]
    rep.data["subdomains"] = {"from_ct_logs": len(subs), "checked": len(resolved), "live": len(live), "hosts": resolved}
    for r in resolved:
        tgt = (r["cname"] or [""])[0].lower()
        if tgt and any(s in tgt for s in TAKEOVER_SUFFIXES) and r["cname_target_resolves"] is False:
            rep.add(
                "high",
                f"Possible subdomain takeover: {r['name']}",
                f"CNAME -> {tgt}, which no longer resolves. Anyone may be able to claim it.",
                "dns",
            )
    sensitive = [
        r["name"]
        for r in live
        if any(w in re.split(r"[.\-]", r["name"].removesuffix("." + domain)) for w in SENSITIVE_WORDS)
    ]
    if sensitive:
        rep.add(
            "medium",
            f"{len(sensitive)} internet-facing hosts with sensitive names",
            ", ".join(sensitive[:12]) + (" ..." if len(sensitive) > 12 else ""),
            "crt.sh",
        )
    if len(subs) > max_subdomains:
        rep.add("info", f"Only the first {max_subdomains} of {len(subs)} CT-log hostnames were resolved", "", "crt.sh")
    return rep
