"""Shared types, configuration, HTTP client with caching, and DNS resolver."""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import sqlite3
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

import dns.asyncresolver
import dns.exception
import dns.resolver
import httpx

__version__ = "0.1.0"
USER_AGENT = f"ThreatLens/{__version__} (+https://github.com/Sparsh-khanal75/threatlens)"
SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


# --------------------------------------------------------------------------- #
# Results
# --------------------------------------------------------------------------- #
@dataclass
class Finding:
    severity: str  # critical | high | medium | low | info
    title: str
    detail: str = ""
    source: str = ""

    def __post_init__(self):
        if self.severity not in SEVERITY_ORDER:
            raise ValueError(f"bad severity {self.severity!r}")


@dataclass
class Report:
    kind: str  # recon | ioc | typosquat
    target: str
    findings: list[Finding] = field(default_factory=list)
    data: dict[str, Any] = field(default_factory=dict)
    errors: list[str] = field(default_factory=list)
    summary: str = ""
    summary_source: str = ""  # "ollama:<model>" or "template"
    generated_at: str = field(default_factory=lambda: time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()))

    def add(self, severity: str, title: str, detail: str = "", source: str = "") -> None:
        self.findings.append(Finding(severity, title, detail, source))

    def sorted_findings(self) -> list[Finding]:
        return sorted(self.findings, key=lambda f: SEVERITY_ORDER[f.severity])

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["findings"] = [asdict(f) for f in self.sorted_findings()]
        return d


# --------------------------------------------------------------------------- #
# Configuration (all optional; modules degrade gracefully without keys)
# --------------------------------------------------------------------------- #
@dataclass
class Config:
    virustotal_key: str | None = None
    abuseipdb_key: str | None = None
    abusech_key: str | None = None  # URLhaus + ThreatFox (free key from auth.abuse.ch)
    ollama_url: str = "http://localhost:11434"
    ollama_model: str = "llama3.1:8b"
    cache_path: str = str(Path.home() / ".cache" / "threatlens" / "cache.sqlite")
    cache_ttl: int = 6 * 3600
    timeout: float = 15.0

    @classmethod
    def from_env(cls) -> Config:
        return cls(
            virustotal_key=os.getenv("VT_API_KEY"),
            abuseipdb_key=os.getenv("ABUSEIPDB_API_KEY"),
            abusech_key=os.getenv("ABUSECH_AUTH_KEY"),
            ollama_url=os.getenv("OLLAMA_URL", cls.ollama_url),
            ollama_model=os.getenv("OLLAMA_MODEL", cls.ollama_model),
            cache_path=os.getenv("THREATLENS_CACHE", cls.cache_path),
        )


# --------------------------------------------------------------------------- #
# Disk cache - be polite to free APIs and make re-runs instant
# --------------------------------------------------------------------------- #
class Cache:
    def __init__(self, path: str | None, ttl: int):
        self.ttl = ttl
        self.db = None
        if path:
            Path(path).parent.mkdir(parents=True, exist_ok=True)
            self.db = sqlite3.connect(path)
            self.db.execute("CREATE TABLE IF NOT EXISTS c (k TEXT PRIMARY KEY, t REAL, v TEXT)")

    @staticmethod
    def key(*parts: Any) -> str:
        return hashlib.sha256(json.dumps(parts, sort_keys=True, default=str).encode()).hexdigest()

    def get(self, key: str) -> Any | None:
        if not self.db:
            return None
        row = self.db.execute("SELECT t, v FROM c WHERE k=?", (key,)).fetchone()
        if row and time.time() - row[0] < self.ttl:
            return json.loads(row[1])
        return None

    def set(self, key: str, value: Any) -> None:
        if self.db:
            self.db.execute("REPLACE INTO c VALUES (?,?,?)", (key, time.time(), json.dumps(value)))
            self.db.commit()


# --------------------------------------------------------------------------- #
# HTTP
# --------------------------------------------------------------------------- #
class Http:
    """httpx wrapper: timeouts, one retry on 429/5xx, per-host concurrency limit, caching of JSON."""

    def __init__(self, cfg: Config, cache: Cache | None = None, per_host: int = 4):
        self.cfg = cfg
        self.cache = cache or Cache(None, 0)
        self.client = httpx.AsyncClient(timeout=cfg.timeout, follow_redirects=True, headers={"User-Agent": USER_AGENT})
        self._limits: dict[str, asyncio.Semaphore] = {}
        self.per_host = per_host

    async def __aenter__(self) -> Http:
        return self

    async def __aexit__(self, *exc) -> None:
        await self.client.aclose()

    async def request(self, method: str, url: str, *, cache: bool = True, **kw) -> httpx.Response:
        host = httpx.URL(url).host
        sem = self._limits.setdefault(host, asyncio.Semaphore(self.per_host))
        async with sem:
            for attempt in range(2):
                resp = await self.client.request(method, url, **kw)
                if resp.status_code == 429 or resp.status_code >= 500:
                    if attempt == 0:
                        await asyncio.sleep(float(resp.headers.get("Retry-After", "2")))
                        continue
                return resp
        return resp

    async def json(self, method: str, url: str, *, ok: tuple[int, ...] = (200,), **kw) -> Any | None:
        """Return parsed JSON, None for 404/no data. Raises for other errors. Cached."""
        key = Cache.key(method, url, kw.get("params"), kw.get("data"), kw.get("json"))
        hit = self.cache.get(key)
        if hit is not None:
            return hit
        resp = await self.request(method, url, **kw)
        if resp.status_code == 404:
            return None
        if resp.status_code not in ok:
            raise httpx.HTTPStatusError(f"{resp.status_code} from {url}", request=resp.request, response=resp)
        value = resp.json()
        self.cache.set(key, value)
        return value


# --------------------------------------------------------------------------- #
# DNS
# --------------------------------------------------------------------------- #
class DNSFailure(Exception):
    """The lookup could not be completed (timeout, no reachable nameserver) - not the same as 'no record'."""


class Resolver:
    """Async DNS lookups returning plain strings. Swappable in tests.

    Returns [] when the name or record type does not exist; raises DNSFailure when the
    question could not be answered, so callers never mistake an outage for a missing record.
    """

    def __init__(self, nameservers: list[str] | None = None, timeout: float = 4.0):
        self.r = dns.asyncresolver.Resolver()
        if nameservers:
            self.r.nameservers = nameservers
        self.r.lifetime = timeout

    async def query(self, name: str, rtype: str) -> list[str]:
        try:
            ans = await self.r.resolve(name, rtype)
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            return []
        except (dns.exception.Timeout, dns.resolver.NoNameservers) as e:
            raise DNSFailure(f"{rtype} {name}: {type(e).__name__}") from e
        out = []
        for r in ans:
            if rtype == "MX":
                out.append(f"{r.preference} {str(r.exchange).rstrip('.')}")
            elif rtype == "TXT":
                out.append(b"".join(r.strings).decode(errors="replace"))
            else:
                out.append(str(r).rstrip("."))
        return out

    async def exists(self, name: str) -> bool:
        """True if the name is registered/delegated (has NS, A, or MX)."""
        for rtype in ("A", "NS", "MX"):
            if await self.query(name, rtype):
                return True
        return False
