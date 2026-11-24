"""Look-alike domain generation and monitoring (dnstwist-style, implemented from scratch)."""

from __future__ import annotations

import asyncio
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone

from .core import Http, Report, Resolver

KEYBOARD = {  # QWERTY neighbours
    "q": "wa",
    "w": "qase",
    "e": "wsdr",
    "r": "edft",
    "t": "rfgy",
    "y": "tghu",
    "u": "yhji",
    "i": "ujko",
    "o": "iklp",
    "p": "ol",
    "a": "qwsz",
    "s": "awedxz",
    "d": "serfcx",
    "f": "drtgvc",
    "g": "ftyhbv",
    "h": "gyujnb",
    "j": "huikmn",
    "k": "jiolm",
    "l": "kop",
    "z": "asx",
    "x": "zsdc",
    "c": "xdfv",
    "v": "cfgb",
    "b": "vghn",
    "n": "bhjm",
    "m": "njk",
    "1": "2q",
    "2": "13w",
    "3": "24e",
    "0": "9p",
}
HOMOGLYPHS = {
    "a": ["4"],
    "b": ["d", "lb"],
    "c": ["e"],
    "d": ["b", "cl"],
    "e": ["3", "c"],
    "g": ["q", "9"],
    "h": ["lh"],
    "i": ["1", "l"],
    "l": ["1", "i"],
    "m": ["rn", "nn"],
    "n": ["m", "r"],
    "o": ["0"],
    "q": ["g"],
    "s": ["5"],
    "t": ["7"],
    "u": ["v"],
    "v": ["u"],
    "w": ["vv"],
    "z": ["2"],
}
VOWELS = "aeiou"
COMMON_TLDS = [
    "com",
    "net",
    "org",
    "co",
    "io",
    "info",
    "biz",
    "xyz",
    "online",
    "site",
    "app",
    "ca",
    "us",
    "shop",
    "top",
    "live",
    "support",
    "cloud",
]
LURE_WORDS = ["login", "secure", "account", "support", "verify", "auth", "portal", "mail", "online", "help"]


@dataclass
class Candidate:
    domain: str
    technique: str
    registered: bool = False
    a: list[str] = field(default_factory=list)
    mx: list[str] = field(default_factory=list)
    ns: list[str] = field(default_factory=list)
    created: str | None = None
    age_days: int | None = None
    risk: int = 0
    reasons: list[str] = field(default_factory=list)


def _split(domain: str) -> tuple[str, str]:
    name, _, tld = domain.lower().partition(".")
    return name, tld


def generate(domain: str, tlds: list[str] | None = None) -> list[tuple[str, str]]:
    """Return (candidate, technique) pairs. Only label-level edits; the TLD is varied separately."""
    name, tld = _split(domain)
    out: dict[str, str] = {}

    def add(label: str, technique: str, t: str = tld):
        label = label.strip("-")
        if label and label != name and len(label) <= 63 and all(c.isalnum() or c == "-" for c in label):
            out.setdefault(f"{label}.{t}", technique)

    for i in range(len(name)):
        add(name[:i] + name[i + 1 :], "omission")
        add(name[:i] + name[i] + name[i:], "repetition")
        if i < len(name) - 1:
            add(name[:i] + name[i + 1] + name[i] + name[i + 2 :], "transposition")
            add(name[: i + 1] + "-" + name[i + 1 :], "hyphenation")
        for k in KEYBOARD.get(name[i], ""):
            add(name[:i] + k + name[i + 1 :], "keyboard replacement")
            add(name[:i] + k + name[i:], "keyboard insertion")
        for g in HOMOGLYPHS.get(name[i], []):
            add(name[:i] + g + name[i + 1 :], "homoglyph")
        if name[i] in VOWELS:
            for v in VOWELS:
                if v != name[i]:
                    add(name[:i] + v + name[i + 1 :], "vowel swap")
        for bit in range(8):  # bitsquatting: a single flipped bit in memory/transit
            c = chr(ord(name[i]) ^ (1 << bit))
            if c.isalnum() and c.islower():
                add(name[:i] + c + name[i + 1 :], "bitsquatting")
    # multi-character homoglyphs (rn -> m etc.)
    for seq, rep in (("rn", "m"), ("m", "rn"), ("vv", "w"), ("w", "vv"), ("cl", "d"), ("d", "cl")):
        if seq in name:
            add(name.replace(seq, rep, 1), "homoglyph")
    for w in LURE_WORDS:
        add(f"{name}-{w}", "brand + lure word")
        add(f"{w}-{name}", "brand + lure word")
        add(f"{name}{w}", "brand + lure word")
    for t in tlds or COMMON_TLDS:
        if t != tld:
            out.setdefault(f"{name}.{t}", "TLD swap")
    if tld.count(".") == 0 and "." not in name:
        out.setdefault(f"{name}{tld}.com", "dot omission")  # e.g. examplecom.com
    return sorted(out.items())


def score(c: Candidate, original_ips: set[str], original_mx: set[str]) -> None:
    if not c.registered:
        return
    c.risk, c.reasons = 20, ["registered"]
    if c.mx and not set(m.split()[-1] for m in c.mx) & original_mx:
        c.risk += 30
        c.reasons.append("has MX - can send/receive phishing email")
    if c.a and not set(c.a) & original_ips:
        c.risk += 20
        c.reasons.append("hosts a website")
    if c.age_days is not None and c.age_days < 30:
        c.risk += 30
        c.reasons.append(f"registered {c.age_days} days ago")
    elif c.age_days is not None and c.age_days < 180:
        c.risk += 10
        c.reasons.append(f"registered {c.age_days} days ago")
    if c.technique in ("homoglyph", "brand + lure word"):
        c.risk += 10
        c.reasons.append(f"{c.technique} - visually deceptive")
    if set(c.a) & original_ips or set(m.split()[-1] for m in c.mx) & original_mx:
        c.risk = 0
        c.reasons = ["shares infrastructure with the original - likely owned defensively by the brand"]
    c.risk = min(c.risk, 100)


async def run_typosquat(
    domain: str,
    http: Http,
    res: Resolver,
    *,
    tlds: list[str] | None = None,
    limit: int = 600,
    rdap_top: int = 25,
    now: datetime | None = None,
) -> Report:
    domain = domain.lower().strip().rstrip(".")
    now = now or datetime.now(timezone.utc)
    rep = Report("typosquat", domain)
    cands = [Candidate(d, t) for d, t in generate(domain, tlds)][:limit]
    orig_a, orig_mx = await asyncio.gather(res.query(domain, "A"), res.query(domain, "MX"))
    original_ips, original_mx = set(orig_a), {m.split()[-1] for m in orig_mx}
    sem = asyncio.Semaphore(40)

    async def check(c: Candidate):
        async with sem:
            c.ns, c.a, c.mx = await asyncio.gather(
                res.query(c.domain, "NS"), res.query(c.domain, "A"), res.query(c.domain, "MX")
            )
            c.registered = bool(c.ns or c.a or c.mx)

    await asyncio.gather(*(check(c) for c in cands))
    registered = [c for c in cands if c.registered]
    for c in registered:  # first pass without age
        score(c, original_ips, original_mx)

    async def age(c: Candidate):
        try:
            data = await http.json("GET", f"https://rdap.org/domain/{c.domain}")
        except Exception:  # noqa: BLE001
            return
        for e in (data or {}).get("events", []):
            if e.get("eventAction") == "registration":
                c.created = e.get("eventDate")
                dt = datetime.fromisoformat(c.created.replace("Z", "+00:00"))
                c.age_days = (now - (dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc))).days

    top = sorted(registered, key=lambda c: -c.risk)[:rdap_top]
    await asyncio.gather(*(age(c) for c in top))
    for c in registered:
        score(c, original_ips, original_mx)
    registered.sort(key=lambda c: (-c.risk, c.domain))

    rep.data = {"generated": len(cands), "registered": len(registered), "candidates": [asdict(c) for c in registered]}
    for c in registered:
        if c.risk >= 70:
            rep.add("high", f"{c.domain} ({c.technique})", "; ".join(c.reasons), "dns+rdap")
        elif c.risk >= 40:
            rep.add("medium", f"{c.domain} ({c.technique})", "; ".join(c.reasons), "dns+rdap")
    parked = sum(1 for c in registered if c.risk < 40)
    if parked:
        rep.add(
            "info",
            f"{parked} other look-alikes registered but low risk",
            "Parked, defensively owned, or no mail/web - keep monitoring.",
            "dns",
        )
    return rep
