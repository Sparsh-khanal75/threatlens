"""IOC parsing: refang, classify and extract indicators from free text."""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass

HASH_LEN = {32: "md5", 40: "sha1", 64: "sha256"}
DOMAIN_RE = re.compile(r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$", re.I)
URL_RE = re.compile(r"^[a-z][a-z0-9+.-]*://", re.I)
EXTRACT_RE = re.compile(
    r"(?:h(?:tt|xx)ps?://[^\s\"'<>]+)"  # urls (incl. hxxp)
    r"|\b[a-f0-9]{64}\b|\b[a-f0-9]{40}\b|\b[a-f0-9]{32}\b"  # hashes
    r"|\b\d{1,3}(?:\[?\.\]?\d{1,3}){3}\b"  # ipv4, possibly defanged
    r"|\b(?:[a-z0-9-]+(?:\[\.\]|\.))+[a-z]{2,63}\b",  # domains, possibly defanged
    re.I,
)


@dataclass(frozen=True)
class IOC:
    value: str
    type: str  # ipv4 | ipv6 | domain | url | md5 | sha1 | sha256


def refang(s: str) -> str:
    s = s.strip().strip("<>\"'")
    s = re.sub(r"^hxxp", "http", s, flags=re.I)
    s = re.sub(r"^fxp", "ftp", s, flags=re.I)
    s = s.replace("[.]", ".").replace("(.)", ".").replace("{.}", ".").replace("[dot]", ".")
    s = s.replace("[:]", ":").replace("[://]", "://")
    return s


def defang(s: str) -> str:
    return re.sub(r"^http", "hxxp", s, flags=re.I).replace(".", "[.]")


def classify(raw: str) -> IOC | None:
    v = refang(raw)
    if not v:
        return None
    if URL_RE.match(v):
        return IOC(v, "url")
    try:
        ip = ipaddress.ip_address(v)
        return IOC(str(ip), "ipv4" if ip.version == 4 else "ipv6")
    except ValueError:
        pass
    if re.fullmatch(r"[a-fA-F0-9]+", v) and len(v) in HASH_LEN:
        return IOC(v.lower(), HASH_LEN[len(v)])
    if DOMAIN_RE.match(v):
        return IOC(v.lower().rstrip("."), "domain")
    return None


def extract(text: str) -> list[IOC]:
    """Pull every indicator out of a blob of text (an email, a report, a chat message)."""
    seen, out = set(), []
    for m in EXTRACT_RE.finditer(text):
        ioc = classify(m.group(0).rstrip(".,;)]"))
        if ioc and ioc not in seen:
            seen.add(ioc)
            out.append(ioc)
    # Drop domains that only appear as the host of an extracted URL
    url_hosts = {re.sub(r"^[a-z]+://", "", i.value).split("/")[0].lower() for i in out if i.type == "url"}
    return [i for i in out if not (i.type == "domain" and i.value in url_hosts)]


def registered_domain(host: str) -> str:
    parts = host.lower().strip(".").split(".")
    multi = {"co.uk", "com.au", "co.in", "co.jp", "com.br", "co.nz", "org.uk", "ac.uk", "gov.uk", "com.np", "co.za"}
    if len(parts) >= 3 and ".".join(parts[-2:]) in multi:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])
