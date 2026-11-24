import base64

import httpx
import respx

from threatlens.core import Config
from threatlens.enrich import VT, Evidence, combine, run_enrichment
from threatlens.ioc import classify

from .conftest import NOW, FakeResolver

BAD_URL = "http://login-paypa1.com/verify"
BAD_IP = "203.0.113.66"


def vt_stats(mal, sus=0, harmless=60):
    return {
        "data": {
            "attributes": {
                "last_analysis_stats": {"malicious": mal, "suspicious": sus, "harmless": harmless, "undetected": 10}
            }
        }
    }


@respx.mock
async def test_malicious_url_and_ip(http, cfg):
    url_id = base64.urlsafe_b64encode(BAD_URL.encode()).decode().rstrip("=")
    respx.get(f"{VT}/urls/{url_id}").mock(return_value=httpx.Response(200, json=vt_stats(12)))
    respx.get(f"{VT}/ip_addresses/{BAD_IP}").mock(return_value=httpx.Response(200, json=vt_stats(1)))
    respx.post("https://urlhaus-api.abuse.ch/v1/url/").mock(
        return_value=httpx.Response(
            200, json={"query_status": "ok", "threat": "malware_download", "url_status": "online", "tags": ["exe"]}
        )
    )
    respx.post("https://urlhaus-api.abuse.ch/v1/host/").mock(
        return_value=httpx.Response(200, json={"query_status": "no_results"})
    )
    respx.post("https://threatfox-api.abuse.ch/api/v1/").mock(
        return_value=httpx.Response(
            200,
            json={
                "query_status": "ok",
                "data": [
                    {
                        "malware_printable": "AsyncRAT",
                        "threat_type": "botnet_cc",
                        "confidence_level": 100,
                        "first_seen": "2026-11-01",
                    }
                ],
            },
        )
    )
    respx.get("https://api.abuseipdb.com/api/v2/check").mock(
        return_value=httpx.Response(
            200, json={"data": {"abuseConfidenceScore": 88, "totalReports": 41, "countryCode": "NL", "isTor": False}}
        )
    )
    respx.get(f"https://internetdb.shodan.io/{BAD_IP}").mock(
        return_value=httpx.Response(
            200, json={"ports": [22, 443], "tags": ["c2"], "vulns": ["CVE-2023-0001"], "hostnames": []}
        )
    )
    respx.get(f"https://rdap.org/ip/{BAD_IP}").mock(
        return_value=httpx.Response(
            200,
            json={
                "name": "EXAMPLE-HOSTING",
                "country": "NL",
                "startAddress": "203.0.113.0",
                "endAddress": "203.0.113.255",
            },
        )
    )
    respx.get("https://rdap.org/domain/login-paypa1.com").mock(
        return_value=httpx.Response(
            200, json={"events": [{"eventAction": "registration", "eventDate": "2026-11-15T00:00:00Z"}]}
        )
    )

    rep = await run_enrichment([classify(BAD_URL), classify(BAD_IP)], http, FakeResolver(), cfg, now=NOW)
    by = {r["ioc"]: r for r in rep.data["results"]}
    url, ip = by[BAD_URL], by[BAD_IP]
    assert url["verdict"] == "malicious" and url["score"] == 100  # VT + URLhaus + ThreatFox + 5-day-old domain
    assert ip["verdict"] == "malicious"  # AbuseIPDB 88% + ThreatFox
    statuses = {e["provider"]: e["status"] for e in url["evidence"]}
    assert statuses["rdap+dns"] == "suspicious"  # 5 days old
    assert rep.findings[0].severity == "critical"
    assert "hxxp://login-paypa1[.]com/verify" in rep.findings[0].title


@respx.mock
async def test_no_keys_keyless_sources_only(http):
    cfg = Config(cache_path="")
    respx.get("https://internetdb.shodan.io/192.0.2.1").mock(
        return_value=httpx.Response(404, json={"detail": "No information"})
    )
    respx.get("https://rdap.org/ip/192.0.2.1").mock(
        return_value=httpx.Response(
            200, json={"name": "TEST-NET-1", "country": None, "startAddress": "192.0.2.0", "endAddress": "192.0.2.255"}
        )
    )
    rep = await run_enrichment([classify("192.0.2.1")], http, FakeResolver(), cfg, now=NOW)
    r = rep.data["results"][0]
    assert r["verdict"] == "clean"
    assert set(rep.data["providers_without_keys"]) == {"virustotal", "abuseipdb", "urlhaus", "threatfox"}


@respx.mock
async def test_provider_error_is_isolated(http, cfg):
    respx.route(url__regex=r".*virustotal.*").mock(return_value=httpx.Response(401, json={}))
    respx.route(url__regex=r".*").mock(return_value=httpx.Response(404))
    rep = await run_enrichment([classify("d41d8cd98f00b204e9800998ecf8427e")], http, FakeResolver(), cfg, now=NOW)
    ev = {e["provider"]: e["status"] for e in rep.data["results"][0]["evidence"]}
    assert ev["virustotal"] == "error"


def test_combine():
    assert combine([Evidence("a", "malicious"), Evidence("b", "malicious")]) == ("malicious", 90)
    assert combine([Evidence("a", "suspicious")]) == ("suspicious", 30)
    assert combine([Evidence("a", "clean"), Evidence("b", "no_data")]) == ("clean", 0)
    assert combine([Evidence("a", "skipped"), Evidence("b", "error")]) == ("unknown", 0)
