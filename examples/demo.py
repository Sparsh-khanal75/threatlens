"""
Offline demo: runs all three modules against SIMULATED data (mocked HTTP + in-memory DNS)
and writes the example reports in this folder. No network access needed.

    python examples/demo.py          # writes .md and .html reports
    python examples/demo.py --show   # also prints them the way the CLI does

All domains/IPs are fictional or from RFC 5737 documentation ranges.
"""

import asyncio
import base64
import sys
from datetime import datetime, timezone
from pathlib import Path

import httpx
import respx

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from tests.conftest import FakeResolver  # noqa: E402
from threatlens import ai, report  # noqa: E402
from threatlens.core import Cache, Config, Http  # noqa: E402
from threatlens.enrich import VT, run_enrichment  # noqa: E402
from threatlens.ioc import extract  # noqa: E402
from threatlens.recon import run_recon  # noqa: E402
from threatlens.typosquat import run_typosquat  # noqa: E402

NOW = datetime(2026, 11, 20, tzinfo=timezone.utc)
OUT = Path(__file__).parent
D = "northwind-demo.com"
CFG = Config(
    virustotal_key="demo", abuseipdb_key="demo", abusech_key="demo", cache_path="", ollama_url="http://127.0.0.1:9"
)  # unreachable on purpose -> template summary


def mock_internet(router: respx.MockRouter) -> FakeResolver:
    # ---- recon -----------------------------------------------------------------------
    router.get(f"https://rdap.org/domain/{D}").mock(
        return_value=httpx.Response(
            200,
            json={
                "events": [
                    {"eventAction": "registration", "eventDate": "2011-06-14T00:00:00Z"},
                    {"eventAction": "expiration", "eventDate": "2027-06-14T00:00:00Z"},
                ],
                "entities": [
                    {"roles": ["registrar"], "vcardArray": ["vcard", [["fn", {}, "text", "Example Registrar, Inc."]]]}
                ],
                "nameservers": [{"ldhName": "ns1.dns-host.example"}, {"ldhName": "ns2.dns-host.example"}],
            },
        )
    )
    router.get("https://crt.sh/").mock(
        return_value=httpx.Response(
            200,
            json=[
                {"name_value": f"www.{D}\nmail.{D}"},
                {"name_value": f"vpn.{D}"},
                {"name_value": f"staging.{D}"},
                {"name_value": f"jenkins.{D}"},
                {"name_value": f"promo.{D}"},
                {"name_value": f"*.cdn.{D}"},
                {"name_value": f"old-shop.{D}"},
            ],
        )
    )
    router.get(f"https://{D}/").mock(
        return_value=httpx.Response(
            200, headers={"server": "Apache/2.4.41 (Ubuntu)", "x-content-type-options": "nosniff"}
        )
    )
    # ---- ioc enrichment --------------------------------------------------------------
    url = "http://northwind-invoices.top/pay/inv88213.php"
    uid = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
    router.get(f"{VT}/urls/{uid}").mock(
        return_value=httpx.Response(
            200,
            json={
                "data": {
                    "attributes": {
                        "last_analysis_stats": {"malicious": 9, "suspicious": 2, "harmless": 55, "undetected": 23}
                    }
                }
            },
        )
    )
    router.post("https://urlhaus-api.abuse.ch/v1/url/").mock(
        return_value=httpx.Response(
            200,
            json={
                "query_status": "ok",
                "threat": "malware_download",
                "url_status": "online",
                "tags": ["exe", "AgentTesla"],
            },
        )
    )
    router.get("https://rdap.org/domain/northwind-invoices.top").mock(
        return_value=httpx.Response(
            200, json={"events": [{"eventAction": "registration", "eventDate": "2026-11-16T09:12:00Z"}]}
        )
    )
    ip = "203.0.113.77"
    router.get(f"{VT}/ip_addresses/{ip}").mock(
        return_value=httpx.Response(
            200,
            json={
                "data": {
                    "attributes": {
                        "last_analysis_stats": {"malicious": 2, "suspicious": 1, "harmless": 60, "undetected": 30}
                    }
                }
            },
        )
    )
    router.get("https://api.abuseipdb.com/api/v2/check").mock(
        return_value=httpx.Response(
            200,
            json={
                "data": {
                    "abuseConfidenceScore": 64,
                    "totalReports": 23,
                    "countryCode": "NL",
                    "isp": "Example Hosting BV",
                }
            },
        )
    )
    router.get(f"https://internetdb.shodan.io/{ip}").mock(
        return_value=httpx.Response(
            200,
            json={"ports": [22, 80, 443, 8443], "tags": ["self-signed"], "vulns": ["CVE-2023-48795"], "hostnames": []},
        )
    )
    router.get(f"https://rdap.org/ip/{ip}").mock(
        return_value=httpx.Response(
            200,
            json={
                "name": "EXAMPLE-HOSTING-NET",
                "country": "NL",
                "startAddress": "203.0.113.0",
                "endAddress": "203.0.113.255",
            },
        )
    )
    h = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    router.get(f"{VT}/files/{h}").mock(return_value=httpx.Response(404))
    router.post("https://urlhaus-api.abuse.ch/v1/host/").mock(
        return_value=httpx.Response(200, json={"query_status": "no_results"})
    )
    router.post("https://urlhaus-api.abuse.ch/v1/payload/").mock(
        return_value=httpx.Response(200, json={"query_status": "no_results"})
    )
    router.post("https://threatfox-api.abuse.ch/api/v1/").mock(
        return_value=httpx.Response(200, json={"query_status": "no_result"})
    )
    router.post("http://127.0.0.1:9/api/chat").mock(side_effect=httpx.ConnectError("no ollama in demo"))
    # ---- typosquat -------------------------------------------------------------------
    router.get("https://rdap.org/domain/northwind-demo-login.com").mock(
        return_value=httpx.Response(
            200, json={"events": [{"eventAction": "registration", "eventDate": "2026-11-18T00:00:00Z"}]}
        )
    )
    router.get("https://rdap.org/domain/northwlnd-demo.com").mock(
        return_value=httpx.Response(
            200, json={"events": [{"eventAction": "registration", "eventDate": "2026-08-02T00:00:00Z"}]}
        )
    )
    router.get(url__regex=r"https://rdap\.org/domain/.*").mock(
        return_value=httpx.Response(
            200, json={"events": [{"eventAction": "registration", "eventDate": "2014-01-01T00:00:00Z"}]}
        )
    )

    return FakeResolver(
        {
            (D, "A"): ["198.51.100.20"],
            (D, "MX"): ["10 mail.northwind-demo.com"],
            (D, "NS"): ["ns1.dns-host.example"],
            (D, "TXT"): ["v=spf1 include:_spf.example-mail.net ip4:198.51.100.0/24 ?all"],
            (f"_dmarc.{D}", "TXT"): ["v=DMARC1; p=none; rua=mailto:dmarc@northwind-demo.com"],
            (f"selector1._domainkey.{D}", "TXT"): ["v=DKIM1; k=rsa; p=MIIBIjANBg..."],
            (f"www.{D}", "A"): ["198.51.100.20"],
            (f"mail.{D}", "A"): ["198.51.100.25"],
            (f"vpn.{D}", "A"): ["198.51.100.30"],
            (f"staging.{D}", "A"): ["198.51.100.31"],
            (f"jenkins.{D}", "A"): ["198.51.100.32"],
            (f"cdn.{D}", "CNAME"): ["d111.cloudfront.example"],
            ("d111.cloudfront.example", "A"): ["198.51.100.40"],
            (f"promo.{D}", "CNAME"): ["northwind-promo.herokuapp.com"],  # dangling -> takeover risk
            (f"old-shop.{D}", "CNAME"): ["northwind.myshopify.com"],
            ("northwind.myshopify.com", "A"): ["198.51.100.50"],
            ("northwind-invoices.top", "A"): ["203.0.113.77"],
            ("northwind-demo-login.com", "NS"): ["ns1.cheap-dns.example"],
            ("northwind-demo-login.com", "A"): ["203.0.113.80"],
            ("northwind-demo-login.com", "MX"): ["10 mx.northwind-demo-login.com"],
            ("northwlnd-demo.com", "NS"): ["ns1.cheap-dns.example"],
            ("northwlnd-demo.com", "MX"): ["10 mx.northwlnd-demo.com"],
            ("northwind-demo.net", "NS"): ["ns1.dns-host.example"],
            ("northwind-demo.net", "A"): ["198.51.100.20"],
            ("northwind-demo.xyz", "NS"): ["ns1.parking.example"],
        }
    )


async def tls(_domain):
    return {"issuer": "Example CA", "expires": "2027-02-01T00:00:00+00:00"}


async def main():
    with respx.mock(assert_all_called=False) as router:
        res = mock_internet(router)
        async with Http(CFG, Cache(None, 0)) as http:
            recon = await run_recon(D, http, res, now=NOW, tls_fn=tls)
            text = OUT.joinpath("phishing_alert.txt").read_text()
            iocs = await run_enrichment(extract(text), http, res, CFG, now=NOW)
            squat = await run_typosquat(D, http, res, now=NOW)
            for rep, name in ((recon, "recon"), (iocs, "ioc"), (squat, "typosquat")):
                await ai.summarise(rep, CFG)
                rep.errors = [e for e in rep.errors if not e.startswith("ollama")]
                rep.summary_source = "template (run with Ollama for an LLM-written briefing)"
                OUT.joinpath(f"{name}_report.md").write_text(
                    "> **Demo report generated from simulated data** (`python examples/demo.py`).\n\n"
                    + report.to_markdown(rep),
                    encoding="utf-8",
                )
                OUT.joinpath(f"{name}_report.html").write_text(
                    report.to_html(rep, banner="Demo report generated from simulated data (python examples/demo.py)"),
                    encoding="utf-8",
                )
                print(f"wrote examples/{name}_report.md/.html ({len(rep.findings)} findings)")
                if "--show" in sys.argv:  # render exactly as the CLI does
                    from threatlens.cli import _show

                    _show(rep)


if __name__ == "__main__":
    asyncio.run(main())
