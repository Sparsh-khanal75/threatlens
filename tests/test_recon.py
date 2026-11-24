import httpx
import respx

from threatlens.core import Report
from threatlens.recon import analyse_dmarc, analyse_spf, run_recon

from .conftest import NOW, FakeResolver

D = "acme-example.com"
RDAP = {
    "events": [
        {"eventAction": "registration", "eventDate": "2015-03-01T00:00:00Z"},
        {"eventAction": "expiration", "eventDate": "2026-12-05T00:00:00Z"},
    ],
    "entities": [{"roles": ["registrar"], "vcardArray": ["vcard", [["fn", {}, "text", "Example Registrar"]]]}],
    "nameservers": [{"ldhName": "NS1.EXAMPLE.NET"}],
    "status": ["active"],
}
CRT = [
    {"name_value": "www.acme-example.com\napi.acme-example.com"},
    {"name_value": "*.dev.acme-example.com"},
    {"name_value": "shop.acme-example.com"},
    {"name_value": "jenkins.acme-example.com"},
    {"name_value": "unrelated.org"},
]


def dns():
    return FakeResolver(
        {
            (D, "A"): ["198.51.100.10"],
            (D, "MX"): ["10 mx.acme-example.com"],
            (D, "NS"): ["ns1.example.net"],
            (D, "TXT"): ["v=spf1 include:_spf.google.com ~all", "google-site-verification=abc"],
            (f"_dmarc.{D}", "TXT"): ["v=DMARC1; p=none"],
            (f"www.{D}", "A"): ["198.51.100.10"],
            (f"api.{D}", "A"): ["198.51.100.11"],
            (f"dev.{D}", "A"): ["198.51.100.12"],
            (f"jenkins.{D}", "A"): ["198.51.100.13"],
            (f"shop.{D}", "CNAME"): ["acme-shop.herokuapp.com"],  # dangling: target has no A record
        }
    )


async def fake_tls(domain):
    return {"issuer": "Let's Encrypt", "expires": "2026-11-30T00:00:00+00:00"}


@respx.mock
async def test_full_recon(http):
    respx.get(f"https://rdap.org/domain/{D}").mock(return_value=httpx.Response(200, json=RDAP))
    respx.get("https://crt.sh/").mock(return_value=httpx.Response(200, json=CRT))
    respx.get(f"https://{D}/").mock(return_value=httpx.Response(200, headers={"server": "nginx/1.18.0"}))
    rep = await run_recon(D, http, dns(), now=NOW, tls_fn=fake_tls)
    titles = " | ".join(f.title for f in rep.findings)
    assert "Possible subdomain takeover: shop.acme-example.com" in titles
    assert "DMARC policy is p=none" in titles
    assert "SPF softfail" in titles
    assert "TLS certificate expires in 10 days" in titles
    assert "Domain expires in 15 days" in titles
    assert "HSTS not set" in titles and "Server version disclosed" in titles
    sensitive = next(f for f in rep.findings if "sensitive names" in f.title)
    assert "jenkins" in sensitive.detail and "dev" in sensitive.detail
    assert rep.data["rdap"]["registrar"] == "Example Registrar"
    assert rep.data["subdomains"]["from_ct_logs"] == 5 and rep.data["subdomains"]["live"] == 5
    assert not rep.errors


@respx.mock
async def test_recon_survives_source_failures(http):
    respx.get(url__regex=r".*").mock(side_effect=httpx.ConnectError("offline"))
    rep = await run_recon(D, http, FakeResolver(), now=NOW, tls_fn=fake_tls)
    assert any("rdap" in e for e in rep.errors) and any("crt.sh" in e for e in rep.errors)
    assert any(f.title == "Domain has no DNS records" for f in rep.findings)


def test_spf_and_dmarc_rules():
    r = Report("recon", "x")
    analyse_spf(["v=spf1 +all"], r)
    analyse_dmarc(["v=DMARC1; p=reject; rua=mailto:d@x.com"], r)
    assert [f.severity for f in r.findings] == ["critical"]
    r2 = Report("recon", "x")
    analyse_spf([], r2)
    analyse_dmarc([], r2)
    assert {f.title for f in r2.findings} == {"No SPF record", "No DMARC record"}


class DownResolver(FakeResolver):
    async def query(self, name, rtype):
        from threatlens.core import DNSFailure

        raise DNSFailure("timeout")


@respx.mock
async def test_dns_outage_is_not_reported_as_missing_records(http):
    respx.get(url__regex=r".*").mock(side_effect=httpx.ConnectError("offline"))
    rep = await run_recon(D, http, DownResolver(), now=NOW, tls_fn=fake_tls)
    titles = {f.title for f in rep.findings}
    assert "No SPF record" not in titles and "No DMARC record" not in titles
    assert any("DNS lookups failed" in e for e in rep.errors)


@respx.mock
async def test_nonexistent_domain_does_not_produce_email_findings(http):
    respx.get(url__regex=r".*rdap.*|.*crt.sh.*").mock(return_value=httpx.Response(404))
    respx.get(url__regex=r"https://no-such.*").mock(side_effect=httpx.ConnectError("NXDOMAIN"))

    async def no_tls(domain):
        return {"error": "gaierror"}

    rep = await run_recon("no-such-domain-xyz.com", http, FakeResolver(), now=NOW, tls_fn=no_tls)
    assert [f.title for f in rep.findings] == ["Domain has no DNS records"]
