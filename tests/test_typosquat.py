import httpx
import respx

from threatlens.typosquat import generate, run_typosquat

from .conftest import NOW, FakeResolver


def test_generation_covers_core_techniques():
    cands = dict(generate("paypal.com"))
    assert cands["paypa1.com"] == "homoglyph"
    assert cands["papyal.com"] == "transposition"
    assert cands["paypl.com"] == "omission"
    assert cands["paypal.net"] == "TLD swap"
    assert cands["paypal-login.com"] == "brand + lure word"
    assert "paypal.com" not in cands
    assert all(c.count(".") == 1 for c in cands)
    m = dict(generate("modern.io"))
    assert m["rnodern.io"] == "homoglyph"  # m -> rn


@respx.mock
async def test_monitoring_scores_real_threats_and_ignores_defensive_registrations(http):
    res = FakeResolver(
        {
            ("acme.com", "A"): ["198.51.100.1"],
            ("acme.com", "MX"): ["10 mx.acme.com"],
            # attacker: new, has mail
            ("acme-login.com", "NS"): ["ns1.cheap-host.example"],
            ("acme-login.com", "A"): ["203.0.113.50"],
            ("acme-login.com", "MX"): ["10 mail.acme-login.com"],
            # defensive registration by the brand: same web server
            ("acme.net", "NS"): ["ns1.acme.com"],
            ("acme.net", "A"): ["198.51.100.1"],
            # parked, old
            ("acrne.com", "NS"): ["ns1.parking.example"],
        }
    )
    respx.get("https://rdap.org/domain/acme-login.com").mock(
        return_value=httpx.Response(
            200, json={"events": [{"eventAction": "registration", "eventDate": "2026-11-17T00:00:00Z"}]}
        )
    )
    respx.get(url__regex=r"https://rdap.org/domain/.*").mock(
        return_value=httpx.Response(
            200, json={"events": [{"eventAction": "registration", "eventDate": "2012-01-01T00:00:00Z"}]}
        )
    )
    rep = await run_typosquat("acme.com", http, res, now=NOW)
    cands = {c["domain"]: c for c in rep.data["candidates"]}
    assert set(cands) == {"acme-login.com", "acme.net", "acrne.com"}
    assert cands["acme-login.com"]["risk"] >= 90 and cands["acme-login.com"]["age_days"] == 3
    assert cands["acme.net"]["risk"] == 0
    assert rep.findings[0].severity == "high" and "acme-login.com" in rep.findings[0].title
