> **Demo report generated from simulated data** (`python examples/demo.py`).

# ThreatLens recon report: `northwind-demo.com`

*Generated 2026-11-24T05:29:08Z by ThreatLens 0.1.0*

## Analyst summary
*Source: template (run with Ollama for an LLM-written briefing)*

**Bottom line:** Recon of `northwind-demo.com` produced 10 findings; highest severity is **high** (1 high, 4 medium, 5 low).

**Key risks**
- [HIGH] Possible subdomain takeover: promo.northwind-demo.com
- [MEDIUM] SPF neutral (?all)
- [MEDIUM] DMARC policy is p=none
- [MEDIUM] HSTS not set - browsers may be downgraded to HTTP
- [MEDIUM] 4 internet-facing hosts with sensitive names

## Findings

| Severity | Finding | Detail | Source |
|---|---|---|---|
| 🔴 high | Possible subdomain takeover: promo.northwind-demo.com | CNAME -> northwind-promo.herokuapp.com, which no longer resolves. Anyone may be able to claim it. | dns |
| 🟠 medium | SPF neutral (?all) | Unauthorised senders are not rejected. | dns |
| 🟠 medium | DMARC policy is p=none | Monitoring only - spoofed mail is not blocked. | dns |
| 🟠 medium | HSTS not set - browsers may be downgraded to HTTP |  | https |
| 🟠 medium | 4 internet-facing hosts with sensitive names | jenkins.northwind-demo.com, old-shop.northwind-demo.com, staging.northwind-demo.com, vpn.northwind-demo.com | crt.sh |
| 🟡 low | No CAA record | Any certificate authority may issue certificates for this domain. | dns |
| 🟡 low | No Content-Security-Policy - weaker protection against XSS |  | https |
| 🟡 low | Referrer-Policy missing - full URLs may leak to third parties |  | https |
| 🟡 low | No clickjacking protection | Neither X-Frame-Options nor CSP frame-ancestors set. | https |
| 🟡 low | Server version disclosed | Apache/2.4.41 (Ubuntu) | https |

## Registration

- Registrar: Example Registrar, Inc.
- Created: 2011-06-14T00:00:00Z (5638 days ago)
- Expires: 2027-06-14T00:00:00Z
- Name servers: ns1.dns-host.example, ns2.dns-host.example

## DNS

- **A**: 198.51.100.20
- **AAAA**: —
- **MX**: 10 mail.northwind-demo.com
- **NS**: ns1.dns-host.example
- **TXT**: v=spf1 include:_spf.example-mail.net ip4:198.51.100.0/24 ?all
- **CAA**: —

## Email security

- SPF: `v=spf1 include:_spf.example-mail.net ip4:198.51.100.0/24 ?all`
- DMARC: `v=DMARC1; p=none; rua=mailto:dmarc@northwind-demo.com`
- DKIM selectors found: selector1

## Attack surface (certificate transparency)

8 hostnames in CT logs, 8 resolve.

| Host | A | CNAME |
|---|---|---|
| cdn.northwind-demo.com |  | d111.cloudfront.example |
| jenkins.northwind-demo.com | 198.51.100.32 |  |
| mail.northwind-demo.com | 198.51.100.25 |  |
| old-shop.northwind-demo.com |  | northwind.myshopify.com |
| promo.northwind-demo.com |  | northwind-promo.herokuapp.com |
| staging.northwind-demo.com | 198.51.100.31 |  |
| vpn.northwind-demo.com | 198.51.100.30 |  |
| www.northwind-demo.com | 198.51.100.20 |  |
