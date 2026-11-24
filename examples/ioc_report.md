> **Demo report generated from simulated data** (`python examples/demo.py`).

# ThreatLens ioc report: `3 indicator(s)`

*Generated 2026-11-24T05:29:08Z by ThreatLens 0.1.0*

## Analyst summary
*Source: template (run with Ollama for an LLM-written briefing)*

**Bottom line:** Enrichment of 3 indicator(s) produced 3 findings; highest severity is **critical** (1 critical, 1 medium, 1 info).

**Key risks**
- [CRITICAL] url hxxp://northwind-invoices[.]top/pay/inv88213[.]php is malicious
- [MEDIUM] ipv4 203[.]0[.]113[.]77 is suspicious

## Findings

| Severity | Finding | Detail | Source |
|---|---|---|---|
| 🟣 critical | url hxxp://northwind-invoices[.]top/pay/inv88213[.]php is malicious | virustotal: 9/89 engines malicious, 2 suspicious; urlhaus: listed: malware_download (online); rdap+dns: domain only 3 days old | enrichment |
| 🟠 medium | ipv4 203[.]0[.]113[.]77 is suspicious | virustotal: 2/93 engines malicious, 1 suspicious; abuseipdb: abuse confidence 64%, 23 reports in 90 days | enrichment |
| 🔵 info | sha256 e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855: no data | No provider returned information. | enrichment |

## Indicators

| Verdict | Score | Type | Indicator | Evidence |
|---|---|---|---|---|
| **malicious** | 100 | url | `hxxp://northwind-invoices[.]top/pay/inv88213[.]php` | virustotal: malicious; urlhaus: malicious; threatfox: no_data; rdap+dns: suspicious |
| **suspicious** | 30 | ipv4 | `203[.]0[.]113[.]77` | virustotal: suspicious; abuseipdb: suspicious; urlhaus: no_data; threatfox: no_data; shodan-internetdb: clean; rdap-ip: clean |
| **unknown** | 0 | sha256 | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` | virustotal: no_data; urlhaus: no_data; threatfox: no_data |
