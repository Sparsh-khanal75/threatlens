> **Demo report generated from simulated data** (`python examples/demo.py`).

# ThreatLens typosquat report: `northwind-demo.com`

*Generated 2026-11-24T05:29:08Z by ThreatLens 0.1.0*

## Analyst summary
*Source: template (run with Ollama for an LLM-written briefing)*

**Bottom line:** Typosquat scan of `northwind-demo.com` produced 3 findings; highest severity is **high** (2 high, 1 info).

**Key risks**
- [HIGH] northwind-demo-login.com (brand + lure word)
- [HIGH] northwlnd-demo.com (homoglyph)

## Findings

| Severity | Finding | Detail | Source |
|---|---|---|---|
| 🔴 high | northwind-demo-login.com (brand + lure word) | registered; has MX - can send/receive phishing email; hosts a website; registered 2 days ago; brand + lure word - visually deceptive | dns+rdap |
| 🔴 high | northwlnd-demo.com (homoglyph) | registered; has MX - can send/receive phishing email; registered 110 days ago; homoglyph - visually deceptive | dns+rdap |
| 🔵 info | 2 other look-alikes registered but low risk | Parked, defensively owned, or no mail/web - keep monitoring. | dns |

## Registered look-alikes

294 permutations generated, 4 registered.

| Risk | Domain | Technique | MX | A | Age (days) |
|---|---|---|---|---|---|
| 100 | `northwind-demo-login.com` | brand + lure word | yes | 203.0.113.80 | 2 |
| 70 | `northwlnd-demo.com` | homoglyph | yes | — | 110 |
| 20 | `northwind-demo.xyz` | TLD swap | — | — | 4706 |
| 0 | `northwind-demo.net` | TLD swap | — | 198.51.100.20 | 4706 |
