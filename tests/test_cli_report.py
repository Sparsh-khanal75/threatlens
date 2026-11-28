from typer.testing import CliRunner

from threatlens import report
from threatlens.cli import app
from threatlens.core import Report


def test_markdown_report_escapes_and_orders():
    r = Report("ioc", "2 indicator(s)")
    r.add("low", "minor", "a|b")
    r.add("critical", "major", "x")
    md = report.to_markdown(r)
    assert md.index("major") < md.index("minor") and "a\\|b" in md
    assert '"severity": "critical"' in report.to_json(r)


def test_cli_version_and_bad_input():
    runner = CliRunner()
    assert "ThreatLens" in runner.invoke(app, ["version"]).output
    res = runner.invoke(app, ["ioc", "definitely not an ioc"])
    assert res.exit_code != 0


def test_html_report_is_self_contained_and_escaped():
    rep = Report(kind="recon", target="example.com")
    rep.add("high", "Possible subdomain takeover", "<script>alert(1)</script>", "dns")
    rep.add("low", "No CAA record", "", "dns")
    rep.summary = "Bottom line: fix the takeover."
    rep.summary_source = "template"
    page = report.to_html(rep)
    assert "Domain recon report" in page
    assert "Possible subdomain takeover" in page
    assert "<script>alert(1)</script>" not in page
    assert "Bottom line: fix the takeover." in page
    assert "<script src" not in page and "<link" not in page
