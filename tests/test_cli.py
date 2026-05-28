import json
from pathlib import Path

from typer.testing import CliRunner

from bomradar.cli import app
from bomradar.models import VulnerabilityFinding
from bomradar.providers.vulnx import VulnxProvider


runner = CliRunner()
OUTPUT_DIR = Path("test-output")


def test_cli_scan_writes_report(monkeypatch) -> None:
    def fake_lookup(self: VulnxProvider, component):
        if component.name == "lodash":
            return [
                VulnerabilityFinding(
                    component_name=component.name,
                    component_version=component.version,
                    purl=component.purl,
                    vulnerability_id="CVE-2021-23337",
                    cve_ids=["CVE-2021-23337"],
                    severity="high",
                    match_confidence="purl_component_match",
                )
            ]
        return []

    monkeypatch.setattr(VulnxProvider, "lookup_component", fake_lookup)
    monkeypatch.setattr(VulnxProvider, "is_installed", lambda self: True)
    output = OUTPUT_DIR / "cli-report.json"

    result = runner.invoke(
        app,
        ["scan", "tests/fixtures/cyclonedx-simple.json", "--json", str(output), "--quiet"],
    )

    assert result.exit_code == 0
    data = json.loads(output.read_text(encoding="utf-8"))
    assert data["scan_summary"]["component_count"] == 3
    assert data["scan_summary"]["finding_count"] == 1


def test_cli_fail_on_returns_one(monkeypatch) -> None:
    monkeypatch.setattr(
        VulnxProvider,
        "lookup_component",
        lambda self, component: [
            VulnerabilityFinding(
                component_name=component.name,
                vulnerability_id="CVE-TEST",
                severity="critical",
            )
        ]
        if component.name == "lodash"
        else [],
    )
    monkeypatch.setattr(VulnxProvider, "is_installed", lambda self: True)

    result = runner.invoke(
        app,
        ["scan", "tests/fixtures/cyclonedx-simple.json", "--fail-on", "critical", "--quiet"],
    )

    assert result.exit_code == 1


def test_cli_prompts_to_install_vulnx(monkeypatch) -> None:
    installed = {}

    monkeypatch.setattr(VulnxProvider, "is_installed", lambda self: False)
    monkeypatch.setattr(VulnxProvider, "lookup_component", lambda self, component: [])
    monkeypatch.setattr(
        "bomradar.cli.install_vulnx",
        lambda: installed.setdefault("path", Path("C:/Users/example/go/bin/vulnx.exe")),
    )

    result = runner.invoke(
        app,
        ["scan", "tests/fixtures/cyclonedx-simple.json"],
        input="y\n",
    )

    assert result.exit_code == 0
    assert installed["path"] == Path("C:/Users/example/go/bin/vulnx.exe")
