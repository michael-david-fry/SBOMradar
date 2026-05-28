import json

from bomradar.models import Component
from bomradar.providers.vulnx import VulnxProvider
from bomradar.utils.subprocess_runner import CommandResult


def test_vulnx_provider_parses_json_results(monkeypatch) -> None:
    component = Component(
        name="openssl",
        version="1.1.1k",
        cpe="cpe:2.3:a:openssl:openssl:1.1.1k:*:*:*:*:*:*:*",
        source_format="cyclonedx-json",
    )

    def runner(command: list[str], timeout: int) -> CommandResult:
        assert command[:2] == ["vulnx", "search"]
        return CommandResult(
            0,
            json.dumps(
                {
                    "results": [
                        {
                            "id": "CVE-2021-3711",
                            "severity": "high",
                            "cvss_score": 7.5,
                            "epss_score": 0.42,
                            "kev": False,
                            "public_poc": True,
                            "nuclei_template": True,
                            "summary": "OpenSSL vulnerability",
                            "references": ["https://example.test/CVE-2021-3711"],
                        }
                    ]
                }
            ),
            "",
        )

    provider = VulnxProvider(runner=runner)
    monkeypatch.setattr(provider, "is_installed", lambda: True)

    findings = provider.lookup_component(component)

    assert len(findings) == 1
    assert findings[0].vulnerability_id == "CVE-2021-3711"
    assert findings[0].match_confidence == "exact_cpe_match"
    assert findings[0].priority_score > 0


def test_vulnx_provider_handles_empty_output(monkeypatch) -> None:
    component = Component(name="left-pad", source_format="cyclonedx-json")
    provider = VulnxProvider(runner=lambda command, timeout: CommandResult(0, "", ""))
    monkeypatch.setattr(provider, "is_installed", lambda: True)

    assert provider.lookup_component(component) == []
