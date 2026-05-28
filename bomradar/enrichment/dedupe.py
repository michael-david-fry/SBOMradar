from __future__ import annotations

from bomradar.models import VulnerabilityFinding


def dedupe_findings(findings: list[VulnerabilityFinding]) -> list[VulnerabilityFinding]:
    seen: set[tuple[str, str, str | None]] = set()
    deduped: list[VulnerabilityFinding] = []
    for finding in findings:
        key = (finding.component_name, finding.vulnerability_id, finding.component_version)
        if key in seen:
            continue
        seen.add(key)
        deduped.append(finding)
    return deduped
