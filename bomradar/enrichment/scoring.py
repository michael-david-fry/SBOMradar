from __future__ import annotations

from bomradar.models import MatchConfidence, VulnerabilityFinding


SEVERITY_ORDER = {"unknown": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def severity_rank(severity: str | None) -> int:
    return SEVERITY_ORDER.get((severity or "unknown").lower(), 0)


def priority_score(finding: VulnerabilityFinding) -> int:
    score = 0
    severity = (finding.severity or "unknown").lower()
    if severity == "critical":
        score += 40
    elif severity == "high":
        score += 30
    elif severity == "medium":
        score += 15
    elif severity == "low":
        score += 5
    if finding.kev:
        score += 25
    if finding.epss_score is not None:
        if finding.epss_score >= 0.7:
            score += 15
        elif finding.epss_score >= 0.3:
            score += 8
    if finding.public_poc:
        score += 10
    if finding.nuclei_template:
        score += 10
    if finding.match_confidence == MatchConfidence.EXACT_CPE_MATCH:
        score += 10
    elif finding.match_confidence == MatchConfidence.PURL_COMPONENT_MATCH:
        score += 8
    elif finding.match_confidence == MatchConfidence.NAME_VERSION_MATCH:
        score += 5
    elif finding.match_confidence == MatchConfidence.NAME_ONLY_MATCH:
        score += 2
    return score
