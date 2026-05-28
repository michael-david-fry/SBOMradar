from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum

from pydantic import BaseModel, Field


class SourceFormat(StrEnum):
    CYCLONEDX_JSON = "cyclonedx-json"
    SPDX_JSON = "spdx-json"


class MatchConfidence(StrEnum):
    EXACT_CPE_MATCH = "exact_cpe_match"
    PURL_COMPONENT_MATCH = "purl_component_match"
    NAME_VERSION_MATCH = "name_version_match"
    NAME_ONLY_MATCH = "name_only_match"
    MANUAL_REVIEW_REQUIRED = "manual_review_required"


class Component(BaseModel):
    name: str
    version: str | None = None
    purl: str | None = None
    cpe: str | None = None
    ecosystem: str | None = None
    bom_ref: str | None = None
    source_format: str
    supplier: str | None = None
    dependency_type: str | None = None


class VulnerabilityFinding(BaseModel):
    component_name: str
    component_version: str | None = None
    purl: str | None = None
    cpe: str | None = None
    vulnerability_id: str
    cve_ids: list[str] = Field(default_factory=list)
    severity: str | None = None
    cvss_score: float | None = None
    epss_score: float | None = None
    kev: bool | None = None
    public_poc: bool | None = None
    nuclei_template: bool | None = None
    summary: str | None = None
    references: list[str] = Field(default_factory=list)
    source: str = "vulnx"
    match_confidence: str = MatchConfidence.MANUAL_REVIEW_REQUIRED
    recommendation: str | None = None
    priority_score: int = 0


class ScanSummary(BaseModel):
    component_count: int = 0
    scanned_component_count: int = 0
    unscannable_component_count: int = 0
    finding_count: int = 0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    unknown_count: int = 0


class ScanReport(BaseModel):
    tool: str = "bomradar"
    scan_summary: ScanSummary
    findings: list[VulnerabilityFinding] = Field(default_factory=list)
    unscannable_components: list[Component] = Field(default_factory=list)
    scanned_components: list[Component] = Field(default_factory=list)
    source_sbom: str | None = None
    timestamp: str = Field(default_factory=lambda: datetime.now(UTC).isoformat())


class BomradarError(Exception):
    """Base scanner error."""


class InvalidSbomError(BomradarError):
    """Raised when an SBOM cannot be parsed."""


class ProviderError(BomradarError):
    """Raised when a vulnerability provider cannot complete a lookup."""
