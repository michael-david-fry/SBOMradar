from __future__ import annotations

import json
import shutil
import subprocess
from typing import Any

from bomradar.enrichment.scoring import priority_score
from bomradar.models import Component, MatchConfidence, ProviderError, VulnerabilityFinding
from bomradar.normalizers.purl import parse_purl
from bomradar.utils.subprocess_runner import CommandResult, Runner, run_command


class VulnxProvider:
    def __init__(self, runner: Runner = run_command, binary: str = "vulnx") -> None:
        self.runner = runner
        self.binary = binary

    def is_installed(self) -> bool:
        return shutil.which(self.binary) is not None

    def ensure_installed(self) -> None:
        if not self.is_installed():
            raise ProviderError(
                "ProjectDiscovery vulnx is not installed or is not on PATH. "
                "Install vulnx and retry, or run tests with the provider mocked."
            )

    def lookup_component(self, component: Component) -> list[VulnerabilityFinding]:
        self.ensure_installed()
        command, confidence = self._build_lookup_command(component)
        if not command:
            return []
        result = self._run(command)
        if result.returncode != 0:
            if _looks_like_empty_or_rate_limited(result.stderr):
                return []
            raise ProviderError(f"vulnx lookup failed for {component.name}: {result.stderr.strip()}")
        return self._parse_findings(result.stdout, component, confidence)

    def explain(self, vulnerability_id: str) -> str:
        self.ensure_installed()
        result = self._run([self.binary, "id", vulnerability_id, "-json"])
        if result.returncode != 0:
            fallback = self._run([self.binary, "id", vulnerability_id])
            if fallback.returncode != 0:
                raise ProviderError(f"vulnx explain failed: {fallback.stderr.strip()}")
            return fallback.stdout.strip()
        return _json_summary(result.stdout) or result.stdout.strip()

    def _run(self, command: list[str]) -> CommandResult:
        try:
            return self.runner(command, 90)
        except FileNotFoundError as exc:
            raise ProviderError("ProjectDiscovery vulnx is not installed or is not on PATH.") from exc
        except subprocess.TimeoutExpired as exc:
            raise ProviderError("vulnx command timed out.") from exc

    def _build_lookup_command(
        self, component: Component
    ) -> tuple[list[str] | None, MatchConfidence]:
        if component.cpe:
            return (
                [self.binary, "search", "-q", component.cpe, "-json"],
                MatchConfidence.EXACT_CPE_MATCH,
            )
        parsed_purl = parse_purl(component.purl)
        if parsed_purl:
            query = f"{parsed_purl.type}:{parsed_purl.name}"
            if parsed_purl.version:
                query = f"{query}@{parsed_purl.version}"
            return ([self.binary, "search", "-q", query, "-json"], MatchConfidence.PURL_COMPONENT_MATCH)
        if component.name and component.version:
            return (
                [self.binary, "search", "-q", f"{component.name} {component.version}", "-json"],
                MatchConfidence.NAME_VERSION_MATCH,
            )
        if component.name:
            return ([self.binary, "search", "-q", component.name, "-json"], MatchConfidence.NAME_ONLY_MATCH)
        return (None, MatchConfidence.MANUAL_REVIEW_REQUIRED)

    def _parse_findings(
        self,
        stdout: str,
        component: Component,
        confidence: MatchConfidence,
    ) -> list[VulnerabilityFinding]:
        records = _load_json_records(stdout)
        findings: list[VulnerabilityFinding] = []
        for record in records:
            vulnerability_id = _first_string(record, ["id", "vulnerability_id", "cve", "cve_id"])
            cve_ids = _list_strings(record, ["cve_ids", "cves", "cve"])
            if not vulnerability_id and cve_ids:
                vulnerability_id = cve_ids[0]
            if not vulnerability_id:
                continue
            finding = VulnerabilityFinding(
                component_name=component.name,
                component_version=component.version,
                purl=component.purl,
                cpe=component.cpe,
                vulnerability_id=vulnerability_id,
                cve_ids=cve_ids or ([vulnerability_id] if vulnerability_id.startswith("CVE-") else []),
                severity=_first_string(record, ["severity", "cvss_severity", "risk"]),
                cvss_score=_first_float(record, ["cvss_score", "cvss", "score"]),
                epss_score=_first_float(record, ["epss_score", "epss"]),
                kev=_first_bool(record, ["kev", "cisa_kev", "is_kev"]),
                public_poc=_first_bool(record, ["public_poc", "poc", "exploit_available"]),
                nuclei_template=_first_bool(record, ["nuclei_template", "template", "has_template"]),
                summary=_first_string(record, ["summary", "description", "title"]),
                references=_list_strings(record, ["references", "refs", "reference"]),
                source="vulnx",
                match_confidence=confidence,
                recommendation=_first_string(record, ["recommendation", "remediation", "fix"]),
            )
            finding.priority_score = priority_score(finding)
            findings.append(finding)
        return findings


def _load_json_records(stdout: str) -> list[dict[str, Any]]:
    text = stdout.strip()
    if not text:
        return []
    try:
        parsed = json.loads(text)
        if isinstance(parsed, list):
            return [item for item in parsed if isinstance(item, dict)]
        if isinstance(parsed, dict):
            for key in ("results", "vulnerabilities", "data", "matches"):
                if isinstance(parsed.get(key), list):
                    return [item for item in parsed[key] if isinstance(item, dict)]
            return [parsed]
    except json.JSONDecodeError:
        records = []
        for line in text.splitlines():
            try:
                item = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(item, dict):
                records.append(item)
        return records
    return []


def _json_summary(stdout: str) -> str | None:
    records = _load_json_records(stdout)
    if not records:
        return None
    record = records[0]
    title = _first_string(record, ["id", "cve", "cve_id", "title"]) or "vulnerability"
    severity = _first_string(record, ["severity", "risk"])
    summary = _first_string(record, ["summary", "description"])
    lines = [title]
    if severity:
        lines.append(f"Severity: {severity}")
    if summary:
        lines.append(summary)
    refs = _list_strings(record, ["references", "refs"])
    if refs:
        lines.append("References:")
        lines.extend(f"- {ref}" for ref in refs)
    return "\n".join(lines)


def _looks_like_empty_or_rate_limited(stderr: str) -> bool:
    lowered = stderr.lower()
    return any(token in lowered for token in ("no result", "not found", "rate limit", "too many requests"))


def _first_string(record: dict[str, Any], keys: list[str]) -> str | None:
    for key in keys:
        value = record.get(key)
        if isinstance(value, str) and value:
            return value
    return None


def _first_float(record: dict[str, Any], keys: list[str]) -> float | None:
    for key in keys:
        value = record.get(key)
        if isinstance(value, (float, int)):
            return float(value)
        if isinstance(value, str):
            try:
                return float(value)
            except ValueError:
                continue
    return None


def _first_bool(record: dict[str, Any], keys: list[str]) -> bool | None:
    for key in keys:
        value = record.get(key)
        if isinstance(value, bool):
            return value
        if isinstance(value, str) and value.lower() in {"true", "false", "yes", "no"}:
            return value.lower() in {"true", "yes"}
    return None


def _list_strings(record: dict[str, Any], keys: list[str]) -> list[str]:
    for key in keys:
        value = record.get(key)
        if isinstance(value, str) and value:
            return [value]
        if isinstance(value, list):
            return [str(item) for item in value if item]
    return []
