from __future__ import annotations

import json
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.table import Table

from bomradar.enrichment.dedupe import dedupe_findings
from bomradar.enrichment.scoring import severity_rank
from bomradar.models import (
    BomradarError,
    Component,
    InvalidSbomError,
    MatchConfidence,
    ScanReport,
    ScanSummary,
    SourceFormat,
    VulnerabilityFinding,
)
from bomradar.parsers.cyclonedx import parse_cyclonedx_json
from bomradar.parsers.spdx import parse_spdx_json
from bomradar.providers.vulnx import VulnxProvider
from bomradar.reports.csv_report import write_csv_report
from bomradar.reports.html_report import write_html_report
from bomradar.reports.json_report import write_json_report
from bomradar.utils.vulnx_installer import install_vulnx

app = typer.Typer(help="Scan SBOM files for vulnerabilities using ProjectDiscovery vulnx.")
console = Console()


FormatOption = Annotated[
    str,
    typer.Option(
        "--format",
        help="Input format: auto, cyclonedx-json, or spdx-json.",
    ),
]


@app.command()
def scan(
    sbom_path: Annotated[Path, typer.Argument(help="Path to a CycloneDX JSON or SPDX JSON SBOM.")],
    format: FormatOption = "auto",
    json_path: Annotated[Path | None, typer.Option("--json", help="Write JSON report.")] = None,
    csv_path: Annotated[Path | None, typer.Option("--csv", help="Write CSV report.")] = None,
    html_path: Annotated[Path | None, typer.Option("--html", help="Write HTML report.")] = None,
    output_dir: Annotated[Path | None, typer.Option("--output-dir", help="Write reports into a directory.")] = None,
    fail_on: Annotated[
        str | None,
        typer.Option("--fail-on", help="Exit 1 if findings meet severity: low, medium, high, critical."),
    ] = None,
    include_low_confidence: Annotated[
        bool,
        typer.Option("--include-low-confidence", help="Retain low-confidence vulnx matches."),
    ] = True,
    quiet: Annotated[bool, typer.Option("--quiet", help="Suppress console tables.")] = False,
    debug: Annotated[bool, typer.Option("--debug", help="Show provider errors per component.")] = False,
) -> None:
    try:
        report_paths = _resolve_report_paths(output_dir, json_path, csv_path, html_path)
        components = _parse_sbom(sbom_path, format)
        provider = VulnxProvider()
        _ensure_vulnx_ready(provider, quiet)
        report = build_scan_report(
            components=components,
            source_sbom=str(sbom_path),
            include_low_confidence=include_low_confidence,
            debug=debug,
            provider=provider,
        )
        _write_reports(report, report_paths)
        if not quiet:
            _print_report(report, report_paths)
        if _meets_fail_threshold(report.findings, fail_on):
            raise typer.Exit(1)
    except BomradarError as exc:
        if not quiet:
            console.print(f"[red]Scanner error:[/red] {exc}")
        raise typer.Exit(2) from exc


@app.command()
def explain(cve_id: Annotated[str, typer.Argument(help="CVE or vulnerability ID to explain.")]) -> None:
    try:
        provider = VulnxProvider()
        _ensure_vulnx_ready(provider, quiet=False)
        console.print(provider.explain(cve_id))
    except BomradarError as exc:
        console.print(f"[red]Scanner error:[/red] {exc}")
        raise typer.Exit(2) from exc


def build_scan_report(
    components: list[Component],
    source_sbom: str | None,
    include_low_confidence: bool = True,
    debug: bool = False,
    provider: VulnxProvider | None = None,
) -> ScanReport:
    provider = provider or VulnxProvider()
    findings: list[VulnerabilityFinding] = []
    scanned_components: list[Component] = []
    unscannable_components: list[Component] = []

    for component in components:
        if not _can_lookup(component):
            unscannable_components.append(component)
            continue
        try:
            component_findings = provider.lookup_component(component)
        except BomradarError:
            if debug:
                raise
            unscannable_components.append(component)
            continue
        scanned_components.append(component)
        if not include_low_confidence:
            component_findings = [
                finding
                for finding in component_findings
                if finding.match_confidence
                not in {
                    MatchConfidence.NAME_ONLY_MATCH,
                    MatchConfidence.MANUAL_REVIEW_REQUIRED,
                }
            ]
        findings.extend(component_findings)

    findings = sorted(dedupe_findings(findings), key=lambda finding: finding.priority_score, reverse=True)
    summary = _summary(components, scanned_components, unscannable_components, findings)
    return ScanReport(
        scan_summary=summary,
        findings=findings,
        unscannable_components=unscannable_components,
        scanned_components=scanned_components,
        source_sbom=source_sbom,
    )


def _parse_sbom(path: Path, format_name: str) -> list[Component]:
    if not path.exists():
        raise InvalidSbomError(f"SBOM file does not exist: {path}")
    resolved_format = _detect_format(path) if format_name == "auto" else format_name
    if resolved_format == SourceFormat.CYCLONEDX_JSON:
        return parse_cyclonedx_json(path)
    if resolved_format == SourceFormat.SPDX_JSON:
        return parse_spdx_json(path)
    raise InvalidSbomError(f"Unsupported SBOM format: {format_name}")


def _detect_format(path: Path) -> str:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise InvalidSbomError(f"Unable to read SBOM JSON: {exc}") from exc
    if "bomFormat" in data and str(data["bomFormat"]).lower() == "cyclonedx":
        return SourceFormat.CYCLONEDX_JSON
    if "spdxVersion" in data or "SPDXID" in data:
        return SourceFormat.SPDX_JSON
    raise InvalidSbomError("Unable to auto-detect SBOM format.")


def _can_lookup(component: Component) -> bool:
    return bool(component.cpe or component.purl or component.name)


def _summary(
    components: list[Component],
    scanned_components: list[Component],
    unscannable_components: list[Component],
    findings: list[VulnerabilityFinding],
) -> ScanSummary:
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "unknown": 0}
    for finding in findings:
        severity = (finding.severity or "unknown").lower()
        counts[severity if severity in counts else "unknown"] += 1
    return ScanSummary(
        component_count=len(components),
        scanned_component_count=len(scanned_components),
        unscannable_component_count=len(unscannable_components),
        finding_count=len(findings),
        critical_count=counts["critical"],
        high_count=counts["high"],
        medium_count=counts["medium"],
        low_count=counts["low"],
        unknown_count=counts["unknown"],
    )


def _resolve_report_paths(
    output_dir: Path | None,
    json_path: Path | None,
    csv_path: Path | None,
    html_path: Path | None,
) -> dict[str, Path]:
    if output_dir:
        output_dir.mkdir(parents=True, exist_ok=True)
        json_path = json_path or output_dir / "bomradar-report.json"
        csv_path = csv_path or output_dir / "bomradar-report.csv"
        html_path = html_path or output_dir / "bomradar-report.html"
    return {
        key: path
        for key, path in {"json": json_path, "csv": csv_path, "html": html_path}.items()
        if path is not None
    }


def _write_reports(report: ScanReport, report_paths: dict[str, Path]) -> None:
    if "json" in report_paths:
        write_json_report(report, report_paths["json"])
    if "csv" in report_paths:
        write_csv_report(report, report_paths["csv"])
    if "html" in report_paths:
        write_html_report(report, report_paths["html"])


def _ensure_vulnx_ready(provider: VulnxProvider, quiet: bool) -> None:
    if provider.is_installed():
        return
    if quiet:
        provider.ensure_installed()
    install = typer.confirm(
        "ProjectDiscovery vulnx is required but was not found on PATH. "
        "Install it now with `go install github.com/projectdiscovery/vulnx/v2/cmd/vulnx@latest` "
        "and add the Go bin directory to PATH?",
        default=True,
    )
    if not install:
        provider.ensure_installed()
    executable = install_vulnx()
    console.print(f"[green]Installed vulnx:[/green] {executable}")
    console.print("The Go bin directory was added to this process PATH and your user PATH.")


def _print_report(report: ScanReport, report_paths: dict[str, Path]) -> None:
    summary = report.scan_summary
    console.print(
        f"[bold]SBOMradar[/bold] scanned {summary.scanned_component_count}/"
        f"{summary.component_count} components and found {summary.finding_count} findings."
    )
    table = Table(title="Findings")
    table.add_column("Component")
    table.add_column("Vulnerability")
    table.add_column("Severity")
    table.add_column("Priority", justify="right")
    table.add_column("Confidence")
    for finding in report.findings[:25]:
        table.add_row(
            finding.component_name,
            finding.vulnerability_id,
            finding.severity or "unknown",
            str(finding.priority_score),
            finding.match_confidence,
        )
    if report.findings:
        console.print(table)
    if report.unscannable_components:
        console.print(f"[yellow]{summary.unscannable_component_count} components were unscannable.[/yellow]")
    for kind, path in report_paths.items():
        console.print(f"Wrote {kind.upper()} report: {path}")


def _meets_fail_threshold(findings: list[VulnerabilityFinding], fail_on: str | None) -> bool:
    if not fail_on:
        return False
    threshold = fail_on.lower()
    if threshold not in {"low", "medium", "high", "critical"}:
        raise BomradarError("--fail-on must be one of: low, medium, high, critical")
    return any(severity_rank(finding.severity) >= severity_rank(threshold) for finding in findings)


if __name__ == "__main__":
    app()
