from __future__ import annotations

from pathlib import Path

from jinja2 import Template

from bomradar.models import ScanReport


HTML_TEMPLATE = """<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>SBOMradar Report</title>
  <style>
    body { font-family: Arial, sans-serif; color: #1f2933; margin: 32px; }
    h1, h2 { color: #102a43; }
    .summary { display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 12px; }
    .metric { border: 1px solid #d9e2ec; border-radius: 6px; padding: 12px; }
    .metric strong { display: block; font-size: 24px; }
    table { border-collapse: collapse; width: 100%; margin: 16px 0 28px; }
    th, td { border: 1px solid #d9e2ec; padding: 8px; text-align: left; vertical-align: top; }
    th { background: #f0f4f8; }
    .critical { color: #b42318; font-weight: bold; }
    .high { color: #b54708; font-weight: bold; }
    .muted { color: #627d98; }
  </style>
</head>
<body>
  <h1>SBOMradar Report</h1>
  <p class="muted">Source: {{ report.source_sbom or "unknown" }} | Timestamp: {{ report.timestamp }}</p>

  <h2>Summary</h2>
  <section class="summary">
    <div class="metric"><strong>{{ s.component_count }}</strong> Components</div>
    <div class="metric"><strong>{{ s.scanned_component_count }}</strong> Scanned</div>
    <div class="metric"><strong>{{ s.finding_count }}</strong> Findings</div>
    <div class="metric"><strong>{{ s.unscannable_component_count }}</strong> Unscannable</div>
    <div class="metric"><strong>{{ s.critical_count }}</strong> Critical</div>
    <div class="metric"><strong>{{ s.high_count }}</strong> High</div>
    <div class="metric"><strong>{{ s.medium_count }}</strong> Medium</div>
    <div class="metric"><strong>{{ s.low_count }}</strong> Low</div>
  </section>

  <h2>Immediate Attention</h2>
  {% set urgent = report.findings | selectattr("priority_score", "ge", 55) | list %}
  {% if urgent %}
  <table>
    <tr><th>Component</th><th>Vulnerability</th><th>Severity</th><th>Priority</th><th>Confidence</th></tr>
    {% for finding in urgent %}
    <tr>
      <td>{{ finding.component_name }} {{ finding.component_version or "" }}</td>
      <td>{{ finding.vulnerability_id }}</td>
      <td class="{{ (finding.severity or 'unknown') | lower }}">{{ finding.severity or "unknown" }}</td>
      <td>{{ finding.priority_score }}</td>
      <td>{{ finding.match_confidence }}</td>
    </tr>
    {% endfor %}
  </table>
  {% else %}
  <p>No findings currently exceed the immediate-attention priority threshold.</p>
  {% endif %}

  <h2>Findings</h2>
  <table>
    <tr>
      <th>Component</th><th>Version</th><th>Vulnerability</th><th>Severity</th>
      <th>CVSS</th><th>EPSS</th><th>KEV</th><th>PoC</th><th>Nuclei</th>
      <th>Confidence</th><th>Recommendation</th><th>References</th>
    </tr>
    {% for finding in report.findings %}
    <tr>
      <td>{{ finding.component_name }}</td>
      <td>{{ finding.component_version or "" }}</td>
      <td>{{ finding.vulnerability_id }}</td>
      <td class="{{ (finding.severity or 'unknown') | lower }}">{{ finding.severity or "unknown" }}</td>
      <td>{{ finding.cvss_score if finding.cvss_score is not none else "" }}</td>
      <td>{{ finding.epss_score if finding.epss_score is not none else "" }}</td>
      <td>{{ finding.kev if finding.kev is not none else "" }}</td>
      <td>{{ finding.public_poc if finding.public_poc is not none else "" }}</td>
      <td>{{ finding.nuclei_template if finding.nuclei_template is not none else "" }}</td>
      <td>{{ finding.match_confidence }}</td>
      <td>{{ finding.recommendation or "" }}</td>
      <td>{{ finding.references | join(", ") }}</td>
    </tr>
    {% endfor %}
  </table>

  <h2>Unscannable Components</h2>
  <table>
    <tr><th>Name</th><th>Version</th><th>Source Ref</th><th>Reason</th></tr>
    {% for component in report.unscannable_components %}
    <tr>
      <td>{{ component.name }}</td>
      <td>{{ component.version or "" }}</td>
      <td>{{ component.bom_ref or "" }}</td>
      <td>No CPE, purl, name, or version lookup could be prepared.</td>
    </tr>
    {% endfor %}
  </table>
</body>
</html>
"""


def write_html_report(report: ScanReport, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    rendered = Template(HTML_TEMPLATE).render(report=report, s=report.scan_summary)
    path.write_text(rendered, encoding="utf-8")
