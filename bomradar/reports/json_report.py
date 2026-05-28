from __future__ import annotations

import json
from pathlib import Path

from bomradar.models import ScanReport


def write_json_report(report: ScanReport, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report.model_dump(mode="json"), indent=2), encoding="utf-8")
