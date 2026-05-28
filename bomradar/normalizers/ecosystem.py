from __future__ import annotations

from bomradar.normalizers.purl import ecosystem_from_purl


def infer_ecosystem(purl: str | None, cpe: str | None = None) -> str | None:
    ecosystem = ecosystem_from_purl(purl)
    if ecosystem:
        return ecosystem
    if cpe:
        return "cpe"
    return None
