from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from bomradar.models import Component, InvalidSbomError, SourceFormat
from bomradar.normalizers.cpe import first_cpe
from bomradar.normalizers.ecosystem import infer_ecosystem


def parse_spdx_json(path: Path) -> list[Component]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise InvalidSbomError(f"Unable to read SPDX JSON SBOM: {exc}") from exc

    packages = data.get("packages")
    if not isinstance(packages, list):
        raise InvalidSbomError("SPDX SBOM is missing a packages array.")

    parsed: list[Component] = []
    for package in packages:
        if not isinstance(package, dict):
            continue
        name = package.get("name")
        if not name or name == "SPDXRef-DOCUMENT":
            continue
        refs = package.get("externalRefs", []) or []
        purl = _external_ref(refs, "purl")
        cpe = first_cpe([_external_ref(refs, "cpe23Type"), _external_ref(refs, "cpe22Type")])
        parsed.append(
            Component(
                name=name,
                version=package.get("versionInfo"),
                purl=purl,
                cpe=cpe,
                ecosystem=infer_ecosystem(purl, cpe),
                bom_ref=package.get("SPDXID"),
                source_format=SourceFormat.SPDX_JSON,
                supplier=_clean_supplier(package.get("supplier")),
            )
        )
    return parsed


def _external_ref(refs: Any, ref_type: str) -> str | None:
    if not isinstance(refs, list):
        return None
    for ref in refs:
        if not isinstance(ref, dict):
            continue
        if ref.get("referenceType") == ref_type and ref.get("referenceLocator"):
            return ref["referenceLocator"]
    return None


def _clean_supplier(supplier: str | None) -> str | None:
    if not supplier or supplier in {"NOASSERTION", "NONE"}:
        return None
    for prefix in ("Organization:", "Person:"):
        if supplier.startswith(prefix):
            return supplier.removeprefix(prefix).strip()
    return supplier
