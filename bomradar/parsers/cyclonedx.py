from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from bomradar.models import Component, InvalidSbomError, SourceFormat
from bomradar.normalizers.cpe import first_cpe
from bomradar.normalizers.ecosystem import infer_ecosystem


def parse_cyclonedx_json(path: Path) -> list[Component]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise InvalidSbomError(f"Unable to read CycloneDX JSON SBOM: {exc}") from exc

    components = data.get("components")
    if not isinstance(components, list):
        raise InvalidSbomError("CycloneDX SBOM is missing a components array.")

    dependency_types = _dependency_types(data.get("dependencies", []))
    parsed: list[Component] = []
    for item in components:
        if not isinstance(item, dict):
            continue
        name = item.get("name")
        if not name:
            continue
        purl = item.get("purl")
        cpe = first_cpe([item.get("cpe"), *_property_values(item, "cpe")])
        bom_ref = item.get("bom-ref")
        parsed.append(
            Component(
                name=name,
                version=item.get("version"),
                purl=purl,
                cpe=cpe,
                ecosystem=infer_ecosystem(purl, cpe),
                bom_ref=bom_ref,
                source_format=SourceFormat.CYCLONEDX_JSON,
                supplier=_supplier_name(item.get("supplier")),
                dependency_type=dependency_types.get(bom_ref),
            )
        )
    return parsed


def _supplier_name(supplier: Any) -> str | None:
    if isinstance(supplier, dict):
        return supplier.get("name")
    if isinstance(supplier, str):
        return supplier
    return None


def _property_values(item: dict[str, Any], needle: str) -> list[str]:
    values = []
    for prop in item.get("properties", []) or []:
        if not isinstance(prop, dict):
            continue
        name = str(prop.get("name", "")).lower()
        if needle in name and prop.get("value"):
            values.append(str(prop["value"]))
    return values


def _dependency_types(dependencies: Any) -> dict[str, str]:
    if not isinstance(dependencies, list):
        return {}
    depended_on = set()
    declared = set()
    for dep in dependencies:
        if not isinstance(dep, dict) or not dep.get("ref"):
            continue
        declared.add(dep["ref"])
        for child in dep.get("dependsOn", []) or []:
            depended_on.add(child)
    result = {ref: "direct" for ref in declared}
    for ref in depended_on:
        result.setdefault(ref, "transitive")
    return result
