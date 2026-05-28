from __future__ import annotations


def normalize_cpe(value: str | None) -> str | None:
    if not value:
        return None
    cpe = value.strip()
    if cpe.startswith("cpe:2.3:") or cpe.startswith("cpe:/"):
        return cpe
    return None


def first_cpe(values: list[str | None]) -> str | None:
    for value in values:
        cpe = normalize_cpe(value)
        if cpe:
            return cpe
    return None
