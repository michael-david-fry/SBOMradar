from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import unquote


@dataclass(frozen=True)
class ParsedPurl:
    type: str
    namespace: str | None
    name: str
    version: str | None


def parse_purl(purl: str | None) -> ParsedPurl | None:
    if not purl or not purl.startswith("pkg:"):
        return None
    body = purl[4:].split("?", 1)[0].split("#", 1)[0]
    if "/" not in body:
        return None
    purl_type, remainder = body.split("/", 1)
    version = None
    if "@" in remainder:
        remainder, version = remainder.rsplit("@", 1)
        version = unquote(version) or None
    parts = [unquote(part) for part in remainder.split("/") if part]
    if not parts:
        return None
    name = parts[-1]
    namespace = "/".join(parts[:-1]) or None
    return ParsedPurl(type=unquote(purl_type), namespace=namespace, name=name, version=version)


def ecosystem_from_purl(purl: str | None) -> str | None:
    parsed = parse_purl(purl)
    if not parsed:
        return None
    aliases = {
        "maven": "maven",
        "npm": "npm",
        "pypi": "pypi",
        "gem": "rubygems",
        "golang": "go",
        "cargo": "cargo",
        "nuget": "nuget",
        "deb": "debian",
        "rpm": "rpm",
    }
    return aliases.get(parsed.type, parsed.type)
