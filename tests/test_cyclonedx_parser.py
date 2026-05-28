from pathlib import Path

from bomradar.parsers.cyclonedx import parse_cyclonedx_json


FIXTURE = Path("tests/fixtures/cyclonedx-simple.json")


def test_cyclonedx_parser_extracts_components() -> None:
    components = parse_cyclonedx_json(FIXTURE)

    assert len(components) == 3
    lodash = components[0]
    assert lodash.name == "lodash"
    assert lodash.version == "4.17.20"
    assert lodash.purl == "pkg:npm/lodash@4.17.20"
    assert lodash.ecosystem == "npm"
    assert lodash.supplier == "OpenJS"
    assert lodash.dependency_type == "direct"


def test_cyclonedx_parser_extracts_cpe() -> None:
    components = parse_cyclonedx_json(FIXTURE)

    openssl = next(component for component in components if component.name == "openssl")
    assert openssl.cpe == "cpe:2.3:a:openssl:openssl:1.1.1k:*:*:*:*:*:*:*"
    assert openssl.ecosystem == "cpe"
