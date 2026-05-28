from pathlib import Path

from bomradar.parsers.spdx import parse_spdx_json


FIXTURE = Path("tests/fixtures/spdx-simple.json")


def test_spdx_parser_extracts_purl_and_supplier() -> None:
    components = parse_spdx_json(FIXTURE)

    django = components[0]
    assert django.name == "django"
    assert django.version == "3.2.0"
    assert django.purl == "pkg:pypi/django@3.2.0"
    assert django.ecosystem == "pypi"
    assert django.supplier == "Django Software Foundation"


def test_spdx_parser_extracts_cpe() -> None:
    components = parse_spdx_json(FIXTURE)

    nginx = next(component for component in components if component.name == "nginx")
    assert nginx.cpe == "cpe:2.3:a:nginx:nginx:1.20.0:*:*:*:*:*:*:*"
    assert nginx.supplier is None
