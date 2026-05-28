from bomradar.normalizers.cpe import normalize_cpe
from bomradar.normalizers.purl import ecosystem_from_purl, parse_purl


def test_parse_purl_extracts_parts() -> None:
    parsed = parse_purl("pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1")

    assert parsed is not None
    assert parsed.type == "maven"
    assert parsed.namespace == "org.apache.logging.log4j"
    assert parsed.name == "log4j-core"
    assert parsed.version == "2.14.1"
    assert ecosystem_from_purl("pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1") == "maven"


def test_normalize_cpe_rejects_non_cpe() -> None:
    assert normalize_cpe("cpe:2.3:a:openssl:openssl:1.1.1k:*:*:*:*:*:*:*") is not None
    assert normalize_cpe("openssl") is None
