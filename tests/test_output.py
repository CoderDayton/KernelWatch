"""Tests for output generation."""

import json

import yaml

from driver_search.models import (
    AnalysisResult,
    Driver,
    DriverHash,
    Vulnerability,
    VulnerabilityType,
)
from driver_search.output.json import analysis_result_to_dict, to_json
from driver_search.output.loldrivers import generate_loldrivers_yaml
from driver_search.output.yara import generate_yara_rule


def test_loldrivers_yaml():
    """Test LOLDrivers YAML generation."""
    driver = Driver(
        name="vuln.sys",
        hashes=DriverHash(sha256="abc", sha1="def", md5="ghi"),
        description="Test Driver",
        vendor="Test Corp",
    )
    result = AnalysisResult(
        driver=driver,
        vulnerabilities=[
            Vulnerability(vuln_type=VulnerabilityType.MSR_WRITE, description="Arbitrary MSR write")
        ],
    )

    yaml_out = generate_loldrivers_yaml(result)
    data = yaml.safe_load(yaml_out)

    assert data["Name"] == "vuln.sys"
    assert data["Category"] == "vulnerable driver"
    assert data["KnownVulnerableSamples"][0]["SHA256"] == "abc"
    assert "MSR" in yaml_out


def test_json_output():
    """Test JSON serialization."""
    driver = Driver(name="test.sys", hashes=DriverHash(sha256="123"))
    result = AnalysisResult(driver=driver)

    data = analysis_result_to_dict(result)
    json_str = to_json(data)

    parsed = json.loads(json_str)
    assert parsed["driver"]["name"] == "test.sys"
    assert parsed["driver"]["hashes"]["sha256"] == "123"


def test_yara_generation():
    """Test YARA rule generation."""
    driver = Driver(
        name="malicious.sys",
        hashes=DriverHash(sha256="deadbeef", imphash="feedface"),
        file_size=1024,
    )
    result = AnalysisResult(driver=driver, risk_score=90)

    rule = generate_yara_rule(result)

    assert "rule suspicious_driver_malicious_sys" in rule
    assert 'hash.sha256(0, filesize) == "deadbeef"' in rule
    assert 'pe.imphash() == "feedface"' in rule
    assert "risk_score = 90" in rule
