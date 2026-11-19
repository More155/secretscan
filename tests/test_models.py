"""Tests de secretscan.models."""

from typing import Any

import pytest
from pydantic import ValidationError

from secretscan.models import Finding, Severity

# Armado con fragmentos para que no quede una clave completa en el repo.
AWS_KEY = "AKIA" + "IOSFODNN7EXAMPLE"


def make_finding(**overrides: Any) -> Finding:
    """Arma un hallazgo válido, permitiendo cambiar algunos campos."""
    data: dict[str, Any] = {
        "rule_id": "aws-access-key",
        "severity": Severity.HIGH,
        "file_path": "src/config.py",
        "line": 10,
        "masked_value": "AKIA********MPLE",
    }
    data.update(overrides)
    return Finding(**data)


def test_severity_values() -> None:
    assert [s.value for s in Severity] == ["high", "medium", "low"]


def test_history_fields_default_to_none() -> None:
    finding = make_finding()
    assert finding.commit is None
    assert finding.author is None
    assert finding.date is None


def test_finding_is_immutable() -> None:
    finding = make_finding()
    with pytest.raises(ValidationError):
        finding.line = 99


def test_finding_rejects_invalid_severity() -> None:
    with pytest.raises(ValidationError):
        make_finding(severity="critical")


@pytest.mark.parametrize("line", [0, -1])
def test_finding_rejects_non_positive_line(line: int) -> None:
    with pytest.raises(ValidationError):
        make_finding(line=line)


def test_finding_rejects_unknown_fields() -> None:
    with pytest.raises(ValidationError):
        make_finding(raw_secret=AWS_KEY)


def test_from_secret_masks_the_value() -> None:
    finding = Finding.from_secret(
        secret=AWS_KEY,
        rule_id="aws-access-key",
        severity=Severity.HIGH,
        file_path="src/config.py",
        line=10,
    )
    assert finding.masked_value == "AKIA********MPLE"


def test_secret_never_appears_in_json_or_repr() -> None:
    finding = Finding.from_secret(
        secret=AWS_KEY,
        rule_id="aws-access-key",
        severity=Severity.HIGH,
        file_path="src/config.py",
        line=10,
    )
    assert AWS_KEY not in finding.model_dump_json()
    assert AWS_KEY not in repr(finding)
