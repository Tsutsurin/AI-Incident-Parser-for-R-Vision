import pytest

from app.main import ROOT, load_reference, validate_result


def test_valid_result():
    refs = load_reference(ROOT / "config")
    result = validate_result(
        {
            "category": "Учетные записи",
            "incident_type": "Неуспешная аутентификация",
            "data": {"src_ip": ["10.10.20.15"], "username": ["ivanov"]},
        },
        refs,
    )
    assert result.data["src_ip"] == ["10.10.20.15"]
    assert result.data["hostname"] == []


def test_unknown_category():
    refs = load_reference(ROOT / "config")
    with pytest.raises(ValueError):
        validate_result(
            {"category": "Неизвестно", "incident_type": "x", "data": {}}, refs
        )


def test_unknown_field():
    refs = load_reference(ROOT / "config")
    with pytest.raises(ValueError):
        validate_result(
            {
                "category": "Учетные записи",
                "incident_type": "Неуспешная аутентификация",
                "data": {"unapproved": ["x"]},
            },
            refs,
        )
