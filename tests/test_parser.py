"""Tests for incident result validation."""

import pytest

from app.main import validate_result


@pytest.fixture
def refs():
    """Return isolated test references."""
    return {
        "categories": [
            "Учетные записи",
            "Сетевая безопасность",
        ],
        "incident_types": {
            "Учетные записи": [
                "Неуспешная аутентификация",
                "Подбор пароля",
            ],
            "Сетевая безопасность": [
                "Подозрительное соединение",
            ],
        },
        "data_fields": {
            "src.ip": "IP-адрес источника",
            "dst.ip": "IP-адрес назначения",
            "username": "Имя учетной записи",
            "src.hostname": "Имя хоста источника",
            "dst.hostname": "Имя хоста назначения",
        },
        "exceptions": [],
    }


def test_valid_result(refs):
    """Accept a valid incident classification."""
    raw = {
        "category": "Учетные записи",
        "incident_type": "Неуспешная аутентификация",
        "data": {
            "src.ip": ["10.10.20.15"],
            "username": ["ivanov"],
        },
    }

    result = validate_result(raw, refs)

    assert result.category == "Учетные записи"
    assert result.incident_type == "Неуспешная аутентификация"
    assert result.data["src.ip"] == ["10.10.20.15"]
    assert result.data["username"] == ["ivanov"]
    assert result.data["dst.ip"] == []


def test_unknown_category(refs):
    """Reject categories not defined in references."""
    raw = {
        "category": "Несуществующая категория",
        "incident_type": "Неуспешная аутентификация",
        "data": {},
    }

    with pytest.raises(ValueError, match="Unknown category"):
        validate_result(raw, refs)


def test_unknown_field(refs):
    """Reject extracted fields not defined in references."""
    raw = {
        "category": "Учетные записи",
        "incident_type": "Неуспешная аутентификация",
        "data": {
            "unknown_field": ["test"],
        },
    }

    with pytest.raises(ValueError, match="Unknown data fields"):
        validate_result(raw, refs)


def test_unknown_incident_type(refs):
    """Reject incident types not belonging to the category."""
    raw = {
        "category": "Учетные записи",
        "incident_type": "Подозрительное соединение",
        "data": {},
    }

    with pytest.raises(ValueError, match="Unknown incident type"):
        validate_result(raw, refs)


def test_duplicate_values(refs):
    """Remove duplicate extracted values."""
    raw = {
        "category": "Учетные записи",
        "incident_type": "Неуспешная аутентификация",
        "data": {
            "src.ip": [
                "10.10.20.15",
                "10.10.20.15",
            ],
        },
    }

    result = validate_result(raw, refs)

    assert result.data["src.ip"] == ["10.10.20.15"]


def test_empty_data(refs):
    """Fill missing data fields with empty arrays."""
    raw = {
        "category": "Учетные записи",
        "incident_type": "Неуспешная аутентификация",
        "data": {},
    }

    result = validate_result(raw, refs)

    assert all(not values for values in result.data.values())
