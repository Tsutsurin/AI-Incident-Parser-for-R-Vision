"""Tests for configuration-driven classification guidance."""

import json

import pytest

from app.main import load_reference, make_messages


def write_config(tmp_path):
    values = {
        "categories": ["Событие безопасности", "Вредоносное программное обеспечение"],
        "incident_types": {
            "Событие безопасности": ["Подозрение на инцидент ИБ"],
            "Вредоносное программное обеспечение": ["Использование ВПО"],
        },
        "data_fields": {"src.ip": "IP источника"},
        "exceptions": [],
    }
    for name, value in values.items():
        (tmp_path / (name + ".json")).write_text(
            json.dumps(value, ensure_ascii=False), encoding="utf-8"
        )


def test_guidance_in_prompt(tmp_path):
    write_config(tmp_path)
    rules = {
        "general_rules": ["Не путай подозрение с подтверждением"],
        "categories": {
            "Событие безопасности": {
                "positive_indicators": ["rundll32.exe keymgr.dll,KRShowKeyMgr"]
            }
        },
    }
    (tmp_path / "classification_rules.json").write_text(
        json.dumps(rules, ensure_ascii=False), encoding="utf-8"
    )
    refs = load_reference(tmp_path)
    messages = make_messages("Тест", refs)
    assert "Не путай подозрение с подтверждением" in messages[1]["content"]
    assert "KRShowKeyMgr" in messages[1]["content"]


def test_guidance_optional(tmp_path):
    write_config(tmp_path)
    refs = load_reference(tmp_path)
    assert "classification_rules" not in refs


def test_unknown_category_rejected(tmp_path):
    write_config(tmp_path)
    (tmp_path / "classification_rules.json").write_text(
        json.dumps({"categories": {"Нет такой категории": {}}}),
        encoding="utf-8"
    )
    with pytest.raises(ValueError, match="unknown categories"):
        load_reference(tmp_path)
