"""Tests for repeated-update compaction and fast inference settings."""

from app.main import compact_incident


def test_repeated_ssh_updates_compacted():
    common = (
        "на хосте10.10.10.10 - test-core зарегистрировано успешное "
        "подключение по протоколу SSH под УЗ nikitos.\n"
        "Хост, с которого был выполнен вход: 10.20.20.20 - test-vdi.corp.com"
    )
    incident = (
        "17 Nov 2026, 09:16:20 UTC " + common +
        "\nОбновление информации по инциденту от 17 Nov 2026, 10:06 UTC\n"
        "17 Nov 2026, 09:42:19 UTC " + common
    )
    result = compact_incident(incident, {})
    assert "2 occurrences" in result
    assert result.count("test-vdi.corp.com") == 1


def test_distinct_hosts_preserved():
    incident = (
        "17 Nov 2026, 09:16:20 UTC host-A\n"
        "Обновление информации по инциденту от 17 Nov 2026, 10:06 UTC\n"
        "17 Nov 2026, 09:42:19 UTC host-B"
    )
    result = compact_incident(incident, {})
    assert "host-A" in result
    assert "host-B" in result


def test_compaction_can_be_disabled():
    incident = "Обновление информации по инциденту от 17 Nov 2026\nabc"
    assert compact_incident(
        incident, {"preprocessing": {"deduplicate_updates": False}}
    ) == incident
