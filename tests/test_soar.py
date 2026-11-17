"""Tests for stateless SOAR CLI contract."""

import io
import json

from app import main_soar


def test_stdin_returns_json_without_files(monkeypatch, capsys, tmp_path):
    expected = {"category": "test", "incident_type": "test", "data": {}}
    seen = []

    def fake_parse(incident, config_dir):
        seen.append((incident, config_dir))
        return expected

    monkeypatch.setattr(main_soar, "parse_incident", fake_parse)
    monkeypatch.setattr("sys.stdin", io.StringIO("Incident from SOAR\n"))
    assert main_soar.main(["--stdin", "--config", str(tmp_path)]) == 0
    captured = capsys.readouterr()
    assert json.loads(captured.out) == expected
    assert captured.err == ""
    assert seen == [("Incident from SOAR\n", tmp_path)]
    assert list(tmp_path.iterdir()) == []


def test_argument_returns_json(monkeypatch, capsys):
    monkeypatch.setattr(
        main_soar,
        "parse_incident",
        lambda incident, config_dir: {"incident": incident},
    )
    assert main_soar.main(["--incident", "test incident"]) == 0
    assert json.loads(capsys.readouterr().out) == {"incident": "test incident"}


def test_error_writes_no_stdout(monkeypatch, capsys):
    def fail(incident, config_dir):
        raise ValueError("Invalid incident")

    monkeypatch.setattr(main_soar, "parse_incident", fail)
    assert main_soar.main(["--incident", "bad"]) == 1
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "Invalid incident" in captured.err
