import pytest
from unittest.mock import patch, mock_open
import json
from agent import rule_engine, alerter

@pytest.fixture
def setup_rules(tmp_path):
    rules_path = tmp_path / "rules.json"
    rules_path.write_text('''
        {
            "watched_files": ["/etc/passwd"],
            "suspicious_processes": ["ncat"],
            "suspicious_parents": ["python"],
            "cmdline_keywords": ["curl"],
            "regex": ["curl.*evil"]
        }
    ''')
    return str(rules_path)

@patch("agent.alerter.alert")
def test_load_rules_invalid_json(mock_alert, tmp_path):
    rules_path = tmp_path / "rules.json"
    rules_path.write_text("{invalid}")
    result = rule_engine.load_rules(str(rules_path))
    assert result == {
        "watched_files": [],
        "suspicious_processes": [],
        "suspicious_parents": [],
        "cmdline_keywords": [],
        "regex": []
    }
    mock_alert.assert_called_once_with(f"Ошибка загрузки правил: Expecting property name enclosed in double quotes: line 1 column 2 (char 1)", level="ERROR")

def test_watched_files(setup_rules):
    rule_engine.load_rules(setup_rules)
    files = rule_engine.get_watched_files()
    assert isinstance(files, list)
    assert "/etc/passwd" in files

def test_is_suspicious_process(setup_rules):
    rule_engine.load_rules(setup_rules)
    assert rule_engine.is_suspicious_process("ncat") is True
    assert rule_engine.is_suspicious_process("bash") is False

def test_is_suspicious_parent(setup_rules):
    rule_engine.load_rules(setup_rules)
    assert rule_engine.is_suspicious_parent("python") is True
    assert rule_engine.is_suspicious_parent("init") is False

def test_check_cmdline_keywords(setup_rules):
    rule_engine.load_rules(setup_rules)
    assert rule_engine.check_cmdline_keywords("curl http://example.com") is True
    assert rule_engine.check_cmdline_keywords("ls -la") is False

def test_check_regex(setup_rules):
    rule_engine.load_rules(setup_rules)
    assert rule_engine.check_regex("curl -fsSL evil.site") is True
    assert rule_engine.check_regex("echo hello") is False