import pytest
from unittest.mock import patch, mock_open
import json
from agent import file_monitor

def test_hash_calculation(tmp_path):
    file = tmp_path / "test.txt"
    file.write_text("hello")
    hash1 = file_monitor.calculate_hash(str(file))
    assert hash1 is not None
    file.write_text("world")
    hash2 = file_monitor.calculate_hash(str(file))
    assert hash1 != hash2

@patch("builtins.open")
def test_hash_calculation_permission_error(open_mock, tmp_path):
    open_mock.side_effect = PermissionError("Access denied")
    with patch("agent.file_monitor.alerter.alert") as mock_alert:
        result = file_monitor.calculate_hash(str(tmp_path / "test.txt"))
        assert result is None
        mock_alert.assert_called_once_with(
            f"Ошибка доступа к файлу {str(tmp_path / 'test.txt')}: Access denied",
            level="ERROR"
        )

def test_load_hash_db_success(tmp_path):
    hash_db_path = tmp_path / "file_hashes.json"
    hash_db_path.write_text('{"/etc/passwd": "abc123"}')
    with patch("agent.file_monitor.HASH_DB_FILE", hash_db_path):
        result = file_monitor.load_hash_db()
        assert result == {"/etc/passwd": "abc123"}

def test_load_hash_db_file_not_found(tmp_path):
    hash_db_path = tmp_path / "file_hashes.json"
    with patch("agent.file_monitor.HASH_DB_FILE", hash_db_path):
        result = file_monitor.load_hash_db()
        assert result == {}

def test_save_hash_db(tmp_path):
    hash_db_path = tmp_path / "file_hashes.json"
    with patch("agent.file_monitor.HASH_DB_FILE", hash_db_path):
        db = {"/etc/passwd": "abc123"}
        file_monitor.save_hash_db(db)
        assert hash_db_path.exists()
        with hash_db_path.open("r") as f:
            assert json.load(f) == db

@patch("agent.file_monitor.load_hash_db")
@patch("agent.file_monitor.alerter.alert")
def test_monitor_files_no_changes(mock_alert, mock_load_hash_db, tmp_path):
    file = tmp_path / "test.txt"
    file.write_text("hello")
    with patch("agent.file_monitor.WATCHED_FILES", [str(file)]):
        mock_load_hash_db.return_value = {
            str(file): file_monitor.calculate_hash(str(file)),
            f"{str(file)}_mtime": file.stat().st_mtime
        }
        file_monitor.monitor_files()
        mock_alert.assert_not_called()

@patch("agent.file_monitor.load_hash_db")
@patch("agent.file_monitor.alerter.alert")
def test_monitor_files_changed(mock_alert, mock_load_hash_db, tmp_path):
    file = tmp_path / "test.txt"
    file.write_text("hello")
    with patch("agent.file_monitor.WATCHED_FILES", [str(file)]):
        mock_load_hash_db.return_value = {str(file): "old_hash"}
        file_monitor.monitor_files()
        mock_alert.assert_called_once_with(f" Изменён файл: `{str(file)}`", level="WARNING")