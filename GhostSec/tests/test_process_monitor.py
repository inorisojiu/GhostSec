import pytest
from unittest.mock import patch, Mock
import psutil
from agent import process_monitor, alerter, rule_engine

def test_is_suspicious_path():
    assert process_monitor.is_suspicious_path("/tmp/test") is True
    assert process_monitor.is_suspicious_path("/usr/bin/python") is False
    assert process_monitor.is_suspicious_path("") is False

@patch("psutil.Process")
def test_get_process_info_success(mock_process):
    mock_proc = Mock()
    mock_proc.pid = 123
    mock_proc.ppid.return_value = 456
    mock_proc.exe.return_value = "/bin/bash"
    mock_proc.cmdline.return_value = ["bash", "-c", "test"]
    mock_proc.parent.return_value = Mock()
    mock_proc.parent.return_value.name.return_value = "init"
    mock_process.return_value = mock_proc
    info = process_monitor.get_process_info(mock_proc)
    assert info == {
        "pid": 123,
        "ppid": 456,
        "exe": "/bin/bash",
        "cmdline": "bash -c test",
        "parent_name": "init"
    }

@patch("psutil.Process")
def test_get_process_info_access_denied(mock_process):
    mock_process.side_effect = psutil.AccessDenied
    info = process_monitor.get_process_info(Mock(pid=123))
    assert info is None

@patch("psutil.pids")
@patch("psutil.Process")
@patch("agent.process_monitor.alerter.alert")
def test_monitor_processes_suspicious(mock_alert, mock_process, mock_pids):
    mock_proc = Mock()
    mock_proc.pid = 123
    mock_proc.ppid.return_value = 456
    mock_proc.exe.return_value = "/tmp/malware"
    mock_proc.cmdline.return_value = ["malware"]
    mock_proc.parent.return_value = Mock()
    mock_proc.parent.return_value.name.return_value = "bash"
    mock_pids.return_value = [123]
    mock_process.return_value = mock_proc
    with patch("agent.process_monitor.known_pids", set()):
        with patch("agent.rule_engine.is_suspicious_parent", return_value=True):
            with patch("agent.rule_engine.check_cmdline_keywords", return_value=True):
                process_monitor.monitor_processes()
                mock_alert.assert_called()