import pytest
import psutil
from unittest.mock import patch, Mock
from agent import network_monitor

def test_is_public_ip():
    assert network_monitor.is_public_ip("8.8.8.8") is True
    assert network_monitor.is_public_ip("192.168.1.1") is False
    assert network_monitor.is_public_ip("0.0.0.0") is False
    assert network_monitor.is_public_ip("") is False

@patch("psutil.net_connections")
def test_monitor_network_access_denied(mock_net_connections):
    mock_net_connections.side_effect = psutil.AccessDenied
    network_monitor.permission_warning_sent = False
    with patch("agent.network_monitor.alerter.alert") as mock_alert:
        network_monitor.monitor_network()
        mock_alert.assert_called_once()
        assert network_monitor.permission_warning_sent is True

@patch("psutil.net_connections")
def test_monitor_network_success(mock_net_connections, monkeypatch):
    mock_conn = Mock(laddr=Mock(ip="127.0.0.1", port=8080), raddr=Mock(ip="8.8.8.8", port=80), pid=123)
    mock_net_connections.return_value = [mock_conn]
    monkeypatch.setattr("agent.network_monitor.known_conns", set())
    monkeypatch.setattr("agent.network_monitor.get_process_info", lambda pid: ("cmd", "/bin/test"))
    with patch("agent.network_monitor.alerter.alert") as mock_alert:
        network_monitor.monitor_network()
        mock_alert.assert_called()

def test_clean_cache():
    network_monitor.known_conns = {(123, "127.0.0.1", 8080, "8.8.8.8", 80, 0)}
    with patch("time.time", return_value=network_monitor.CACHE_TTL + 1):
        network_monitor.clean_cache()
        assert not network_monitor.known_conns  
