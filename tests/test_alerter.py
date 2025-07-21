import pytest
from unittest.mock import patch
from agent import alerter

def test_init_valid_config():
    config = {
        "telegram_token": "test_token",
        "telegram_chat_id": "test_chat_id",
        "alert_methods": ["telegram", "log"],
        "log_file": "test.log"
    }
    alerter.init(config)
    assert alerter.TG_TOKEN == "test_token"
    assert alerter.TG_CHAT_ID == "test_chat_id"
    assert alerter.ALERT_METHODS == ["telegram", "log"]

def test_init_missing_telegram_config():
    config = {"alert_methods": ["telegram"], "log_file": "test.log"}
    with pytest.raises(ValueError, match="Telegram token or chat ID not provided"):
        alerter.init(config)

@patch.dict("os.environ", {"TELEGRAM_TOKEN": "env_token", "TELEGRAM_CHAT_ID": "env_chat_id"})
def test_init_with_dotenv():
    config = {"telegram_token": "config_token", "telegram_chat_id": "config_chat_id", "alert_methods": ["telegram"]}
    alerter.init(config)
    assert alerter.TG_TOKEN == "env_token"
    assert alerter.TG_CHAT_ID == "env_chat_id"

@patch("requests.post")
def test_send_telegram_alert_success(mock_post):
    mock_post.return_value.status_code = 200
    alerter.init({"telegram_token": "test_token", "telegram_chat_id": "test_chat_id", "alert_methods": ["telegram"]})
    alerter.send_telegram_alert("Test message")
    mock_post.assert_called_once_with(
        "https://api.telegram.org/bottest_token/sendMessage",
        json={"chat_id": "test_chat_id", "text": "Test message"},
        timeout=5
    )

@patch("requests.post")
@patch("agent.alerter.logger")
def test_send_telegram_alert_failure(mock_logger, mock_post):
    mock_post.return_value.status_code = 400
    mock_post.return_value.text = "Bad Request"
    alerter.init({"telegram_token": "test_token", "telegram_chat_id": "test_chat_id", "alert_methods": ["telegram"]})
    alerter.send_telegram_alert("Test message")
    mock_logger.error.assert_called_once_with("Telegram API error: Bad Request")

@patch("agent.alerter.logger")
def test_alert_log_only(mock_logger):
    alerter.init({"alert_methods": ["log"], "log_file": "test.log"})
    alerter.alert("Test message", level="INFO")
    mock_logger.log.assert_called_once()

@patch("requests.post")
@patch("agent.alerter.logger")
def test_alert_telegram_and_log(mock_logger, mock_post):
    mock_post.return_value.status_code = 200
    alerter.init({
        "telegram_token": "test_token",
        "telegram_chat_id": "test_chat_id",
        "alert_methods": ["telegram", "log"],
        "log_file": "test.log"
    })
    alerter.alert("Test message", level="WARNING")
    mock_post.assert_called_once()
    mock_logger.log.assert_called_once()
