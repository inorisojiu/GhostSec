import logging
from logging.handlers import RotatingFileHandler
import requests
from pathlib import Path
from typing import List, Optional
from dotenv import load_dotenv
import os

load_dotenv()

logger = logging.getLogger("SecMon")
logger.setLevel(logging.INFO)
handler = RotatingFileHandler("secmon.log", maxBytes=5*1024*1024, backupCount=3)
handler.setFormatter(logging.Formatter("[%(asctime)s] %(levelname)s: %(message)s"))
logger.addHandler(handler)

TG_TOKEN: Optional[str] = None
TG_CHAT_ID: Optional[str] = None
ALERT_METHODS: List[str] = ["telegram", "log"]

def init(config_data: dict) -> None:
    global TG_TOKEN, TG_CHAT_ID, ALERT_METHODS
    TG_TOKEN = os.getenv("TELEGRAM_TOKEN") or config_data.get("telegram_token")
    TG_CHAT_ID = os.getenv("TELEGRAM_CHAT_ID") or config_data.get("telegram_chat_id")   
    ALERT_METHODS = config_data.get("alert_methods", ["telegram", "log"])
    
    if "telegram" in ALERT_METHODS and (not TG_TOKEN or not TG_CHAT_ID):
        raise ValueError("Telegram token or chat ID not provided in settings.json or .env")
    
    log_file = config_data.get("log_file", "secmon.log")
    handler.baseFilename = str(Path(log_file).resolve())

def send_telegram_alert(message: str) -> None:
    if "telegram" not in ALERT_METHODS or not TG_TOKEN or not TG_CHAT_ID:
        return
    url = f"https://api.telegram.org/bot{TG_TOKEN}/sendMessage"
    payload = {"chat_id": TG_CHAT_ID, "text": message}
    try:
        response = requests.post(url, json=payload, timeout=5)
        if response.status_code != 200:
            logger.error(f"Telegram API error: {response.text}")
    except Exception as e:
        logger.error(f"Telegram send error: {e}")

def alert(message: str, level: str = "INFO") -> None:
    log_level = getattr(logging, level.upper(), logging.INFO)
    if "log" in ALERT_METHODS:
        logger.log(log_level, message)
    if "telegram" in ALERT_METHODS:
        send_telegram_alert(message)