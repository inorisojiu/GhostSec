import json
import re
from pathlib import Path
from agent import alerter

RULES = {
    "watched_files": [],
    "suspicious_processes": [],
    "suspicious_parents": [],
    "cmdline_keywords": [],
    "regex": []
}

def load_rules(rules_file: str) -> dict:
    global RULES
    try:
        with open(rules_file, "r") as f:
            RULES = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError) as e:
        alerter.alert(f"Ошибка загрузки правил: {e}", level="ERROR")
        RULES = {
            "watched_files": [],
            "suspicious_processes": [],
            "suspicious_parents": [],
            "cmdline_keywords": [],
            "regex": []
        }
    return RULES

def get_watched_files() -> list:
    return RULES.get("watched_files", [])

def is_suspicious_process(process_name: str) -> bool:
    return process_name.lower() in [p.lower() for p in RULES.get("suspicious_processes", [])]

def is_suspicious_parent(parent_name: str) -> bool:
    return parent_name.lower() in [p.lower() for p in RULES.get("suspicious_parents", [])]

def check_cmdline_keywords(cmdline: str) -> bool:
    cmdline = cmdline.lower()
    for keyword in RULES.get("cmdline_keywords", []):
        if keyword.lower() in cmdline:
            return True
    return False

def check_regex(cmdline: str) -> bool:
    for pattern in RULES.get("regex", []):
        try:
            if re.search(pattern, cmdline, re.IGNORECASE):
                return True
        except re.error as e:
            alerter.alert(f"Некорректное регулярное выражение {pattern}: {e}", level="ERROR")
    return False