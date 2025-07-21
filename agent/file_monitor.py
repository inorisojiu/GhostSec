import hashlib
import json
import os
from pathlib import Path
from agent import alerter, rule_engine

HASH_DB_FILE = Path("config/file_hashes.json")
WATCHED_FILES = []

def init(config_data: dict) -> None:
    global WATCHED_FILES
    WATCHED_FILES = rule_engine.get_watched_files()

def calculate_hash(file_path: str) -> str | None:
    try:
        with open(file_path, "rb") as f:
            sha256 = hashlib.sha256()
            while chunk := f.read(8192):
                sha256.update(chunk)
            return sha256.hexdigest()
    except (PermissionError, FileNotFoundError) as e:
        alerter.alert(f"Ошибка доступа к файлу {file_path}: {e}", level="ERROR")
        return None

def load_hash_db() -> dict:
    try:
        with open(HASH_DB_FILE, "r") as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return {}

def save_hash_db(db: dict) -> None:
    HASH_DB_FILE.parent.mkdir(parents=True, exist_ok=True)
    with open(HASH_DB_FILE, "w") as f:
        json.dump(db, f, indent=2)

def monitor_files() -> None:
    print(f"Checking files: {WATCHED_FILES}")
    db = load_hash_db()
    for file_path in WATCHED_FILES:
        print(f"Checking file: {file_path}")
        if not os.path.exists(file_path):
            continue
        current_hash = calculate_hash(file_path)
        if current_hash is None:
            continue
        current_mtime = os.path.getmtime(file_path)
        old_hash = db.get(file_path)
        old_mtime = db.get(f"{file_path}_mtime")
        print(f"{file_path} old_hash: {old_hash}")
        print(f"{file_path} new_hash: {current_hash}")
        if old_hash and (old_hash != current_hash or old_mtime != current_mtime):
            alerter.alert(f" Изменён файл: `{file_path}`", level="WARNING")
        db[file_path] = current_hash
        db[f"{file_path}_mtime"] = current_mtime
    save_hash_db(db)

def run() -> None:
    import time
    while True:
        monitor_files()
        time.sleep(60)  
