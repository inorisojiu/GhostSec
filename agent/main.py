import threading
import time
import signal
import sys
import json
from agent import file_monitor, process_monitor, network_monitor, alerter

shutdown_flag = threading.Event()

def load_settings():
    try:
        with open("config/settings.json") as f:
            return json.load(f)
    except Exception as e:
        alerter.alert(f"Не удалось загрузить настройки: {e}")
        return {}

def handle_exit(sig, frame):
    alerter.alert("Агент SecMon_Lite завершает работу...")
    shutdown_flag.set()

def start_monitor(func, name):
    def wrapper():
        alerter.alert(f"Запуск модуля: {name}")
        while not shutdown_flag.is_set():
            try:
                func()
            except Exception as e:
                alerter.alert(f"Ошибка в {name}: {e}")
            time.sleep(1)
    thread = threading.Thread(target=wrapper, daemon=True)
    thread.start()
    return thread

def main():
    signal.signal(signal.SIGINT, handle_exit)
    signal.signal(signal.SIGTERM, handle_exit)

    settings = load_settings()
    alerter.init(settings)

    threads = [
        start_monitor(file_monitor.run, "File Monitor"),
        start_monitor(process_monitor.run, "Process Monitor"),
        start_monitor(network_monitor.run, "Network Monitor"),
    ]

    alerter.alert(" SecMon_Lite агент запущен и отслеживает систему.")
    while not shutdown_flag.is_set():
        time.sleep(1)

    for t in threads:
        t.join(timeout=3)

if __name__ == "__main__":
    main()
