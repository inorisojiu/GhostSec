import psutil
import time
import os

from agent import alerter

SUSPICIOUS_PATHS = ["/tmp", "/dev/shm", "/var/tmp"]

known_pids = set()

def is_suspicious_path(path):
    return any(path.startswith(sus_path) for sus_path in SUSPICIOUS_PATHS)

def get_process_info(proc):
    try:
        return {
            "pid": proc.pid,
            "ppid": proc.ppid(),
            "exe": proc.exe(),
            "cmdline": " ".join(proc.cmdline()),
            "parent_name": proc.parent().name() if proc.parent() else "unknown"
        }
    except Exception:
        return None

def monitor_processes():
    global known_pids
    current_pids = set(psutil.pids())

    new_pids = current_pids - known_pids

    for pid in new_pids:
        try:
            proc = psutil.Process(pid)
            info = get_process_info(proc)
            if not info:
                continue

            exe_path = info["exe"]
            parent = info["parent_name"]

            alerts = []

            if is_suspicious_path(exe_path):
                alerts.append(f" Запуск из подозрительного пути: `{exe_path}`")

            if parent in ["nginx", "apache2", "sshd", "systemd", "bash", "sh", "zsh"]:
                if "python" in info["cmdline"] or "nc" in info["cmdline"]:
                    alerts.append(f" Подозрительный родитель `{parent}` для процесса: `{info['cmdline']}`")

            for alert in alerts:
                alerter.alert(f"{alert}\n`PID:` {info['pid']}, `PPID:` {info['ppid']}, `CMD:` {info['cmdline']}")

        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

    known_pids.update(new_pids)

def run():
    global known_pids
    known_pids = set(psutil.pids())  
    while True:
        monitor_processes()
        time.sleep(3)
