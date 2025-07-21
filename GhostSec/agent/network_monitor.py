import psutil
import time
import traceback
import os
import platform
from typing import Set, Tuple
from agent import alerter

SUSPICIOUS_PORTS = {4444, 1337, 31337, 5555, 9001}
known_conns: Set[Tuple] = set()
CACHE_TTL = 3600
SCAN_INTERVAL = 5
permission_warning_sent = False

def is_public_ip(ip: str) -> bool:
    if not ip or ip in ('0.0.0.0', '::'):
        return False
    private_blocks = (
        '10.', '172.16.', '172.17.', '172.18.', '172.19.', '172.20.', '172.21.',
        '172.22.', '172.23.', '172.24.', '172.25.', '172.26.', '172.27.',
        '172.28.', '172.29.', '172.30.', '172.31.', '192.168.', '127.'
    )
    return not any(ip.startswith(block) for block in private_blocks)

def clean_cache() -> None:
    global known_conns
    current_time = time.time()
    known_conns = {(pid, lip, lport, rip, rport, timestamp)
                   for pid, lip, lport, rip, rport, timestamp in known_conns
                   if current_time - timestamp < CACHE_TTL}

def get_process_info(pid: int) -> Tuple[str, str]:
    try:
        proc = psutil.Process(pid)
        cmdline = ' '.join(proc.cmdline()) if proc.cmdline() else 'n/a'
        exe = proc.exe() or 'n/a'
        return cmdline, exe
    except psutil.NoSuchProcess:
        return 'процесс завершён', 'n/a'
    except psutil.AccessDenied:
        return 'доступ запрещён', 'n/a'
    except Exception as e:
        return f'ошибка: {str(e)}', 'ошибка'

def check_permissions() -> bool:
    return not (platform.system() == 'Darwin' and os.geteuid() != 0)

def monitor_network() -> None:
    global known_conns, permission_warning_sent

    if not check_permissions() and not permission_warning_sent:
        alerter.alert(" На macOS требуется запуск с правами root (sudo) для доступа к сетевым соединениям.", level="WARNING")
        permission_warning_sent = True
        return

    try:
        clean_cache()
        conns = psutil.net_connections(kind='inet')
    except psutil.AccessDenied:
        if not permission_warning_sent:
            alerter.alert(" Нет прав доступа для получения сетевых соединений. Запустите с sudo.", level="ERROR")
            permission_warning_sent = True
        return
    except Exception as e:
        alerter.alert(f" Ошибка при получении сетевых соединений:\n`{traceback.format_exc()}`", level="ERROR")
        return

    current_time = time.time()
    for conn in conns:
        try:
            if not conn.laddr:
                continue

            remote_ip = conn.raddr.ip if conn.raddr else None
            remote_port = conn.raddr.port if conn.raddr else None
            conn_id = (conn.pid, conn.laddr.ip, conn.laddr.port, remote_ip, remote_port, current_time)

            if any(cid[:5] == conn_id[:5] for cid in known_conns):
                continue
            known_conns.add(conn_id)

            alerts = []
            if remote_ip and is_public_ip(remote_ip):
                alerts.append(f" Внешнее соединение: {remote_ip}:{remote_port or 'n/a'}")
            if (remote_port and remote_port in SUSPICIOUS_PORTS) or (conn.laddr.port in SUSPICIOUS_PORTS):
                alerts.append(f" Подозрительный порт: {remote_port or conn.laddr.port}")

            if alerts:
                cmdline, exe = get_process_info(conn.pid)
                for alert in alerts:
                    alerter.alert(
                        f"{alert}\n`PID:` {conn.pid}\n`CMD:` {cmdline}\n`EXE:` {exe}\n`Local:` {conn.laddr.ip}:{conn.laddr.port}",
                        level="WARNING"
                    )
        except psutil.AccessDenied:
            if not permission_warning_sent:
                alerter.alert(f" Ошибка доступа при обработке соединения (PID: {conn.pid}): Запустите с sudo.", level="ERROR")
                permission_warning_sent = True
            continue
        except Exception as e:
            alerter.alert(f"Ошибка при обработке соединения (PID: {conn.pid}):\n`{traceback.format_exc()}`", level="ERROR")
            continue

def run(scan_interval: int = SCAN_INTERVAL) -> None:
    while True:
        monitor_network()
        time.sleep(scan_interval)