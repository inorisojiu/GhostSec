# SecMonLite (GhostSec)
Лёгкий инструмент для мониторинга безопасности, отслеживающий изменения файлов, сетевые подключения и подозрительные процессы на системах Linux и macOS. Отправляет уведомления через Telegram бота и логирует события в файл.

[![CI](https://github.com/inorisojiu/GhostSec/actions/workflows/ci.yml/badge.svg)](https://github.com/inorisojiu/GhostSec/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

## Возможности
- **Мониторинг файлов**: Отслеживает изменения в заданных файлах с помощью SHA-256 хэшей.
- **Мониторинг сети**: Обнаруживает подозрительные подключения к публичным IP-адресам.
- **Мониторинг процессов**: Идентифицирует подозрительные процессы по заданным правилам (имя, родитель, командная строка, регулярные выражения).
- **Уведомления**: Отправляет алерты через Telegram и записывает события в лог-файл.
- **Гибкая конфигурация**: Правила мониторинга задаются в файле [rules.json](https://github.com/inorisojiu/GhostSec/blob/main/rules/rules.json).
- **Тестирование**: Полное покрытие тестами с использованием `pytest`.

## Требования
- Python 3.10 или выше
- Права root (для мониторинга процессов)
- Поддерживаемые ОС: Linux, macOS
- Зависимости, указанные в [GhostSec/requirements.txt](https://github.com/inorisojiu/GhostSec/blob/main/requirements.txt)

**Примечание**: Используйте HTTPS для Telegram API, чтобы обеспечить безопасность передачи данных.
 
## Установка
1. Клонируйте репозиторий:
   ```bash
   git clone https://github.com/inorisojiu/GhostSec.git
   ```

2. Установите зависимости:
   ```bash
   pip install -r requirements.txt
   ```

## Настройка
1. Создайте файл `.env` для хранения чувствительных данных:
   ```bash
   echo "TELEGRAM_TOKEN=your_telegram_bot_token" >> .env
   echo "TELEGRAM_CHAT_ID=your_telegram_chat_id" >> .env
   ```
   - Замените `your_telegram_bot_token` на токен вашего Telegram-бота.
   - Замените `your_telegram_chat_id` на ID чата для уведомлений.

2. Отредактируйте [settings.json](https://github.com/inorisojiu/GhostSec/blob/main/config/settings.json), если нужно изменить настройки (например, путь к лог-файлу или интервал мониторинга)

3. Настройте правила мониторинга в [rules.json](https://github.com/inorisojiu/GhostSec/blob/main/rules/rules.json)
   
 

## Запуск
Запустите приложение (требуются права root для мониторинга процессов):
```bash
sudo python3 agent/main.py
```

- Логи сохраняются в `secmon.log` (путь задаётся в `settings.json`).
- Уведомления отправляются в Telegram, если настроен `.env`.

## Тестирование
Для запуска тестов используйте `pytest`:
```bash
pytest test/
```

Все 28 тестов проверяют функциональность модулей:
- [alerter.py](https://github.com/inorisojiu/GhostSec/blob/main/agent/alerter.py): Отправка уведомлений через Telegram и логирование.
- [file_monitor.py](https://github.com/inorisojiu/GhostSec/blob/main/agent/file_monitor.py): Вычисление хэшей и мониторинг файлов.
- [network_monitor.py](https://github.com/inorisojiu/GhostSec/blob/main/agent/network_monitor.py): Проверка сетевых подключений.
- [process_monitor.py](https://github.com/inorisojiu/GhostSec/blob/main/agent/process_monitor.py): Обнаружение подозрительных процессов.
- [rule_engine.py](https://github.com/inorisojiu/GhostSec/blob/main/agent/rule_engine.py): Загрузка и применение правил.

Для проверки покрытия тестами:
```bash
pip install pytest-cov
pytest --cov=agent test/
```

## Контакт

Исследователь: inorisojiu

Для вопросов, багов и предложений - создавайте issue или pull request
