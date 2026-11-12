# Audit Agent

Самостоятельный Go-бинарник для сбора Linux Audit, окон записи, экспорта JSONL,
компактного `llm.json` и отдельного запроса к LLM. Python, libauparse и CGO не нужны.
Сборщик работает внутри VM; `analyze` запускается на компьютере проверяющего.
Ключ LLM в VM не передаётся. Успешность упражнения по-прежнему определяет Ansible.

## Сборка и проверки

Для разработки нужен Go 1.23+. В корне репозитория:

```bash
go test ./...
go vet ./...
go run tools/build.go
```

Сборка создаёт `bin/windows-amd64/incident-audit.exe` на Windows (либо нативный
бинарник на другой ОС) и статический `bin/linux-amd64/incident-audit` для VM.
В бинарник включены audit rules, конфигурация dispatcher и Bash hook.
На машине пользователя Go не нужен. Далее `incident-audit` означает нативный бинарник.

## Установка

Цель: Ubuntu/Debian x86_64, systemd, ядро с Linux Audit, root или sudo без пароля.
Установщик ставит через APT только `auditd`; для имён syscall используется его
`ausyscall` (таблицы x86_64 и i386 загружаются при запуске сборщика).

```bash
incident-audit deploy root@vm.example.com --vm-id training-01 --verify
incident-audit deploy admin@vm.example.com --sudo --identity ~/.ssh/id_ed25519 --port 2222
incident-audit deploy --bundle-only dist/audit-agent.tar.gz
```

`--binary` задаёт Linux-бинарник (по умолчанию `bin/linux-amd64/incident-audit`).
Используется OpenSSH; дополнительные `--ssh-option` передаются как `-o`.
Архив содержит только бинарник, без ключей, локальных профилей и журналов.
Существующий архив не перезаписывается. Локально внутри VM:

```bash
sudo ./incident-audit install --vm-id training-01
sudo incident-audit verify
```

`--skip-packages` пропускает APT. VM ID создаётся при первой установке, если не
задан явно; повторная установка сохраняет ID и логи. Immutable policy и правило
`never,task` останавливают установку.

## Контракт записи

После установки запись выключена. После подготовки инфраструктуры и внесения
инцидента внешняя система вызывает start. Перед валидацией нужно дождаться stop:

```bash
sudo incident-audit start --session-id attempt-001
sudo incident-audit stop --session-id attempt-001
```

`stop` ждёт подтверждения kernel-маркера dispatcher-процессом, замораживает окно,
перечитывает raw audit logs, объединяет их с Bash/JSONL, убирает дубликаты,
сортирует события и создаёт `actions.jsonl`, manifest и `llm.json` с provenance.
Ответ — JSON со `phase: stopped` и путями `output`, `manifest`, `llm`,
`llm_sources`, `llm_stats`; те же пути находятся в `artifacts`.

Сохраняются идемпотентность start/stop, запрет параллельных окон и повторного
использования закрытого ID, исходная граница при повторе неудавшегося экспорта,
защита от stop старой попытки при активной новой, проверка boot ID после reboot.
ID: 1–96 ASCII букв/цифр, точек, `_`, `-`; первый символ — буква или цифра.
Границы различают audit events с одинаковым временем по kernel serial.

```bash
incident-audit status
incident-audit mark hint_used
incident-audit export --session-id attempt-001
incident-audit export --all --output /root/all-audit.jsonl
incident-audit compact --session-id attempt-001 --effects-limit 24 --exec-limit 12
incident-audit compact-file --input ./actions.jsonl --max-bytes 262144
```

Диагностический `--all` не ограничивает окно. `--include-instrumentation` включает
служебные события; по умолчанию они исключены. Компактный формат отделяет Bash
от контекста exec/syscall, сохраняет неизвестные статусы, порядок эффектов,
повторы и ссылки на исходные события. Известные шаблоны секретов маскируются
только в компактном пакете.

## Файлы и ограничения

- `/etc/incidentsim/audit-context.json` — постоянный VM ID.
- `/var/log/incidentsim/capture.json` — текущая/последняя попытка.
- `/var/log/incidentsim/sessions/ID/` — `session.json`, `events.jsonl`, `actions.jsonl`,
  `actions.manifest.json`, `llm.json`, `llm.sources.json`, `llm.stats.json`.
- `/var/log/incidentsim/collector-health.json` — состояние dispatcher и ошибки.
- `/var/log/audit/audit.log*` — исходные журналы auditd.

Каталоги журналов — 0700, JSON/JSONL — 0600. JSONL ротируется по 16 MiB
(4 файла), raw audit — 8 файлов по 16 MiB. Экспорт объединяет ограниченный объём
журналов в памяти. stdout/stderr и содержимое файлов не записываются.
Root может отключить сбор. Bash hook действует в новых интерактивных root Bash;
для открытой сессии: `source /etc/profile.d/incidentsim-audit.sh`.

## LLM и демонстрация

[LLM](docs/llm.md), [проверка на VM](docs/demo.md), [компактный формат](docs/compact-format.md).

LLM остаётся отдельной командой `incident-audit analyze`. Start/stop не вызывают
API. `verify` проверяет установленный агент через настоящий Linux auditd и Bash;
команда отказывается прерывать активную запись. Автотесты сравнивают Go-экспорт
с 25 пакетами прежней Python-версии и проверяют HTTP-клиент на локальном сервере.
