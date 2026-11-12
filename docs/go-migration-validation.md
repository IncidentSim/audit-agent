# Проверка переноса на Go

Первичная среда проверки: Windows amd64; Go 1.23.2 для standalone-агента, Go 1.26
для существующего TUI. Проверка не обращается к платному LLM API.

В `audit-agent`:

```bash
go test ./... -count=1
go vet ./...
go run tools/build.go
```

Автотесты проверяют 25 эталонных Python-пакетов и provenance, параллельные
записи JSONL, идемпотентность и границы сессий, восстановление после ошибки
экспорта, reboot, raw-log recovery, Unicode/фрагментацию EXECVE, b32 syscalls,
подлинность USER-маркеров, запрос/ответ HTTP, ключи, бюджеты, таймауты,
redirect, неполный ответ и запрет повторного запроса в существующий output.

В `tui-ansible-runner`:

```bash
go generate ./internal/auditbinary
go test ./cmd/incidentctl -run 'Test(Audit|InlineLLM|Solution|Packaged)' -count=1
go vet ./...
go build -o bin/incidentctl.exe ./cmd/incidentctl
```

Интеграционный тест запускает включённый в TUI настоящий Go-бинарник агента,
локальный HTTP-сервер и проверяет итоговый `analysis.md`. В тесте очищен PATH:
Python и Go недоступны дочернему клиенту. Дополнительно проверяются загрузочный
ELF-заголовок Linux x86_64, отсутствие динамического загрузчика и tar-пакет VM.

Нативный Go-клиент также проверен на предоставленном `llm.json` через `analyze
--dry-run`. Linux-бинарники агента/TUI и Linux test binary скомпилированы с
`CGO_ENABLED=0`. Это проверка сборки, не запуск Linux-тестов.

Полный `go test ./...` TUI в этой среде не проходит: недоступен WSL Bash,
Git subprocess не может создать signal pipe, Windows ACL запрещает операции
с временными SSH-ключами/VM state; есть Unix-специфичные ожидания прав 0600
и путей. Эти проверки находятся вне изменённого audit/LLM-потока.

При первичной проверке настоящий Linux auditd/systemd здесь не запускался: WSL возвращал Access
denied, Docker engine недоступен. Завершающая проверка на отдельной VM:

```bash
sudo ./incident-audit install
sudo incident-audit verify
```

`verify` выполняет реальные exec/file/Bash-действия и проверяет отсутствие
потерь, включение буферизованного хвоста перед stop, исключение валидации,
права файлов и provenance. До успешного прогона этой команды на VM нельзя
считать подтверждённой работу с настоящим kernel audit.

Совместимость: LLM остаётся отдельным процессом; JSON-профили и основные
артефакты сохранены. Удалён необязательный офлайн-подсчёт через Python
`tokenizers` (`token_counts: null`); фактический расход берётся из API `usage`.

## Регрессия OOM при остановке записи (2026-11-12)

На действующей VM журнал ядра подтвердил OOM kill процесса `incident-audit`
с RSS 266084 KiB. VM имела 469 MiB RAM без swap, raw audit занимал около 63 MiB,
а почти все raw events не содержали EOE. Экспорт оставил попытку в `stopping`
с уже сохранённой stop boundary.

Экспорт переведён на внешнюю стабильную сортировку порциями по 2 MiB и слияние
не более 16 файлов одновременно. Raw events собираются после группировки на
диске; нормализованные события также объединяются и сортируются на диске.
JSONL публикуется атомарно без общего строкового буфера. Compact читает источник
в два прохода и считает SHA-256 потоком. Добавлен мягкий Linux GC-бюджет 64 MiB.

Проверены прежние 25 эталонных пакетов и provenance, межсессионная фильтрация,
raw recovery, перемешанные события без EOE через ротации, стабильность нескольких
проходов слияния и приоритет raw recovery над JSONL-дубликатами.

Нагрузочный тест на Linux/WSL прошёл в systemd cgroup с `MemoryMax=128M`,
`MemorySwapMax=0`: экспорт и compact 100000 событий внутри окна без EOE,
все 100002 события вместе с границами сохранены. Время 13 секунд,
максимальный RSS 16720 KiB по `/usr/bin/time -v`. Тест использует много
файловых операций, поэтому запускается отдельно:

```bash
CGO_ENABLED=0 go test -c -o bin/linux-amd64/agent.test ./internal/agent
sudo systemd-run --wait --pipe -p MemoryMax=128M -p MemorySwapMax=0 \
  /usr/bin/env INCIDENT_AUDIT_MEMORY_TEST=1 /usr/bin/time -v \
  "$PWD/bin/linux-amd64/agent.test" -test.run=TestExportMemoryStress -test.v
```

На исходной VM бинарник заменён атомарно, без перезапуска auditd и без сброса
попытки; прежний сохранён как `/usr/local/sbin/incident-audit.before-memory-fix`.
Повторный `control ... stop` завершился успешно: состояние `stopped`,
449 экспортированных событий из четырёх raw-файлов, LLM-пакет 22017 байт.
Границы kernel serial 52187–52675 и `stopped_at` 2026-11-12T14:01:16.036Z
совпали с состоянием до восстановления. Незавершённые временные экспорты
удалены, исходные raw-логи сохранены. Это проверка остановки/экспорта текущей
попытки; оценка решения Ansible и запрос к платному LLM не запускались.
