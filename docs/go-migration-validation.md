# Проверка переноса на Go

Среда проверки: Windows amd64; Go 1.23.2 для standalone-агента, Go 1.26
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

Настоящий Linux auditd/systemd здесь не запускался: WSL возвращает Access
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
