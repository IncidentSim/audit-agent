# Проверка на отдельной учебной VM

Соберите агент через `go run tools/build.go`, установите его на VM командой
`incident-audit deploy root@vm --verify`. Для сбора не нужны Python и ключ LLM.

На одноразовой VM, до начала пользовательской записи:

```bash
sudo incident-audit demo-provision
sudo incident-audit start --session-id unique-attempt-id
```

`demo-provision` создаёт Go HTTP-сервис, проверяет исправный порт 8080, затем
вносит неисправность порта. Команда сбрасывает задачу; запускать её во время
пользовательской попытки нельзя.

На компьютере проверяющего создайте `analysis/demo-current/session.json`:

```json
{"session_id":"unique-attempt-id","target":"root@vm-ip","ssh_command":["ssh","-i","/path/to/key","-o","BatchMode=yes"]}
```

`ssh_command` — доверенная локальная конфигурация; поддерживается SSH через WSL.
Пути ключей должны соответствовать выбранному окружению.

```bash
incident-audit demo connect --run-dir analysis/demo-current
incident-audit demo finish --run-dir analysis/demo-current --config config/llm.local.json
```

Внутри SSH выполните задание из [task.md](../examples/http-service/task.md).
`finish` закрывает запись, скачивает журналы, пересобирает пакет, вызывает на VM
`incident-audit demo-validate` за пределами окна и запускает отдельный LLM-анализ
на хосте. Отчёт — `report/analysis.md` и JSON. Ключ в VM не передаётся.
`finish --dry-run` закрывает запись и выполняет валидацию без вызова модели.
Для новой попытки нужен новый session ID.
