# Отдельный LLM-клиент

Команды выполняются на компьютере проверяющего. Нужен нативный Go-бинарник
`incident-audit` (на Windows — `incident-audit.exe`); Python не используется.

Скопируйте `config/llm.example.json` в `config/llm.local.json`. Задайте ключ через
`DEEPSEEK_API_KEY` либо `.secrets/deepseek-api-key`, как указано в выбранном
профиле. Переменная окружения имеет приоритет. Пути ключа и промпта считаются
от каталога профиля; аргументы CLI — от текущего каталога. Ключевые файлы,
локальная конфигурация и отчёты исключены из Git.

```bash
incident-audit analyze --config config/llm.local.json --input /path/to/llm.json \
  --task /path/to/task.md --validation /path/to/validation.json --dry-run

incident-audit analyze --config config/llm.local.json --input /path/to/llm.json \
  --task /path/to/task.md --validation /path/to/validation.json --output analysis/attempt-001
```

`--dry-run` проверяет пакет и размер запроса без ключа, сети и создания отчёта.
`--validation` необязателен. `--profile` выбирает профиль. Поддерживается
Chat Completions API; адрес может содержать `/v1`. JSON-профили совместимы.
`proxy_mode: direct` отключает прокси; `environment` использует окружение HTTP(S).
HTTPS проверяет системные CA; HTTP разрешён только на loopback для тестов.

`analysis.md` содержит постмортем; `analysis.json` — текст, модель, usage, ID ответа
и SHA256 пакета/запроса. Ключ и промежуточные рассуждения не сохраняются.
Существующий output блокирует новый запрос. Автоматических повторов и переходов
по HTTP redirect нет. Ошибки HTTP/сети не включают тело ответа или API-ключ.

Размеры ограничивают `max_request_bytes`/`max_response_bytes`. Пакет не усекается.
Ответ с `finish_reason != stop` не публикуется: при необходимости измените
`max_tokens` и явно повторите запрос в новый каталог.
