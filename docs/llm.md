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

**Защита от необоснованного объяснения (ограниченная).** Если `actions` пуст
(в том числе есть только `context`), LLM не вызывается и ключ не нужен:
`analysis.md` содержит программно сформированный результат «записанных действий
участника нет», счётчики и статус проверки; `analysis.json` — `llm_skipped: true`.
Для непустых `actions` отчёт начинается с достоверного блока, который строит
программа, а не модель: счётчики, статус проверки (`passed` из JSON-результата;
остальные поля показываются как есть) и список записанных действий. Ниже идёт
текст модели с пометкой, что он не является доказательством. Результат
`--validation` разбирается детерминированно: для конверта runner (`passed`,
`error`, `status`, `report.status`, `report.scenario`, `report.attempt_id`,
`report.complete`, `report.checks[]` с `id`/`status`/`description`/`expected`/
`observed`/`evidence`) выводятся эти поля, значения усекаются до 200 символов,
журнал `output` не показывается. «Принята» — только если `passed` равен `true`,
оба статуса (`status`, `report.status`) в точности `pass`, `report.complete`
равен `true`, есть хотя бы одна проверка и все проверки `pass`. Любое
противоречие (например `passed: true` при `status: error`) — «не принята».
Это консервативный показ вердикта runner, а не второй оценщик. Устаревший объект
без `status`/`report` оценивается по `passed` (поле `output` скрыто), не-JSON
текст — статус неизвестен. `analysis` в `analysis.json` — тот же итоговый Markdown, что
и `analysis.md` (без завершающего перевода строки); исходный текст модели —
в поле `explanation`. Промпт требует
ссылаться на действия как `[action:ID]`, на context — `[context:ID]`. Ответ с
ссылкой на несуществующий ID или на ID context в виде `[action:ID]` отклоняется
(`invalid action reference`), отчёт не публикуется. **Пределы:** проверяются
только такие явные ссылки в скобках, и только существование/тип ID. Смысл
утверждений, пересказ stdout, причинные выводы и свободные упоминания
(«действие 3») не проверяются; галлюцинации это не исключает.

`analysis.md` содержит постмортем; `analysis.json` — текст, модель, usage, ID ответа
и SHA256 пакета/запроса. Ключ и промежуточные рассуждения не сохраняются.
Существующий output блокирует новый запрос. Автоматических повторов и переходов
по HTTP redirect нет. Ошибки HTTP/сети не включают тело ответа или API-ключ.

Размеры ограничивают `max_request_bytes`/`max_response_bytes`. Пакет не усекается.
Ответ с `finish_reason != stop` не публикуется: при необходимости измените
`max_tokens` и явно повторите запрос в новый каталог.
