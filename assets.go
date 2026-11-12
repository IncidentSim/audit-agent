package auditassets

import "embed"

//go:embed config/50-incidentsim.rules config/incidentsim-json.conf config/incidentsim-audit.sh docs/prompts/llm-analysis-prompt.md examples/http-service/task.md
var Files embed.FS
