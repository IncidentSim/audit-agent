package agent

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode"
)

type AnalyzeOptions struct {
	Config, Profile, Input, Task, Validation, Output string
	DryRun                                           bool
}

func Analyze(ctx context.Context, o AnalyzeOptions) (Object, error) {
	c, e := readJSON(o.Config)
	if e != nil {
		return nil, e
	}
	profile := o.Profile
	if profile == "" {
		profile = str(c["active_profile"])
	}
	p, ok := obj(c["profiles"])[profile]
	if !ok {
		return nil, errors.New("unknown LLM profile")
	}
	provider := obj(p)
	if str(provider["adapter"]) != "chat_completions" {
		return nil, errors.New("unsupported adapter; supported: chat_completions")
	}
	u, e := url.Parse(str(provider["base_url"]))
	if e != nil || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Scheme != "https" && !(u.Scheme == "http" && (u.Hostname() == "localhost" || u.Hostname() == "127.0.0.1" || u.Hostname() == "::1"))) {
		return nil, errors.New("base_url must be HTTPS without credentials/query; HTTP is allowed only on loopback")
	}
	for _, k := range []string{"max_request_bytes", "max_response_bytes"} {
		n := num(c[k])
		if n <= 0 || n != float64(int64(n)) {
			return nil, fmt.Errorf("%s must be a positive integer", k)
		}
	}
	if strings.TrimSpace(str(provider["model"])) == "" || num(provider["timeout_seconds"]) <= 0 {
		return nil, errors.New("model and timeout_seconds must be valid")
	}
	mode := str(provider["proxy_mode"])
	if mode != "" && mode != "direct" && mode != "environment" {
		return nil, errors.New("proxy_mode must be environment or direct")
	}
	source, e := os.ReadFile(o.Input)
	if e != nil {
		return nil, e
	}
	var packet Object
	if e = json.Unmarshal(source, &packet); e != nil {
		return nil, e
	}
	if num(packet["v"]) != 1 || str(packet["session"]) == "" {
		return nil, errors.New("input must be a compact llm.json packet, version 1")
	}
	if _, ok := packet["actions"].([]any); !ok {
		return nil, errors.New("input actions must be an array")
	}
	actions := list(packet["actions"])
	// With no participant actions the model has nothing to ground an explanation in:
	// never ask it to reconstruct history from context telemetry.
	skipLLM := len(actions) == 0
	task, e := os.ReadFile(o.Task)
	if e != nil {
		return nil, e
	}
	if len(bytes.TrimSpace(task)) == 0 {
		return nil, errors.New("task description is empty")
	}
	validation, provided := "Результат валидации не предоставлен.", false
	if o.Validation != "" {
		b, err := os.ReadFile(o.Validation)
		if err != nil {
			return nil, err
		}
		validation, provided = string(b), true
	}
	folder := filepath.Dir(o.Config)
	prompt, e := os.ReadFile(filepath.Join(folder, str(c["prompt_file"])))
	if e != nil {
		return nil, e
	}
	params := Object{}
	if provider["parameters"] != nil {
		var ok bool
		params, ok = provider["parameters"].(map[string]any)
		if !ok {
			return nil, errors.New("parameters must be an object")
		}
	}
	request := clone(params)
	for _, k := range []string{"model", "messages", "stream"} {
		if _, ok := params[k]; ok {
			return nil, errors.New("parameters must be an object without model/messages/stream overrides")
		}
	}
	payload := Object{"report_type": "incident_postmortem", "execution_context": Object{"orchestrator": "CLI on the learner computer; LLM request runs there", "learner_environment": "terminal inside the exercise VM", "preparation": "VM creation, infra and incident injection happen before recording", "validation": "Ansible runs after recording stops; do not attribute it to learner actions", "scope": "training incident; no real production impact is established"}, "task": strings.TrimSpace(string(task)), "validation": validation, "recording": packet}
	request["model"] = provider["model"]
	request["stream"] = false
	request["messages"] = []Object{{"role": "system", "content": string(prompt)}, {"role": "user", "content": string(JSON(payload))}}
	body := JSON(request)
	if !skipLLM && len(body) > int(num(c["max_request_bytes"])) {
		return nil, errors.New("request exceeds max_request_bytes; no actions were truncated or sent")
	}
	summary := Object{"profile": profile, "model": provider["model"], "session": packet["session"], "request_bytes": len(body), "dry_run": o.DryRun, "llm_skipped": skipLLM}
	if o.DryRun {
		return summary, nil
	}
	if o.Output == "" {
		return nil, errors.New("output directory is required")
	}
	if e = os.MkdirAll(filepath.Dir(o.Output), 0700); e != nil {
		return nil, e
	}
	if e = os.Mkdir(o.Output, 0700); e != nil {
		return nil, e
	}
	defer func() { _ = os.Remove(o.Output) }() // succeeds only while the directory is empty, i.e. after a failure
	if skipLLM {
		text := renderRecord(packet, validation, provided, true) + "\n"
		if e = publishReport(o.Output, Object{"v": 1, "report_type": "incident_postmortem", "session": packet["session"], "llm_skipped": true, "created_at": now(), "packet_sha256": fmt.Sprintf("%x", sha256.Sum256(source)), "analysis": strings.TrimSuffix(text, "\n")}, text); e != nil {
			return nil, e
		}
		summary["output"] = filepath.Join(o.Output, "analysis.md")
		return summary, nil
	}
	key := strings.TrimSpace(os.Getenv(str(provider["api_key_env"])))
	if key == "" && str(provider["api_key_file"]) != "" {
		b, err := os.ReadFile(filepath.Join(folder, str(provider["api_key_file"])))
		if err != nil && !os.IsNotExist(err) {
			return nil, err
		}
		key = strings.TrimSpace(strings.TrimPrefix(string(b), "\ufeff"))
	}
	if key == "" {
		return nil, errors.New("API key is missing; set api_key_env or create api_key_file from the selected profile")
	}
	if strings.IndexFunc(key, unicode.IsSpace) >= 0 {
		return nil, errors.New("API key must be one token without whitespace")
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	if mode == "direct" {
		transport.Proxy = nil
	} else {
		transport.Proxy = http.ProxyFromEnvironment
	}
	defer transport.CloseIdleConnections()
	client := http.Client{Transport: transport, Timeout: time.Duration(num(provider["timeout_seconds"]) * float64(time.Second)), CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	req, e := http.NewRequestWithContext(ctx, "POST", strings.TrimRight(str(provider["base_url"]), "/")+"/chat/completions", bytes.NewReader(body))
	if e != nil {
		return nil, e
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+key)
	response, e := client.Do(req)
	if e != nil {
		return nil, networkError(e, mode)
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		hint := map[int]string{400: "check model and parameters", 401: "check API key", 402: "check provider balance", 407: "proxy authentication required", 429: "provider rate limit; retry later"}[response.StatusCode]
		if hint == "" {
			hint = "provider request failed"
		}
		return nil, fmt.Errorf("LLM HTTP %d: %s", response.StatusCode, hint)
	}
	limit := int64(num(c["max_response_bytes"]))
	raw, e := io.ReadAll(io.LimitReader(response.Body, limit+1))
	if e != nil {
		return nil, networkError(e, mode)
	}
	if int64(len(raw)) > limit {
		return nil, errors.New("LLM response exceeds max_response_bytes")
	}
	var answer struct {
		Choices []struct {
			Message      struct{ Content string }
			FinishReason string `json:"finish_reason"`
		}
		Model string
		ID    string
		Usage any
	}
	if json.Unmarshal(raw, &answer) != nil || len(answer.Choices) == 0 || strings.TrimSpace(answer.Choices[0].Message.Content) == "" {
		return nil, errors.New("invalid LLM response or missing answer text")
	}
	if answer.Choices[0].FinishReason != "stop" {
		return nil, errors.New("LLM response is incomplete or blocked (finish_reason is not stop); no report published")
	}
	if answer.Model == "" {
		answer.Model = str(provider["model"])
	}
	content := answer.Choices[0].Message.Content
	if e = checkReferences(content, actions, list(packet["context"])); e != nil {
		return nil, e
	}
	report := Object{"v": 1, "report_type": "incident_postmortem", "session": packet["session"], "profile": profile, "model": answer.Model, "base_url": provider["base_url"], "response_id": answer.ID, "created_at": now(), "packet_sha256": fmt.Sprintf("%x", sha256.Sum256(source)), "request_sha256": fmt.Sprintf("%x", sha256.Sum256(body)), "usage": answer.Usage, "explanation": content}
	text := renderRecord(packet, validation, provided, false) + "\n## Объяснение модели\n\n" + explanationNote + "\n\n" + content + "\n"
	report["analysis"] = strings.TrimSuffix(text, "\n") // same final Markdown as analysis.md; raw model text is in "explanation"
	if e = publishReport(o.Output, report, text); e != nil {
		return nil, e
	}
	summary["usage"] = answer.Usage
	summary["output"] = filepath.Join(o.Output, "analysis.md")
	return summary, nil
}

const explanationNote = "> Текст ниже сгенерирован моделью и не является доказательством. Достоверны только разделы выше. Программно проверены лишь явные ссылки вида `[action:N]` и `[context:N]` — на существование ID и тип записи; смысл утверждений не проверяется."

// Only bracketed references are machine-checkable; free-form mentions ("действие 3") are not.
var referencePattern = regexp.MustCompile(`\[(action|context):\s*(\d+)\s*\]`)

func recordIDs(rows []any) map[int]bool {
	ids := map[int]bool{}
	for _, r := range rows {
		if n := int(num(obj(r)["id"])); n > 0 {
			ids[n] = true
		}
	}
	return ids
}

// checkReferences rejects explicit references to IDs absent from their own list.
// Context rows are unattributed telemetry, so an [action:N] naming a context ID is invalid.
func checkReferences(text string, actions, context []any) error {
	known := map[string]map[int]bool{"action": recordIDs(actions), "context": recordIDs(context)}
	for _, m := range referencePattern.FindAllStringSubmatch(text, -1) {
		var n int
		fmt.Sscan(m[2], &n)
		if !known[m[1]][n] {
			return fmt.Errorf("invalid action reference [%s:%d] in LLM answer; no report published", m[1], n)
		}
	}
	return nil
}

func publishReport(dir string, report Object, markdown string) error {
	if e := Atomic(filepath.Join(dir, "analysis.json"), report); e != nil {
		return e
	}
	return AtomicText(filepath.Join(dir, "analysis.md"), []byte(markdown))
}

// renderRecord builds the deterministic, model-independent part of the report.
func renderRecord(packet Object, validation string, provided, noActions bool) string {
	actions, rows := list(packet["actions"]), list(packet["context"])
	var b strings.Builder
	fmt.Fprintf(&b, "# Постмортем: данные записи\n\nСессия: `%v`\n\n## Достоверные данные (сформированы программой, не моделью)\n\n", packet["session"])
	if noActions {
		b.WriteString("**Записанных действий участника нет.** Объяснение не формировалось, LLM не вызывалась: история участника не восстанавливается из context-телеметрии.\n\n")
	}
	b.WriteString("### Проверки записи\n\n")
	fmt.Fprintf(&b, "- Действий участника: %d\n- Записей context (авторство не установлено): %d\n", len(actions), len(rows))
	if cov := obj(packet["coverage"]); cov["user_commands"] != nil {
		fmt.Fprintf(&b, "- coverage.user_commands: %v\n", cov["user_commands"])
	}
	b.WriteString("\n### Независимая проверка (Ansible)\n\n")
	b.WriteString(renderValidation(validation, provided))
	b.WriteString("\n### Записанные действия участника\n\n")
	if len(actions) == 0 {
		b.WriteString("Нет.\n")
	}
	for _, a := range actions {
		r := obj(a)
		rc := "неизвестно"
		if r["rc"] != nil {
			rc = fmt.Sprint(r["rc"])
		}
		cmd := strings.NewReplacer("`", "'", "\n", " ", "\r", " ").Replace(str(r["cmd"]))
		fmt.Fprintf(&b, "- [action:%d] t=%vс rc=%s `%s`\n", int(num(r["id"])), r["t"], rc, cmd)
	}
	return b.String()
}

// short renders a value on one line, bounded, so a check's evidence can never dump a log.
func short(v any) string {
	s, ok := v.(string)
	if !ok {
		s = strings.TrimSpace(string(JSON(v)))
	}
	s = strings.NewReplacer("`", "'", "\n", " ", "\r", " ").Replace(s)
	if r := []rune(s); len(r) > 200 {
		s = string(r[:200]) + "…"
	}
	return s
}

// passedStatus accepts only the runner's exact success word; anything else is not acceptance.
func passedStatus(v any) bool { return str(v) == "pass" }

// renderValidation renders the runner envelope {passed, error, output, status, report{schema, scenario,
// attempt_id, status, complete, checks[]}} deterministically and never prints the output log.
// "accepted" requires passed=true, both statuses exactly "pass", complete=true and a nonempty list of
// passing checks. This is a conservative display of the runner's verdict, not a second grader.
// A legacy object without status/report falls back to its passed flag; non-JSON text is unknown.
func renderValidation(raw string, provided bool) string {
	if !provided {
		return "Результат проверки не предоставлен; статус неизвестен.\n"
	}
	var v Object
	if json.Unmarshal([]byte(raw), &v) != nil || v == nil {
		return fmt.Sprintf("Статус проверки неизвестен: результат не JSON-объект (%d байт, не показан).\n", len(raw))
	}
	if _, hasStatus := v["status"]; !hasStatus && v["report"] == nil {
		return renderLegacyValidation(v)
	}
	report := obj(v["report"])
	checks := list(report["checks"])
	var problems []string
	if v["passed"] != true {
		problems = append(problems, "passed не true")
	}
	if !passedStatus(v["status"]) {
		if v["status"] == "error" {
			problems = append(problems, "статус верхнего уровня: ошибка")
		} else {
			problems = append(problems, "статус верхнего уровня не pass: "+short(v["status"]))
		}
	}
	if v["report"] == nil {
		problems = append(problems, "нет report")
	} else {
		if !passedStatus(report["status"]) {
			problems = append(problems, "report.status не pass: "+short(report["status"]))
		}
		if report["complete"] != true {
			problems = append(problems, "отчёт неполный (report.complete не true)")
		}
	}
	if v["report"] != nil && len(checks) == 0 {
		problems = append(problems, "нет проверок (report.checks пуст)")
	}
	for _, c := range checks {
		if !passedStatus(obj(c)["status"]) {
			problems = append(problems, "проверка "+short(obj(c)["id"])+": "+short(obj(c)["status"]))
		}
	}
	var b strings.Builder
	if len(problems) == 0 {
		b.WriteString("Итог: принята\n")
	} else {
		b.WriteString("Итог: не принята (" + strings.Join(problems, "; ") + ")\n")
	}
	fmt.Fprintf(&b, "\n- passed: `%s`\n- status: `%s`\n- report.status: `%s`\n- report.complete: `%s`\n- report.scenario: `%s`\n- report.attempt_id: `%s`\n", short(v["passed"]), short(v["status"]), short(report["status"]), short(report["complete"]), short(report["scenario"]), short(report["attempt_id"]))
	if v["error"] != nil {
		fmt.Fprintf(&b, "- error: `%s`\n", short(v["error"]))
	}
	if len(checks) > 0 {
		b.WriteString("\nПроверки:\n\n")
	}
	for _, c := range checks {
		r := obj(c)
		fmt.Fprintf(&b, "- `%s` — %s; description: `%s`; expected: `%s`; observed: `%s`; evidence: `%s`\n", short(r["id"]), short(r["status"]), short(r["description"]), short(r["expected"]), short(r["observed"]), short(r["evidence"]))
	}
	return b.String() + "\nУспешная проверка подтверждает только проверенные критерии. Журнал output не показывается.\n"
}

func renderLegacyValidation(v Object) string {
	status := "не определён (нет поля passed)"
	if p, ok := v["passed"].(bool); ok {
		status = map[bool]string{true: "пройдена", false: "не пройдена"}[p]
	}
	keys := make([]string, 0, len(v))
	for k := range v {
		if k != "output" { // raw log is never displayed
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	out := "Статус: " + status + " (устаревший формат без status/report)\n\n"
	for _, k := range keys {
		out += fmt.Sprintf("- %s: `%s`\n", k, short(v[k]))
	}
	return out + "\nУспешная проверка подтверждает только проверенные критерии.\n"
}

func networkError(e error, mode string) error {
	detail := "network connection failed"
	var cert x509.UnknownAuthorityError
	var verify *tls.CertificateVerificationError
	var dns *net.DNSError
	var ne net.Error
	switch {
	case errors.As(e, &cert) || errors.As(e, &verify):
		detail = "TLS certificate verification failed; check system CA certificates"
	case errors.As(e, &dns):
		detail = "DNS lookup failed"
	case errors.As(e, &ne) && ne.Timeout():
		detail = "connection or response timed out"
	case strings.Contains(e.Error(), "407"):
		detail = "proxy authentication required"
	}
	if mode == "direct" {
		detail += " (direct connection)"
	}
	return errors.New("LLM " + detail + "; no automatic retry was made")
}
