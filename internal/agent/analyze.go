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
	task, e := os.ReadFile(o.Task)
	if e != nil {
		return nil, e
	}
	if len(bytes.TrimSpace(task)) == 0 {
		return nil, errors.New("task description is empty")
	}
	validation := "Результат валидации не предоставлен."
	if o.Validation != "" {
		b, err := os.ReadFile(o.Validation)
		if err != nil {
			return nil, err
		}
		validation = string(b)
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
	if len(body) > int(num(c["max_request_bytes"])) {
		return nil, errors.New("request exceeds max_request_bytes; no actions were truncated or sent")
	}
	summary := Object{"profile": profile, "model": provider["model"], "session": packet["session"], "request_bytes": len(body), "dry_run": o.DryRun}
	if o.DryRun {
		return summary, nil
	}
	if o.Output == "" {
		return nil, errors.New("output directory is required")
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
	if e = os.MkdirAll(filepath.Dir(o.Output), 0700); e != nil {
		return nil, e
	}
	if e = os.Mkdir(o.Output, 0700); e != nil {
		return nil, e
	}
	defer func() { _ = os.Remove(o.Output) }()
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
	report := Object{"v": 1, "report_type": "incident_postmortem", "session": packet["session"], "profile": profile, "model": answer.Model, "base_url": provider["base_url"], "response_id": answer.ID, "created_at": now(), "packet_sha256": fmt.Sprintf("%x", sha256.Sum256(source)), "request_sha256": fmt.Sprintf("%x", sha256.Sum256(body)), "usage": answer.Usage, "analysis": content}
	if e = Atomic(filepath.Join(o.Output, "analysis.json"), report); e != nil {
		return nil, e
	}
	if e = AtomicText(filepath.Join(o.Output, "analysis.md"), []byte(content+"\n")); e != nil {
		return nil, e
	}
	summary["usage"] = answer.Usage
	summary["output"] = filepath.Join(o.Output, "analysis.md")
	return summary, nil
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
