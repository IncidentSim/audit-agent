package agent

import (
	"context"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writePacket(t *testing.T, o AnalyzeOptions, actions, contextRows []any) {
	t.Helper()
	if e := Atomic(o.Input, Object{"v": 1, "session": "attempt-1", "actions": actions, "context": contextRows}); e != nil {
		t.Fatal(e)
	}
}

// writeValidation stores an Ansible-style result and wires it into the options.
func writeValidation(t *testing.T, o *AnalyzeOptions, v Object) {
	t.Helper()
	o.Validation = filepath.Join(filepath.Dir(o.Config), "validation.json")
	if e := Atomic(o.Validation, v); e != nil {
		t.Fatal(e)
	}
}

func TestAnalyzeEmptyActionsNeverCallsProvider(t *testing.T) {
	for name, rows := range map[string][]any{"empty": {}, "context-only": {Object{"id": 7, "exec": "ls"}}} {
		t.Run(name, func(t *testing.T) {
			o, _, calls := analysisFixture(t, func(w http.ResponseWriter, r *http.Request) { t.Error("provider reached for empty actions") })
			writePacket(t, o, []any{}, rows)
			writeValidation(t, &o, Object{"passed": true, "service_active": true, "http_status": 200})
			os.Remove(filepath.Join(filepath.Dir(o.Config), "key")) // no key is needed: no request is made
			result, e := Analyze(context.Background(), o)
			if e != nil || calls.Load() != 0 || result["llm_skipped"] != true {
				t.Fatal(result, e)
			}
			b, e := os.ReadFile(filepath.Join(o.Output, "analysis.md"))
			md := string(b)
			for _, want := range []string{"Записанных действий участника нет", "service_active", "пройдена", "Действий участника: 0"} {
				if e != nil || !strings.Contains(md, want) {
					t.Fatalf("missing %q (%v)\n%s", want, e, md)
				}
			}
			report, _ := readJSON(filepath.Join(o.Output, "analysis.json"))
			if report["llm_skipped"] != true || report["model"] != nil {
				t.Fatal(report)
			}
		})
	}
}

func TestAnalyzeEmptyActionsDryRun(t *testing.T) {
	o, _, calls := analysisFixture(t, func(w http.ResponseWriter, r *http.Request) { t.Error("provider reached") })
	writePacket(t, o, []any{}, []any{})
	o.DryRun = true
	v, e := Analyze(context.Background(), o)
	if e != nil || v["llm_skipped"] != true || calls.Load() != 0 {
		t.Fatal(v, e)
	}
}

func TestAnalyzeNonemptyRequestsAndRendersAuthoritativeSections(t *testing.T) {
	o, _, calls := analysisFixture(t, func(w http.ResponseWriter, r *http.Request) {
		answer(w)
	})
	writePacket(t, o, []any{Object{"id": 1, "t": 2.5, "cmd": "systemctl restart app", "rc": 0}, Object{"id": 2, "cmd": "false", "rc": nil}}, []any{Object{"id": 3}})
	writeValidation(t, &o, Object{"passed": false, "http_status": 500})
	if _, e := Analyze(context.Background(), o); e != nil || calls.Load() != 1 {
		t.Fatal(e, calls.Load())
	}
	b, _ := os.ReadFile(filepath.Join(o.Output, "analysis.md"))
	md := string(b)
	for _, want := range []string{"не пройдена", "http_status", "systemctl restart app", "`false`", "rc=неизвестно", "Постмортем: действие 1."} {
		if !strings.Contains(md, want) {
			t.Fatalf("missing %q\n%s", want, md)
		}
	}
	if strings.Index(md, "systemctl restart app") > strings.Index(md, "Постмортем: действие 1.") {
		t.Fatal("deterministic history must precede model text")
	}
}

func TestAnalyzeRejectsInvalidActionReferences(t *testing.T) {
	for name, text := range map[string]string{"unknown-id": "Шаг [action:99].", "context-as-action": "Шаг [action:3].", "action-as-context": "Фон [context:1]."} {
		t.Run(name, func(t *testing.T) {
			o, _, calls := analysisFixture(t, func(w http.ResponseWriter, r *http.Request) {
				w.Write(JSON(Object{"choices": []any{Object{"message": Object{"content": text}, "finish_reason": "stop"}}}))
			})
			writePacket(t, o, []any{Object{"id": 1, "cmd": "ls", "rc": 0}}, []any{Object{"id": 3}})
			_, e := Analyze(context.Background(), o)
			if e == nil || !strings.Contains(e.Error(), "invalid action reference") || calls.Load() != 1 {
				t.Fatal(e)
			}
			if _, e = os.Stat(o.Output); !os.IsNotExist(e) {
				t.Fatal("rejected explanation left a report")
			}
		})
	}
}

func TestAnalyzeAcceptsValidReferences(t *testing.T) {
	o, _, _ := analysisFixture(t, func(w http.ResponseWriter, r *http.Request) {
		w.Write(JSON(Object{"choices": []any{Object{"message": Object{"content": "Шаг [action:1], фон [context:3]."}, "finish_reason": "stop"}}}))
	})
	writePacket(t, o, []any{Object{"id": 1, "cmd": "ls", "rc": 0}}, []any{Object{"id": 3}})
	if _, e := Analyze(context.Background(), o); e != nil {
		t.Fatal(e)
	}
}

// envelope mirrors the real runner validation.json; scenario and attempt_id are nested in report.
func envelope(passed any, top, nested string, complete any, checks any) string {
	return string(JSON(Object{"passed": passed, "status": top, "output": "RAW-LOG-LINE-MUST-NOT-APPEAR", "report": Object{"schema": "incidentsim.verify/v1", "scenario": "postgres-hba-reject", "attempt_id": "ATTEMPT-XYZ", "status": nested, "complete": complete, "checks": checks}}))
}

var goodChecks = []any{
	Object{"id": "service_active", "status": "pass", "description": "service runs", "expected": "active", "observed": "active", "evidence": "systemctl is-active"},
	Object{"id": "health_body", "status": "pass", "description": "health ok", "expected": 200, "observed": 200, "evidence": "GET /health"},
}

func goodEnvelope() string { return envelope(true, "pass", "pass", true, goodChecks) }

func TestRenderValidationEnvelope(t *testing.T) {
	good := renderValidation(goodEnvelope(), true)
	for _, want := range []string{"Итог: принята", "postgres-hba-reject", "ATTEMPT-XYZ", "report.status: `pass`", "service_active", "health_body", "service runs", "expected", "observed", "evidence", "systemctl is-active"} {
		if !strings.Contains(good, want) {
			t.Errorf("missing %q\n%s", want, good)
		}
	}
	if strings.Contains(good, "RAW-LOG-LINE") {
		t.Error("output log dumped")
	}
	failedCheck := []any{Object{"id": "health_body", "status": "fail", "expected": 200, "observed": nil, "evidence": "refused"}}
	errorCheck := []any{Object{"id": "health_body", "status": "error"}}
	for name, tc := range map[string]struct{ raw, want string }{
		"top-error-with-passed":     {envelope(true, "error", "pass", true, goodChecks), "ошибка"},
		"top-passed-false":          {envelope(false, "pass", "pass", true, goodChecks), "passed не true"},
		"passed-missing":            {envelope(nil, "pass", "pass", true, goodChecks), "passed не true"},
		"nested-fail-contradiction": {envelope(true, "pass", "fail", true, goodChecks), "report.status не pass"},
		"nested-error":              {envelope(true, "pass", "error", true, goodChecks), "report.status не pass"},
		"incomplete":                {envelope(true, "pass", "pass", false, goodChecks), "неполный"},
		"complete-missing":          {envelope(true, "pass", "pass", nil, goodChecks), "неполный"},
		"no-checks":                 {envelope(true, "pass", "pass", true, []any{}), "нет проверок"},
		"no-report":                 {string(JSON(Object{"status": "pass", "passed": true})), "нет report"},
		"failed-check":              {envelope(true, "pass", "pass", true, failedCheck), "не принята"},
		"error-check":               {envelope(true, "pass", "pass", true, errorCheck), "не принята"},
		"invented-synonym":          {envelope(true, "passed", "passed", true, goodChecks), "не pass"},
		"real-fail-example":         {envelope(false, "fail", "fail", true, failedCheck), "не принята"},
	} {
		got := renderValidation(tc.raw, true)
		if strings.Contains(got, "Итог: принята") || !strings.Contains(got, tc.want) {
			t.Errorf("%s: want %q and no acceptance\n%s", name, tc.want, got)
		}
	}
}

func TestRenderValidationLegacyAndUnknown(t *testing.T) {
	if got := renderValidation(`{"passed":true,"service_active":true,"output":"LEGACY-LOG"}`, true); !strings.Contains(got, "пройдена") || strings.Contains(got, "LEGACY-LOG") || !strings.Contains(got, "service_active") {
		t.Error(got)
	}
	got := renderValidation("PLAY RECAP SECRET-LOG ok=3", true)
	if !strings.Contains(got, "неизвестен") || strings.Contains(got, "SECRET-LOG") {
		t.Error(got)
	}
	if got = renderValidation("", false); !strings.Contains(got, "неизвестен") {
		t.Error(got)
	}
}

func TestAnalysisJSONEqualsRenderedMarkdown(t *testing.T) {
	for _, skip := range []bool{true, false} {
		o, _, _ := analysisFixture(t, func(w http.ResponseWriter, r *http.Request) { answer(w) })
		actions := []any{Object{"id": 1, "cmd": "ls", "rc": 0}}
		if skip {
			actions = []any{}
		}
		writePacket(t, o, actions, []any{})
		o.Validation = filepath.Join(filepath.Dir(o.Config), "validation.json")
		if e := AtomicText(o.Validation, []byte(goodEnvelope())); e != nil {
			t.Fatal(e)
		}
		if _, e := Analyze(context.Background(), o); e != nil {
			t.Fatal(e)
		}
		report, _ := readJSON(filepath.Join(o.Output, "analysis.json"))
		b, _ := os.ReadFile(filepath.Join(o.Output, "analysis.md"))
		text, ok := report["analysis"].(string)
		if !ok || text != strings.TrimSuffix(string(b), "\n") || !strings.Contains(text, "service_active") {
			t.Fatalf("skip=%v analysis mismatch: %v", skip, report["analysis"])
		}
	}
}

func TestEmbeddedPromptDefinesReferenceContract(t *testing.T) {
	b, e := os.ReadFile("../../docs/prompts/llm-analysis-prompt.md")
	if e != nil {
		t.Fatal(e)
	}
	for _, want := range []string{"[action:", "[context:", "не выдумывай"} {
		if !strings.Contains(string(b), want) {
			t.Errorf("prompt lacks %q", want)
		}
	}
}
