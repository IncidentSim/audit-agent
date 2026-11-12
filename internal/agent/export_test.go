package agent

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestExportRawRecoveryAndSessionIsolation(t *testing.T) {
	root := t.TempDir()
	a := &Agent{Root: root, RawDir: filepath.Join(root, "raw"), VMID: "vm", auditStatus: func() ([]byte, error) { return []byte("enabled 1\nlost 0\n"), nil }}
	a.Store = &Store{Root: root, Boot: "boot", Write: Append}
	os.MkdirAll(a.RawDir, 0700)
	dir := a.Store.directory("attempt")
	os.MkdirAll(dir, 0700)
	stamp := time.Unix(1730000000, 123000000).UTC().Format(time.RFC3339Nano)
	w := Object{"session_id": "attempt", "vm_id": "vm", "boot_id": "boot", "phase": "stopped", "started_at": stamp, "stopped_at": stamp, "start_boundary": Object{"serial": 41, "timestamp": stamp}, "stop_boundary": Object{"serial": 44, "timestamp": stamp}}
	if e := a.Store.save(w); e != nil {
		t.Fatal(e)
	}
	if e := Atomic(filepath.Join(root, "collector-health.json"), Object{"conversion_errors": 0}); e != nil {
		t.Fatal(e)
	}
	// Raw logs recover both missing telemetry and a damaged JSONL version of an event.
	raw := records(40) + records(42) + records(43) + records(44)
	if e := os.WriteFile(filepath.Join(a.RawDir, "audit.log"), []byte(raw), 0600); e != nil {
		t.Fatal(e)
	}
	if e := Append(Object{"event_id": "vm:audit:1730000000.123:42", "vm_id": "vm", "capture_session_id": "attempt", "source": "auditd", "audit_serial": 42, "timestamp": stamp, "kind": "damaged"}, filepath.Join(dir, "events.jsonl")); e != nil {
		t.Fatal(e)
	}
	result, e := a.Export(ExportOptions{Session: "attempt"}, nil)
	if e != nil {
		t.Fatal(e)
	}
	events, e := ReadEvents(str(result["output"]))
	if e != nil || len(events) != 4 {
		t.Fatal(len(events), e)
	}
	execs := 0
	for _, event := range events {
		if event["source"] == "auditd" {
			execs++
			if event["kind"] != "exec" || (num(event["audit_serial"]) != 42 && num(event["audit_serial"]) != 43) {
				t.Fatal(event)
			}
		}
	}
	if execs != 2 {
		t.Fatal(execs)
	}
	packet, e := readJSON(str(result["llm"]))
	if e != nil || len(list(packet["context"])) != 2 {
		t.Fatal(packet, e)
	}
	manifest, e := readJSON(str(result["manifest"]))
	if e != nil || num(manifest["raw_logs_reparsed"]) != 1 {
		t.Fatal(manifest, e)
	}
	info, _ := os.Stat(str(result["output"]))
	if os.PathSeparator != '\\' && info.Mode().Perm() != 0600 {
		t.Fatal("export permissions")
	}
	if _, e = a.Export(ExportOptions{All: true, Session: "attempt"}, nil); e == nil {
		t.Fatal("conflicting selection accepted")
	}
}
func TestCompactFailureKeepsPublishedSource(t *testing.T) {
	dir := t.TempDir()
	source := filepath.Join(dir, "actions.jsonl")
	event := Object{"event_id": "a", "timestamp": "2026-11-11T00:00:01Z", "capture_session_id": "a", "source": "bash", "kind": "command_start", "command_id": "1", "command": "true"}
	Append(event, source)
	Atomic(filepath.Join(dir, "actions.manifest.json"), Object{"capture": Object{"phase": "stopped", "session_id": "a", "started_at": "2026-11-11T00:00:00Z", "stopped_at": "2026-11-11T00:00:02Z"}})
	o := CompactOptions{Input: source, EffectsLimit: 24, ExecLimit: 12}
	result, e := Compact(o)
	if e != nil {
		t.Fatal(e)
	}
	before, _ := os.ReadFile(str(result["llm"]))
	o.MaxBytes = 1
	if _, e = Compact(o); e == nil || !strings.Contains(e.Error(), "silently dropped") {
		t.Fatal(e)
	}
	after, _ := os.ReadFile(str(result["llm"]))
	if string(before) != string(after) {
		t.Fatal("failed compact replaced packet")
	}
	o.Output = source
	if _, e = Compact(o); e == nil {
		t.Fatal("source overwritten")
	}
}
