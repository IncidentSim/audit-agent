package agent

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"runtime/debug"
	"strings"
	"testing"
	"time"
)

func exportFixture(t *testing.T, count int) (*Agent, Object) {
	t.Helper()
	root := t.TempDir()
	a := &Agent{Root: root, RawDir: filepath.Join(root, "raw"), VMID: "vm", auditStatus: func() ([]byte, error) { return []byte("enabled 1\nlost 0\n"), nil }}
	a.Store = &Store{Root: root, Boot: "boot", Write: Append}
	if err := os.MkdirAll(a.RawDir, 0700); err != nil {
		t.Fatal(err)
	}
	stamp := time.Unix(1730000000, 123000000).UTC().Format(time.RFC3339Nano)
	window := Object{"session_id": "attempt", "vm_id": "vm", "boot_id": "boot", "phase": "stopped", "started_at": stamp, "stopped_at": stamp, "start_boundary": Object{"serial": 1, "timestamp": stamp}, "stop_boundary": Object{"serial": count + 2, "timestamp": stamp}}
	if err := a.Store.save(window); err != nil {
		t.Fatal(err)
	}
	if err := Atomic(filepath.Join(root, "collector-health.json"), Object{"conversion_errors": 0}); err != nil {
		t.Fatal(err)
	}
	return a, window
}

func TestExportInterleavedRawWithoutEOECrossesRotations(t *testing.T) {
	a, _ := exportFixture(t, 43)
	stale := filepath.Join(a.Root, ".export-interrupted")
	if err := os.Mkdir(stale, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(stale, "raw-0"), []byte("unfinished snapshot"), 0600); err != nil {
		t.Fatal(err)
	}
	older, current := "", ""
	for _, serial := range []int{43, 42} {
		lines := strings.Split(strings.TrimSpace(records(serial)), "\n")
		// First half of each event is in an older rotation, with events
		// interleaved. Raw audit logs need not contain EOE at all.
		older += strings.Join(lines[:2], "\n") + "\n"
		current += strings.Join(lines[2:len(lines)-1], "\n") + "\n"
	}
	for name, text := range map[string]string{"audit.log.1": older, "audit.log": current} {
		if err := os.WriteFile(filepath.Join(a.RawDir, name), []byte(text), 0600); err != nil {
			t.Fatal(err)
		}
	}
	result, err := a.Export(ExportOptions{Session: "attempt"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(stale); !os.IsNotExist(err) {
		t.Fatalf("interrupted export snapshot was retained: %v", err)
	}
	rows, err := ReadEvents(str(result["output"]))
	if err != nil || len(rows) != 4 {
		t.Fatalf("rows %d: %v", len(rows), err)
	}
	for _, row := range rows {
		if row["source"] == "auditd" && len(list(obj(row["process"])["argv"])) != 4 {
			t.Fatalf("split event was not reconstructed: %v", row)
		}
	}
}

// Run under a Linux memory cgroup, e.g. MemoryMax=128M and MemorySwapMax=0.
func TestExportMemoryStress(t *testing.T) {
	if os.Getenv("INCIDENT_AUDIT_MEMORY_TEST") != "1" {
		t.Skip("opt-in memory/cgroup regression")
	}
	previous := debug.SetMemoryLimit(64 << 20)
	defer debug.SetMemoryLimit(previous)
	const count = 100000
	a, _ := exportFixture(t, count)
	file, err := os.Create(filepath.Join(a.RawDir, "audit.log"))
	if err != nil {
		t.Fatal(err)
	}
	writer := bufio.NewWriter(file)
	for serial := 2; serial < count+2; serial++ {
		// A common noisy syscall, with no EOE: parsing and exporting must be
		// bounded even when all 100,000 events are inside the capture window.
		_, err = fmt.Fprintf(writer, "type=SYSCALL msg=audit(1730000000.123:%d): arch=c000003e syscall=257 success=yes exit=3 ppid=99 pid=100 auid=0 uid=0 euid=0 tty=pts0 ses=3 comm=\"worker\" exe=\"/usr/bin/worker\" key=\"incsim_file\"\ntype=CWD msg=audit(1730000000.123:%d): cwd=\"/tmp\"\ntype=PATH msg=audit(1730000000.123:%d): item=0 name=\"/dev/null\" nametype=NORMAL\n", serial, serial, serial)
		if err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Flush(); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	result, err := a.Export(ExportOptions{Session: "attempt"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if num(result["events"]) != count+2 {
		t.Fatalf("lost events: %v", result)
	}
	stats, err := readJSON(str(result["llm_stats"]))
	if err != nil || num(stats["input_events"]) != count+2 || num(obj(stats["discarded"])["terminal_device_opens"]) != count {
		t.Fatalf("compact counts: %v, %v", stats, err)
	}
}
