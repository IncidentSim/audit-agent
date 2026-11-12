package agent

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

func storeFixture(t *testing.T) (*Store, func() (Object, error)) {
	t.Helper()
	s := &Store{Root: t.TempDir(), Boot: "boot-1", Write: Append}
	serial := 0
	return s, func() (Object, error) {
		serial += 10
		return Object{"serial": serial, "timestamp": fmt.Sprintf("2026-11-11T00:00:%02d.000Z", serial/10), "boot_id": s.Boot}, nil
	}
}
func TestCaptureLifecycleAndBoundaries(t *testing.T) {
	s, b := storeFixture(t)
	state, e := s.Start("attempt", "vm", b)
	if e != nil {
		t.Fatal(e)
	}
	again, e := s.Start("attempt", "vm", func() (Object, error) { t.Fatal("idempotent start called boundary"); return nil, nil })
	if e != nil || again["started_at"] != state["started_at"] {
		t.Fatal(again, e)
	}
	if _, e = s.Start("other", "vm", b); e == nil {
		t.Fatal("parallel session permitted")
	}
	event := Object{"vm_id": "vm", "source": "auditd", "timestamp": "2026-11-11T00:00:01.000Z", "event_id": "vm:audit:1:11", "audit_serial": 11}
	if ok, e := s.Record(event); !ok || e != nil {
		t.Fatal(ok, e)
	}
	event["audit_serial"] = 10
	if ok, _ := s.Record(event); ok {
		t.Fatal("included start boundary")
	}
	if _, e = s.Stop("other", b, func(Object) (Object, error) { t.Fatal("wrong session finalized"); return nil, nil }); e == nil {
		t.Fatal("wrong stop allowed")
	}
	state, e = s.Stop("attempt", b, func(w Object) (Object, error) {
		if w["phase"] != "stopped" {
			t.Fatal(w)
		}
		return Object{"llm": "packet"}, nil
	})
	if e != nil {
		t.Fatal(e)
	}
	if ok, e := s.Record(event); ok || e != nil {
		t.Fatal("recorded after stop", e)
	}
	again, e = s.Stop("attempt", b, func(Object) (Object, error) { t.Fatal("repeated stop exported"); return nil, nil })
	if e != nil || again["stopped_at"] != state["stopped_at"] {
		t.Fatal(e)
	}
	if _, e = s.Start("attempt", "vm", b); e == nil {
		t.Fatal("reused stopped identity")
	}
	if _, e = s.Start("new", "vm", b); e != nil {
		t.Fatal(e)
	}
	if _, e = s.Stop("attempt", b, nil); e == nil {
		t.Fatal("old stop allowed during new recording")
	}
}
func TestStopRetryRetainsCutoff(t *testing.T) {
	s, b := storeFixture(t)
	if _, e := s.Start("a", "vm", b); e != nil {
		t.Fatal(e)
	}
	fail := errors.New("export failed")
	_, e := s.Stop("a", b, func(Object) (Object, error) { return nil, fail })
	if !errors.Is(e, fail) {
		t.Fatal(e)
	}
	state, _ := s.Get("a")
	cutoff := state["stopped_at"]
	if _, e = s.Stop("a", func() (Object, error) { t.Fatal("cutoff changed"); return nil, nil }, func(w Object) (Object, error) {
		if w["stopped_at"] != cutoff {
			t.Fatal(w)
		}
		return Object{}, nil
	}); e != nil {
		t.Fatal(e)
	}
}
func TestCaptureRebootAndBadIDs(t *testing.T) {
	s, b := storeFixture(t)
	for _, id := range []string{"", "../escape", "-bad", "a/b", "привет"} {
		if _, e := s.Start(id, "vm", b); e == nil {
			t.Fatal(id)
		}
	}
	s.Start("a", "vm", b)
	s.Boot = "boot-2"
	if _, e := s.Start("a", "vm", b); e == nil {
		t.Fatal("reboot start")
	}
	if _, e := s.Stop("a", b, nil); e == nil {
		t.Fatal("reboot stop")
	}
	if ok, _ := s.Record(Object{}); ok {
		t.Fatal("reboot recorded")
	}
}
func TestConcurrentWriters(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "events.jsonl")
	var wg sync.WaitGroup
	for worker := 0; worker < 8; worker++ {
		wg.Add(1)
		go func(worker int) {
			defer wg.Done()
			for i := 0; i < 30; i++ {
				if e := Append(Object{"event_id": fmt.Sprintf("%d-%d", worker, i), "command": "a\nb \"c\""}, file); e != nil {
					t.Error(e)
				}
			}
		}(worker)
	}
	wg.Wait()
	events, e := ReadEvents(file)
	if e != nil || len(events) != 240 {
		t.Fatal(len(events), e)
	}
	info, _ := os.Stat(file)
	if info.Mode().Perm() != 0600 && os.PathSeparator != '\\' {
		t.Fatal("permissions")
	}
}
