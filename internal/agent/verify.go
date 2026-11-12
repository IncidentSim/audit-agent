package agent

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

// Verify exercises the installed collector through real kernel audit and Bash hooks.
// It refuses to interrupt an active participant recording.
func (a *Agent) Verify() (Object, error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	initial, e := a.Status()
	if e != nil {
		return nil, e
	}
	current := obj(initial["capture"])
	if len(current) > 0 && current["phase"] != "stopped" {
		return nil, errors.New("verification requires an idle collector; active user recording was left untouched")
	}
	login, e := os.ReadFile("/proc/thread-self/loginuid")
	if e != nil {
		return nil, e
	}
	if strings.TrimSpace(string(login)) == "4294967295" {
		if e = os.WriteFile("/proc/thread-self/loginuid", []byte(fmt.Sprint(os.Getuid())), 0600); e != nil {
			return nil, e
		}
	}
	id := "incsim-smoke-" + token()[:12]
	argument := id + " words\nпривет"
	before, after, tail := id+"-before", id+"-validator", id+"-last-before-stop"
	quiet := func(command string, args ...string) error { cmd := exec.Command(command, args...); return cmd.Run() }
	if e = quiet("/usr/bin/printf", "%s", before); e != nil {
		return nil, e
	}
	if _, e = a.Store.Start(id, a.VMID, a.Boundary); e != nil {
		return nil, e
	}
	stopped := false
	defer func() {
		if !stopped {
			_, _ = a.Store.Stop(id, a.Boundary, func(w Object) (Object, error) { return a.Export(ExportOptions{}, w) })
		}
	}()
	dir, e := os.MkdirTemp("", id)
	if e != nil {
		return nil, e
	}
	defer os.RemoveAll(dir)
	if e = quiet("/usr/bin/printf", "%s", argument); e != nil {
		return nil, e
	}
	source, target := filepath.Join(dir, id+"-source"), filepath.Join(dir, id+"-renamed")
	for _, args := range [][]string{{"/usr/bin/touch", source}, {"/usr/bin/mv", source, target}, {"/usr/bin/chmod", "600", target}, {"/usr/bin/rm", target}} {
		if e = quiet(args[0], args[1:]...); e != nil {
			return nil, e
		}
	}
	script := "cd " + shellQuote(dir) + "\nfalse # " + id + "-false\nprintf repeat # " + id + "-repeat\nprintf repeat # " + id + "-repeat\nprintf builtin > " + id + "-builtin\nexit # " + id + "-exit\n"
	shellContext, cancelShell := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancelShell()
	cmd := exec.CommandContext(shellContext, "/bin/bash", "--noprofile", "--rcfile", "/etc/profile.d/incidentsim-audit.sh", "-i")
	cmd.Stdin = strings.NewReader(script)
	cmd.Env = append(os.Environ(), "HISTFILE=/dev/null", "PS1=", "PS2=")
	if b, err := cmd.CombinedOutput(); err != nil {
		return nil, fmt.Errorf("interactive test shell failed: %w (%s)", err, b)
	}
	b, e := os.ReadFile(filepath.Join(dir, id+"-builtin"))
	if e != nil || string(b) != "builtin" {
		return nil, errors.New("Bash builtin output missing")
	}
	if _, e = a.Store.Record(Object{"schema_version": 1, "event_id": token(), "timestamp": now(), "vm_id": a.VMID, "source": "control", "kind": "marker", "label": id}); e != nil {
		return nil, e
	}
	live := filepath.Join(a.Store.directory(id), "events.jsonl")
	liveEvents := []Object{}
	for i := 0; i < 40; i++ {
		liveEvents, e = ReadEvents(live)
		if e != nil {
			return nil, e
		}
		external, completed, exited := false, false, false
		for _, event := range liveEvents {
			for _, v := range list(obj(event["process"])["argv"]) {
				external = external || v == argument
			}
			completed = completed || (event["source"] == "bash" && event["kind"] == "command_finish" && event["command"] == "false # "+id+"-false" && num(event["exit_status"]) == 1)
			exited = exited || (event["source"] == "bash" && event["kind"] == "command_start" && event["command"] == "exit # "+id+"-exit")
		}
		if external && completed && exited {
			break
		}
		if i == 39 {
			return nil, errors.New("missing real-time exec, Bash completion or exit-command input")
		}
		time.Sleep(250 * time.Millisecond)
	}
	if e = quiet("/usr/bin/printf", "%s", tail); e != nil {
		return nil, e
	}
	state, e := a.Store.Stop(id, a.Boundary, func(w Object) (Object, error) { return a.Export(ExportOptions{}, w) })
	if e != nil {
		return nil, e
	}
	stopped = true
	artifacts := obj(state["artifacts"])
	info, e := os.Stat(live)
	if e != nil {
		return nil, e
	}
	size := info.Size()
	if e = quiet("/usr/bin/printf", "%s", after); e != nil {
		return nil, e
	}
	artifacts, e = a.Export(ExportOptions{Session: id}, nil)
	if e != nil {
		return nil, e
	}
	events, e := ReadEvents(str(artifacts["output"]))
	if e != nil {
		return nil, e
	}
	foundArgument, foundTail, foundFile := false, false, false
	seen := map[string]bool{}
	last := float64(0)
	for _, event := range events {
		id := str(event["event_id"])
		if seen[id] || moment(event["timestamp"]) < last {
			return nil, errors.New("export is not sorted and deduplicated")
		}
		seen[id] = true
		last = moment(event["timestamp"])
		for _, v := range list(obj(event["process"])["argv"]) {
			foundArgument = foundArgument || v == argument
			foundTail = foundTail || v == tail
			if v == before || v == after {
				return nil, errors.New("capture boundaries leaked")
			}
		}
		for _, v := range list(event["paths"]) {
			foundFile = foundFile || strings.Contains(str(obj(v)["name"]), id)
		}
		if event["capture_session_id"] != state["session_id"] {
			return nil, errors.New("event belongs to another session")
		}
	}
	if !foundArgument || !foundTail || !foundFile {
		return nil, errors.New("export lost exec arguments, buffered tail or file effects")
	}
	info, e = os.Stat(live)
	if e != nil || info.Size() != size {
		return nil, errors.New("JSONL kept growing after stop")
	}
	manifest, e := readJSON(str(artifacts["manifest"]))
	if e != nil {
		return nil, e
	}
	if num(obj(manifest["audit"])["enabled"]) != 1 || num(obj(manifest["audit"])["lost"]) != num(obj(initial["audit"])["lost"]) || num(manifest["invalid_jsonl_lines"]) != 0 || num(obj(manifest["collector"])["conversion_errors"]) != 0 {
		return nil, errors.New("audit is disabled, lost events or reported conversion errors")
	}
	packet, e := readJSON(str(artifacts["llm"]))
	if e != nil {
		return nil, e
	}
	failed, repeats := false, 0
	for _, v := range list(packet["actions"]) {
		row := obj(v)
		failed = failed || (row["cmd"] == "false # "+id+"-false" && num(row["rc"]) == 1)
		if row["cmd"] == "printf repeat # "+id+"-repeat" {
			repeats++
		}
		if strings.Contains(str(row["cmd"]), "__incidentsim_") || strings.Contains(string(JSON(row["effects"])), "/var/log/incidentsim/") {
			return nil, errors.New("collector instrumentation leaked into user actions")
		}
	}
	if !failed || repeats != 2 {
		return nil, errors.New("compact export lost actual status or merged repeated commands")
	}
	sourceBytes, e := os.ReadFile(str(artifacts["output"]))
	if e != nil {
		return nil, e
	}
	refs, e := readJSON(str(artifacts["llm_sources"]))
	if e != nil {
		return nil, e
	}
	if refs["sha256"] != fmt.Sprintf("%x", sha256.Sum256(sourceBytes)) {
		return nil, errors.New("provenance hash mismatch")
	}
	for _, v := range obj(refs["actions"]) {
		for _, id := range list(v) {
			if !seen[str(id)] {
				return nil, errors.New("invalid provenance reference")
			}
		}
	}
	for _, k := range []string{"output", "manifest", "llm", "llm_stats", "llm_sources"} {
		info, e := os.Stat(str(artifacts[k]))
		if e != nil || info.Mode().Perm() != 0600 {
			return nil, errors.New("private export permissions required")
		}
	}
	compactBytes, e := os.ReadFile(str(artifacts["llm"]))
	if e != nil {
		return nil, e
	}
	if len(compactBytes) >= len(sourceBytes) || bytes.Contains(compactBytes, []byte(before)) || bytes.Contains(compactBytes, []byte(after)) {
		return nil, errors.New("compact size or boundary check failed")
	}
	return Object{"result": "PASS", "events_in_export": len(events), "llm_actions": len(list(packet["actions"])), "source_bytes": len(sourceBytes), "compact_bytes": len(compactBytes), "audit_lost": obj(manifest["audit"])["lost"]}, nil
}
