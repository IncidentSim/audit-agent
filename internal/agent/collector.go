package agent

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

type Agent struct {
	Root, ContextPath, RawDir string
	Store                     *Store
	VMID                      string
	auditStatus               func() ([]byte, error)
}

func OpenAgent() (*Agent, error) {
	cfg, e := readJSON("/etc/incidentsim/audit-context.json")
	if e != nil {
		return nil, e
	}
	boot, e := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if e != nil {
		return nil, e
	}
	a := &Agent{Root: "/var/log/incidentsim", ContextPath: "/etc/incidentsim/audit-context.json", RawDir: "/var/log/audit", VMID: str(cfg["vm_id"])}
	a.Store = &Store{Root: a.Root, Boot: strings.TrimSpace(string(boot)), Write: Append}
	return a, nil
}
func Append(event Object, path string) error {
	if e := os.MkdirAll(filepath.Dir(path), 0700); e != nil {
		return e
	}
	unlock, e := lock(filepath.Join(filepath.Dir(path), ".events.lock"))
	if e != nil {
		return e
	}
	defer unlock()
	line := append(JSON(event), '\n')
	if info, e := os.Stat(path); e == nil && info.Size()+int64(len(line)) > 16<<20 {
		for i := 3; i > 0; i-- {
			old := path
			if i > 1 {
				old = fmt.Sprintf("%s.%d", path, i-1)
			}
			if _, e := os.Stat(old); e == nil {
				if e = os.Rename(old, fmt.Sprintf("%s.%d", path, i)); e != nil {
					return e
				}
			}
		}
	}
	f, e := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if e != nil {
		return e
	}
	_, e = f.Write(line)
	ce := f.Close()
	if e == nil {
		e = ce
	}
	return e
}
func (a *Agent) Boundary() (Object, error) {
	tok := token()
	if out, e := exec.Command("auditctl", "-m", "incsim_boundary="+tok).CombinedOutput(); e != nil {
		return nil, fmt.Errorf("audit boundary marker failed: %w (%s)", e, strings.TrimSpace(string(out)))
	}
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		v, e := readJSON(filepath.Join(a.Root, "boundary-ack.json"))
		if e == nil && v["token"] == tok {
			return Object{"timestamp": v["timestamp"], "serial": v["serial"], "boot_id": v["boot_id"]}, nil
		}
		if e != nil && !os.IsNotExist(e) {
			return nil, e
		}
		time.Sleep(50 * time.Millisecond)
	}
	return nil, errors.New("audit dispatcher did not acknowledge the boundary; inspect auditd and retry")
}
func (a *Agent) Status() (Object, error) {
	status := a.auditStatus
	if status == nil {
		status = func() ([]byte, error) { return exec.Command("auditctl", "-s").Output() }
	}
	out, e := status()
	if e != nil {
		return nil, e
	}
	kernel := Object{}
	for _, line := range strings.Split(string(out), "\n") {
		f := strings.Fields(line)
		if len(f) < 2 {
			continue
		}
		n, err := strconv.Atoi(f[1])
		if err == nil {
			kernel[f[0]] = n
		} else {
			kernel[f[0]] = strings.Join(f[1:], " ")
		}
	}
	capture, e := a.Store.Current()
	if e != nil {
		return nil, e
	}
	health, e := readJSON(filepath.Join(a.Root, "collector-health.json"))
	if e != nil && !os.IsNotExist(e) {
		return nil, e
	}
	return Object{"vm_id": a.VMID, "checked_at": now(), "audit": kernel, "capture": capture, "collector": health, "retention": Object{"jsonl_file_mib": 16, "jsonl_files": 4, "raw_file_mib": 16, "raw_files": 8}}, nil
}
func (a *Agent) Stream(ctx context.Context, input io.Reader) error {
	if e := LoadSyscalls(); e != nil {
		return e
	}
	if e := os.MkdirAll(a.Root, 0700); e != nil {
		return e
	}
	total, conversionErrors := 0, 0
	type pending struct {
		At       time.Time
		Boundary Object
	}
	boundaries := []pending{}
	health := func(stopped bool) error {
		v := Object{"updated_at": now(), "pid": os.Getpid(), "events_written": total, "conversion_errors": conversionErrors}
		if stopped {
			v["stopped_at"] = now()
		}
		return Atomic(filepath.Join(a.Root, "collector-health.json"), v)
	}
	parser := NewAuditParser(func(e *AuditEvent) error {
		if b := BoundaryInEvent(e, a.Store.Boot); b != nil {
			boundaries = append(boundaries, pending{time.Now(), b})
			return nil
		}
		event, err := Normalize(e, a.VMID)
		if err != nil {
			return err
		}
		written, err := a.Store.Record(event)
		if written {
			total++
		}
		return err
	})
	report := func(e error) {
		if e != nil {
			conversionErrors++
			fmt.Fprintln(os.Stderr, "JSONL conversion failed; raw audit log retained")
		}
	}
	type scanned struct {
		line string
		err  error
	}
	lines := make(chan scanned, 64)
	done := make(chan struct{})
	defer close(done)
	go func() {
		defer close(lines)
		s := bufio.NewScanner(input)
		s.Buffer(make([]byte, 65536), 32<<20)
		for s.Scan() {
			select {
			case lines <- scanned{line: s.Text()}:
			case <-done:
				return
			}
		}
		if e := s.Err(); e != nil {
			select {
			case lines <- scanned{err: e}:
			case <-done:
			}
		}
	}()
	if e := health(false); e != nil {
		return e
	}
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	lastHealth := time.Now()
	defer health(true)
	for {
		select {
		case <-ctx.Done():
			report(parser.Flush(0))
			return nil
		case line, ok := <-lines:
			if !ok {
				report(parser.Flush(0))
				return nil
			}
			if line.err != nil {
				return line.err
			}
			report(parser.Feed(line.line))
		case <-ticker.C:
			report(parser.Flush(2 * time.Second))
			for len(boundaries) > 0 && time.Since(boundaries[0].At) >= 2100*time.Millisecond {
				if e := Atomic(filepath.Join(a.Root, "boundary-ack.json"), boundaries[0].Boundary); e != nil {
					return e
				}
				boundaries = boundaries[1:]
			}
			if time.Since(lastHealth) >= 5*time.Second {
				if e := health(false); e != nil {
					return e
				}
				lastHealth = time.Now()
			}
		}
	}
}
func (a *Agent) Shell(phase, history string, pid int, cwd, tty string, status *int) error {
	if phase != "start" && phase != "finish" {
		return errors.New("phase must be start or finish")
	}
	m := regexp.MustCompile(`(?s)^\s*(\d+)\s+(.*)$`).FindStringSubmatch(history)
	if m == nil {
		return nil
	}
	actor := Object{"uid": os.Getuid(), "effective_uid": os.Geteuid()}
	for k, f := range map[string]string{"login_uid": "loginuid", "session_id": "sessionid"} {
		b, _ := os.ReadFile(fmt.Sprintf("/proc/%d/%s", pid, f))
		actor[k] = number(string(b))
	}
	identity := fmt.Sprintf("%s:%d:%s", a.Store.Boot, pid, m[1])
	event := Object{"schema_version": 1, "event_id": "shell:" + identity + ":" + phase, "command_id": identity, "timestamp": now(), "vm_id": a.VMID, "source": "bash", "kind": "command_" + phase, "origin": "session", "actor": actor, "shell_pid": pid, "tty": tty, "cwd": cwd, "command": m[2], "exit_status": nil}
	if phase == "finish" && status != nil {
		event["exit_status"] = *status
	}
	_, e := a.Store.Record(event)
	return e
}

type ExportOptions struct {
	Session, Output             string
	All, IncludeInstrumentation bool
}

func snapshot(source, target string) error {
	r, e := os.Open(source)
	if e != nil {
		return e
	}
	defer r.Close()
	info, e := r.Stat()
	if e != nil {
		return e
	}
	w, e := os.OpenFile(target, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if e != nil {
		return e
	}
	_, e = io.CopyN(w, r, info.Size())
	ce := w.Close()
	if e == nil {
		e = ce
	}
	return e
}
func (a *Agent) Export(o ExportOptions, w Object) (Object, error) {
	if o.All && o.Session != "" {
		return nil, errors.New("--all and --session-id are mutually exclusive")
	}
	if w == nil && !o.All {
		var e error
		w, e = a.Store.Get(o.Session)
		if e != nil {
			return nil, e
		}
		if w["phase"] != "stopped" {
			return nil, errors.New("stop the recording session before exporting its final snapshot")
		}
	}
	source := a.Root
	if w != nil {
		source = a.Store.directory(str(w["session_id"]))
	}
	output := o.Output
	if output == "" {
		output = filepath.Join(source, "actions.jsonl")
	}
	unlock, e := lock(filepath.Join(a.Root, ".export.lock"))
	if e != nil {
		return nil, e
	}
	defer unlock()
	// A SIGKILL/OOM cannot run deferred cleanup. With the export lock held,
	// these private snapshots belong only to interrupted previous exports.
	entries, e := os.ReadDir(a.Root)
	if e != nil {
		return nil, e
	}
	for _, entry := range entries {
		if entry.IsDir() && strings.HasPrefix(entry.Name(), ".export-") {
			if e = os.RemoveAll(filepath.Join(a.Root, entry.Name())); e != nil {
				return nil, e
			}
		}
	}
	temporary, e := os.MkdirTemp(a.Root, ".export-")
	if e != nil {
		return nil, e
	}
	defer os.RemoveAll(temporary)
	candidates := &diskSort{dir: temporary}
	bad := 0
	insert := func(v Object, replace bool) error {
		if e := required(v, "event_id", "timestamp"); e != nil {
			return e
		}
		if w != nil {
			if !InWindow(v, w) {
				return nil
			}
			v = clone(v)
			v["capture_session_id"] = w["session_id"]
		}
		if v["origin"] == "instrumentation" && !o.IncludeInstrumentation {
			return nil
		}
		priority := byte(0)
		if replace {
			priority = 1
		}
		return candidates.Add(str(v["event_id"]), append([]byte{priority}, JSON(v)...))
	}
	dirs := []string{source}
	if w == nil {
		sessions, _ := filepath.Glob(filepath.Join(a.Root, "sessions", "*"))
		dirs = append(dirs, sessions...)
	}
	index := 0
	for _, dir := range dirs {
		info, err := os.Stat(dir)
		if err != nil || !info.IsDir() {
			continue
		}
		release, err := lock(filepath.Join(dir, ".events.lock"))
		if err != nil {
			return nil, err
		}
		files, err := filepath.Glob(filepath.Join(dir, "events.jsonl*"))
		if err != nil {
			release()
			return nil, err
		}
		for _, f := range files {
			frozen := filepath.Join(temporary, fmt.Sprintf("json-%d", index))
			index++
			if err = snapshot(f, frozen); err != nil {
				break
			}
		}
		release()
		if err != nil {
			return nil, err
		}
	}
	files, _ := filepath.Glob(filepath.Join(temporary, "json-*"))
	for _, file := range files {
		f, err := os.Open(file)
		if err != nil {
			return nil, err
		}
		s := bufio.NewScanner(f)
		s.Buffer(make([]byte, 65536), 32<<20)
		for s.Scan() {
			var event Object
			if json.Unmarshal(s.Bytes(), &event) != nil || required(event, "event_id", "timestamp") != nil {
				bad++
				continue
			}
			if err = insert(event, false); err != nil {
				f.Close()
				return nil, err
			}
		}
		err = s.Err()
		f.Close()
		if err != nil {
			return nil, err
		}
	}
	raw, _ := filepath.Glob(filepath.Join(a.RawDir, "audit.log*"))
	sort.Slice(raw, func(i, j int) bool {
		suffix := func(s string) int { n, _ := strconv.Atoi(strings.TrimPrefix(filepath.Base(s), "audit.log.")); return n }
		return suffix(raw[i]) > suffix(raw[j])
	})
	parser := NewAuditParser(func(e *AuditEvent) error {
		v, err := Normalize(e, a.VMID)
		if err != nil {
			return err
		}
		return insert(v, true)
	})
	// Freeze every raw file before parsing: exporter syscalls cannot extend the snapshot.
	for i, file := range raw {
		if e = snapshot(file, filepath.Join(temporary, fmt.Sprintf("raw-%d", i))); e != nil {
			return nil, e
		}
	}
	rawRecords := &diskSort{dir: temporary}
	for i := range raw {
		f, err := os.Open(filepath.Join(temporary, fmt.Sprintf("raw-%d", i)))
		if err != nil {
			return nil, err
		}
		s := bufio.NewScanner(f)
		s.Buffer(make([]byte, 65536), 32<<20)
		for s.Scan() {
			key, keep, keyErr := rawExportKey(s.Text(), w)
			if keyErr != nil {
				f.Close()
				return nil, keyErr
			}
			if !keep {
				continue
			}
			if e = rawRecords.Add(key, s.Bytes()); e != nil {
				f.Close()
				return nil, e
			}
		}
		err = s.Err()
		f.Close()
		if err != nil {
			return nil, err
		}
	}
	previous := ""
	if e = rawRecords.Finish(func(row sortRecord) error {
		if row.key != previous {
			if err := parser.Flush(0); err != nil {
				return err
			}
			previous = row.key
		}
		return parser.Feed(string(row.data))
	}); e != nil {
		return nil, e
	}
	if e = parser.Flush(0); e != nil {
		return nil, e
	}
	if w != nil {
		for label, field := range map[string]string{"recording_started": "start_boundary", "recording_stopped": "stop_boundary"} {
			b := obj(w[field])
			if e = insert(Object{"schema_version": 1, "event_id": fmt.Sprintf("%s:capture:%s:%s", a.VMID, w["session_id"], label), "timestamp": b["timestamp"], "vm_id": a.VMID, "source": "control", "kind": "marker", "origin": "control", "capture_session_id": w["session_id"], "label": label, "audit_serial": b["serial"]}, false); e != nil {
				return nil, e
			}
		}
	}
	summary, e := publishExport(candidates, output, temporary)
	if e != nil {
		return nil, e
	}
	manifest, e := a.Status()
	if e != nil {
		return nil, e
	}
	manifest["capture"] = nil
	if w != nil {
		sealed := clone(w)
		delete(sealed, "artifacts")
		manifest["capture"] = sealed
	}
	manifest["schema_version"] = 1
	manifest["events"] = summary.Count
	manifest["first_event"] = summary.First
	manifest["last_event"] = summary.Last
	manifest["invalid_jsonl_lines"] = bad
	manifest["raw_logs_reparsed"] = len(raw)
	manifest["output"] = output
	manifest["limitations"] = []string{"Retention is bounded; older rotated logs may be absent.", "Audit does not capture stdout, stderr or file contents.", "Root can disable or alter this guest-local telemetry.", "Bash hooks apply to new interactive Bash sessions."}
	manifestPath := strings.TrimSuffix(output, filepath.Ext(output)) + ".manifest.json"
	if e = Atomic(manifestPath, manifest); e != nil {
		return nil, e
	}
	result := Object{"output": output, "events": summary.Count, "manifest": manifestPath}
	if w != nil {
		compact, err := Compact(CompactOptions{Input: output, Manifest: manifestPath, EffectsLimit: 24, ExecLimit: 12})
		if err != nil {
			return nil, err
		}
		for _, k := range []string{"llm", "llm_sources", "llm_stats", "compact_bytes"} {
			result[k] = compact[k]
		}
		result["llm_actions"] = compact["actions"]
	}
	return result, nil
}

// Control preserves the TUI's durable attempt pointer and recovery after a lost SSH reply.
func (a *Agent) Control(work, name, operation, session string) ([]byte, error) {
	dir := filepath.Join(work, ".audit")
	if e := os.MkdirAll(dir, 0700); e != nil {
		return nil, e
	}
	unlock, e := lock(filepath.Join(dir, "control.lock"))
	if e != nil {
		return nil, e
	}
	defer unlock()
	file := filepath.Join(dir, "attempt.json")
	state, e := readJSON(file)
	if e != nil && !os.IsNotExist(e) {
		return nil, e
	}
	save := func() error { return Atomic(file, state) }
	stopPrevious := func() (Object, error) {
		if state == nil {
			return nil, nil
		}
		id := str(state["session_id"])
		if state["starting"] == true {
			if _, e := a.Store.Start(id, a.VMID, a.Boundary); e != nil {
				return nil, e
			}
			delete(state, "starting")
			if e := save(); e != nil {
				return nil, e
			}
		}
		return a.Store.Stop(id, a.Boundary, func(w Object) (Object, error) { return a.Export(ExportOptions{}, w) })
	}
	switch operation {
	case "reset":
		_, e = stopPrevious()
		return nil, e
	case "start":
		if _, e = stopPrevious(); e != nil {
			return nil, e
		}
		state = Object{"exercise": name, "session_id": session, "starting": true}
		if e = save(); e != nil {
			return nil, e
		}
		v, err := a.Store.Start(session, a.VMID, a.Boundary)
		if err != nil {
			return nil, err
		}
		if v["phase"] != "recording" {
			return nil, errors.New("audit did not enter recording phase")
		}
		delete(state, "starting")
		return nil, save()
	case "stop":
		if state == nil || state["exercise"] != name {
			return nil, errors.New("no audit attempt for this exercise; run infra/start first")
		}
		v, err := stopPrevious()
		if err != nil {
			return nil, err
		}
		if v["phase"] != "stopped" {
			return nil, errors.New("audit did not stop")
		}
		b, err := os.ReadFile(str(obj(v["artifacts"])["llm"]))
		if err != nil {
			return nil, err
		}
		var packet Object
		if json.Unmarshal(b, &packet) != nil || packet["session"] != state["session_id"] {
			return nil, errors.New("audit packet belongs to a different attempt")
		}
		return b, nil
	default:
		return nil, errors.New("unknown audit action")
	}
}
