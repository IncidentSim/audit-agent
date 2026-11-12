package agent

import (
	"bufio"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"os"
	"path"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strings"
)

var redactions = []*regexp.Regexp{
	regexp.MustCompile(`(?i)(https?://)[^/\s:@]+:[^@\s/]+@`),
	regexp.MustCompile(`(?i)(Authorization:\s*(?:Bearer|Basic)\s+)[^\s'"]+`),
	regexp.MustCompile(`(?i)(--(?:password|passwd|token|api-key|secret|access-key)(?:=|\s+))('[^']*'|"[^"]*"|[^\s;&|]+)`),
	regexp.MustCompile(`(?i)(\b(?:[A-Z_]*PASSWORD|[A-Z_]*TOKEN|[A-Z_]*API_KEY|[A-Z_]*SECRET)=)('[^']*'|"[^"]*"|[^\s;&|]+)`),
}

func redact(s string) string {
	for i, r := range redactions {
		replacement := "${1}<secret>"
		if i == 0 {
			replacement = "${1}<credentials>@"
		}
		s = r.ReplaceAllString(s, replacement)
	}
	return s
}
func redactTree(v any) any {
	switch x := v.(type) {
	case string:
		return redact(x)
	case []Object:
		for i := range x {
			x[i] = redactTree(x[i]).(Object)
		}
		return x
	case []any:
		for i := range x {
			x[i] = redactTree(x[i])
		}
		return x
	case Object:
		for k, t := range x {
			x[k] = redactTree(t)
		}
		return x
	}
	return v
}
func safeArgv(v any) []any {
	r := []any{}
	secret := false
	for _, a := range list(v) {
		s := "<missing-argument>"
		if a != nil {
			s = str(a)
		}
		if secret {
			r = append(r, "<secret>")
			secret = false
			continue
		}
		r = append(r, redact(s))
		secret = regexp.MustCompile(`(?i)^--(password|passwd|token|api-key|secret|access-key)$`).MatchString(s)
	}
	return r
}

// shellWords covers POSIX quotes, escapes and shell punctuation without executing input.
func shellWords(s string) ([]string, bool) {
	r := []string{}
	var b strings.Builder
	quote := rune(0)
	escaped, active := false, false
	flush := func() {
		if active {
			r = append(r, b.String())
			b.Reset()
			active = false
		}
	}
	for _, c := range s {
		if escaped {
			if quote == '"' && !strings.ContainsRune("$`\"\\\n", c) {
				b.WriteRune('\\')
			}
			if c != '\n' {
				b.WriteRune(c)
			}
			escaped = false
			active = true
			continue
		}
		if c == '\\' && quote != '\'' {
			escaped = true
			active = true
			continue
		}
		if quote != 0 {
			if c == quote {
				quote = 0
			} else {
				b.WriteRune(c)
			}
			active = true
			continue
		}
		if c == '\'' || c == '"' {
			quote = c
			active = true
			continue
		}
		if strings.ContainsRune(" \t\r\n", c) {
			flush()
			continue
		}
		if strings.ContainsRune(";&|()<>", c) {
			flush()
			r = append(r, string(c))
			continue
		}
		b.WriteRune(c)
		active = true
	}
	flush()
	return r, quote == 0 && !escaped
}
func shellQuote(s string) string {
	if s == "" {
		return "''"
	}
	if regexp.MustCompile(`^[a-zA-Z0-9_@%+=:,./-]+$`).MatchString(s) {
		return s
	}
	return "'" + strings.ReplaceAll(s, "'", "'\"'\"'") + "'"
}
func argvCommand(v any) string {
	a := safeArgv(v)
	s := []string{}
	for _, v := range a {
		s = append(s, shellQuote(str(v)))
	}
	return strings.Join(s, " ")
}
func argvVisible(args any, cmd string) bool {
	a := list(args)
	if len(a) == 0 {
		return false
	}
	for _, v := range a {
		if v == nil {
			return false
		}
	}
	words, ok := shellWords(cmd)
	if !ok {
		return false
	}
	for i := 0; i+len(a) <= len(words); i++ {
		match := path.Base(words[i]) == path.Base(str(a[0]))
		for j := 1; j < len(a); j++ {
			match = match && words[i+j] == str(a[j])
		}
		if match {
			return true
		}
	}
	return false
}
func controlCommand(cmd string) bool {
	if strings.ContainsAny(cmd, ";|&$<>`\n") {
		return false
	}
	a, ok := shellWords(cmd)
	return ok && len(a) >= 2 && path.Base(a[0]) == "incident-audit" && strings.Contains(" start stop status export compact mark shell ", " "+a[1]+" ")
}
func controlWrapper(e Object) bool {
	a := list(obj(e["process"])["argv"])
	return str(e["kind"]) == "exec" && len(a) == 3 && strings.Contains(" bash sh dash ", " "+path.Base(str(a[0]))+" ") && (a[1] == "-c" || a[1] == "-lc") && controlCommand(str(a[2]))
}
func collectorEvent(e Object) bool {
	p := obj(e["process"])
	return e["origin"] == "instrumentation" || (p["name"] == "incident-audit" && (strings.HasPrefix(path.Base(str(p["executable"])), "python") || path.Base(str(p["executable"])) == "incident-audit"))
}

type actorID struct {
	Login, UID, Session any
	TTY                 string
}

func actorKey(e Object) actorID {
	a, p := obj(e["actor"]), obj(e["process"])
	tty := str(e["tty"])
	if tty == "" {
		tty = str(p["tty"])
	}
	tty = strings.TrimPrefix(tty, "/dev/")
	if tty == "(none)" || tty == "none" || tty == "?" {
		tty = ""
	}
	tty = regexp.MustCompile(`^pts(\d+)$`).ReplaceAllString(tty, "pts/$1")
	uid, ok := a["effective_uid"]
	if !ok {
		uid = a["uid"]
	}
	return actorID{a["login_uid"], uid, a["session_id"], tty}
}
func sameSession(a, b actorID) bool {
	return (a.Login == nil || b.Login == nil || a.Login == b.Login) && (a.UID == nil || b.UID == nil || a.UID == b.UID) && (a.Session == nil || b.Session == nil || a.Session == b.Session)
}
func sessionKey(e Object) string {
	a := obj(e["actor"])
	if a["login_uid"] == nil || a["session_id"] == nil {
		return ""
	}
	return string(JSON([]any{a["login_uid"], a["session_id"]}))
}

type detailGroup struct {
	Detail Object
	Count  int
}
type action struct {
	Key, Kind        string
	Start            float64
	End              *float64
	Actor            actorID
	Cmd              any
	RC               any
	CWD, CWDAfter    any
	ShellPID         any
	Refs             []any
	Effects, Execs   []detailGroup
	Parent           *action
	Note, ExecFailed any
	Missing          bool
}

func newAction(e Object, kind, key string) *action {
	p := obj(e["process"])
	cwd := e["cwd"]
	if cwd == nil {
		cwd = p["cwd"]
	}
	a := &action{Key: key, Kind: kind, Start: moment(e["timestamp"]), Actor: actorKey(e), CWD: cwd, ShellPID: e["shell_pid"], Refs: []any{}}
	a.ref(e)
	return a
}
func (a *action) ref(e Object) {
	id := e["event_id"]
	for _, v := range a.Refs {
		if v == id {
			return
		}
	}
	a.Refs = append(a.Refs, id)
}
func groupAdd(groups []detailGroup, d Object) []detailGroup {
	if len(groups) > 0 && reflect.DeepEqual(groups[len(groups)-1].Detail, d) {
		groups[len(groups)-1].Count++
	} else {
		groups = append(groups, detailGroup{d, 1})
	}
	return groups
}
func fileDetail(e Object, a *action) Object {
	call := str(e["syscall"])
	if call == "" {
		call = "file"
	}
	op := call
	if call == "open" || call == "openat" || call == "creat" {
		op = "write_open"
	} else if call == "openat2" {
		op = "open"
	}
	d := Object{"op": op, "p": nil}
	names := []any{}
	for _, v := range list(e["paths"]) {
		p := obj(v)
		n := str(p["name"])
		if p["nametype"] == "PARENT" || n == "" || n == "(null)" {
			continue
		}
		found := false
		for _, v := range names {
			found = found || v == n
		}
		if !found {
			names = append(names, n)
		}
	}
	if len(names) == 1 {
		d["p"] = names[0]
	} else if len(names) > 1 {
		d["p"] = names
	}
	if e["syscall_return"] != nil && num(e["syscall_return"]) < 0 {
		d["sysrc"] = e["syscall_return"]
	} else if e["syscall_success"] == nil {
		d["result_unknown"] = true
	}
	cwd := obj(e["process"])["cwd"]
	if cwd != nil && cwd != a.CWD {
		for _, n := range names {
			if !strings.HasPrefix(str(n), "/") {
				d["cwd"] = cwd
			}
		}
	}
	return d
}
func limited(groups []detailGroup, limit int) ([]Object, int) {
	indices := make([]int, len(groups))
	for i := range indices {
		indices[i] = i
	}
	priority := func(d Object) int {
		if _, ok := d["sysrc"]; ok {
			return 0
		}
		if d["op"] == "open" || d["op"] == "write_open" {
			return 2
		}
		return 1
	}
	sort.SliceStable(indices, func(i, j int) bool { return priority(groups[indices[i]].Detail) < priority(groups[indices[j]].Detail) })
	chosen := map[int]bool{}
	for i := 0; i < len(indices) && i < limit; i++ {
		chosen[indices[i]] = true
	}
	result := []Object{}
	omitted := 0
	for i, g := range groups {
		if !chosen[i] {
			omitted += g.Count
			continue
		}
		d := clone(g.Detail)
		if g.Count > 1 {
			d["n"] = g.Count
		}
		result = append(result, d)
	}
	return result, omitted
}
func ReadEvents(file string) ([]Object, error) {
	f, e := os.Open(file)
	if e != nil {
		return nil, e
	}
	defer f.Close()
	r := []Object{}
	s := bufio.NewScanner(f)
	s.Buffer(make([]byte, 65536), 32<<20)
	line := 0
	for s.Scan() {
		line++
		if len(strings.TrimSpace(s.Text())) == 0 {
			continue
		}
		var v Object
		if json.Unmarshal(s.Bytes(), &v) != nil {
			return nil, fmt.Errorf("invalid JSONL at line %d", line)
		}
		r = append(r, v)
	}
	return r, s.Err()
}
func BuildPacket(events []Object, manifest Object, effectsLimit, execLimit int) (Object, Object, Object, error) {
	w := obj(manifest["capture"])
	if w["phase"] != "stopped" {
		return nil, nil, nil, errors.New("a manifest with a stopped recording window is required")
	}
	if effectsLimit < 0 || execLimit < 0 {
		return nil, nil, nil, errors.New("detail limits must be nonnegative")
	}
	baseline, end := moment(w["started_at"]), moment(w["stopped_at"])
	actions := []*action{}
	shells := map[string]*action{}
	discarded := Object{}
	discard := func(k string) { discarded[k] = num(discarded[k]) + 1 }
	ssh, controls := map[string]bool{}, map[string]bool{}
	for _, e := range events {
		if e["capture_session_id"] != w["session_id"] {
			return nil, nil, nil, errors.New("event belongs to another recording window")
		}
		session := sessionKey(e)
		p := obj(e["process"])
		if session != "" && (p["executable"] == "/usr/sbin/sshd" || p["executable"] == "/usr/bin/sshd") {
			ssh[session] = true
		}
		if session != "" && controlWrapper(e) {
			controls[session] = true
		}
		if e["source"] != "bash" {
			continue
		}
		if controlCommand(str(e["command"])) {
			discard("instrumentation")
			continue
		}
		id := str(e["command_id"])
		a := shells[id]
		if a == nil {
			a = newAction(e, "command", id)
			a.Missing = e["kind"] != "command_start"
			shells[id] = a
			actions = append(actions, a)
		}
		a.ref(e)
		a.Cmd = e["command"]
		if e["kind"] == "command_start" {
			a.Start = moment(e["timestamp"])
			a.CWD = e["cwd"]
			a.Missing = false
		} else {
			t := moment(e["timestamp"])
			a.End = &t
			a.RC = e["exit_status"]
			a.CWDAfter = e["cwd"]
		}
	}
	byShell := map[any][]*action{}
	first := map[string]float64{}
	for _, a := range actions {
		if a.Missing {
			continue
		}
		byShell[a.ShellPID] = append(byShell[a.ShellPID], a)
		if a.Actor.Login != nil && a.Actor.Session != nil {
			s := string(JSON([]any{a.Actor.Login, a.Actor.Session}))
			v, ok := first[s]
			if !ok || a.Start < v {
				first[s] = a.Start
			}
		}
	}
	for _, g := range byShell {
		sort.SliceStable(g, func(i, j int) bool { return g[i].Start < g[j].Start })
	}
	for s := range controls {
		_, has := first[s]
		if !ssh[s] || has {
			delete(controls, s)
		}
	}
	shellAt := func(pid any, t float64, actor actorID) *action {
		g := byShell[pid]
		i := sort.Search(len(g), func(i int) bool { return g[i].Start > t }) - 1
		if i < 0 {
			return nil
		}
		a := g[i]
		until := end
		if a.End != nil {
			until = *a.End
		} else if i+1 < len(g) {
			until = g[i+1].Start
		}
		if t <= until && sameSession(actor, a.Actor) {
			return a
		}
		return nil
	}
	type ownership struct {
		PPID   any
		Action *action
	}
	owners := map[any]ownership{}
	unattributed := 0
	for _, e := range events {
		source, kind := str(e["source"]), str(e["kind"])
		if source == "bash" {
			continue
		}
		if collectorEvent(e) {
			discard("instrumentation")
			continue
		}
		session := sessionKey(e)
		t := moment(e["timestamp"])
		if source == "auditd" {
			if controls[session] {
				discard("control_connection")
				continue
			}
			if start, ok := first[session]; ok && ssh[session] && t < start {
				discard("ssh_initialization")
				continue
			}
		}
		if kind == "file" && (e["syscall"] == "open" || e["syscall"] == "openat") && e["syscall_success"] == true {
			names := []string{}
			for _, v := range list(e["paths"]) {
				p := obj(v)
				if p["nametype"] != "PARENT" && p["name"] != "(null)" {
					names = append(names, str(p["name"]))
				}
			}
			only := len(names) > 0
			for _, n := range names {
				only = only && (n == "/dev/null" || n == "/dev/tty")
			}
			if only {
				discard("terminal_device_opens")
				continue
			}
		}
		if source == "control" {
			if e["label"] == "recording_started" || e["label"] == "recording_stopped" {
				discard("boundary_markers")
				continue
			}
			a := newAction(e, "note", str(e["event_id"]))
			a.Note = e["label"]
			actions = append(actions, a)
			continue
		}
		if source != "auditd" || (kind != "exec" && kind != "file" && kind != "connect" && kind != "chdir") {
			important := []any{}
			for _, d := range list(e["details"]) {
				typ := str(obj(d)["type"])
				if strings.HasPrefix(typ, "AVC") || strings.HasPrefix(typ, "USER_AVC") || strings.HasPrefix(typ, "SECCOMP") || strings.HasPrefix(typ, "ANOM_") {
					important = append(important, d)
				}
			}
			if len(important) > 0 {
				a := newAction(e, "system", str(e["event_id"]))
				a.Note = important
				actions = append(actions, a)
			} else {
				if kind == "" {
					kind = "unknown"
				}
				discard(kind)
			}
			continue
		}
		p := obj(e["process"])
		pid, ppid, actor := p["pid"], p["ppid"], actorKey(e)
		owner := shellAt(pid, t, actor)
		if owner == nil {
			owner = shellAt(ppid, t, actor)
		}
		cached, parent := owners[pid], owners[ppid]
		valid := func(a *action) bool { return a != nil && sameSession(actor, a.Actor) && (a.End == nil || t <= *a.End) }
		if owner == nil && cached.PPID == ppid && valid(cached.Action) {
			owner = cached.Action
		}
		if owner == nil && valid(parent.Action) {
			owner = parent.Action
		}
		if owner == nil && kind != "exec" && (p["executable"] == "/usr/sbin/sshd" || p["executable"] == "/usr/bin/sshd") {
			discard("ssh_transport")
			continue
		}
		if kind == "exec" {
			args := p["argv"]
			if owner != nil && owner == cached.Action && owner.Kind == "exec" {
				owner = shellAt(ppid, t, actor)
				if owner == nil && valid(parent.Action) {
					owner = parent.Action
				}
			}
			if owner == nil {
				owner = newAction(e, "exec", str(e["event_id"]))
				if len(list(args)) > 0 {
					owner.Cmd = argvCommand(args)
				}
				if e["syscall_success"] == false {
					owner.ExecFailed = e["syscall_return"]
				}
				owner.Parent = parent.Action
				actions = append(actions, owner)
			} else if e["syscall_success"] == false || !argvVisible(args, str(owner.Cmd)) {
				d := Object{"argv": safeArgv(args)}
				if e["syscall_success"] == false {
					d["sysrc"] = e["syscall_return"]
				}
				owner.Execs = groupAdd(owner.Execs, d)
			}
			owner.ref(e)
			if pid != nil && len(byShell[pid]) == 0 {
				owners[pid] = ownership{ppid, owner}
			}
			continue
		}
		if owner == nil {
			owner = newAction(e, "effect", str(e["event_id"]))
			owner.Parent = parent.Action
			actions = append(actions, owner)
			unattributed++
		}
		owner.ref(e)
		if kind == "file" {
			owner.Effects = groupAdd(owner.Effects, fileDetail(e, owner))
		} else if kind == "connect" {
			d := Object{"op": "connect", "to": e["socket_addresses"]}
			if len(list(e["socket_addresses"])) == 0 {
				d["to"] = nil
			}
			if e["syscall_return"] != nil && num(e["syscall_return"]) < 0 {
				d["sysrc"] = e["syscall_return"]
			}
			owner.Effects = groupAdd(owner.Effects, d)
		} else if owner.Kind != "command" {
			owner.Effects = groupAdd(owner.Effects, fileDetail(e, owner))
		}
	}
	sort.SliceStable(actions, func(i, j int) bool {
		if actions[i].Start == actions[j].Start {
			return actions[i].Key < actions[j].Key
		}
		return actions[i].Start < actions[j].Start
	})
	confirmed, unconfirmed := []*action{}, []*action{}
	for _, a := range actions {
		if a.Kind == "exec" || a.Kind == "effect" {
			unconfirmed = append(unconfirmed, a)
		} else {
			confirmed = append(confirmed, a)
		}
	}
	actions = append(confirmed, unconfirmed...)
	ids := map[string]int{}
	actorIDs := map[actorID]int{}
	actors := Object{}
	common := map[actorID]any{}
	for i, a := range actions {
		ids[a.Key] = i + 1
		if actorIDs[a.Actor] == 0 {
			id := len(actorIDs) + 1
			actorIDs[a.Actor] = id
			row := Object{}
			for k, v := range (Object{"login_uid": a.Actor.Login, "uid": a.Actor.UID, "audit_session": a.Actor.Session, "tty": a.Actor.TTY}) {
				if v != nil && v != "" {
					row[k] = v
				}
			}
			actors[fmt.Sprint(id)] = row
		}
	}
	for actor, id := range actorIDs {
		counts := map[any]int{}
		best := 0
		for _, a := range actions {
			if a.Actor == actor && a.CWD != nil {
				counts[a.CWD]++
			}
		}
		for _, a := range actions {
			if a.Actor == actor && a.CWD != nil {
				if counts[a.CWD] > best {
					best = counts[a.CWD]
					common[actor] = a.CWD
				}
			}
		}
		if best > 0 {
			obj(actors[fmt.Sprint(id)])["cwd"] = common[actor]
		}
	}
	timeline, contextRows := []Object{}, []Object{}
	refs := Object{}
	omitted, redacted := 0, 0
	round := func(v float64) float64 { return math.Round(v*1000) / 1000 }
	for _, a := range actions {
		id := ids[a.Key]
		row := Object{"id": id, "t": round(a.Start - baseline), "s": actorIDs[a.Actor]}
		if a.Cmd != nil {
			cmd := redact(str(a.Cmd))
			row["cmd"] = cmd
			row["rc"] = a.RC
			if cmd != a.Cmd {
				redacted++
			}
		}
		if a.Kind != "command" {
			row["via"] = a.Kind
		}
		if a.End != nil && !a.Missing {
			row["dt"] = round(*a.End - a.Start)
		}
		if a.CWD == nil || a.CWD != common[a.Actor] {
			row["cwd"] = a.CWD
		}
		if a.CWDAfter != nil && a.CWDAfter != "" && a.CWDAfter != a.CWD {
			row["cwd_after"] = a.CWDAfter
		}
		if a.Missing {
			row["missing_start"] = true
		}
		if a.ExecFailed != nil {
			row["exec_sysrc"] = a.ExecFailed
		}
		if a.Parent != nil && ids[a.Parent.Key] != 0 {
			row["parent"] = ids[a.Parent.Key]
		}
		if a.Note != nil {
			row["note"] = a.Note
		}
		for _, field := range []string{"effects", "exec"} {
			groups, limit := a.Effects, effectsLimit
			if field == "exec" {
				groups, limit = a.Execs, execLimit
			}
			details, n := limited(groups, limit)
			if len(details) > 0 {
				row[field] = details
			}
			if n > 0 {
				row[field+"_omitted"] = n
				omitted += n
			}
		}
		if a.Kind == "exec" || a.Kind == "effect" {
			contextRows = append(contextRows, row)
		} else {
			timeline = append(timeline, row)
		}
		refs[fmt.Sprint(id)] = a.Refs
	}
	packet := Object{"v": 1, "session": w["session_id"], "duration_s": round(end - baseline), "actors": actors, "coverage": Object{"stdout": false, "file_contents": false, "exit_status": "bash_only", "audit_lost_total": obj(manifest["audit"])["lost"], "dispatcher_errors": obj(manifest["collector"])["conversion_errors"], "unattributed_effects": unattributed, "omitted_details": omitted, "attribution": "best_effort_pid_parent_and_shell_interval", "user_commands": len(shells), "redaction": "known_secret_patterns_only"}, "legend": Object{"t": "seconds since recording start", "s": "actor ID", "dt": "observed command duration in seconds", "rc": "observed Bash status; null is unknown", "cwd": "actor cwd is the default; null is unknown", "sysrc": "syscall return, not program status; -115 means connect in progress", "effects": "observed operations, not file diffs; order is preserved", "via": "exec lacks a Bash command; effect has uncertain attribution", "context": "unattributed telemetry; never treat as user-entered commands"}, "actions": timeline, "context": contextRows}
	stats := Object{"input_events": len(events), "actions": len(timeline), "context_rows": len(contextRows), "shell_commands": len(shells), "discarded": discarded, "omitted_details": omitted, "redacted_command_rows": redacted}
	return redactTree(packet).(Object), refs, stats, nil
}

type CompactOptions struct {
	Input, Manifest, Output           string
	EffectsLimit, ExecLimit, MaxBytes int
}

func Compact(o CompactOptions) (Object, error) {
	if o.MaxBytes < 0 {
		return nil, errors.New("max-bytes must be nonnegative")
	}
	if o.Manifest == "" {
		o.Manifest = strings.TrimSuffix(o.Input, filepath.Ext(o.Input)) + ".manifest.json"
	}
	if o.Output == "" {
		o.Output = filepath.Join(filepath.Dir(o.Input), "llm.json")
	}
	base := strings.TrimSuffix(o.Output, filepath.Ext(o.Output))
	sources, statsPath := base+".sources.json", base+".stats.json"
	for _, out := range []string{o.Output, sources, statsPath} {
		a, _ := filepath.Abs(out)
		for _, in := range []string{o.Input, o.Manifest} {
			b, _ := filepath.Abs(in)
			same := a == b
			if ai, e := os.Stat(a); e == nil {
				if bi, e := os.Stat(b); e == nil {
					same = same || os.SameFile(ai, bi)
				}
			}
			if same {
				return nil, errors.New("compact output must not overwrite full source data or manifest")
			}
		}
	}
	manifest, e := readJSON(o.Manifest)
	if e != nil {
		return nil, e
	}
	events, e := ReadEvents(o.Input)
	if e != nil {
		return nil, e
	}
	packet, refs, stats, e := BuildPacket(events, manifest, o.EffectsLimit, o.ExecLimit)
	if e != nil {
		return nil, e
	}
	text := append(JSON(packet), '\n')
	if o.MaxBytes > 0 && len(text) > o.MaxBytes {
		return nil, fmt.Errorf("compact packet is %d bytes, above %d; no commands were silently dropped", len(text), o.MaxBytes)
	}
	source, e := os.ReadFile(o.Input)
	if e != nil {
		return nil, e
	}
	stats["source_bytes"] = len(source)
	stats["compact_bytes"] = len(text)
	stats["byte_reduction_pct"] = math.Round(10000*(1-float64(len(text))/math.Max(1, float64(len(source))))) / 100
	stats["token_counts"] = nil
	if e = Atomic(sources, Object{"source": o.Input, "sha256": fmt.Sprintf("%x", sha256.Sum256(source)), "actions": refs}); e != nil {
		return nil, e
	}
	if e = Atomic(statsPath, stats); e != nil {
		return nil, e
	}
	if e = AtomicText(o.Output, text); e != nil {
		return nil, e
	}
	result := clone(stats)
	result["llm"] = o.Output
	result["llm_sources"] = sources
	result["llm_stats"] = statsPath
	return result, nil
}
