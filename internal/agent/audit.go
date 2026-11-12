package agent

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"os/exec"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

type AuditRecord struct {
	Type, Text string
	Fields     map[string]string
}
type AuditEvent struct {
	ID             string
	Seconds        int64
	Millis, Serial int
	Records        []AuditRecord
	Updated        time.Time
}
type AuditParser struct {
	Pending map[string]*AuditEvent
	Ready   func(*AuditEvent) error
}

var auditStamp = regexp.MustCompile(`(?:^|\s)msg=audit\((\d+)\.(\d+):(\d+)\):`)
var fieldPattern = regexp.MustCompile(`([a-zA-Z0-9_\[\]]+)=("[^"]*"|'[^']*'|[^\s]+)`)
var argumentPattern = regexp.MustCompile(`^a(\d+)(?:\[(\d+)\])?$`)

func NewAuditParser(ready func(*AuditEvent) error) *AuditParser {
	return &AuditParser{Pending: map[string]*AuditEvent{}, Ready: ready}
}
func (p *AuditParser) Feed(line string) error {
	m := auditStamp.FindStringSubmatch(line)
	if m == nil {
		if strings.TrimSpace(line) == "" {
			return nil
		}
		return errors.New("audit record has no event timestamp")
	}
	sec, _ := strconv.ParseInt(m[1], 10, 64)
	msText := m[2] + "000"
	ms, _ := strconv.Atoi(msText[:3])
	serial, _ := strconv.Atoi(m[3])
	id := m[1] + "." + m[2] + ":" + m[3]
	fields := map[string]string{}
	for _, f := range fieldPattern.FindAllStringSubmatch(line, -1) {
		if f[1] != "msg" {
			fields[f[1]] = f[2]
		}
	}
	kind := fields["type"]
	if kind == "" {
		return errors.New("audit record has no type")
	}
	e := p.Pending[id]
	if e == nil {
		e = &AuditEvent{ID: id, Seconds: sec, Millis: ms, Serial: serial}
		p.Pending[id] = e
	}
	e.Updated = time.Now()
	e.Records = append(e.Records, AuditRecord{kind, line, fields})
	if kind == "EOE" {
		delete(p.Pending, id)
		return p.Ready(e)
	}
	return nil
}
func (p *AuditParser) Flush(age time.Duration) error {
	events := []*AuditEvent{}
	for _, e := range p.Pending {
		if age == 0 || time.Since(e.Updated) >= age {
			events = append(events, e)
		}
	}
	sort.Slice(events, func(i, j int) bool {
		if events[i].Seconds != events[j].Seconds {
			return events[i].Seconds < events[j].Seconds
		}
		if events[i].Millis != events[j].Millis {
			return events[i].Millis < events[j].Millis
		}
		return events[i].Serial < events[j].Serial
	})
	for _, e := range events {
		delete(p.Pending, e.ID)
		if err := p.Ready(e); err != nil {
			return err
		}
	}
	return nil
}
func auditBytes(v string) []byte {
	if len(v) >= 2 && v[0] == '"' && v[len(v)-1] == '"' {
		return []byte(v[1 : len(v)-1])
	}
	if b, e := hex.DecodeString(v); e == nil && len(b) > 0 {
		return b
	}
	return []byte(v)
}
func decoded(v string) string { return escapedUTF8(auditBytes(v)) }

// Preserve invalid bytes explicitly, matching the former backslashreplace export.
func escapedUTF8(b []byte) string {
	var out strings.Builder
	for len(b) > 0 {
		r, size := utf8.DecodeRune(b)
		if r == utf8.RuneError && size == 1 {
			fmt.Fprintf(&out, "\\x%02x", b[0])
		} else {
			out.WriteRune(r)
		}
		b = b[size:]
	}
	return out.String()
}
func number(v string) any {
	n, e := strconv.ParseInt(strings.TrimSpace(v), 10, 64)
	if e != nil || n == -1 || n == 4294967295 {
		return nil
	}
	return float64(n)
}
func auditTime(e *AuditEvent) string {
	return time.Unix(e.Seconds, int64(e.Millis)*1e6).UTC().Format("2006-01-02T15:04:05.000Z07:00")
}

// Tables are loaded once from the audit package, including 32-bit compatibility syscalls.
// Built-ins cover the recorded syscalls when parsing fixtures away from Linux.
var syscall64 = map[int]string{2: "open", 3: "close", 42: "connect", 59: "execve", 76: "truncate", 77: "ftruncate", 80: "chdir", 81: "fchdir", 82: "rename", 83: "mkdir", 84: "rmdir", 85: "creat", 86: "link", 87: "unlink", 88: "symlink", 90: "chmod", 91: "fchmod", 92: "chown", 93: "fchown", 94: "lchown", 132: "utime", 188: "setxattr", 189: "lsetxattr", 190: "fsetxattr", 197: "removexattr", 198: "lremovexattr", 199: "fremovexattr", 235: "utimes", 257: "openat", 258: "mkdirat", 260: "fchownat", 263: "unlinkat", 264: "renameat", 265: "linkat", 266: "symlinkat", 268: "fchmodat", 280: "utimensat", 316: "renameat2", 322: "execveat", 437: "openat2"}
var syscall32 = map[int]string{5: "open", 8: "creat", 9: "link", 10: "unlink", 11: "execve", 12: "chdir", 14: "mknod", 15: "chmod", 16: "lchown", 30: "utime", 38: "rename", 39: "mkdir", 40: "rmdir", 83: "symlink", 92: "truncate", 93: "ftruncate", 94: "fchmod", 95: "fchown", 102: "socketcall", 133: "fchdir", 182: "chown", 226: "setxattr", 227: "lsetxattr", 228: "fsetxattr", 235: "removexattr", 236: "lremovexattr", 237: "fremovexattr", 271: "utimes", 295: "openat", 296: "mkdirat", 298: "fchownat", 301: "unlinkat", 302: "renameat", 303: "linkat", 304: "symlinkat", 306: "fchmodat", 320: "utimensat", 353: "renameat2", 358: "execveat", 362: "connect", 437: "openat2"}

func LoadSyscalls() error {
	tool, err := exec.LookPath("ausyscall")
	if err != nil {
		// auditd launches plugins with execve(..., NULL), without PATH.
		// Resolve the auditd utility from standard system directories as well.
		for _, dir := range []string{"/usr/bin", "/usr/sbin", "/bin", "/sbin"} {
			if candidate, lookupErr := exec.LookPath(path.Join(dir, "ausyscall")); lookupErr == nil {
				tool, err = candidate, nil
				break
			}
		}
		if err != nil {
			return fmt.Errorf("locate ausyscall (install the auditd package): %w", err)
		}
	}
	for arch, table := range map[string]map[int]string{"x86_64": syscall64, "i386": syscall32} {
		out, e := exec.Command(tool, arch, "--dump").Output()
		if e != nil {
			return fmt.Errorf("load %s syscall names: %w", arch, e)
		}
		for _, line := range strings.Split(string(out), "\n") {
			f := strings.Fields(line)
			if len(f) == 2 {
				n, e := strconv.Atoi(f[0])
				if e == nil {
					table[n] = f[1]
				}
			}
		}
	}
	return nil
}
func socketAddress(v string) string {
	b, e := hex.DecodeString(v)
	if e != nil || len(b) < 2 {
		return v
	}
	family := binary.LittleEndian.Uint16(b)
	switch family {
	case 1:
		return "{ saddr_fam=local path=" + strings.TrimRight(string(b[2:]), "\x00") + " }"
	case 2:
		if len(b) >= 8 {
			return fmt.Sprintf("{ saddr_fam=inet laddr=%s lport=%d }", net.IP(b[4:8]), binary.BigEndian.Uint16(b[2:4]))
		}
	case 10:
		if len(b) >= 24 {
			return fmt.Sprintf("{ saddr_fam=inet6 laddr=%s lport=%d }", net.IP(b[8:24]), binary.BigEndian.Uint16(b[2:4]))
		}
	}
	return v
}
func Normalize(e *AuditEvent, vmID string) (Object, error) {
	raw, actorRaw := map[string]string{}, map[string]string{}
	hasSyscall := false
	for _, r := range e.Records {
		if r.Type == "SYSCALL" {
			raw = r.Fields
			hasSyscall = true
		}
		if actorRaw["auid"] == "" && r.Fields["auid"] != "" {
			actorRaw = r.Fields
		}
	}
	if hasSyscall {
		actorRaw = raw
	}
	actor := Object{}
	for k, f := range map[string]string{"login_uid": "auid", "uid": "uid", "effective_uid": "euid", "session_id": "ses"} {
		actor[k] = number(actorRaw[f])
	}
	actor["user"] = nil
	if raw["uid"] == "0" {
		actor["user"] = "root"
	} else if raw["uid"] != "" {
		actor["user"] = raw["uid"]
	}
	process := Object{"pid": number(raw["pid"]), "ppid": number(raw["ppid"]), "executable": nil, "name": nil, "tty": nil, "cwd": nil}
	for k, f := range map[string]string{"executable": "exe", "name": "comm", "tty": "tty"} {
		if raw[f] != "" {
			process[k] = decoded(raw[f])
		}
	}
	pieces := map[int]map[int][]byte{}
	argc := -1
	paths := []any{}
	addresses := []any{}
	details := []any{}
	warnings := []any{}
	var proctitle []any
	for _, r := range e.Records {
		f := r.Fields
		switch r.Type {
		case "CWD":
			process["cwd"] = decoded(f["cwd"])
		case "EXECVE":
			if s, ok := f["argc"]; ok {
				n, err := strconv.Atoi(s)
				if err != nil || n < 0 || n > 1<<20 {
					return nil, errors.New("invalid EXECVE argc")
				}
				argc = n
			}
			for name, v := range f {
				m := argumentPattern.FindStringSubmatch(name)
				if m == nil {
					continue
				}
				i, _ := strconv.Atoi(m[1])
				j, _ := strconv.Atoi(m[2])
				if pieces[i] == nil {
					pieces[i] = map[int][]byte{}
				}
				pieces[i][j] = auditBytes(v)
			}
		case "PATH":
			v := Object{}
			for k, x := range f {
				if k != "type" {
					v[k] = decoded(x)
				}
			}
			paths = append(paths, v)
		case "SOCKADDR":
			addresses = append(addresses, socketAddress(f["saddr"]))
		case "PROCTITLE":
			b, err := hex.DecodeString(f["proctitle"])
			if err == nil {
				if !utf8.Valid(b) {
					warnings = append(warnings, Object{"record_type": r.Type, "field": "proctitle", "raw": f["proctitle"]})
				}
				for _, s := range strings.Split(strings.TrimRight(string(b), "\x00"), "\x00") {
					proctitle = append(proctitle, strings.ToValidUTF8(s, "\ufffd"))
				}
			}
		}
		if !hasSyscall {
			v := Object{}
			for k, x := range f {
				if k != "type" {
					v[k] = decoded(x)
				}
			}
			details = append(details, Object{"type": r.Type, "fields": v})
		}
	}
	argv := []any{}
	if argc >= 0 {
		for i := 0; i < argc; i++ {
			fragments := pieces[i]
			if fragments == nil {
				argv = append(argv, nil)
				continue
			}
			indices := []int{}
			for j := range fragments {
				indices = append(indices, j)
			}
			sort.Ints(indices)
			b := []byte{}
			for _, j := range indices {
				b = append(b, fragments[j]...)
			}
			if !utf8.Valid(b) {
				warnings = append(warnings, Object{"record_type": "EXECVE", "field": fmt.Sprintf("a%d", i)})
			}
			argv = append(argv, escapedUTF8(b))
		}
	} else if len(proctitle) > 0 {
		argv = proctitle
	}
	process["argv"] = argv
	var call any
	key := any(nil)
	if raw["syscall"] != "" {
		n, _ := strconv.Atoi(raw["syscall"])
		table := syscall64
		if raw["arch"] == "40000003" {
			table = syscall32
		}
		if s := table[n]; s != "" {
			call = s
		} else {
			call = raw["syscall"]
		}
	}
	if raw["key"] != "" {
		key = decoded(raw["key"])
	}
	kind := "audit"
	switch {
	case call == "execve" || call == "execveat":
		kind = "exec"
	case key == "incsim_connect":
		kind = "connect"
	case key == "incsim_chdir":
		kind = "chdir"
	case strings.HasPrefix(str(key), "incsim_"):
		kind = "file"
	default:
		for _, r := range e.Records {
			if strings.HasPrefix(r.Type, "USER_") || strings.HasPrefix(r.Type, "CRED_") || strings.HasPrefix(r.Type, "LOGIN") {
				kind = "authentication"
			}
		}
	}
	origin := "session"
	for i := 0; i < len(argv) && i < 2; i++ {
		if argv[i] == "/usr/local/sbin/incident-audit" {
			origin = "instrumentation"
		}
	}
	if path.Base(str(process["executable"])) == "incident-audit" || process["name"] == "incident-audit" {
		origin = "instrumentation"
	}
	if len(argv) == 3 && path.Base(str(argv[0])) == "auditctl" && argv[1] == "-m" && regexp.MustCompile(`^incsim_boundary=[a-f0-9]{32}$`).MatchString(str(argv[2])) {
		origin = "instrumentation"
	}
	var success, result any
	if hasSyscall {
		success = raw["success"] == "yes"
		if raw["exit"] != "" {
			n, err := strconv.ParseInt(raw["exit"], 10, 64)
			if err != nil {
				return nil, err
			}
			result = n
		}
	}
	event := Object{"schema_version": 1, "event_id": fmt.Sprintf("%s:audit:%d.%03d:%d", vmID, e.Seconds, e.Millis, e.Serial), "timestamp": auditTime(e), "vm_id": vmID, "source": "auditd", "kind": kind, "audit_serial": e.Serial, "origin": origin, "actor": actor, "process": process, "syscall": call, "syscall_success": success, "syscall_return": result, "audit_key": key, "paths": paths}
	if !hasSyscall {
		event["details"] = details
	}
	if len(addresses) > 0 {
		event["socket_addresses"] = addresses
	}
	if len(warnings) > 0 {
		event["decoding_warnings"] = warnings
	}
	return event, nil
}
func BoundaryInEvent(e *AuditEvent, boot string) Object {
	for _, r := range e.Records {
		if r.Type == "USER" {
			m := regexp.MustCompile(`\bincsim_boundary=([a-f0-9]{32})\b`).FindStringSubmatch(r.Text)
			if m != nil {
				return Object{"token": m[1], "serial": e.Serial, "boot_id": boot, "timestamp": auditTime(e)}
			}
		}
	}
	return nil
}
