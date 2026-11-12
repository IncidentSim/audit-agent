package agent

import (
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"
)

func records(serial int) string {
	stamp := fmt.Sprintf("msg=audit(1730000000.123:%d):", serial)
	return fmt.Sprintf("type=SYSCALL %s arch=c000003e syscall=59 success=yes exit=0 ppid=10 pid=11 auid=0 uid=0 euid=0 tty=pts0 ses=3 comm=\"printf\" exe=\"/usr/bin/printf\" key=\"incsim_exec\"\ntype=EXECVE %s argc=4 a0=\"/usr/bin/printf\" a1=25730A a2_len=9 a2[0]=74776F20 a2[1]=776F726473 a3_len=12 a3[0]=D0 a3[1]=BFD180D0B8D0B2D0B5D182\ntype=CWD %s cwd=\"/tmp\"\ntype=PATH %s item=0 name=\"/usr/bin/printf\" nametype=NORMAL\ntype=EOE %s\n", stamp, stamp, stamp, stamp, stamp)
}
func TestAuditInterleavedAndUnicode(t *testing.T) {
	events := []Object{}
	p := NewAuditParser(func(e *AuditEvent) error { v, err := Normalize(e, "vm"); events = append(events, v); return err })
	a, b := strings.Split(strings.TrimSpace(records(42)), "\n"), strings.Split(strings.TrimSpace(records(43)), "\n")
	for i := range a {
		if e := p.Feed(a[i]); e != nil {
			t.Fatal(e)
		}
		if e := p.Feed(b[i]); e != nil {
			t.Fatal(e)
		}
	}
	if e := p.Flush(0); e != nil {
		t.Fatal(e)
	}
	if len(events) != 2 {
		t.Fatal(len(events))
	}
	for _, v := range events {
		if !reflect.DeepEqual(obj(v["process"])["argv"], []any{"/usr/bin/printf", "%s\n", "two words", "привет"}) {
			t.Fatal(v)
		}
		if v["kind"] != "exec" || v["syscall"] != "execve" || obj(v["actor"])["login_uid"] != float64(0) || v["syscall_success"] != true {
			t.Fatal(v)
		}
		if _, ok := v["exit_status"]; ok {
			t.Fatal("invented program status")
		}
	}
}
func TestAuditFailureAnd32Bit(t *testing.T) {
	p := NewAuditParser(func(e *AuditEvent) error {
		v, err := Normalize(e, "vm")
		if v["syscall"] != "execve" || v["syscall_return"] != int64(-2) || v["syscall_success"] != false {
			t.Fatal(v)
		}
		return err
	})
	for _, line := range strings.Split(strings.TrimSpace(strings.ReplaceAll(strings.ReplaceAll(strings.ReplaceAll(records(1), "arch=c000003e syscall=59", "arch=40000003 syscall=11"), "success=yes", "success=no"), "exit=0", "exit=-2")), "\n") {
		if e := p.Feed(line); e != nil {
			t.Fatal(e)
		}
	}
}
func TestAuditIncompleteFlushAndBoundaryAuthority(t *testing.T) {
	count := 0
	p := NewAuditParser(func(e *AuditEvent) error { count++; return nil })
	lines := strings.Split(records(1), "\n")
	p.Feed(lines[0])
	p.Flush(time.Hour)
	if count != 0 {
		t.Fatal("flushed live event")
	}
	p.Flush(0)
	if count != 1 {
		t.Fatal("lost last event")
	}
	tok := strings.Repeat("a", 32)
	p = NewAuditParser(func(e *AuditEvent) error {
		b := BoundaryInEvent(e, "boot")
		if b == nil || b["token"] != tok {
			t.Fatal("no USER boundary")
		}
		return nil
	})
	p.Feed("type=USER msg=audit(1730000000.123:2): pid=10 msg='incsim_boundary=" + tok + "'")
	p.Flush(0)
	fake := &AuditEvent{Records: []AuditRecord{{Type: "EXECVE", Text: "a2=incsim_boundary=" + tok}}}
	if BoundaryInEvent(fake, "boot") != nil {
		t.Fatal("exec forged a boundary")
	}
}
func TestAuditCollectorOrigin(t *testing.T) {
	p := NewAuditParser(func(e *AuditEvent) error {
		v, err := Normalize(e, "vm")
		if v["origin"] != "instrumentation" {
			t.Fatal(v)
		}
		return err
	})
	for _, line := range strings.Split(strings.TrimSpace(strings.ReplaceAll(records(1), "exe=\"/usr/bin/printf\"", "exe=\"/usr/local/sbin/incident-audit\"")), "\n") {
		p.Feed(line)
	}
}
