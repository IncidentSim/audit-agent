package agent

import (
	"context"
	"io"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

func TestDispatcherReadyWithoutPATH(t *testing.T) {
	available := false
	for _, dir := range []string{"/usr/bin", "/usr/sbin", "/bin", "/sbin"} {
		if _, err := exec.LookPath(filepath.Join(dir, "ausyscall")); err == nil {
			available = true
		}
	}
	if !available {
		t.Skip("requires the auditd package (ausyscall)")
	}
	// auditd execve() starts plugins with no environment, including no PATH.
	t.Setenv("PATH", "")
	root := t.TempDir()
	a := &Agent{Root: root, VMID: "test-vm", Store: &Store{Root: root, Boot: "test-boot", Write: Append}}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	input, writer := io.Pipe()
	defer input.Close()
	defer writer.Close()
	finished := make(chan error, 1)
	go func() { finished <- a.Stream(ctx, input) }()
	deadline := time.After(3 * time.Second)
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case err := <-finished:
			t.Fatalf("dispatcher exited before readiness: %v", err)
		case <-deadline:
			t.Fatal("dispatcher did not write readiness")
		case <-ticker.C:
			health, err := readJSON(filepath.Join(root, "collector-health.json"))
			if err != nil {
				continue
			}
			if health["stopped_at"] != nil || num(health["conversion_errors"]) != 0 {
				t.Fatalf("unhealthy dispatcher: %v", health)
			}
			cancel()
			if err := <-finished; err != nil {
				t.Fatal(err)
			}
			return
		}
	}
}
