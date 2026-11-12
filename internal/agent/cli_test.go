package agent

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestFreshVMResetDoesNotRequireInstalledContext(t *testing.T) {
	var out bytes.Buffer
	if e := CLI(context.Background(), []string{"control", t.TempDir(), "exercise", "reset", ""}, &out); e != nil {
		t.Fatal(e)
	}
	if out.Len() != 0 {
		t.Fatal("reset produced output")
	}
}
func TestHostCLIHelp(t *testing.T) {
	var out bytes.Buffer
	if e := CLI(context.Background(), []string{"--help"}, &out); e != nil || !strings.Contains(out.String(), "analyze") {
		t.Fatal(e, out.String())
	}
}
func TestVMIdentityPreserved(t *testing.T) {
	path := filepath.Join(t.TempDir(), "context.json")
	id, e := SelectVMID("", path)
	if e != nil || id == "" {
		t.Fatal(id, e)
	}
	Atomic(path, Object{"vm_id": id})
	if again, e := SelectVMID("", path); e != nil || again != id {
		t.Fatal(again, e)
	}
	if _, e = SelectVMID("other", path); e == nil {
		t.Fatal("identity overwritten")
	}
	for _, id := range []string{" ", "bad\nidentity", "bad\x00identity"} {
		if _, e = SelectVMID(id, filepath.Join(t.TempDir(), "new")); e == nil {
			t.Fatal("invalid identity accepted")
		}
	}
}
func TestBundleRejectsNonELFAndSymlink(t *testing.T) {
	path := filepath.Join(t.TempDir(), "binary")
	os.WriteFile(path, []byte("not ELF"), 0600)
	if _, e := Bundle(path); e == nil {
		t.Fatal("invalid guest binary accepted")
	}
	link := path + "-link"
	if e := os.Symlink(path, link); e == nil {
		if _, e = Bundle(link); e == nil {
			t.Fatal("symlink packaged")
		}
	}
}
