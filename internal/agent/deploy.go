package agent

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"unicode"
)

func Bundle(binary string) ([]byte, error) {
	info, e := os.Lstat(binary)
	if e != nil {
		return nil, e
	}
	if !info.Mode().IsRegular() {
		return nil, errors.New("missing regular package binary")
	}
	data, e := os.ReadFile(binary)
	if e != nil {
		return nil, e
	}
	if len(data) < 20 || !bytes.Equal(data[:4], []byte{0x7f, 'E', 'L', 'F'}) || data[4] != 2 || data[5] != 1 || data[18] != 62 || data[19] != 0 {
		return nil, errors.New("guest binary must be Linux x86_64 ELF")
	}
	var b bytes.Buffer
	z := gzip.NewWriter(&b)
	w := tar.NewWriter(z)
	if e = w.WriteHeader(&tar.Header{Name: "incident-audit", Mode: 0755, Size: int64(len(data))}); e != nil {
		return nil, e
	}
	if _, e = w.Write(data); e != nil {
		return nil, e
	}
	if e = w.Close(); e != nil {
		return nil, e
	}
	if e = z.Close(); e != nil {
		return nil, e
	}
	return b.Bytes(), nil
}
func sshDestination(s string) error {
	if s == "" || strings.HasPrefix(s, "-") || strings.IndexFunc(s, func(c rune) bool { return unicode.IsSpace(c) || unicode.IsControl(c) }) >= 0 {
		return errors.New("specify an SSH destination such as admin@vm.example.com")
	}
	return nil
}
func Deploy(ctx context.Context, args []string, out io.Writer) error {
	f := flag.NewFlagSet("deploy", flag.ContinueOnError)
	f.SetOutput(out)
	target := ""
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		target, args = args[0], args[1:]
	}
	sudo := f.Bool("sudo", false, "passwordless sudo")
	vm := f.String("vm-id", "", "stable VM identity")
	identity := f.String("identity", "", "SSH key path")
	port := f.Int("port", 22, "SSH port")
	skip := f.Bool("skip-packages", false, "skip apt")
	verify := f.Bool("verify", false, "run guest smoke check")
	binary := f.String("binary", "bin/linux-amd64/incident-audit", "Linux guest executable")
	bundleOnly := f.String("bundle-only", "", "new tar.gz path")
	var options stringsFlag
	f.Var(&options, "ssh-option", "OpenSSH option")
	if e := f.Parse(args); e != nil {
		return e
	}
	if f.NArg() > 0 {
		if target != "" || f.NArg() != 1 {
			return errors.New("unexpected positional arguments")
		}
		target = f.Arg(0)
	}
	if *port < 1 || *port > 65535 {
		return errors.New("SSH port must be between 1 and 65535")
	}
	bundle, e := Bundle(*binary)
	if e != nil {
		return e
	}
	if *bundleOnly != "" {
		if target != "" {
			return errors.New("use either SSH target or --bundle-only")
		}
		if e = os.MkdirAll(filepath.Dir(*bundleOnly), 0700); e != nil {
			return e
		}
		file, e := os.OpenFile(*bundleOnly, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if e != nil {
			return e
		}
		_, e = file.Write(bundle)
		ce := file.Close()
		if e == nil {
			e = ce
		}
		if e == nil {
			fmt.Fprintf(out, "Created %s (%d bytes)\n", *bundleOnly, len(bundle))
		}
		return e
	}
	if e = sshDestination(target); e != nil {
		return e
	}
	argv := []string{"-T", "-o", "BatchMode=yes", "-o", "ConnectTimeout=15", "-o", "StrictHostKeyChecking=accept-new", "-p", fmt.Sprint(*port)}
	if *identity != "" {
		argv = append(argv, "-i", expandHome(*identity))
	}
	for _, o := range options {
		argv = append(argv, "-o", o)
	}
	prefix := ""
	if *sudo {
		prefix = "sudo -n "
	}
	install := prefix + `"$stage/incident-audit" install`
	if *vm != "" {
		install += " --vm-id " + shellQuote(*vm)
	}
	if *skip {
		install += " --skip-packages"
	}
	script := `set -eu
stage=$(mktemp -d)
trap 'rm -rf -- "$stage"' EXIT
tar -xzf - -C "$stage" --no-same-owner --no-same-permissions
chmod 700 "$stage/incident-audit"
` + install + "\n"
	if *verify {
		script += prefix + "/usr/local/sbin/incident-audit verify\n"
	}
	argv = append(argv, target, script)
	cmd := exec.CommandContext(ctx, "ssh", argv...)
	cmd.Stdin = bytes.NewReader(bundle)
	cmd.Stdout = out
	cmd.Stderr = out
	if e = cmd.Run(); e != nil {
		return fmt.Errorf("SSH deployment failed: %w", e)
	}
	return nil
}

type stringsFlag []string

func (s *stringsFlag) String() string     { return strings.Join(*s, ",") }
func (s *stringsFlag) Set(v string) error { *s = append(*s, v); return nil }
func expandHome(s string) string {
	if strings.HasPrefix(s, "~/") || strings.HasPrefix(s, "~\\") {
		h, e := os.UserHomeDir()
		if e == nil {
			return filepath.Join(h, s[2:])
		}
	}
	return s
}
