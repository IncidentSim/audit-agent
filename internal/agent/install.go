package agent

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	assets "incidentsim/audit-agent"
)

func run(command string, args ...string) error {
	cmd := exec.Command(command, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if e := cmd.Run(); e != nil {
		return fmt.Errorf("%s: %w", command, e)
	}
	return nil
}
func backup(file string) error {
	if _, e := os.Stat(file + ".before-incidentsim"); e == nil {
		return nil
	}
	b, e := os.ReadFile(file)
	if os.IsNotExist(e) {
		return nil
	}
	if e != nil {
		return e
	}
	return AtomicText(file+".before-incidentsim", b)
}
func SelectVMID(requested, contextPath string) (string, error) {
	if requested != "" && (strings.TrimSpace(requested) == "" || strings.ContainsAny(requested, "\r\n\x00")) {
		return "", errors.New("invalid VM identity")
	}
	existing, e := readJSON(contextPath)
	if e == nil {
		vm := str(existing["vm_id"])
		if vm == "" {
			return "", errors.New("existing context has no VM identity")
		}
		if requested != "" && requested != vm {
			return "", errors.New("existing audit context belongs to another VM")
		}
		return vm, nil
	}
	if !os.IsNotExist(e) {
		return "", e
	}
	if requested != "" {
		return requested, nil
	}
	host, _ := os.Hostname()
	return host + "-" + token()[:12], nil
}
func Install(vm string, skipPackages bool) error {
	if runtime.GOOS != "linux" || runtime.GOARCH != "amd64" {
		return errors.New("this installer supports Linux x86_64")
	}
	if os.Geteuid() != 0 {
		return errors.New("run as root or use sudo")
	}
	if _, e := os.Stat("/run/systemd/system"); e != nil {
		return errors.New("systemd must be running on the target machine")
	}
	cmdline, e := os.ReadFile("/proc/cmdline")
	if e != nil {
		return e
	}
	for _, s := range strings.Fields(string(cmdline)) {
		if s == "audit=0" || s == "audit=off" {
			return errors.New("kernel command line disables audit")
		}
	}
	vm, e = SelectVMID(vm, "/etc/incidentsim/audit-context.json")
	if e != nil {
		return e
	}
	if !skipPackages {
		if e = run("apt-get", "update", "-qq"); e != nil {
			return e
		}
		cmd := exec.Command("apt-get", "install", "-y", "--no-install-recommends", "auditd")
		cmd.Env = append(os.Environ(), "DEBIAN_FRONTEND=noninteractive")
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if e = cmd.Run(); e != nil {
			return e
		}
	}
	status, e := exec.Command("auditctl", "-s").Output()
	if e != nil {
		return fmt.Errorf("Linux Audit is not accessible: %w", e)
	}
	for _, line := range strings.Split(string(status), "\n") {
		if strings.Join(strings.Fields(line), " ") == "enabled 2" {
			return errors.New("audit policy is immutable; reboot with a mutable policy before installing")
		}
	}
	rules, e := exec.Command("auditctl", "-l").Output()
	if e != nil {
		return e
	}
	if strings.Contains(string(rules), "-a never,task") {
		return errors.New("an existing never,task audit rule disables syscall collection; review that policy first")
	}
	if e = LoadSyscalls(); e != nil {
		return e
	}
	for _, dir := range []string{"/var/log/incidentsim", "/var/log/audit", "/etc/incidentsim"} {
		if e = os.MkdirAll(dir, 0700); e != nil {
			return e
		}
		if e = os.Chmod(dir, 0700); e != nil {
			return e
		}
	}
	contextPath := "/etc/incidentsim/audit-context.json"
	if _, e = os.Stat(contextPath); os.IsNotExist(e) {
		if e = Atomic(contextPath, Object{"schema_version": 1, "vm_id": vm, "installed_at": now()}); e != nil {
			return e
		}
	}
	executable, e := os.Executable()
	if e != nil {
		return e
	}
	binary, e := os.ReadFile(executable)
	if e != nil {
		return e
	}
	target := "/usr/local/sbin/incident-audit"
	if e = AtomicText(target, binary); e != nil {
		return e
	}
	if e = os.Chmod(target, 0755); e != nil {
		return e
	}
	for source, destination := range map[string]string{"config/50-incidentsim.rules": "/etc/audit/rules.d/50-incidentsim.rules", "config/incidentsim-json.conf": "/etc/audit/plugins.d/incidentsim-json.conf", "config/incidentsim-audit.sh": "/etc/profile.d/incidentsim-audit.sh"} {
		b, err := assets.Files.ReadFile(source)
		if err != nil {
			return err
		}
		b = []byte(strings.ReplaceAll(string(b), "\r\n", "\n"))
		if e = AtomicText(destination, b); e != nil {
			return e
		}
		mode := os.FileMode(0600)
		if strings.HasSuffix(destination, ".sh") {
			mode = 0644
		} else if strings.HasSuffix(destination, ".conf") {
			mode = 0640
		}
		if e = os.Chmod(destination, mode); e != nil {
			return e
		}
	}
	configPath := "/etc/audit/auditd.conf"
	if e = backup(configPath); e != nil {
		return e
	}
	b, e := os.ReadFile(configPath)
	if e != nil {
		return e
	}
	overrides := map[string]string{"log_group": "root", "max_log_file": "16", "num_logs": "8", "max_log_file_action": "ROTATE", "freq": "10", "q_depth": "8192"}
	lines := strings.Split(strings.TrimRight(string(b), "\n"), "\n")
	for i, line := range lines {
		k := strings.TrimSpace(strings.SplitN(line, "=", 2)[0])
		if v, ok := overrides[k]; ok {
			lines[i] = k + " = " + v
			delete(overrides, k)
		}
	}
	for k, v := range overrides {
		lines = append(lines, k+" = "+v)
	}
	if e = AtomicText(configPath, []byte(strings.Join(lines, "\n")+"\n")); e != nil {
		return e
	}
	bashrc := "/etc/bash.bashrc"
	b, e = os.ReadFile(bashrc)
	if e != nil {
		return e
	}
	include := "source /etc/profile.d/incidentsim-audit.sh"
	if !strings.Contains(string(b), include) {
		if e = backup(bashrc); e != nil {
			return e
		}
		if e = AtomicText(bashrc, append(b, []byte("\n# IncidentSim: log interactive root Bash commands.\n"+include+"\n")...)); e != nil {
			return e
		}
		if e = os.Chmod(bashrc, 0644); e != nil {
			return e
		}
	}
	if e = run("systemctl", "enable", "auditd.service"); e != nil {
		return e
	}
	started := time.Now()
	if e = run("systemctl", "restart", "auditd.service"); e != nil {
		return e
	}
	if e = run("augenrules", "--load"); e != nil {
		return e
	}
	for time.Since(started) < 10*time.Second {
		health, err := readJSON(filepath.Join("/var/log/incidentsim", "collector-health.json"))
		if err == nil && moment(health["updated_at"]) >= float64(started.UnixNano())/1e9 && health["stopped_at"] == nil && num(health["conversion_errors"]) == 0 {
			rules, err = exec.Command("auditctl", "-l").Output()
			if err != nil {
				return err
			}
			if !strings.Contains(string(rules), "incsim_exec") {
				return errors.New("audit rules were not loaded")
			}
			fmt.Fprintln(os.Stdout, "Audit configured. Call incident-audit start after infrastructure preparation.")
			return nil
		}
		time.Sleep(250 * time.Millisecond)
	}
	health, healthErr := os.ReadFile("/var/log/incidentsim/collector-health.json")
	if healthErr != nil {
		health = []byte(healthErr.Error())
	}
	journal, journalErr := exec.Command("journalctl", "-u", "auditd.service", "--since", fmt.Sprintf("@%d", started.Unix()), "-n", "40", "--no-pager").CombinedOutput()
	if journalErr != nil {
		journal = append(journal, []byte("\njournalctl: "+journalErr.Error())...)
	}
	return fmt.Errorf("JSONL dispatcher did not become ready\ncollector health: %s\nauditd journal:\n%s", strings.TrimSpace(string(health)), strings.TrimSpace(string(journal)))
}
