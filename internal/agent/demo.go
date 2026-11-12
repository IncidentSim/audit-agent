package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	assets "incidentsim/audit-agent"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

func DemoServe(args []string) error {
	f := flag.NewFlagSet("demo-serve", flag.ContinueOnError)
	port := f.String("port", os.Getenv("PORT"), "HTTP port")
	if e := f.Parse(args); e != nil {
		return e
	}
	if *port == "" {
		*port = "8080"
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) { fmt.Fprintln(w, "audit-demo-ready") })
	return http.ListenAndServe(":"+*port, mux)
}
func demoHealth(port string) bool {
	client := http.Client{Timeout: time.Second, Transport: &http.Transport{Proxy: nil}}
	r, e := client.Get("http://127.0.0.1:" + port + "/health")
	if e != nil {
		return false
	}
	defer r.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(r.Body, 4096))
	return r.StatusCode == 200 && strings.TrimSpace(string(b)) == "audit-demo-ready"
}
func DemoProvision() error {
	if os.Geteuid() != 0 {
		return errors.New("run as root")
	}
	unit := `[Unit]
Description=Audit demo HTTP service
After=network.target
[Service]
User=www-data
EnvironmentFile=/etc/default/audit-demo
ExecStart=/usr/local/sbin/incident-audit demo-serve
Restart=on-failure
[Install]
WantedBy=multi-user.target
`
	if e := AtomicText("/etc/systemd/system/audit-demo.service", []byte(unit)); e != nil {
		return e
	}
	if e := os.Chmod("/etc/systemd/system/audit-demo.service", 0644); e != nil {
		return e
	}
	if e := AtomicText("/etc/default/audit-demo", []byte("PORT=8080\n")); e != nil {
		return e
	}
	if e := os.Chmod("/etc/default/audit-demo", 0644); e != nil {
		return e
	}
	for _, args := range [][]string{{"daemon-reload"}, {"enable", "audit-demo"}, {"restart", "audit-demo"}} {
		if e := run("systemctl", args...); e != nil {
			return e
		}
	}
	wait := func(port string) error {
		for i := 0; i < 100; i++ {
			if demoHealth(port) {
				return nil
			}
			time.Sleep(200 * time.Millisecond)
		}
		return errors.New("demo service did not become ready")
	}
	if e := wait("8080"); e != nil {
		return e
	}
	if e := AtomicText("/etc/default/audit-demo", []byte("PORT=8090\n")); e != nil {
		return e
	}
	if e := os.Chmod("/etc/default/audit-demo", 0644); e != nil {
		return e
	}
	if e := run("systemctl", "restart", "audit-demo"); e != nil {
		return e
	}
	if e := wait("8090"); e != nil {
		return e
	}
	if demoHealth("8080") {
		return errors.New("fault injection did not break port 8080")
	}
	fmt.Println("PASS: healthy baseline verified; fault injected; port 8080 unavailable")
	return nil
}
func DemoValidate() Object {
	active := exec.Command("systemctl", "is-active", "--quiet", "audit-demo").Run() == nil
	body := demoHealth("8080")
	v := Object{"service_active": active, "url": "http://127.0.0.1:8080/health", "http_status": nil, "body_matches": body, "passed": active && body}
	if body {
		v["http_status"] = 200
	} else {
		v["error"] = "HTTP endpoint unavailable"
	}
	return v
}
func Demo(ctx context.Context, args []string, out io.Writer) error {
	if len(args) == 0 {
		return errors.New("demo requires connect or finish")
	}
	op := args[0]
	f := flag.NewFlagSet("demo", flag.ContinueOnError)
	dir := f.String("run-dir", "", "demo run directory")
	config := f.String("config", "config/llm.local.json", "LLM profile")
	dry := f.Bool("dry-run", false, "no LLM request")
	if e := f.Parse(args[1:]); e != nil {
		return e
	}
	if *dir == "" {
		return errors.New("--run-dir is required")
	}
	settings, e := readJSON(filepath.Join(*dir, "session.json"))
	if e != nil {
		return e
	}
	id := str(settings["session_id"])
	if e = ValidSession(id); e != nil {
		return e
	}
	target := str(settings["target"])
	if e = sshDestination(target); e != nil {
		return e
	}
	ssh := []string{}
	for _, v := range list(settings["ssh_command"]) {
		ssh = append(ssh, str(v))
	}
	if len(ssh) == 0 {
		return errors.New("session ssh_command must contain an SSH command")
	}
	if op == "connect" {
		cmd := exec.CommandContext(ctx, ssh[0], append(ssh[1:], "-tt", target)...)
		cmd.Stdin = os.Stdin
		cmd.Stdout = out
		cmd.Stderr = out
		return cmd.Run()
	}
	if op != "finish" {
		return errors.New("unknown demo operation")
	}
	remote := func(arguments ...string) ([]byte, error) {
		quoted := []string{}
		for _, a := range arguments {
			quoted = append(quoted, shellQuote(a))
		}
		cmd := exec.CommandContext(ctx, ssh[0], append(append([]string{}, ssh[1:]...), target, strings.Join(quoted, " "))...)
		cmd.Stderr = out
		return cmd.Output()
	}
	fmt.Fprintln(out, "Stopping recording...")
	b, e := remote("/usr/local/sbin/incident-audit", "stop", "--session-id", id)
	if e != nil {
		return e
	}
	var state Object
	if e = json.Unmarshal(b, &state); e != nil {
		return e
	}
	if state["phase"] != "stopped" {
		return errors.New("recording is not stopped; validation was not started")
	}
	artifacts := filepath.Join(*dir, "artifacts")
	for _, file := range []string{"llm.json", "llm.stats.json", "llm.sources.json", "actions.jsonl", "actions.manifest.json"} {
		b, e = remote("cat", "/var/log/incidentsim/sessions/"+id+"/"+file)
		if e != nil {
			return e
		}
		if e = AtomicText(filepath.Join(artifacts, file), b); e != nil {
			return e
		}
	}
	if _, e = Compact(CompactOptions{Input: filepath.Join(artifacts, "actions.jsonl"), EffectsLimit: 24, ExecLimit: 12}); e != nil {
		return e
	}
	fmt.Fprintln(out, "Logs collected. Running validation outside the recording window...")
	b, e = remote("/usr/local/sbin/incident-audit", "demo-validate")
	if e != nil {
		return e
	}
	validation := filepath.Join(*dir, "validation.json")
	if e = AtomicText(validation, b); e != nil {
		return e
	}
	task, _ := assets.Files.ReadFile("examples/http-service/task.md")
	taskPath := filepath.Join(*dir, "task.md")
	if e = AtomicText(taskPath, task); e != nil {
		return e
	}
	result, e := Analyze(ctx, AnalyzeOptions{Config: *config, Input: filepath.Join(artifacts, "llm.json"), Task: taskPath, Validation: validation, Output: filepath.Join(*dir, "report"), DryRun: *dry})
	if e != nil {
		return e
	}
	fmt.Fprintln(out, string(JSON(result)))
	if !*dry {
		b, e = os.ReadFile(str(result["output"]))
		if e == nil {
			_, e = io.Copy(out, bytes.NewReader(b))
		}
	}
	return e
}
