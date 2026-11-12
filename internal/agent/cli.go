package agent

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

func CLI(ctx context.Context, args []string, out io.Writer) error {
	if len(args) == 0 {
		return errors.New("usage: incident-audit <start|stop|status|stream|shell|mark|export|compact|analyze|install|deploy|verify|demo|demo-serve|demo-provision|demo-validate|control>")
	}
	op, args := args[0], args[1:]
	if op == "--help" || op == "-h" || op == "help" {
		fmt.Fprintln(out, "incident-audit <start|stop|status|stream|shell|mark|export|compact|compact-file|analyze|install|deploy|verify|demo|demo-serve|demo-provision|demo-validate|control>")
		return nil
	}
	f := flag.NewFlagSet(op, flag.ContinueOnError)
	f.SetOutput(out)
	emit := func(v any) { fmt.Fprintln(out, string(JSON(v))) }
	switch op {
	case "analyze":
		o := AnalyzeOptions{}
		f.StringVar(&o.Config, "config", "config/llm.local.json", "LLM configuration")
		f.StringVar(&o.Profile, "profile", "", "profile override")
		f.StringVar(&o.Input, "input", "", "compact packet")
		f.StringVar(&o.Task, "task", "", "task Markdown")
		f.StringVar(&o.Validation, "validation", "", "validation result")
		f.StringVar(&o.Output, "output", "", "new report directory")
		f.BoolVar(&o.DryRun, "dry-run", false, "validate without a network request")
		if e := f.Parse(args); e != nil {
			return e
		}
		if o.Input == "" || o.Task == "" {
			return errors.New("--input and --task are required")
		}
		v, e := Analyze(ctx, o)
		if e == nil {
			emit(v)
		}
		return e
	case "install":
		vm := f.String("vm-id", "", "stable VM identity")
		skip := f.Bool("skip-packages", false, "skip apt")
		if e := f.Parse(args); e != nil {
			return e
		}
		return Install(*vm, *skip)
	case "deploy":
		return Deploy(ctx, args, out)
	case "demo":
		return Demo(ctx, args, out)
	case "demo-serve":
		return DemoServe(args)
	case "demo-provision":
		return DemoProvision()
	case "demo-validate":
		v := DemoValidate()
		emit(v)
		return nil
	case "compact-file":
		o := CompactOptions{EffectsLimit: 24, ExecLimit: 12}
		compactFlags(f, &o)
		f.StringVar(&o.Input, "input", "", "full JSONL snapshot")
		f.StringVar(&o.Manifest, "manifest", "", "snapshot manifest")
		if e := f.Parse(args); e != nil {
			return e
		}
		if o.Input == "" {
			return errors.New("--input is required")
		}
		v, e := Compact(o)
		if e == nil {
			emit(v)
		}
		return e
	case "verify":
		a, e := OpenAgent()
		if e != nil {
			return e
		}
		v, e := a.Verify()
		if e == nil {
			emit(v)
		}
		return e
	}
	// Guest commands require Linux audit context; host analyze/compact/deploy do not.
	if op == "control" && len(args) == 4 && args[2] == "reset" {
		// On a fresh VM there is no context or attempt yet. The staged binary
		// must be able to reset before its first installation.
		if _, err := os.Stat(filepath.Join(args[0], ".audit", "attempt.json")); os.IsNotExist(err) {
			return nil
		}
	}
	a, e := OpenAgent()
	if e != nil {
		return e
	}
	switch op {
	case "stream":
		return a.Stream(ctx, os.Stdin)
	case "status":
		v, e := a.Status()
		if e == nil {
			emit(v)
		}
		return e
	case "start", "stop":
		sid := f.String("session-id", "", "recording identity")
		if e = f.Parse(args); e != nil {
			return e
		}
		if *sid == "" {
			return errors.New("--session-id is required")
		}
		var v Object
		if op == "start" {
			v, e = a.Store.Start(*sid, a.VMID, a.Boundary)
		} else {
			v, e = a.Store.Stop(*sid, a.Boundary, func(w Object) (Object, error) { return a.Export(ExportOptions{}, w) })
			if e == nil {
				for k, x := range obj(v["artifacts"]) {
					v[k] = x
				}
			}
		}
		if e == nil {
			emit(v)
		}
		return e
	case "export":
		o := ExportOptions{}
		f.StringVar(&o.Session, "session-id", "", "recording identity")
		f.StringVar(&o.Output, "output", "", "snapshot path")
		f.BoolVar(&o.All, "all", false, "unfiltered diagnostics")
		f.BoolVar(&o.IncludeInstrumentation, "include-instrumentation", false, "include collector operations")
		if e = f.Parse(args); e != nil {
			return e
		}
		v, e := a.Export(o, nil)
		if e == nil {
			emit(v)
		}
		return e
	case "compact":
		o := CompactOptions{EffectsLimit: 24, ExecLimit: 12}
		compactFlags(f, &o)
		sid := f.String("session-id", "", "recording identity")
		if e = f.Parse(args); e != nil {
			return e
		}
		w, e := a.Store.Get(*sid)
		if e != nil {
			return e
		}
		if w["phase"] != "stopped" {
			return errors.New("stop recording before preparing an LLM packet")
		}
		unlock, e := lock(filepath.Join(a.Root, ".export.lock"))
		if e != nil {
			return e
		}
		defer unlock()
		o.Input = filepath.Join(a.Store.directory(str(w["session_id"])), "actions.jsonl")
		v, e := Compact(o)
		if e == nil {
			emit(v)
		}
		return e
	case "shell":
		phase := f.String("phase", "", "start or finish")
		history := f.String("history", "", "Bash history entry")
		pid := f.Int("shell-pid", 0, "Bash PID")
		cwd := f.String("cwd", "", "working directory")
		tty := f.String("tty", "", "terminal")
		status := f.Int("status", 0, "Bash exit status")
		if e = f.Parse(args); e != nil {
			return e
		}
		if *pid <= 0 || *cwd == "" {
			return errors.New("--shell-pid and --cwd are required")
		}
		return a.Shell(*phase, *history, *pid, *cwd, *tty, status)
	case "mark":
		if len(args) != 1 {
			return errors.New("mark requires a label")
		}
		v := Object{"schema_version": 1, "event_id": token(), "timestamp": now(), "vm_id": a.VMID, "source": "control", "kind": "marker", "origin": "control", "label": args[0]}
		written, e := a.Store.Record(v)
		if e != nil {
			return e
		}
		if !written {
			return errors.New("annotations require an active recording session")
		}
		state, e := a.Store.Current()
		if e == nil {
			emit(Object{"label": args[0], "capture_session_id": state["session_id"]})
		}
		return e
	case "control":
		if len(args) != 4 {
			return errors.New("control requires work, exercise, action and session")
		}
		b, e := a.Control(args[0], args[1], args[2], args[3])
		if e == nil && len(b) > 0 {
			_, e = out.Write(b)
		}
		return e
	default:
		return fmt.Errorf("unknown operation %q", op)
	}
}
func compactFlags(f *flag.FlagSet, o *CompactOptions) {
	f.StringVar(&o.Output, "output", "", "compact packet path")
	f.IntVar(&o.EffectsLimit, "effects-limit", 24, "effects per action")
	f.IntVar(&o.ExecLimit, "exec-limit", 12, "execs per action")
	f.IntVar(&o.MaxBytes, "max-bytes", 0, "fail if packet exceeds byte budget")
}
