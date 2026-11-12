package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"incidentsim/audit-agent/internal/agent"
	"os"
	"os/signal"
	"runtime"
	"runtime/debug"
	"syscall"
)

func main() {
	// Leave room for the guest's services on 512 MiB VMs. This is a GC target,
	// not an excuse to retain an unbounded history; exporters spill to disk.
	if runtime.GOOS == "linux" && os.Getenv("GOMEMLIMIT") == "" {
		debug.SetMemoryLimit(64 << 20)
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	if e := agent.CLI(ctx, os.Args[1:], os.Stdout); e != nil {
		if errors.Is(e, flag.ErrHelp) {
			return
		}
		fmt.Fprintln(os.Stderr, "incident-audit:", e)
		os.Exit(1)
	}
}
