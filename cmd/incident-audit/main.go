package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"incidentsim/audit-agent/internal/agent"
	"os"
	"os/signal"
	"syscall"
)

func main() {
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
