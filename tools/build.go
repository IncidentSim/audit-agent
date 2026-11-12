//go:build ignore

// Build a native executable and a static Linux x86_64 guest executable.
package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

func main() {
	platforms := [][2]string{{runtime.GOOS, runtime.GOARCH}, {"linux", "amd64"}}
	seen := map[string]bool{}
	for _, p := range platforms {
		key := p[0] + "-" + p[1]
		if seen[key] {
			continue
		}
		seen[key] = true
		name := "incident-audit"
		if p[0] == "windows" {
			name += ".exe"
		}
		output := filepath.Join("bin", key, name)
		cmd := exec.Command("go", "build", "-trimpath", "-ldflags=-s -w", "-o", output, "./cmd/incident-audit")
		for _, v := range os.Environ() {
			k, _, _ := strings.Cut(v, "=")
			if k != "GOOS" && k != "GOARCH" && k != "CGO_ENABLED" {
				cmd.Env = append(cmd.Env, v)
			}
		}
		cmd.Env = append(cmd.Env, "GOOS="+p[0], "GOARCH="+p[1], "CGO_ENABLED=0")
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		fmt.Println("Building", output)
		if e := cmd.Run(); e != nil {
			panic(e)
		}
	}
}
