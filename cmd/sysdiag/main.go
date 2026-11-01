package main

import (
	"context"
	"io"
	"os"
	"os/signal"
	"syscall"
)

func main() {
	os.Exit(runProcess(os.Args[1:], os.Stdin, os.Stdout, os.Stderr, defaultDependencies()))
}

func runProcess(args []string, stdin io.Reader, stdout, stderr io.Writer, deps dependencies) int {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	return runCommand(ctx, args, stdin, stdout, stderr, deps)
}
