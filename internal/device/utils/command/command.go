package command

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os/exec"
	"strings"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// Run creates a command and executes it, printing a log line and the command's output to stdout.
func Run(logger *zap.Logger, timeout time.Duration, parts ...string) error {
	return RunWithModifier(logger, timeout, nil, parts...)
}

// RunWithModifier creates a command and applies the given modifier function to it (if non-nil).
func RunWithModifier(logger *zap.Logger, timeout time.Duration, modifier func(*exec.Cmd), parts ...string) error {
	if len(parts) < 1 {
		return fmt.Errorf("cannot run an empty command (got no parts)")
	}

	fullCommand := strings.Join(parts, " ") // used in log lines only

	// initialize a new context with timeout
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, parts[0], parts[1:]...)

	// run the given modifier function if any was provided.
	if modifier != nil {
		modifier(cmd)
	}

	// set up stdout.
	var stdoutBuf bytes.Buffer
	if cmd.Stdout == nil {
		cmd.Stdout = &stdoutBuf
	} else {
		cmd.Stdout = io.MultiWriter(&stdoutBuf, cmd.Stdout)
	}

	// set up stderr.
	var stderrBuf bytes.Buffer
	if cmd.Stderr == nil {
		cmd.Stderr = &stderrBuf
	} else {
		cmd.Stderr = io.MultiWriter(&stderrBuf, cmd.Stderr)
	}

	// run the command.
	err := cmd.Run()

	// set up logger fields, checking whether there
	// is any output in stdout/stderr data to include.
	loggerOpts := []zapcore.Field{zap.String("command", fullCommand)}
	if stdoutData := strings.TrimSuffix(stdoutBuf.String(), "\n"); stdoutData != "" {
		loggerOpts = append(loggerOpts, zap.String("stdout", stdoutData))
	}
	if stderrData := strings.TrimSuffix(stderrBuf.String(), "\n"); stderrData != "" {
		loggerOpts = append(loggerOpts, zap.String("stderr", stderrData))
	}

	// log result and return.
	if err != nil {
		logger.Debug("failed to run command", append(loggerOpts, zap.String("error", err.Error()))...)
		return err
	}
	logger.Debug("successfully ran command", loggerOpts...)
	return nil
}
