//go:build windows
// +build windows

package process

import "go.uber.org/zap"

// SetupUserAndGroups on Windows is a NO-OP because Windows doesn't support
// changing uid, gid, or groups in the same way as the other platforms.
func SetupUserAndGroups(logger *zap.Logger, params *Parameters) error {
	logger.Warn("Changing a process' uid, gid, and groups is not supported on Windows...")
	return nil
}
