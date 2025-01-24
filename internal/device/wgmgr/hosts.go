package wgmgr

import (
	"bufio"
	"fmt"
	"os"
	"runtime"
	"strings"
)

const marker = "# Added by Border0"

func hostsFilePath() string {
	switch runtime.GOOS {
	case "windows":
		return `C:\Windows\System32\drivers\etc\hosts`
	default: // Linux, macOS, etc.
		return "/etc/hosts"
	}
}

func (wgm *wireGuardManager) updateHostfile(skipHost *string) error {
	// Lock the update process
	wgm.hostLock.Lock()
	defer wgm.hostLock.Unlock()

	// Open the hosts file
	file, err := os.Open(hostsFilePath())
	if err != nil {
		return err
	}
	defer file.Close()

	// Read existing lines and filter out old entries with our marker
	scanner := bufio.NewScanner(file)
	var lines []string

	for scanner.Scan() {
		line := scanner.Text()
		if !strings.Contains(line, marker) {
			lines = append(lines, line) // Keep non-marker lines
		}
	}
	if err := scanner.Err(); err != nil {
		return err
	}

	// Append new entries
	for ip, hostname := range wgm.hosts(skipHost) {
		lines = append(lines, fmt.Sprintf("%s %s %s", ip, hostname, marker))
	}

	// Build the new content before writing
	lineEnding := "\n"
	if runtime.GOOS == "windows" {
		lineEnding = "\r\n"
	}
	var newContent strings.Builder
	for _, line := range lines {
		newContent.WriteString(line + lineEnding)
	}

	// Re-open the file for writing and truncate it
	file, err = os.OpenFile(hostsFilePath(), os.O_WRONLY|os.O_TRUNC, 0)
	if err != nil {
		return fmt.Errorf("failed to open hosts file for writing: %v", err)
	}
	defer file.Close()

	// Write the new content
	_, err = file.WriteString(newContent.String())
	if err != nil {
		return fmt.Errorf("failed to write to hosts file: %v", err)
	}

	return nil

}
