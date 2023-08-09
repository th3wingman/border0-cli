package install

import (
	"context"
	"errors"

	"github.com/borderzero/border0-cli/internal/util"
)

// RunInstallWizard runs the connector install wizard for the local machine.
func RunInstallWizard(ctx context.Context, version string) error {
	if !util.RunningAsAdministrator() {
		return errors.New("command must be ran as system administrator")
	}

	return nil
}
