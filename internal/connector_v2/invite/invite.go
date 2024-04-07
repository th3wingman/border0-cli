package invite

import (
	"context"
	"fmt"
	"path/filepath"

	"github.com/borderzero/border0-cli/internal"
	border0 "github.com/borderzero/border0-cli/internal/api"
	"github.com/borderzero/border0-cli/internal/connector_v2/config"
	"github.com/borderzero/border0-cli/internal/files"
	"github.com/borderzero/border0-cli/internal/util"
)

// ExchangeForConnectorToken uses an invite code to create a new connector and connector token,
// and then returns the connector token.
func ExchangeForConnectorToken(ctx context.Context, inviteCode string) (connectorToken string, err error) {
	// check if the connector token is already present in a file invite_<inviteCode> from the .border0 directory
	// if it is, return it, this will make the invite code "reusable", so the user can run `border0 connector start`
	// command again with the same --invite <inviteCode> flag, copied from portal's connector install page,
	// for docker container use case.
	connectorToken, err = readConnectorTokenFromFile(inviteCode)
	if err != nil {
		return "", err
	}
	if connectorToken != "" {
		return connectorToken, nil
	}

	// connector token not yet writen to file, this is the first time the invite code is used, so we need to
	// use the invite code to exchange for a connector token
	border0Client := border0.NewAPI(border0.WithVersion(internal.Version))

	hostname, err := util.GetFormattedHostname()
	if err != nil {
		return "", fmt.Errorf("failed to get system hostname: %w", err)
	}

	reply, err := border0Client.CreateConnectorWithInstallToken(ctx, hostname, inviteCode)
	if err != nil {
		return "", fmt.Errorf("failed to create connector with invite code: %w", err)
	}
	connectorToken = reply.ConnectorToken.Token

	// write the connector token to a file invite_<inviteCode> in the .border0 directory, so it can be reused
	// when the user runs `border0 connector start` again with the same --invite <inviteCode> flag
	err = writeConnectorTokenToFiles(inviteCode, connectorToken)
	if err != nil {
		return "", err
	}

	return connectorToken, nil
}

// ExchangeForAwsConnectorToken uses an invite code to create a new connector and connector token.
// It excludes some of the behaviour of the ExchangeForConnectorToken because we are getting a connector
// token for a *remote* machine, not the *local* machine.
func ExchangeForAwsConnectorToken(ctx context.Context, name, inviteCode string) (connectorID, connectorToken string, err error) {
	// connector token not yet writen to file, this is the first time the invite code is used, so we need to
	// use the invite code to exchange for a connector token
	border0Client := border0.NewAPI(border0.WithVersion(internal.Version))

	reply, err := border0Client.CreateConnectorWithInstallToken(ctx, name, inviteCode)
	if err != nil {
		return "", "", fmt.Errorf("failed to create connector with invite code: %w", err)
	}
	connectorID = reply.Connector.ConnectorID
	connectorToken = reply.ConnectorToken.Token

	return connectorID, connectorToken, nil
}

func readConnectorTokenFromFile(inviteCode string) (string, error) {
	dotBorder0Dir, err := files.DotBorder0Dir()
	if err != nil {
		return "", fmt.Errorf("failed to get .border0 directory: %w", err)
	}
	connectorTokenFile := filepath.Join(dotBorder0Dir, fmt.Sprintf("invite_%s", inviteCode))
	if files.Exists(connectorTokenFile) {
		connectorToken, err := files.ReadIntoString(connectorTokenFile)
		if err != nil {
			return "", fmt.Errorf("failed to read connector token from file: %w", err)
		}
		return connectorToken, nil
	}
	return "", nil
}

func writeConnectorTokenToFiles(inviteCode, connectorToken string) error {
	dotBorder0Dir, err := files.DotBorder0Dir()
	if err != nil {
		return fmt.Errorf("failed to get .border0 directory: %w", err)
	}

	// write the connector token to a file invite_<inviteCode> in the .border0 directory
	// so it can be reused when the user runs `border0 connector start` again WITH the same --invite <inviteCode> flag
	connectorTokenFile := filepath.Join(dotBorder0Dir, fmt.Sprintf("invite_%s", inviteCode))
	if err := files.WriteStringToFile(connectorTokenFile, connectorToken); err != nil {
		return fmt.Errorf("failed to write connector token to file %s: %w", connectorTokenFile, err)
	}

	// write the connector token to the config file in the .border0 directory
	// so it can be reused when the user runs `border0 connector start` again WITHOUT the --invite flag
	border0ConfigFile := filepath.Join(dotBorder0Dir, "config.yaml")
	return config.WriteToFile(border0ConfigFile, &config.Configuration{Token: connectorToken})
}
