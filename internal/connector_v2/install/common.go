package install

import (
	"context"
	"fmt"
	"os"

	border0 "github.com/borderzero/border0-cli/internal/api"
	"github.com/borderzero/border0-cli/internal/api/models"
	"github.com/borderzero/border0-go/lib/types/set"
	"github.com/borderzero/border0-go/lib/types/slice"
	"github.com/borderzero/border0-go/types/service"
)

func maxString(s string, max int) string {
	if len(s) > max {
		return s[:max]
	}
	return s
}

func getUniqueConnectorName(ctx context.Context, version, prefix string) (string, error) {
	border0Client := border0.NewAPI(border0.WithVersion(version))

	connectors, err := border0Client.ListConnectors(ctx)
	if err != nil {
		return "", fmt.Errorf("failed to list connectors via the Border0 API: %v", err)
	}

	takenNames := set.New(slice.Transform(connectors, func(c models.Connector) string { return c.Name })...)

	proposedName := prefix

	for i := 1; true; i++ {
		if !takenNames.Has(proposedName) {
			return proposedName, nil
		}
		proposedName = fmt.Sprintf("%s-%d", prefix, i)
	}

	// should never reach this code but compiler needs it
	return "", fmt.Errorf("failed to get a unique connector name to use")
}

func createNewBorder0Connector(
	ctx context.Context,
	connectorName string,
	connectorDescription string,
	cliVersion string,
	useSudoUser bool,
) (*models.Connector, error) {
	border0Client := border0.NewAPI(border0.WithVersion(cliVersion))

	var builtInSshServiceConfig *service.BuiltInSshServiceConfiguration
	if useSudoUser {
		sudoUser := os.Getenv("SUDO_USER")
		if sudoUser != "" {
			builtInSshServiceConfig = &service.BuiltInSshServiceConfiguration{
				UsernameProvider: service.UsernameProviderDefined,
				Username:         sudoUser,
			}
		}
	}
	connector, err := border0Client.CreateConnector(ctx, connectorName, connectorDescription, true, builtInSshServiceConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create a new Border0 connector via the Border0 API: %v", err)
	}

	fmt.Printf("🚀 Border0 connector \"%s\" created successfully!\n", connectorName)

	return connector, nil
}

func generateNewBorder0ConnectorToken(
	ctx context.Context,
	connectorId string,
	cliVersion string,
	tokenName string,
) (*models.ConnectorToken, error) {
	border0Client := border0.NewAPI(border0.WithVersion(cliVersion))

	createTokenCtx, createTokenCtxCancel := context.WithTimeout(ctx, timeoutCreateBorder0Token)
	defer createTokenCtxCancel()

	token, err := border0Client.CreateConnectorToken(
		createTokenCtx,
		connectorId,
		tokenName,
		nil,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create a new Border0 token for connector via the Border0 API: %v", err)
	}

	fmt.Printf("🚀 Border0 connector token \"%s\" created successfully!\n", token.Name)

	return token, nil
}
