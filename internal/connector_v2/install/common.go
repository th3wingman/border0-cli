package install

import (
	"context"
	"fmt"
	"time"

	"github.com/AlecAivazis/survey/v2"
	border0 "github.com/borderzero/border0-cli/internal/api"
	"github.com/borderzero/border0-cli/internal/api/models"
	"github.com/borderzero/border0-go/lib/types/set"
	"github.com/borderzero/border0-go/lib/types/slice"
)

func promptForBorder0ConnectorName(ctx context.Context, cliVersion, suggestion string) (string, error) {
	if suggestion == "" {
		suggestion = fmt.Sprintf("my-connector-%d", time.Now().Unix())
	}

	var connectorNameTarget string
	err := survey.AskOne(
		&survey.Input{
			Message: "What name would you like for your new connector?",
			Default: suggestion,
		},
		&connectorNameTarget,
		survey.WithValidator(survey.Required),
		survey.WithValidator(getBorder0ConnectorNameValidator(ctx, cliVersion)),
		// TODO: validator for connector name regex
	)
	if err != nil {
		return "", fmt.Errorf("failed to ask survey question: %v", err)
	}
	return connectorNameTarget, nil
}

// returns a survey.Validator that checks that a given connector name does not already exist.
func getBorder0ConnectorNameValidator(ctx context.Context, version string) survey.Validator {
	border0Client := border0.NewAPI(border0.WithVersion(version))

	return func(userInput interface{}) error {
		// cast to string
		connectorName, ok := userInput.(string)
		if !ok {
			return fmt.Errorf("user input not a string")
		}

		connectors, err := border0Client.ListConnectors(ctx)
		if err != nil {
			return fmt.Errorf("failed to list connectors via the Border0 API: %v", err)
		}

		for _, connector := range connectors {
			if connector.Name == connectorName {
				return fmt.Errorf("A connector with the name %s already existst in the organization", connectorName)
			}
		}

		// success!
		return nil
	}
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
) (*models.Connector, error) {
	border0Client := border0.NewAPI(border0.WithVersion(cliVersion))

	connector, err := border0Client.CreateConnector(ctx, connectorName, connectorDescription, true)
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
