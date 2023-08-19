package upstreamdata

import (
	"fmt"

	"github.com/borderzero/border0-cli/internal/api/models"
	"github.com/borderzero/border0-go/types/service"
)

func (u *UpstreamDataBuilder) buildUpstreamDataForHttpService(s *models.Socket, config *service.HttpServiceConfiguration) error {
	if config == nil {
		return fmt.Errorf("got http service with no http service configuration")
	}

	hostname, port := u.fetchVariableFromSource(config.Hostname), int(config.Port)

	s.ConnectorData.TargetHostname = hostname
	s.ConnectorData.Port = port
	s.TargetHostname = hostname
	s.TargetPort = port
	s.UpstreamHttpHostname = &hostname

	return nil
}
