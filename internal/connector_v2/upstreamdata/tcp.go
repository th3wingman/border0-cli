package upstreamdata

import (
	"fmt"

	"github.com/borderzero/border0-cli/internal/api/models"
	"github.com/borderzero/border0-go/types/service"
)

func (u *UpstreamDataBuilder) buildUpstreamDataForTcpService(s *models.Socket, config *service.TcpServiceConfiguration) error {
	if config == nil {
		return fmt.Errorf("got tcp service with no tcp service configuration")
	}

	hostname, port := config.Hostname, int(config.Port)
	s.ConnectorData.TargetHostname = hostname
	s.ConnectorData.Port = port
	s.TargetHostname = hostname
	s.TargetPort = port

	return nil
}
