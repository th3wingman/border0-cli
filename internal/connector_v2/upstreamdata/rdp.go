package upstreamdata

import (
	"fmt"

	"github.com/borderzero/border0-cli/internal/api/models"
	"github.com/borderzero/border0-go/types/service"
)

func (u *UpstreamDataBuilder) buildUpstreamDataForRdpService(s *models.Socket, config *service.RdpServiceConfiguration) error {
	if config == nil {
		return fmt.Errorf("got rdp service with no rdp service configuration")
	}

	hostname, port := config.Hostname, int(config.Port)
	s.ConnectorData.TargetHostname = hostname
	s.ConnectorData.Port = port
	s.TargetHostname = hostname
	s.TargetPort = port

	return nil
}
