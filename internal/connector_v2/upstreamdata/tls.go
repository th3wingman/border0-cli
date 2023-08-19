package upstreamdata

import (
	"fmt"

	"github.com/borderzero/border0-cli/internal/api/models"
	"github.com/borderzero/border0-go/types/service"
)

func (u *UpstreamDataBuilder) buildUpstreamDataForTlsService(s *models.Socket, config *service.TlsServiceConfiguration) error {
	if config == nil {
		return fmt.Errorf("got tls service with no tls service configuration")
	}

	hostname, port := u.fetchVariableFromSource(config.Hostname), int(config.Port)

	s.ConnectorData.TargetHostname = hostname
	s.ConnectorData.Port = port
	s.TargetHostname = hostname
	s.TargetPort = port

	return nil
}
