package upstreamdata

import (
	"fmt"

	"github.com/borderzero/border0-cli/internal/api/models"
	"github.com/borderzero/border0-go/types/service"
)

func (u *UpstreamDataBuilder) buildUpstreamDataForVpnService(s *models.Socket, config *service.VpnServiceConfiguration) error {
	if config == nil {
		return fmt.Errorf("got vpn service with no vpn service configuration")
	}
	s.ConnectorLocalData.AdvertisedRoutes = config.AdvertisedRoutes
	s.ConnectorLocalData.DHCPPoolSubnet = config.DHCPPoolSubnet
	return nil
}
