package upstreamdata

import (
	"errors"
	"fmt"

	"github.com/borderzero/border0-cli/internal/api/models"
	"github.com/borderzero/border0-go/types/service"
)

func (u *UpstreamDataBuilder) buildUpstreamDataForTlsService(s *models.Socket, config *service.TlsServiceConfiguration) error {
	if config == nil {
		return fmt.Errorf("got tls service with no tls service configuration")
	}
	// FIXME: implement
	return errors.New("Have not implemented handling upstream data for tls services")
}
