package upstreamdata

import (
	"errors"
	"fmt"

	"github.com/borderzero/border0-cli/internal/api/models"
	"github.com/borderzero/border0-go/types/service"
)

func (u *UpstreamDataBuilder) buildUpstreamDataForHttpService(s *models.Socket, config *service.HttpServiceConfiguration) error {
	if config == nil {
		return fmt.Errorf("got http service with no http service configuration")
	}
	// FIXME: implement
	return errors.New("Have not implemented handling upstream data for http services")
}
