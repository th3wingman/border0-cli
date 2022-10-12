package discover

import (
	"context"

	"github.com/borderzero/border0-cli/internal/api/models"
	"github.com/borderzero/border0-cli/internal/connector/config"
)

type DiscoverState struct {
	State     map[string]interface{}
	RunsCount int64
}
type CustomParams map[string]interface{}
type Discover interface {
	Find(ctx context.Context, cfg config.Config, state DiscoverState) ([]models.Socket, error)
	SkipRun(ctx context.Context, cfg config.Config, state DiscoverState) bool
	WaitSeconds() int64
	Name() string
}
