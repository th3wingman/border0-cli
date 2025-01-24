package k8sapilib

import (
	"context"
	"fmt"
	"time"

	gcache "github.com/Code-Hex/go-generics-cache"
	"github.com/borderzero/border0-cli/internal/api/models"
	"github.com/borderzero/border0-cli/internal/border0"
)

type k8sPolicyEvaluator interface {
	Evaluate(ctx context.Context, socket *models.Socket, clientIP, userEmail, sessionKey string) ([]any, map[string][]string, error)
}

// cachedK8sPolicyEvaluator is an implementation of k8sPolicyEvaluator
// which caches results for a given duration. This is useful to prevent
// the connector from hammering the API with evaluation requests. Hitting
// this rate limit could be particularly common when clients are using
// clients which perform actions on their behalf such as Lens, k9s, etc.
type cachedK8sPolicyEvaluator struct {
	inner        k8sPolicyEvaluator
	cache        *gcache.Cache[string, []any]
	cacheItemTTL time.Duration
}

func newCachedPolicyEvaluator(api border0.Border0API, cacheJanitorInterval, cacheTTL time.Duration) k8sPolicyEvaluator {
	return &cachedK8sPolicyEvaluator{
		inner:        api,
		cache:        gcache.New[string, []any](gcache.WithJanitorInterval[string, []any](cacheJanitorInterval)),
		cacheItemTTL: cacheTTL,
	}
}

// Evaluate returns cached results if available, otherwise fresh
// results, saving them in the cache prior to returning.
func (e *cachedK8sPolicyEvaluator) Evaluate(
	ctx context.Context,
	socket *models.Socket,
	clientIP, userEmail, sessionKey string,
) ([]any, map[string][]string, error) {
	key := fmt.Sprintf("%s-%s-%s-%s", socket.SocketID, clientIP, userEmail, sessionKey)

	if values, ok := e.cache.Get(key); ok {
		return values, nil, nil
	}

	values, _, err := e.inner.Evaluate(ctx, socket, clientIP, userEmail, sessionKey)
	if err != nil {
		return nil, nil, err
	}

	e.cache.Set(key, values, gcache.WithExpiration(e.cacheItemTTL))
	return values, nil, nil
}
