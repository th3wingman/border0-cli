package refresher

import (
	"context"
	"crypto/tls"
	"fmt"
	"sync"
	"time"

	"go.uber.org/zap"
)

type RefreshFunc func() (*tls.Certificate, time.Time, error)

type Refresher struct {
	sync.RWMutex

	// dynamic - managed by lock
	current   *tls.Certificate
	refreshAt time.Time

	// static
	afterFailurePeriod time.Duration
	refreshFunc        RefreshFunc
}

func New(
	ctx context.Context,
	logger *zap.Logger,
	afterFailurePeriod time.Duration,
	refreshFunc RefreshFunc,
) (*Refresher, error) {
	r := &Refresher{
		afterFailurePeriod: afterFailurePeriod,
		refreshFunc:        refreshFunc,
		refreshAt:          time.Now(),
	}
	if err := r.refresh(); err != nil {
		return nil, fmt.Errorf("failed to retrieve initial certificate: %v", err)
	}
	logger.Info("initial certificate established", zap.String("next_refresh_in", time.Until(r.getRefreshAt()).String()))
	go r.start(ctx, logger)
	return r, nil
}

func (r *Refresher) GetCurrent() *tls.Certificate {
	r.RLock()
	defer r.RUnlock()
	return r.current
}

func (r *Refresher) getRefreshAt() time.Time {
	r.RLock()
	defer r.RUnlock()
	return r.refreshAt
}

func (r *Refresher) refresh() error {
	newCert, refreshAt, err := r.refreshFunc()
	if err != nil {
		return fmt.Errorf("failed to refresh certificate: %v", err)
	}
	r.Lock()
	defer r.Unlock()
	r.current = newCert
	r.refreshAt = refreshAt
	return nil
}

func (r *Refresher) start(ctx context.Context, logger *zap.Logger) {
	refreshTimer := time.NewTimer(time.Until(r.getRefreshAt()))
	defer refreshTimer.Stop()

	for {
		select {
		case <-ctx.Done():
			return // stop
		case <-refreshTimer.C:
			if err := r.refresh(); err != nil {
				logger.Error("failed to refresh certificate", zap.Error(err))
				refreshTimer.Reset(r.afterFailurePeriod)
				continue
			}
			nextRefreshIn := time.Until(r.getRefreshAt())
			logger.Info("certificate refreshed", zap.String("next_refresh_in", nextRefreshIn.String()))
			refreshTimer.Reset(nextRefreshIn)
		}
	}
}
