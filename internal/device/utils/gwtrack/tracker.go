package gwtrack

import (
	"context"
	"fmt"
	"time"

	"github.com/borderzero/border0-cli/internal/device/utils/routes"
	"github.com/borderzero/border0-go/lib/types/syncmap"
	"go.uber.org/atomic"
	"go.uber.org/zap"
)

// Tracker represents a periodic monitor
// for the current default gateway.
type Tracker interface {
	Subscribe() Subscriber
	Close()
}

// Subscriber represents a Tracker subscriber.
type Subscriber interface {
	Close()
	C() <-chan *Update
}

// tracker is the default Tracker implementation.
type tracker struct {
	logger   *zap.Logger
	routeMgr routes.RouteManager

	interval time.Duration
	timeout  time.Duration

	currentV4 *atomic.Pointer[Gateway]
	currentV6 *atomic.Pointer[Gateway]

	subscribers *syncmap.Map[string, chan<- *Update]

	stop context.CancelFunc
}

type gatewayLookupResult struct {
	iface string
	addr  string
	ok    bool
	err   error
}

// NewTracker returns a new default implementation of
// the Tracker interface. Tracker periodically checks
// what the network interface and address of the default
// gateway is. On any change it will notify all subscribers.
func NewTracker(
	logger *zap.Logger,
	routeMgr routes.RouteManager,
) Tracker {
	ctx, ctxc := context.WithCancel(context.Background())
	t := &tracker{
		logger:      logger,
		routeMgr:    routeMgr,
		interval:    time.Second * 5,
		timeout:     time.Second * 5,
		currentV4:   atomic.NewPointer(&Gateway{}),
		currentV6:   atomic.NewPointer(&Gateway{}),
		subscribers: syncmap.New[string, chan<- *Update](),
		stop:        ctxc,
	}

	t.logger.Info("gateway tracker starting")

	// do one without notifying
	t.doV4Check()
	t.doV6Check()

	go func() {
		for {
			select {
			case <-ctx.Done():
				t.logger.Info("gateway tracker stopping", zap.Error(ctx.Err()))
				return
			case <-time.After(t.interval):
				t.logger.Debug("gateway tracker check starting")

				update := &Update{}

				beforeV4, afterV4, modifiedV4, okV4 := t.doV4Check()
				if okV4 {
					update.GatewayV4 = &GatewayUpdate{
						Before:   beforeV4,
						After:    afterV4,
						Modified: modifiedV4,
					}
				}

				beforeV6, afterV6, modifiedV6, okV6 := t.doV6Check()
				if okV6 {
					update.GatewayV6 = &GatewayUpdate{
						Before:   beforeV6,
						After:    afterV6,
						Modified: modifiedV6,
					}
				}

				if modifiedV4 || modifiedV6 {
					notifySubscribers(t.subscribers, update)
				}
			}
		}
	}()
	return t
}

// Close closes a tracker.
func (t *tracker) Close() { t.stop() }

// Subscribe adds a subscriber to the tracker.
func (t *tracker) Subscribe() Subscriber { return newSubscriber(t) }

// doV4Check performs the check for the default IPv4 gateway.
func (t *tracker) doV4Check() (before *Gateway, after *Gateway, modified bool, ok bool) {
	results := make(chan *gatewayLookupResult)
	go func() {
		defer close(results)
		iface, addr, ok, err := t.routeMgr.GetDefaultV4Gateway()
		results <- &gatewayLookupResult{iface, addr, ok, err}
	}()

	select {
	case result := <-results:
		if result.err != nil {
			t.logger.Error("failed to get default gateway for IPv4", zap.Error(result.err))
			return t.currentV4.Load(), nil, false, false
		}
		after := &Gateway{Interface: result.iface, Address: result.addr, OK: result.ok}
		before := t.currentV4.Swap(after)
		return before, after, !before.Equal(after), true
	case <-time.After(t.timeout):
		t.logger.Error("failed to get default gateway for IPv4", zap.Error(fmt.Errorf("timed out after %s", t.timeout.String())))
		return t.currentV4.Load(), nil, false, false
	}
}

// doV6Check performs the check for the default IPv6 gateway.
func (t *tracker) doV6Check() (before *Gateway, after *Gateway, modified bool, ok bool) {
	results := make(chan *gatewayLookupResult)
	go func() {
		defer close(results)
		iface, addr, ok, err := t.routeMgr.GetDefaultV6Gateway()
		results <- &gatewayLookupResult{iface, addr, ok, err}
	}()

	select {
	case result := <-results:
		if result.err != nil {
			t.logger.Error("failed to get default gateway for IPv6", zap.Error(result.err))
			return t.currentV6.Load(), nil, false, false
		}
		after := &Gateway{Interface: result.iface, Address: result.addr, OK: result.ok}
		before := t.currentV6.Swap(after)
		return before, after, !before.Equal(after), true
	case <-time.After(t.timeout):
		t.logger.Error("failed to get default gateway for IPv6", zap.Error(fmt.Errorf("timed out after %s", t.timeout.String())))
		return t.currentV6.Load(), nil, false, false
	}
}

// notifySubscribers writes an update to all subscribers' channels.
func notifySubscribers(subscribers *syncmap.Map[string, chan<- *Update], update *Update) {
	subscribers.Range(func(subscriberID string, subscriberC chan<- *Update) bool {
		subscriberC <- update
		return true
	})
}

// closeSubscribers closes all subscribers' channels.
func closeSubscribers(subscribers *syncmap.Map[string, chan<- *Update]) {
	subscribers.Range(func(subscriberID string, subscriberC chan<- *Update) bool {
		subscribers.Delete(subscriberID)
		close(subscriberC)
		return true
	})
}
