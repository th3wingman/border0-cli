package dns

import (
	"context"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/borderzero/border0-go/lib/types/set"
	"go.uber.org/zap"
)

// ResolutionInput represents a single hostname to be resolved
// along with what IP addresses should be returned in the event
// of a failure or timeout.
type ResolutionInput struct {
	Hostname string
	Defaults []netip.Addr
}

// result represents the output of the
// net.LookupIP function as a struct.
type result struct {
	ips []net.IP
	err error
}

// ResolveOrDefaults resolves a list of inputs or returns their defaults.
func ResolveOrDefaults(logger *zap.Logger, timeout time.Duration, inputs ...*ResolutionInput) []netip.Addr {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	addresses := set.NewConcurrencySafe[netip.Addr]()

	var wg sync.WaitGroup
	for _, input := range inputs {
		wg.Add(1)
		go func() {
			defer wg.Done()
			resolveTimeout(ctx, logger, input, addresses)
		}()
	}
	wg.Wait()

	return addresses.Slice()
}

// resolveTimeout resolves a single input and adds resolved
// addresses to the given addresses set. If resolution
// fails or times out, a log is emitted and the input's
// defaults are injected into the addresses set.
func resolveTimeout(
	ctx context.Context,
	logger *zap.Logger,
	input *ResolutionInput,
	addresses set.Set[netip.Addr],
) {
	results := make(chan result)
	defer close(results)

	go func() {
		ips, err := net.LookupIP(input.Hostname)
		select {
		case <-ctx.Done():
			return
		default:
			results <- result{ips: ips, err: err}
		}
	}()

	select {
	case result := <-results:
		if result.err != nil {
			logger.Info(
				"failed to resolve hostname, will use default",
				zap.String("hostname", input.Hostname),
				zap.Any("default", input.Defaults),
				zap.Error(result.err),
			)
			addresses.Add(input.Defaults...)
			return
		}
		for _, ip := range result.ips {
			if parsedAddr, ok := netip.AddrFromSlice(ip); ok {
				logger.Info("resolved hostname", zap.String("hostname", input.Hostname), zap.String("ip", parsedAddr.String()))
				addresses.Add(parsedAddr)
			}
		}
		return
	case <-ctx.Done():
		logger.Info(
			"timed out while resolving hostname, will use default",
			zap.String("hostname", input.Hostname),
			zap.Any("default", input.Defaults),
		)
		addresses.Add(input.Defaults...)
		return
	}
}
