package ipfw

import (
	"fmt"
	"runtime"
	"time"

	"go.uber.org/zap"
)

const defaultForwardingCommandTimeout = time.Second * 10

var errNotSupported = fmt.Errorf("enabling kernel-based IP forwarding is not supported on %s", runtime.GOOS)

// ForwardingManager represents an entity capable of IP forwarding.
type ForwardingManager interface {
	SetupIPv4Forwarding() error
	SetupIPv6Forwarding() error
}

// platform-independent implementation of ForwardingManager.
type forwardingManager struct{ ForwardingManager }

// NewManager returns a platform-independent implementation of ForwardingManager.
func NewManager(logger *zap.Logger) ForwardingManager {
	return &forwardingManager{newManagerForPlatform(logger)}
}
