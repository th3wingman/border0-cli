package rebind

import (
	"net"
	"time"

	"github.com/borderzero/border0-go/lib/types/set"
)

const alreadyRebindingWait = time.Second * 2

// ValidAllowedMethods is a set containing all valid methods.
var ValidAllowedMethods = set.New(
	MethodUdp4,
	MethodUdp6,
	MethodUdpR,
)

// PacketConn represents a re-bindable net.PacketConn wrapper. The
// ability to re-bind is particularly useful in roaming environments
// where a machine's network interfaces change frequently and
// listeners must be re-started to listen on all interfaces.
type PacketConn interface {
	net.PacketConn

	Method() string
	Rebind() error
	Port() uint16
	IsOpen() bool
	IsBinding() bool

	ShouldRebindOnError(error) bool
}
