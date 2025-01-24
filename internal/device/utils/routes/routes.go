package routes

import (
	"errors"
	"net/netip"
	"time"

	"go.uber.org/zap"
)

const defaultRouteCommandTimeout = time.Second * 10

// NOTE(@adrianosela): do not remove this. VSCode will claim it's not
// used because VSCode only checks it's not used for your GOOS, but
// it may be used by one of the platform specific implementations of
// RouteManager in this package.
var errNotImplemented = errors.New("not implemented")

// RouteManager represents an entity capable of managing routes.
type RouteManager interface {
	GetDnsResolvers() ([]netip.Addr, error)

	GetDefaultV4Gateway() (string, string, bool, error)
	GetDefaultV6Gateway() (string, string, bool, error)

	AssignV4Address(iface, ipv4 string) error
	AssignV6Address(iface, ipv6 string) error

	AddV4Route(iface, cidrv4 string) error
	AddV6Route(iface, cidrv6 string) error
	AddV4RouteViaGateway(iface, gwip, cidrv4 string) error
	AddV6RouteViaGateway(iface, gwip, cidrv6 string) error
	DeleteRoute(cidr string, gwip string) error

	RouteExists(cidr, gwip string) (bool, error)
}

// platform-independent implementation of RouteManager.
type routeManager struct{ RouteManager }

// NewManager returns a platform-independent implementation of RouteManager.
func NewManager(logger *zap.Logger) RouteManager {
	return &routeManager{newManagerForPlatform(logger)}
}
