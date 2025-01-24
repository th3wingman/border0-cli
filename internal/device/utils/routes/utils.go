package routes

import (
	"fmt"
	"net"
	"net/netip"

	"github.com/borderzero/border0-cli/internal/device/state"
)

const (
	// IPv4DefaultRoute represents the entire IPv4 Internet.
	IPv4DefaultRoute = "0.0.0.0/0"

	// IPv6DefaultRoute represents the entire IPv6 Internet.
	IPv6DefaultRoute = "::/0"
)

const (
	// IPv4InternetFirstHalf represents the first half of the whole IPv4 Internet CIDR.
	IPv4InternetFirstHalf = "0.0.0.0/1"

	// IPv4InternetSecondHalf represents the second half of the whole IPv4 Internet CIDR.
	IPv4InternetSecondHalf = "128.0.0.0/1"

	// IPv6InternetFirstHalf represents the first half of the whole IPv6 Internet CIDR.
	IPv6InternetFirstHalf = "::/1"

	// IPv6InternetSecondHalf represents the second half of the whole IPv6 Internet CIDR.
	IPv6InternetSecondHalf = "8000::/1"
)

// SetDefaultV4Route sets routes equivalent to setting a "default" route (i.e. 0.0.0.0/0)
// by instead setting two /1s (0.0.0.0/1 and 128.0.0.0/1). This is desirable because
// if the machine already has a default route we would have to delete it or otherwise
// configure other means of prioritizing *our* default route. By setting two more
// specific routes, we benefit from our default-equivalent routes being selected.
func SetDefaultV4Route(rm RouteManager, state state.State, iface, publicKey, svcName string) error {
	if err := rm.AddV4Route(iface, IPv4InternetFirstHalf); err != nil {
		return fmt.Errorf("failed to set first half of default ipv4 route (%s): %v", IPv4InternetFirstHalf, err)
	}
	state.AddServiceManagedRoute(IPv4InternetFirstHalf, publicKey, svcName)
	if err := rm.AddV4Route(iface, IPv4InternetSecondHalf); err != nil {
		return fmt.Errorf("failed to set second half of default ipv4 route (%s): %v", IPv4InternetFirstHalf, err)
	}
	state.AddServiceManagedRoute(IPv4InternetSecondHalf, publicKey, svcName)
	return nil
}

// SetDefaultV6Route sets routes equivalent to setting a "default" route (i.e. ::/0)
// by instead setting two /1s (::/1 and 8000::/1). This is desirable because if
// the machine already has a default route we would have to delete it or otherwise
// configure other means of prioritizing *our* default route. By setting two more
// specific routes, we benefit from our default-equivalent routes being selected.
func SetDefaultV6Route(rm RouteManager, state state.State, iface, publicKey, svcName string) error {
	if err := rm.AddV6Route(iface, IPv6InternetFirstHalf); err != nil {
		return fmt.Errorf("failed to set first half of default ipv6 route (%s): %v", IPv6InternetFirstHalf, err)
	}
	state.AddServiceManagedRoute(IPv6InternetFirstHalf, publicKey, svcName)
	if err := rm.AddV6Route(iface, IPv6InternetSecondHalf); err != nil {
		return fmt.Errorf("failed to set second half of default ipv6 route (%s): %v", IPv6InternetSecondHalf, err)
	}
	state.AddServiceManagedRoute(IPv6InternetSecondHalf, publicKey, svcName)
	return nil
}

// AssignAddresses assigns an interface its IPv4 and IPv6 addresses.
func AssignAddresses(rm RouteManager, iface string, ipv4cidr string, ipv6cidr string) error {
	if ipv4cidr != "" {
		ipv4, _, err := net.ParseCIDR(ipv4cidr)
		if err != nil {
			return fmt.Errorf("failed to parse IPv4 address cidr %s: %v", ipv4cidr, err)
		}
		if err := rm.AssignV4Address(iface, ipv4.String()); err != nil {
			return fmt.Errorf("failed to assign IPv4 address %s to interface %s: %v", ipv4.String(), iface, err)
		}
	}
	if ipv6cidr != "" {
		ipv6, _, err := net.ParseCIDR(ipv6cidr)
		if err != nil {
			return fmt.Errorf("failed to parse IPv6 address cidr %s: %v", ipv6cidr, err)
		}
		if err := rm.AssignV6Address(iface, ipv6.String()); err != nil {
			return fmt.Errorf("failed to assign IPv6 address %s to interface %s: %v", ipv6.String(), iface, err)
		}
	}
	return nil
}

// EnsureBypassRoutes sets routes on the default interface to ensure
// that those destinations are always routed via the internet.
func EnsureBypassRoutes(rm RouteManager, state state.State, addrs []netip.Addr) error {
	ipv4Iface, ipv4Gateway, hasV4, err := rm.GetDefaultV4Gateway()
	if err != nil {
		return fmt.Errorf("failed to determine default IPv4 network interfaces: %v", err)
	}
	ipv6Iface, ipv6Gateway, hasV6, err := rm.GetDefaultV6Gateway()
	if err != nil {
		return fmt.Errorf("failed to determine default IPv6 network interfaces: %v", err)
	}
	resolverAddrs, err := rm.GetDnsResolvers()
	if err != nil {
		return fmt.Errorf("failed to get DNS resolvers: %v", err)
	}

	for i, addr := range append(addrs, resolverAddrs...) {
		// skip interface-scoped addresses, there's no need to bypass those
		if addr.IsInterfaceLocalMulticast() || addr.IsLinkLocalUnicast() || addr.IsLinkLocalMulticast() {
			continue
		}
		// NOTE: order here matters, as Is6() includes IPv4-mapped IPv6 addresses.
		if addr.Is6() {
			if hasV6 {
				prefix := fmt.Sprintf("%s/128", addr.String())

				// skip addresses that are already set
				exists, err := rm.RouteExists(prefix, ipv6Gateway)
				if err != nil {
					return fmt.Errorf("failed to check IPv6 bypass route existence for route at index %d (%s): %v", i, prefix, err)
				}

				if !exists {
					if err := rm.AddV6RouteViaGateway(ipv6Iface, ipv6Gateway, prefix); err != nil {
						return fmt.Errorf("failed to set IPv6 bypass route at index %d (%s): %v", i, prefix, err)
					}
				}
				state.AddNonServiceManagedRoute(fmt.Sprintf("%s %s", prefix, ipv6Gateway))
			}
			continue
		}
		if addr.Is4() {
			if hasV4 {
				prefix := fmt.Sprintf("%s/32", addr.String())

				// skip addresses that are already set
				exists, err := rm.RouteExists(prefix, ipv4Gateway)
				if err != nil {
					return fmt.Errorf("failed to check IPv4 bypass route existence for route at index %d (%s): %v", i, prefix, err)
				}

				if !exists {
					if err := rm.AddV4RouteViaGateway(ipv4Iface, ipv4Gateway, prefix); err != nil {
						return fmt.Errorf("failed to set IPv4 bypass route at index %d (%s): %v", i, prefix, err)
					}
				}
				state.AddNonServiceManagedRoute(fmt.Sprintf("%s %s", prefix, ipv4Gateway))
			}
			continue
		}
		return fmt.Errorf("failed to set bypass route at index %d %s: not an ipv4 nor ipv6 cidr", i, addr.String())
	}
	return nil
}
