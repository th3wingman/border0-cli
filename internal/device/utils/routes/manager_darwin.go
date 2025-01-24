//go:build darwin

package routes

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"net/netip"
	"os/exec"
	"regexp"
	"strings"
	"time"

	"github.com/borderzero/border0-cli/internal/device/utils/command"
	"github.com/borderzero/border0-go/lib/types/set"
	"go.uber.org/zap"
)

const (
	dnsResolverRetrievalMethodScutil        = "scutil"
	dnsResolverRetrievalMethodResolvDotConf = "resolv.conf"
)

// platform-dependent implementation of RouteManager (for Darwin).
type managerDarwin struct {
	logger                      *zap.Logger
	timeout                     time.Duration
	dnsResolverRetrievalMethods []string
}

// newManagerForPlatform returns the default platform-dependent
// implementation of RouteManager (for Darwin).
func newManagerForPlatform(logger *zap.Logger) RouteManager {
	return &managerDarwin{
		logger:  logger,
		timeout: defaultRouteCommandTimeout,
		dnsResolverRetrievalMethods: []string{
			dnsResolverRetrievalMethodScutil,
			dnsResolverRetrievalMethodResolvDotConf,
		},
	}
}

// GetDnsResolvers returns all DNS resolver addresses.
func (m *managerDarwin) GetDnsResolvers() ([]netip.Addr, error) {
	errs := []error{}
	for _, method := range m.dnsResolverRetrievalMethods {
		switch method {
		case dnsResolverRetrievalMethodScutil:
			addrs, err := getDnsResolversFromScutil(m.logger, m.timeout)
			if err != nil {
				errs = append(errs, fmt.Errorf("failed to retrieve resolver addresses via scutil: %v", err))
				continue
			}
			return addrs, nil
		case dnsResolverRetrievalMethodResolvDotConf:
			addrs, err := getDnsResolversFromResolvDotConf(m.logger)
			if err != nil {
				errs = append(errs, fmt.Errorf("failed to retrieve resolver addresses via parsing resolv.conf file: %v", err))
				continue
			}
			return addrs, nil
		default:
			errs = append(errs, fmt.Errorf("got an invalid dns resolver retrieval method \"%s\"", method))
			continue
		}
	}
	return nil, fmt.Errorf("failed to retrieve dns resolvers: no methods succeeded. Errors: %v", errors.Join(errs...))
}

// GetDefaultV4Gateway gets the interface name and
// the IP address of the default gateway for IPv4.
func (m *managerDarwin) GetDefaultV4Gateway() (string, string, bool, error) {
	return getDefaultGateway(m.logger, m.timeout, 4)
}

// GetDefaultV6Gateway gets the interface name and
// the IP address of the default gateway for IPv6.
func (m *managerDarwin) GetDefaultV6Gateway() (string, string, bool, error) {
	return getDefaultGateway(m.logger, m.timeout, 6)
}

// AssignV4Address assigns an IPv4 address to a given interface.
func (m *managerDarwin) AssignV4Address(iface, ipv4 string) error {
	return command.Run(
		m.logger,
		m.timeout,

		"ifconfig",
		iface,
		"inet",
		ipv4,
		ipv4,
		"up",
	)
}

// AssignV6Address assigns an IPv6 address to a given interface.
func (m *managerDarwin) AssignV6Address(iface, ipv6 string) error {
	return command.Run(
		m.logger,
		m.timeout,

		"ifconfig",
		iface,
		"inet6",
		ipv6,
		ipv6,
		"prefixlen",
		"128",
		"up",
	)
}

// AddV4Route adds a route for traffic for an IPv4 subnet to be routed to the given interface.
func (m *managerDarwin) AddV4Route(iface, cidrv4 string) error {
	return command.Run(
		m.logger,
		m.timeout,

		"route",
		"add",
		"-inet", cidrv4,
		"-interface", iface,
	)
}

// AddV6Route adds a route for traffic for an IPv6 subnet to be routed to the given interface.
func (m *managerDarwin) AddV6Route(iface, cidrv6 string) error {
	return command.Run(
		m.logger,
		m.timeout,

		"route",
		"add",
		"-inet6", cidrv6,
		"-interface", iface,
	)
}

// AddV4RouteViaGateway adds a route for traffic for an IPv4 subnet to be routed to the given gateway.
func (m *managerDarwin) AddV4RouteViaGateway(_, gwip, cidrv4 string) error {
	return command.Run(
		m.logger,
		m.timeout,

		"route",
		"add",
		"-inet", cidrv4,
		gwip,
	)
}

// AddV6RouteViaGateway adds a route for traffic for an IPv6 subnet to be routed to the given gateway.
func (m *managerDarwin) AddV6RouteViaGateway(_, gwip, cidrv6 string) error {
	return command.Run(
		m.logger,
		m.timeout,

		"route",
		"add",
		"-inet6", cidrv6,
		gwip,
	)
}

// DeleteRoute deletes a route for a given CIDR (v4 or v6) and gateway IP.
func (m *managerDarwin) DeleteRoute(cidr string, gwip string) error {
	if prefix, err := netip.ParsePrefix(cidr); err == nil {
		args := []string{"route", "delete"}

		switch {
		case prefix.Addr().Is6():
			args = append(args, "-inet6", cidr)
		case prefix.Addr().Is4():
			args = append(args, "-inet", cidr)
		default:
			return fmt.Errorf("\"%s\" is not a valid IPv4 or IPv6 cidr", cidr)
		}

		if gwip != "" {
			args = append(args, gwip)
		}

		return command.Run(
			m.logger,
			m.timeout,
			args...,
		)
	}
	return fmt.Errorf("\"%s\" is not a valid IPv4 or IPv6 cidr", cidr)
}

// RouteExists checks if a route for the given CIDR exists (optionally via the given gateway).
func (m *managerDarwin) RouteExists(cidr, gwip string) (bool, error) {
	prefix, err := netip.ParsePrefix(cidr)
	if err != nil {
		return false, fmt.Errorf("failed to parse cidr %s: %v", cidr, err)
	}

	if prefix.Addr().Is6() {
		return m.v6RouteExistsViaGateway(cidr, gwip)
	}
	return m.v4RouteExistsViaGateway(cidr, gwip)
}

// v4RouteExistsViaGateway checks if an IPv4 route for the given CIDR exists.
func (m *managerDarwin) v4RouteExistsViaGateway(cidrv4, gwip string) (bool, error) {
	var outputBuffer bytes.Buffer
	err := command.RunWithModifier(
		m.logger,
		m.timeout,
		func(c *exec.Cmd) { c.Stdout = &outputBuffer },

		"route",
		"-n", // no dns resolutions
		"get",
		"-inet",
		cidrv4,
	)
	if err != nil {
		return false, err
	}

	scanner := bufio.NewScanner(&outputBuffer)
	for scanner.Scan() {
		line := scanner.Text()

		// sample successful output (when route has a gateway IP):
		// 11:00 $ route -n get -inet 141.101.90.0/32
		//    route to: 141.101.90.0
		// destination: 141.101.90.0
		//        mask: 255.255.255.255
		//     gateway: 192.168.1.254
		//   interface: en0
		//       flags: <UP,GATEWAY,DONE,STATIC,PRCLONING>
		//  recvpipe  sendpipe  ssthresh  rtt,msec    rttvar  hopcount      mtu     expire
		//        0         0         0         0         0         0      1500         0
		if strings.Contains(line, "gateway:") {
			if strings.Contains(line, gwip) {
				return true, nil
			}
		}

		// sample successful output (when route does NOT have a gateway IP):
		// 11:00 $ route -n get -inet 100.124.0.0/16
		// 	  route to: 100.124.0.0
		// destination: 100.124.0.0
		// 		  mask: 255.255.0.0
		//   interface: utun9
		// 	     flags: <UP,DONE,STATIC,PRCLONING>
		//  recvpipe  sendpipe  ssthresh  rtt,msec    rttvar  hopcount      mtu     expire
		// 		  0         0         0         0         0         0      1420         0
		//
		// NOTE(@adrianosela): This basically just checks for the IP
		// having any route present without caring about the gateway.
		if gwip == "" && strings.Contains(line, "interface:") {
			return true, nil
		}
	}
	if err := scanner.Err(); err != nil {
		return false, fmt.Errorf("failed to scan output buffer: %v", err)
	}
	return false, nil
}

// v6RouteExistsViaGateway checks if an IPv6 route for the given CIDR exists.
func (m *managerDarwin) v6RouteExistsViaGateway(cidrv6, gwip string) (bool, error) {
	var outputBuffer bytes.Buffer
	err := command.RunWithModifier(
		m.logger,
		m.timeout,
		func(c *exec.Cmd) { c.Stdout = &outputBuffer },

		"route",
		"-n", // no dns resolutions
		"get",
		"-inet6",
		cidrv6,
	)
	if err != nil {
		return false, err
	}

	scanner := bufio.NewScanner(&outputBuffer)
	for scanner.Scan() {
		line := scanner.Text()

		// sample successful output (when route has a gateway IP):
		// 10:47 $ route -n get -inet6 2600:9000:a71e:be1b:7c70:88f:e550:9d1a/128
		//    route to: 2600:9000:a71e:be1b:7c70:88f:e550:9d1a
		// destination: 2600:9000:a71e:be1b:7c70:88f:e550:9d1a
		//     gateway: fe80::66cc:22ff:fe21:5a20%en0
		//   interface: en0
		//       flags: <UP,GATEWAY,HOST,DONE,STATIC>
		//  recvpipe  sendpipe  ssthresh  rtt,msec    rttvar  hopcount      mtu     expire
		//        0         0         0         0         0         0      1500         0
		if strings.Contains(line, "gateway:") {
			if strings.Contains(line, gwip) {
				return true, nil
			}
		}

		// sample successful output (when route does NOT have a gateway IP):
		// 11:00 $ route -n get -inet6 2600:1901:0:d110::/128
		//    route to: 2600:1901:0:d110::
		// destination: 2600:1901:0:d110::
		//   interface: utun9
		//       flags: <UP,HOST,DONE,LLINFO,STATIC>
		//  recvpipe  sendpipe  ssthresh  rtt,msec    rttvar  hopcount      mtu     expire
		//        0         0         0         0         0         0      1420         0
		//
		// NOTE(@adrianosela): This basically just checks for the IP
		// having any route present without caring about the gateway.
		if gwip == "" && strings.Contains(line, "interface:") {
			return true, nil
		}
	}
	if err := scanner.Err(); err != nil {
		return false, fmt.Errorf("failed to scan output buffer: %v", err)
	}
	return false, nil
}

// getDefaultGateway returns the name and IP address
// of the default gateway for the given IP version.
func getDefaultGateway(
	logger *zap.Logger,
	timeout time.Duration,
	ipVersion uint8,
) (string, string, bool, error) {

	var cmd []string
	switch ipVersion {
	case 4:
		cmd = []string{
			"route",
			"-n", // no dns resolutions
			"get",
			"-inet",
			"default",
		}
	case 6:
		cmd = []string{
			"route",
			"-n", // no dns resolutions
			"get",
			"-inet6",
			"default",
		}
	default:
		return "", "", false, fmt.Errorf("invalid IP version %d", ipVersion)
	}

	var outputBuffer bytes.Buffer

	err := command.RunWithModifier(
		logger,
		timeout,
		func(c *exec.Cmd) { c.Stdout = &outputBuffer },
		cmd...,
	)
	if err != nil {
		return "", "", false, err
	}

	output := outputBuffer.String()
	if strings.Contains(output, "not in table") {
		return "", "", false, nil
	}

	iface := ""
	gwip := ""

	for _, line := range strings.Split(output, "\n") {
		if strings.Contains(line, "gateway:") {
			parts := strings.Split(line, ":")
			if len(parts) < 2 {
				return "", "", false, fmt.Errorf("unexpected gateway line in command output: %s", line)
			}
			// NOTE: join parts to support IPv6 (which likely contains colons)
			gwip = strings.TrimSpace(strings.Join(parts[1:], ":"))
			continue
		}
		if strings.Contains(line, "interface:") {
			parts := strings.Split(line, ":")
			if len(parts) < 2 {
				return "", "", false, fmt.Errorf("unexpected interface line in command output: %s", line)
			}
			iface = strings.TrimSpace(parts[1])
			continue
		}
	}

	if iface == "" || gwip == "" {
		return iface, gwip, false, nil
	}
	return iface, gwip, true, nil
}

// getDnsResolversFromScutil leverages the built-in
// program "scutil" to determine the nameserver addresses.
func getDnsResolversFromScutil(
	logger *zap.Logger,
	timeout time.Duration,
) ([]netip.Addr, error) {
	var outputBuffer bytes.Buffer

	err := command.RunWithModifier(
		logger,
		timeout,
		func(c *exec.Cmd) { c.Stdout = &outputBuffer },

		"scutil", "--dns",
	)
	if err != nil {
		return nil, err
	}

	nameserverRegex := regexp.MustCompile(`nameserver\[\d+\]\s*:\s*(\S+)`)
	servers := set.New[netip.Addr]()
	scanner := bufio.NewScanner(&outputBuffer)

	for scanner.Scan() {
		line := scanner.Text()
		matches := nameserverRegex.FindStringSubmatch(line)
		if len(matches) > 0 {
			// FindStringSubmatch() always returns the full match of the
			// entire pattern against the string in index 0. In our case
			// if the regex matches for a line "  nameserver[0] : 179.51.50.203"
			// then index 0 will include "nameserver[0] : 179.51.50.203".
			// Further indices will include captured groups (the stuff in
			// the regex surrounded by parentheses). In our regex, the
			// only group is (\S+), designed to capture the IP address.
			// Index 1 will contain the captured group e.g. 179.51.50.203
			// for the input above.
			if len(matches) < 2 {
				logger.Warn(
					"got a nameserver regex match that did not have an IP address",
					zap.String("match", matches[0]),
				)
				continue
			}

			server := matches[1]
			addr, err := netip.ParseAddr(server)
			if err != nil {
				logger.Warn(
					"got a nameserver that failed to parse as an IP address",
					zap.String("server", server),
					zap.Error(err),
				)
				continue
			}
			servers.Add(addr)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("failed to scan output buffer: %v", err)
	}

	return servers.Slice(), nil
}
