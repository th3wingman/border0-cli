//go:build linux

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
	dnsResolverRetrievalMethodResolvectl      = "resolvectl"
	dnsResolverRetrievalMethodSystemdResolved = "systemd-resolved"
	dnsResolverRetrievalMethodResolvDotConf   = "resolv.conf"
)

// platform-dependent implementation of RouteManager (for Linux).
type managerLinux struct {
	logger                      *zap.Logger
	timeout                     time.Duration
	dnsResolverRetrievalMethods []string
}

// newManagerForPlatform returns the default platform-dependent
// implementation of RouteManager (for Linux).
func newManagerForPlatform(logger *zap.Logger) RouteManager {
	return &managerLinux{
		logger:  logger,
		timeout: defaultRouteCommandTimeout,
		dnsResolverRetrievalMethods: []string{
			dnsResolverRetrievalMethodResolvectl,
			dnsResolverRetrievalMethodSystemdResolved,
			dnsResolverRetrievalMethodResolvDotConf,
		},
	}
}

// GetDnsResolvers returns all DNS resolver addresses.
func (m *managerLinux) GetDnsResolvers() ([]netip.Addr, error) {
	errs := []error{}
	for _, method := range m.dnsResolverRetrievalMethods {
		switch method {
		case dnsResolverRetrievalMethodResolvectl:
			addrs, err := getDnsResolversFromResolvectl(m.logger, m.timeout)
			if err != nil {
				errs = append(errs, fmt.Errorf("failed to retrieve resolver addresses via resolvectl: %v", err))
				continue
			}
			return addrs, nil
		case dnsResolverRetrievalMethodSystemdResolved:
			addrs, err := getDnsResolversFromSystemdResolved(m.logger, m.timeout)
			if err != nil {
				errs = append(errs, fmt.Errorf("failed to retrieve resolver addresses via systemd-resolved: %v", err))
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
func (m *managerLinux) GetDefaultV4Gateway() (string, string, bool, error) {
	return getDefaultGateway(m.logger, m.timeout, 4)
}

// GetDefaultV6Gateway gets the interface name and
// the IP address of the default gateway for IPv6.
func (m *managerLinux) GetDefaultV6Gateway() (string, string, bool, error) {
	return getDefaultGateway(m.logger, m.timeout, 6)
}

// AssignV4Address assigns an IPv4 address to a given interface.
func (m *managerLinux) AssignV4Address(iface, ipv4 string) error {
	err := command.Run(
		m.logger,
		m.timeout,

		"ip",
		"address",
		"add", fmt.Sprintf("%s/32", ipv4),
		"dev", iface,
	)
	if err != nil {
		return err
	}
	return ensureInterfaceIsUp(m.logger, m.timeout, iface)
}

// AssignV6Address assigns an IPv6 address to a given interface.
func (m *managerLinux) AssignV6Address(iface, ipv6 string) error {
	err := command.Run(
		m.logger,
		m.timeout,

		"ip",
		"-6",
		"address",
		"add", fmt.Sprintf("%s/128", ipv6),
		"dev", iface,
	)
	if err != nil {
		return err
	}
	return ensureInterfaceIsUp(m.logger, m.timeout, iface)
}

// AddV4Route adds a route for traffic for an IPv4 subnet to be routed to the given interface.
func (m *managerLinux) AddV4Route(iface, cidrv4 string) error {
	var stderrBuffer bytes.Buffer

	err := command.RunWithModifier(
		m.logger,
		m.timeout,
		func(c *exec.Cmd) { c.Stderr = &stderrBuffer },

		"ip",
		"route",
		"add", cidrv4,
		"dev", iface,
	)
	if err != nil {
		// not an error if the route already exists e.g. if we see stderr match:
		// - RTNETLINK answers: File exists
		if strings.Contains(strings.ToLower(stderrBuffer.String()), "file exists") {
			return nil
		}
		return err
	}

	return nil
}

// AddV6Route adds a route for traffic for an IPv6 subnet to be routed to the given interface.
func (m *managerLinux) AddV6Route(iface, cidrv6 string) error {
	var stderrBuffer bytes.Buffer

	err := command.RunWithModifier(
		m.logger,
		m.timeout,
		func(c *exec.Cmd) { c.Stderr = &stderrBuffer },

		"ip",
		"-6",
		"route",
		"add", cidrv6,
		"dev", iface,
	)
	if err != nil {
		// not an error if the route already exists e.g. if we see stderr match:
		// - RTNETLINK answers: File exists
		if strings.Contains(strings.ToLower(stderrBuffer.String()), "file exists") {
			return nil
		}
		return err
	}

	return nil
}

// AddV4RouteViaGateway adds a route for traffic for an IPv4 subnet to be routed to the given gateway.
func (m *managerLinux) AddV4RouteViaGateway(iface, gwip, cidrv4 string) error {
	return command.Run(
		m.logger,
		m.timeout,

		"ip",
		"route",
		"add", cidrv4,
		"via", gwip,
		"dev", iface,
	)
}

// AddV6RouteViaGateway adds a route for traffic for an IPv6 subnet to be routed to the given gateway.
func (m *managerLinux) AddV6RouteViaGateway(iface, gwip, cidrv6 string) error {
	return command.Run(
		m.logger,
		m.timeout,

		"ip",
		"-6",
		"route",
		"add", cidrv6,
		"via", gwip,
		"dev", iface,
	)
}

// RouteExists checks if a route for the given CIDR exists (optionally via the given gateway).
func (m *managerLinux) RouteExists(cidr, gwip string) (bool, error) {
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
func (m *managerLinux) v4RouteExistsViaGateway(cidrv4, gwip string) (bool, error) {
	var outputBuffer bytes.Buffer
	err := command.RunWithModifier(
		m.logger,
		m.timeout,
		func(c *exec.Cmd) { c.Stdout = &outputBuffer },

		"ip",
		"route",
		"show",
		cidrv4,
	)
	if err != nil {
		return false, err
	}

	// sample successful output (when route has a gateway IP):
	// 11:00 $ ip route show 3.19.84.165/32
	// 3.19.84.165 via 137.184.160.1 dev eth0
	//
	// NOTE(@adrianosela): Linux may sometimes remove the subnet mask from /32s
	// CIDRs so we check for the presense of the IP with and without the mask.
	expectedOutputs := []string{
		fmt.Sprintf("%s via %s dev", cidrv4, gwip),
		fmt.Sprintf("%s via %s dev", strings.TrimSuffix(cidrv4, "/32"), gwip),
	}

	// sample successful output (when route does NOT have a gateway IP):
	// 11:00 $ ip route show 100.124.0.0/16
	// 100.124.0.0/16 dev utun9 scope link
	if gwip == "" {
		// NOTE(@adrianosela): Linux may sometimes remove the subnet mask from /32s
		// CIDRs so we check for the presense of the IP with and without the mask.
		expectedOutputs = []string{
			fmt.Sprintf("%s dev", cidrv4),
			fmt.Sprintf("%s dev", strings.TrimSuffix(cidrv4, "/32")),
		}
	}

	output := outputBuffer.String()
	for _, line := range strings.Split(output, "\n") {
		for _, expectedOutput := range expectedOutputs {
			if strings.HasPrefix(line, expectedOutput) {
				return true, nil
			}
		}
	}
	return false, nil
}

// v6RouteExistsViaGateway checks if an IPv6 route for the given CIDR exists.
func (m *managerLinux) v6RouteExistsViaGateway(cidrv6, gwip string) (bool, error) {
	var outputBuffer bytes.Buffer
	err := command.RunWithModifier(
		m.logger,
		m.timeout,
		func(c *exec.Cmd) { c.Stdout = &outputBuffer },

		"ip",
		"-6",
		"route",
		"show",
		cidrv6,
	)
	if err != nil {
		return false, err
	}

	// sample successful output (when route has a gateway IP):
	// 11:00 $ ip -6 route show 2a06:98c1:3200::
	// 2a06:98c1:3200:: via 2604:a880:400:d0::1 dev eth0 metric 1024 pref medium
	//
	// NOTE(@adrianosela): Linux may sometimes remove the subnet mask from /128s
	// CIDRs so we check for the presense of the IP with and without the mask.
	expectedOutputs := []string{
		fmt.Sprintf("%s via %s dev", cidrv6, gwip),
		fmt.Sprintf("%s via %s dev", strings.TrimSuffix(cidrv6, "/128"), gwip),
	}

	// sample successful output (when route does NOT have a gateway IP):
	// 11:00 $ ip -6 route show fd62:6f72:6465:7230::
	// fd62:6f72:6465:7230:: dev utun metric 1024 pref medium
	if gwip == "" {
		// NOTE(@adrianosela): Linux may sometimes remove the subnet mask from /128s
		// CIDRs so we check for the presense of the IP with and without the mask.
		expectedOutputs = []string{
			fmt.Sprintf("%s dev", cidrv6),
			fmt.Sprintf("%s dev", strings.TrimSuffix(cidrv6, "/128")),
		}
	}

	output := outputBuffer.String()
	for _, line := range strings.Split(output, "\n") {
		for _, expectedOutput := range expectedOutputs {
			if strings.HasPrefix(line, expectedOutput) {
				return true, nil
			}
		}
	}
	return false, nil
}

// DeleteRoute deletes a route for a given CIDR (v4 or v6).
func (m *managerLinux) DeleteRoute(cidr string, gwip string) error {
	if prefix, err := netip.ParsePrefix(cidr); err == nil {
		args := []string{"ip"}
		switch {
		case prefix.Addr().Is6():
			args = append(args, "-6")
		case prefix.Addr().Is4():
			// (no additional args for v4)
		default:
			return fmt.Errorf("\"%s\" is not a valid IPv4 or IPv6 cidr", cidr)
		}

		args = append(args, "route", "del", cidr)
		if gwip != "" {
			args = append(args, "via", gwip)
		}

		return command.Run(
			m.logger,
			m.timeout,
			args...,
		)
	}
	return fmt.Errorf("\"%s\" is not a valid IPv4 or IPv6 cidr", cidr)
}

// ensureInterfaceIsUp ensures that the given interface is up
func ensureInterfaceIsUp(
	logger *zap.Logger,
	timeout time.Duration,
	iface string,
) error {
	return command.Run(
		logger,
		timeout,

		"ip",
		"link",
		"set",
		"dev", iface,
		"up",
	)
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
			"ip",
			"route",
			"show",
			"default",
		}
	case 6:
		cmd = []string{
			"ip",
			"-6",
			"route",
			"show",
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
	for _, line := range strings.Split(output, "\n") {
		if strings.HasPrefix(line, "default via") {
			parts := strings.Fields(line)
			if len(parts) > 5 {
				return parts[4], parts[2], true, nil
			}
		}
	}
	return "", "", false, nil
}

// getDnsResolversFromSystemdResolved leverages the built-in
// "systemd-resolve" to determine the nameserver addresses
// from systemd's resolved service.
func getDnsResolversFromSystemdResolved(
	logger *zap.Logger,
	timeout time.Duration,
) ([]netip.Addr, error) {
	var outputBuffer bytes.Buffer

	err := command.RunWithModifier(
		logger,
		timeout,
		func(c *exec.Cmd) { c.Stdout = &outputBuffer },

		"systemd-resolve",
		"--status",
	)
	if err != nil {
		return nil, err
	}

	nameserverRegex := regexp.MustCompile(`DNS Servers: (([0-9a-fA-F:.]+\s*)+)$`)
	servers := set.New[netip.Addr]()
	scanner := bufio.NewScanner(&outputBuffer)

	for scanner.Scan() {
		line := scanner.Text()
		if matches := nameserverRegex.FindStringSubmatch(line); len(matches) > 0 {
			// FindStringSubmatch() always returns the full match of the
			// entire pattern against the string in index 0. In our case
			// if the regex matches for a line "DNS Servers: 67.207.67.2"
			// then index 0 will include "DNS Servers: 67.207.67.2".
			// Further indices will include captured groups (the stuff in
			// the regex surrounded by parentheses). In our regex, the
			// only group is (([0-9a-fA-F:.]+\s*)+), designed to capture
			// the space-separated IP addresses. Index 1 will contain the
			// captured group e.g. 67.207.67.2 for the input above.
			if len(matches) < 2 {
				logger.Warn(
					"got a nameserver regex match that did not have an IP address",
					zap.String("match", matches[0]),
				)
				continue
			}
			for _, server := range strings.Fields(matches[1]) {
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
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("failed to scan output buffer: %v", err)
	}

	return servers.Slice(), nil
}

// getDnsResolversFromScutil leverages the built-in
// "resolvectl" to determine the nameserver addresses
// from systemd's resolved service.
func getDnsResolversFromResolvectl(
	logger *zap.Logger,
	timeout time.Duration,
) ([]netip.Addr, error) {
	var outputBuffer bytes.Buffer

	err := command.RunWithModifier(
		logger,
		timeout,
		func(c *exec.Cmd) { c.Stdout = &outputBuffer },

		"resolvectl",
		"--no-pager",
		"status",
	)
	if err != nil {
		return nil, err
	}

	nameserverRegex := regexp.MustCompile(`(?m)^[\s]+DNS Servers: (([0-9a-fA-F:.]+\s*)+)$`)
	servers := set.New[netip.Addr]()
	scanner := bufio.NewScanner(&outputBuffer)

	for scanner.Scan() {
		line := scanner.Text()
		if matches := nameserverRegex.FindStringSubmatch(line); len(matches) > 0 {
			// FindStringSubmatch() always returns the full match of the
			// entire pattern against the string in index 0. In our case
			// if the regex matches for a line "DNS Servers: 67.207.67.2"
			// then index 0 will include "DNS Servers: 67.207.67.2".
			// Further indices will include captured groups (the stuff in
			// the regex surrounded by parentheses). In our regex, the
			// only group is (([0-9a-fA-F:.]+\s*)+), designed to capture
			// the space-separated IP addresses. Index 1 will contain the
			// captured group e.g. 67.207.67.2 for the input above.
			if len(matches) < 2 {
				logger.Warn(
					"got a nameserver regex match that did not have an IP address",
					zap.String("match", matches[0]),
				)
				continue
			}
			for _, server := range strings.Fields(matches[1]) {
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
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("failed to scan output buffer: %v", err)
	}

	return servers.Slice(), nil
}
