//go:build windows

package routes

import (
	"bufio"
	"bytes"
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

// platform-dependent implementation of RouteManager (for Windows).
type managerWindows struct {
	logger  *zap.Logger
	timeout time.Duration
}

// newManagerForPlatform returns the default platform-dependent
// implementation of RouteManager (for Windows).
func newManagerForPlatform(logger *zap.Logger) RouteManager {
	return &managerWindows{
		logger:  logger,
		timeout: defaultRouteCommandTimeout,
	}
}

// GetDnsResolvers returns all DNS resolver addresses.
func (m *managerWindows) GetDnsResolvers() ([]netip.Addr, error) {
	servers := set.New[netip.Addr]()

	// Get IPv4 DNS servers
	var outputBuffer bytes.Buffer
	err := command.RunWithModifier(
		m.logger,
		m.timeout,
		func(c *exec.Cmd) { c.Stdout = &outputBuffer },
		"netsh", "interface", "ipv4", "show", "dns",
	)
	if err != nil {
		return nil, err
	}

	scanner := bufio.NewScanner(&outputBuffer)
	dnsRegex := regexp.MustCompile(`^\s*DNS servers configured through DHCP:\s*([0-9.]+)`)
	staticDNSRegex := regexp.MustCompile(`^\s*Statically Configured DNS Servers:\s*([0-9.]+)`)

	for scanner.Scan() {
		line := scanner.Text()
		for _, re := range []*regexp.Regexp{dnsRegex, staticDNSRegex} {
			if matches := re.FindStringSubmatch(line); len(matches) > 1 {
				addr, err := netip.ParseAddr(matches[1])
				if err != nil {
					m.logger.Warn("failed to parse IPv4 DNS server address", zap.Error(err))
					continue
				}
				servers.Add(addr)
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("IPv4 scanner error: %w", err)
	}

	// Get IPv6 DNS servers
	outputBuffer.Reset()
	err = command.RunWithModifier(
		m.logger,
		m.timeout,
		func(c *exec.Cmd) { c.Stdout = &outputBuffer },
		"netsh", "interface", "ipv6", "show", "dns",
	)
	if err != nil {
		return nil, err
	}

	scanner = bufio.NewScanner(&outputBuffer)
	dnsRegexV6 := regexp.MustCompile(`^\s*DNS servers configured through DHCP:\s*([0-9a-fA-F:]+)`)
	staticDNSRegexV6 := regexp.MustCompile(`^\s*Statically Configured DNS Servers:\s*([0-9a-fA-F:]+)`)

	for scanner.Scan() {
		line := scanner.Text()
		for _, re := range []*regexp.Regexp{dnsRegexV6, staticDNSRegexV6} {
			if matches := re.FindStringSubmatch(line); len(matches) > 1 {
				addr, err := netip.ParseAddr(matches[1])
				if err != nil {
					m.logger.Warn("failed to parse IPv6 DNS server address", zap.Error(err))
					continue
				}
				servers.Add(addr)
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("IPv6 scanner error: %w", err)
	}

	return servers.Slice(), nil
}

// GetDefaultV4Gateway gets the interface name and
// the IP address of the default gateway for IPv4.
func (m *managerWindows) GetDefaultV4Gateway() (string, string, bool, error) {
	var outputBuffer bytes.Buffer

	err := command.RunWithModifier(
		m.logger,
		m.timeout,
		func(c *exec.Cmd) { c.Stdout = &outputBuffer },
		"route", "print", "0.0.0.0",
	)
	if err != nil {
		return "", "", false, err
	}

	scanner := bufio.NewScanner(&outputBuffer)
	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Fields(line)
		if len(fields) >= 5 && fields[0] == "0.0.0.0" && fields[1] == "0.0.0.0" {
			return fields[4], fields[2], true, nil
		}
	}

	if err := scanner.Err(); err != nil {
		return "", "", false, fmt.Errorf("scanner error: %w", err)
	}
	return "", "", false, nil
}

// GetDefaultV6Gateway gets the interface name and
// the IP address of the default gateway for IPv6.
func (m *managerWindows) GetDefaultV6Gateway() (string, string, bool, error) {
	var outputBuffer bytes.Buffer

	err := command.RunWithModifier(
		m.logger,
		m.timeout,
		func(c *exec.Cmd) { c.Stdout = &outputBuffer },
		"netsh", "interface", "ipv6", "show", "route",
	)
	if err != nil {
		return "", "", false, err
	}

	scanner := bufio.NewScanner(&outputBuffer)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.Contains(line, "::/0") {
			fields := strings.Fields(line)
			if len(fields) >= 4 {
				return fields[3], fields[2], true, nil
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return "", "", false, fmt.Errorf("scanner error: %w", err)
	}
	return "", "", false, nil
}

// AssignV4Address assigns an IPv4 address to a given interface.
func (m *managerWindows) AssignV4Address(iface, ipv4 string) error {
	return command.Run(
		m.logger,
		m.timeout,
		"netsh", "interface", "ipv4", "add", "address",
		fmt.Sprintf("name=%s", iface),
		fmt.Sprintf("address=%s", ipv4),
		"mask=255.255.255.255",
	)
}

// AssignV6Address assigns an IPv6 address to a given interface.
func (m *managerWindows) AssignV6Address(iface, ipv6 string) error {
	return command.Run(
		m.logger,
		m.timeout,
		"netsh", "interface", "ipv6", "add", "address",
		fmt.Sprintf("interface=%s", iface),
		fmt.Sprintf("address=%s", ipv6),
	)
}

// helper function to find interface index
func (m *managerWindows) getInterfaceIndex(iface string, isIPv6 bool) (string, error) {
	var outputBuffer bytes.Buffer
	ipVersion := "ipv4"
	if isIPv6 {
		ipVersion = "ipv6"
	}

	err := command.RunWithModifier(
		m.logger,
		m.timeout,
		func(c *exec.Cmd) { c.Stdout = &outputBuffer },
		"netsh", "interface", ipVersion, "show", "interface",
	)
	if err != nil {
		return "", fmt.Errorf("failed to get interface information: %w", err)
	}

	scanner := bufio.NewScanner(&outputBuffer)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) >= 5 && fields[4] == iface {
			return fields[0], nil
		}
	}

	if err := scanner.Err(); err != nil {
		return "", fmt.Errorf("scanner error: %w", err)
	}
	return "", fmt.Errorf("interface %s not found", iface)
}

// helper function to run a command
func (m *managerWindows) runCommand(args []string) error {
	var cmdOutput, cmdError bytes.Buffer
	err := command.RunWithModifier(
		m.logger,
		m.timeout,
		func(c *exec.Cmd) {
			c.Stdout = &cmdOutput
			c.Stderr = &cmdError
		},
		args...,
	)

	if err != nil {
		output := fmt.Sprintf("%s%s", cmdOutput.String(), cmdError.String())
		if strings.Contains(output, "already exists") {
			return nil
		}
	}
	return err
}

// AddV4Route adds a route for traffic for an IPv4 subnet to be routed to the given interface.
func (m *managerWindows) AddV4Route(iface, cidrv4 string) error {
	ifIndex, err := m.getInterfaceIndex(iface, false)
	if err != nil {
		return err
	}

	prefix, err := netip.ParsePrefix(cidrv4)
	if err != nil {
		return fmt.Errorf("invalid CIDR format: %w", err)
	}

	bits := prefix.Bits()
	var mask uint32 = 0xffffffff << (32 - bits)
	maskStr := fmt.Sprintf("%d.%d.%d.%d",
		byte(mask>>24), byte(mask>>16), byte(mask>>8), byte(mask))

	if err := m.runCommand([]string{
		"route", "-p", "add",
		prefix.Addr().String(),
		"mask", maskStr,
		"0.0.0.0",
		"metric", "1",
		"if", ifIndex,
	}); err != nil {
		m.logger.Info("non-fatal error adding v4 route",
			zap.String("cidr", cidrv4),
			zap.String("interface", iface),
			zap.Error(err))
	}
	return nil
}

// AddV6Route adds a route for traffic for an IPv6 subnet to be routed to the given interface.
func (m *managerWindows) AddV6Route(iface, cidrv6 string) error {
	ifIndex, err := m.getInterfaceIndex(iface, true)
	if err != nil {
		return err
	}

	if err := m.runCommand([]string{
		"netsh", "interface", "ipv6", "add", "route",
		cidrv6,
		fmt.Sprintf("interface=%s", ifIndex),
		"store=active",
		"publish=yes",
	}); err != nil {
		m.logger.Info("non-fatal error adding v6 route",
			zap.String("cidr", cidrv6),
			zap.String("interface", iface),
			zap.Error(err))
	}
	return nil
}

// AddV4RouteViaGateway adds a route for traffic for an IPv4 subnet to be routed to the given gateway.
func (m *managerWindows) AddV4RouteViaGateway(_, gwip, cidrv4 string) error {
	return command.Run(
		m.logger,
		m.timeout,
		"route", "add", cidrv4, "mask", "255.255.255.255", gwip,
	)
}

// AddV6RouteViaGateway adds a route for traffic for an IPv6 subnet to be routed to the given gateway.
func (m *managerWindows) AddV6RouteViaGateway(_, gwip, cidrv6 string) error {
	return command.Run(
		m.logger,
		m.timeout,
		"netsh", "interface", "ipv6", "add", "route",
		cidrv6, fmt.Sprintf("nexthop=%s", gwip),
	)
}

// DeleteRoute deletes a route for a given CIDR (v4 or v6).
func (m *managerWindows) DeleteRoute(cidr string, gwip string) error {
	prefix, err := netip.ParsePrefix(cidr)
	if err != nil {
		return fmt.Errorf("invalid CIDR format: %w", err)
	}

	// For IPv4 routes
	if prefix.Addr().Is4() {
		bits := prefix.Bits()
		var mask uint32 = 0xffffffff << (32 - bits)
		maskStr := fmt.Sprintf("%d.%d.%d.%d",
			byte(mask>>24), byte(mask>>16), byte(mask>>8), byte(mask))

		args := []string{"route", "delete", prefix.Addr().String(), "mask", maskStr}
		if gwip != "" {
			args = append(args, gwip)
		}

		return m.runCommand(args)
	}

	// For IPv6 routes
	// First get the interface index from the route table
	var routeOutput bytes.Buffer
	err = command.RunWithModifier(
		m.logger,
		m.timeout,
		func(c *exec.Cmd) { c.Stdout = &routeOutput },
		"netsh", "interface", "ipv6", "show", "route",
	)
	if err != nil {
		return fmt.Errorf("failed to get route information: %w", err)
	}

	// Find the interface index for this route
	scanner := bufio.NewScanner(&routeOutput)
	var ifIndex string
	for scanner.Scan() {
		line := scanner.Text()
		if strings.Contains(line, cidr) {
			fields := strings.Fields(line)
			if len(fields) >= 4 {
				ifIndex = fields[3]
				break
			}
		}
	}

	if ifIndex == "" {
		m.logger.Info("route not found, considering it deleted",
			zap.String("cidr", cidr))
		return nil
	}

	// Try both stores
	stores := []string{"active", "persistent"}
	for _, store := range stores {
		err := m.runCommand([]string{
			"netsh", "interface", "ipv6", "delete", "route",
			fmt.Sprintf("prefix=%s", cidr),
			fmt.Sprintf("interface=%s", ifIndex),
			fmt.Sprintf("store=%s", store),
		})
		if err != nil {
			m.logger.Warn("failed to delete route from store",
				zap.String("store", store),
				zap.Error(err))
		}
	}

	return nil
}

// RouteExists checks if a route for the given CIDR exists (optionally via the given gateway).
func (m *managerWindows) RouteExists(cidr, gwip string) (bool, error) {
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
func (m *managerWindows) v4RouteExistsViaGateway(cidrv4, gwip string) (bool, error) {
	var outputBuffer bytes.Buffer
	err := command.RunWithModifier(
		m.logger,
		m.timeout,
		func(c *exec.Cmd) { c.Stdout = &outputBuffer },
		"netsh", "interface", "ipv4", "show", "route",
	)
	if err != nil {
		return false, nil
	}

	scanner := bufio.NewScanner(&outputBuffer)
	// Skip the header lines (including empty line and header)
	scanner.Scan()
	scanner.Scan()

	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Fields(line)
		if len(fields) >= 6 {
			prefix := fields[3]
			gateway := fields[5]

			if prefix == cidrv4 {
				// If gwip is empty, we only care that the route exists
				if gwip == "" {
					return true, nil
				}

				return gateway == gwip, nil
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return false, fmt.Errorf("failed to scan output buffer: %v", err)
	}
	return false, nil
}

// v6RouteExistsViaGateway checks if an IPv6 route for the given CIDR exists.
func (m *managerWindows) v6RouteExistsViaGateway(cidrv6, gwip string) (bool, error) {
	var outputBuffer bytes.Buffer
	err := command.RunWithModifier(
		m.logger,
		m.timeout,
		func(c *exec.Cmd) { c.Stdout = &outputBuffer },
		"netsh", "interface", "ipv6", "show", "route",
	)
	if err != nil {
		return false, nil
	}

	scanner := bufio.NewScanner(&outputBuffer)
	// Skip header lines (empty line and header)
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) >= 4 && fields[3] == cidrv6 {
			// If gwip is empty, we only care that the route exists
			if gwip == "" {
				return true, nil
			}
			// Otherwise check if the gateway matches
			// Gateway could be in field 5 or later due to interface names with spaces
			for i := 5; i < len(fields); i++ {
				if fields[i] == gwip {
					return true, nil
				}
			}
			// Found the CIDR but gateway doesn't match
			return false, nil
		}
	}

	if err := scanner.Err(); err != nil {
		return false, fmt.Errorf("failed to scan output buffer: %v", err)
	}
	return false, nil
}
