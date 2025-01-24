//go:build linux

package nat

import (
	"fmt"
	"strconv"
	"time"

	"github.com/coreos/go-iptables/iptables"
	"go.uber.org/zap"
)

const (
	border0NATComment = "added by Border0"

	tableFilter = "filter"
	tableNAT    = "nat"

	chainInput       = "INPUT"
	chainPostRouting = "POSTROUTING"
	chainForward     = "FORWARD"
)

// ruleOperation represents the type of NAT rule operation
type ruleOperation string

const (
	operationAdd    ruleOperation = "add"
	operationDelete ruleOperation = "delete"
)

// platform-dependent implementation of NATManager (for Linux).
type managerLinux struct {
	logger  *zap.Logger
	timeout time.Duration
	ipt     *iptables.IPTables
	ip6t    *iptables.IPTables
}

// newManagerForPlatform returns the default platform-dependent
// implementation of NATManager (for Linux).
//
// Parameters:
// - logger: A zap logger instance for logging operations.
//
// Returns a new NATManager instance and any error encountered during initialization.
func newManagerForPlatform(logger *zap.Logger) (NATManager, error) {
	ipt, err := iptables.NewWithProtocol(iptables.ProtocolIPv4)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize iptables client: %v", err)
	}
	ip6t, err := iptables.NewWithProtocol(iptables.ProtocolIPv6)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize ip6tables client: %v", err)
	}
	return &managerLinux{
		logger:  logger,
		timeout: defaultNATCommandTimeout,
		ipt:     ipt,
		ip6t:    ip6t,
	}, nil
}

// ruleExists checks if a NAT rule exists in the POSTROUTING chain.
//
// Parameters:
// - isIPv6: Use IPv6 rules if true, otherwise IPv4.
// - devicesRange: CIDR range of devices (e.g., 10.0.0.0/24).
// - iface: Network interface name.
//
// Returns true if the rule exists, false otherwise, and any error encountered.
func (m *managerLinux) ruleExists(isIPv6 bool, devicesRange, iface string) (bool, error) {
	ruleSpec := []string{
		"-s", devicesRange,
		"!", "-o", iface,
		"-j", "MASQUERADE",
		"-m", "comment",
		"--comment", border0NATComment,
	}

	if isIPv6 {
		return m.ip6t.Exists(tableNAT, chainPostRouting, ruleSpec...)
	}
	return m.ipt.Exists(tableNAT, chainPostRouting, ruleSpec...)
}

// getRuleSpec returns the rule specification for the NAT POSTROUTING chain.
//
// Parameters:
// - devicesRange: CIDR range of devices (e.g., 10.0.0.0/24).
// - iface: Network interface name.
//
// Returns a slice of strings representing the iptables rule specification.
func (m *managerLinux) getRuleSpec(devicesRange, iface string) []string {
	return []string{
		"-s", devicesRange,
		"!", "-o", iface,
		"-j", "MASQUERADE",
		"-m", "comment",
		"--comment", border0NATComment,
	}
}

// manageForwardRules manages the FORWARD chain rules in the `filter` table.
// Ensures traffic can be forwarded between the VPN interface and other interfaces.
//
// Parameters:
// - isIPv6: Use IPv6 rules if true, otherwise IPv4.
// - devicesRange: CIDR range of devices (e.g., 10.0.0.0/24).
// - iface: Network interface name.
// - op: Operation to perform (add or delete).
//
// Returns an error if the operation fails.
func (m *managerLinux) manageForwardRules(isIPv6 bool, devicesRange, iface string, op ruleOperation) error {
	ipt := m.ipt
	if isIPv6 {
		ipt = m.ip6t
	}

	ruleSpecs := m.getForwardRuleSpecs(devicesRange, iface)

	for _, ruleSpec := range ruleSpecs {
		exists, err := ipt.Exists(tableFilter, chainForward, ruleSpec...)
		if err != nil {
			return err
		}

		switch op {
		case operationAdd:
			if exists {
				continue
			}
			if err := ipt.InsertUnique(tableFilter, chainForward, 1, ruleSpec...); err != nil {
				return err
			}
		case operationDelete:
			if !exists {
				continue
			}
			if err := ipt.Delete(tableFilter, chainForward, ruleSpec...); err != nil {
				return err
			}
		default:
			return fmt.Errorf("unknown operation: %s", op)
		}
	}
	return nil
}

// getForwardRuleSpecs returns the rule specifications for the FORWARD chain.
// Creates both inbound and outbound rules for the specified interface and CIDR range.
//
// Parameters:
// - devicesRange: CIDR range of devices (e.g., 10.0.0.0/24).
// - iface: Network interface name.
//
// Returns a slice of rule specifications, one for inbound and one for outbound traffic.
func (m *managerLinux) getForwardRuleSpecs(devicesRange, iface string) [][]string {
	return [][]string{
		// inbound rule
		{
			"-i", iface,
			"-s", devicesRange,
			"-m", "comment",
			"--comment", border0NATComment,
			"-j", "ACCEPT",
		},
		// outbound rule
		{
			"-o", iface,
			"-d", devicesRange,
			"-m", "comment",
			"--comment", border0NATComment,
			"-j", "ACCEPT",
		},
	}
}

// getInputRuleSpec returns the rule specification for the INPUT chain.
//
// Parameters:
// - port: udp port for WireGuard traffic
//
// Returns the INPUT rule specification.
func getInputRuleSpec(port int) []string {
	return []string{
		"-p", "udp",
		"-m", "udp",
		"--dport", strconv.Itoa(port),
		"-m", "comment",
		"--comment", border0NATComment,
		"-j", "ACCEPT",
	}
}

// manageRule manages both NAT and FORWARD rules for the specified interface and CIDR range.
// This is a high-level function that coordinates the management of all required firewall rules.
//
// Parameters:
// - isIPv6: Use IPv6 rules if true, otherwise IPv4.
// - devicesRange: CIDR range of devices (e.g., 10.0.0.0/24).
// - iface: Network interface name.
// - op: Operation to perform (add or delete).
//
// Returns an error if either NAT or FORWARD rule management fails.
func (m *managerLinux) manageRule(isIPv6 bool, devicesRange, iface string, op ruleOperation) error {
	if err := m.manageNATRule(isIPv6, devicesRange, iface, op); err != nil {
		return err
	}
	return m.manageForwardRules(isIPv6, devicesRange, iface, op)
}

// manageNATRule manages NAT rules in the POSTROUTING chain of the `nat` table.
// Ensures traffic from clients is NATed.
//
// Parameters:
// - isIPv6: Use IPv6 rules if true, otherwise IPv4.
// - devicesRange: CIDR range of devices (e.g., 10.0.0.0/24).
// - iface: Network interface name.
// - op: Operation to perform (add or delete).
//
// Returns an error if the operation fails.
func (m *managerLinux) manageNATRule(isIPv6 bool, devicesRange, iface string, op ruleOperation) error {
	exists, err := m.ruleExists(isIPv6, devicesRange, iface)
	if err != nil {
		return err
	}

	ruleSpec := m.getRuleSpec(devicesRange, iface)

	ipVersion := 4
	ipt := m.ipt
	if isIPv6 {
		ipt = m.ip6t
		ipVersion = 6
	}

	switch op {
	case operationAdd:
		if exists {
			m.logger.Debug(fmt.Sprintf("IPv%d NAT rule already exists, skipping", ipVersion))
			return nil
		}
		return ipt.Append(tableNAT, chainPostRouting, ruleSpec...)
	case operationDelete:
		if !exists {
			m.logger.Debug(fmt.Sprintf("IPv%d NAT rule doesn't exist, skipping cleanup", ipVersion))
			return nil
		}
		return ipt.Delete(tableNAT, chainPostRouting, ruleSpec...)
	default:
		return fmt.Errorf("unknown operation: %s", op)
	}
}

// SetupIPv4NAT configures IPv4 NAT rules for the specified interface and CIDR range.
// This includes both NAT and FORWARD chain rules.
//
// Parameters:
// - devicesRange: CIDR range of devices (e.g., 10.0.0.0/24).
// - iface: Network interface name.
//
// Returns an error if the setup fails.
func (m *managerLinux) SetupIPv4NAT(devicesRange, iface string) error {
	return m.manageRule(false, devicesRange, iface, operationAdd)
}

// SetupIPv6NAT configures IPv6 NAT rules for the specified interface and CIDR range.
// This includes both NAT and FORWARD chain rules.
//
// Parameters:
// - devicesRange: CIDR range of devices (e.g., fd00::/64).
// - iface: Network interface name.
//
// Returns an error if the setup fails.
func (m *managerLinux) SetupIPv6NAT(devicesRange, iface string) error {
	return m.manageRule(true, devicesRange, iface, operationAdd)
}

// CleanupIPv4NAT removes IPv4 NAT rules for the specified interface and CIDR range.
// This includes both NAT and FORWARD chain rules.
//
// Parameters:
// - devicesRange: CIDR range of devices (e.g., 10.0.0.0/24).
// - iface: Network interface name.
//
// Returns an error if the cleanup fails.
func (m *managerLinux) CleanupIPv4NAT(devicesRange, iface string) error {
	return m.manageRule(false, devicesRange, iface, operationDelete)
}

// CleanupIPv6NAT removes IPv6 NAT rules for the specified interface and CIDR range.
// This includes both NAT and FORWARD chain rules.
//
// Parameters:
// - devicesRange: CIDR range of devices (e.g., fd00::/64).
// - iface: Network interface name.
//
// Returns an error if the cleanup fails.
func (m *managerLinux) CleanupIPv6NAT(devicesRange, iface string) error {
	return m.manageRule(true, devicesRange, iface, operationDelete)
}

// SetupIPv4WireGuardIngress sets up ingress for udp-over-ipv4 traffic to the WireGuard bind port.
//
// Parameters:
// - port: udp port for WireGuard traffic
//
// Returns an error if the operation fails.
func (n *managerLinux) SetupIPv4WireGuardIngress(port int) error {
	return n.ipt.InsertUnique(
		tableFilter,
		chainInput,
		1,
		getInputRuleSpec(port)...,
	)
}

// SetupIPv4WireGuardIngress sets up ingress for udp-over-ipv6 traffic to the WireGuard bind port.
//
// Parameters:
// - port: udp port for WireGuard traffic
//
// Returns an error if the operation fails.
func (n *managerLinux) SetupIPv6WireGuardIngress(port int) error {
	return n.ip6t.InsertUnique(
		tableFilter,
		chainInput,
		1,
		getInputRuleSpec(port)...,
	)
}

// CleanupIPv4WireGuardIngress removes ingress for udp-over-ipv4 traffic to the WireGuard bind port.
//
// Parameters:
// - port: udp port for WireGuard traffic
//
// Returns an error if the operation fails.
func (n *managerLinux) CleanupIPv4WireGuardIngress(port int) error {
	// NOTE(@adrianosela): not using DeleteIfExists because the iptables library we use has some issues
	// where Exists() returns false for existing rules in certain iptables/OS combinations.
	return n.ipt.Delete(
		tableFilter,
		chainInput,
		getInputRuleSpec(port)...,
	)
}

// CleanupIPv6WireGuardIngress removes ingress for udp-over-ipv6 traffic to the WireGuard bind port.
//
// Parameters:
// - port: udp port for WireGuard traffic
//
// Returns an error if the operation fails.
func (n *managerLinux) CleanupIPv6WireGuardIngress(port int) error {
	// NOTE(@adrianosela): not using DeleteIfExists because the iptables library we use has some issues
	// where Exists() returns false for existing rules in certain iptables/OS combinations.
	return n.ip6t.Delete(
		tableFilter,
		chainInput,
		getInputRuleSpec(port)...,
	)
}
