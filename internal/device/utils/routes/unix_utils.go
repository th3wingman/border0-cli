package routes

import (
	"bufio"
	"net/netip"
	"os"
	"strings"

	"go.uber.org/zap"
)

func getDnsResolversFromResolvDotConf(logger *zap.Logger) ([]netip.Addr, error) {
	file, err := os.Open("/etc/resolv.conf")
	if err != nil {
		return nil, err
	}
	defer file.Close()

	servers := []netip.Addr{}
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "nameserver") {
			fields := strings.Fields(line)
			if len(fields) > 1 {
				nameserver := fields[1]
				addr, err := netip.ParseAddr(nameserver)
				if err != nil {
					logger.Error(
						"failed to parse DNS resolver address as IP address",
						zap.String("nameserver", nameserver),
						zap.Error(err),
					)
					continue
				}
				servers = append(servers, addr)
			}
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return servers, nil
}
