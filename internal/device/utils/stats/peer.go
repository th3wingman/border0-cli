package stats

import "time"

// Connection represents connection statistics and status.
type Connection struct {
	Method    string    `json:"method"`
	Address   string    `json:"address"`
	RTT       string    `json:"rtt"`
	Loss      string    `json:"loss"`
	MTU       string    `json:"mtu"`
	Score     string    `json:"score"`
	Active    bool      `json:"active"`
	LastProbe time.Time `json:"last_probe"`
}

// Peer represents peer statistics and status.
type Peer struct {
	PublicKey   string       `json:"public_key"`
	Alias       string       `json:"alias"`
	PrivateIPv4 string       `json:"private_ipv4"`
	PrivateIPv6 string       `json:"private_ipv6"`
	Connections []Connection `json:"connections"`
}
