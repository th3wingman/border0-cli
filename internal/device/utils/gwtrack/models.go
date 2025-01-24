package gwtrack

// Gateway represents a network gateway.
type Gateway struct {
	Interface string
	Address   string
	OK        bool
}

type GatewayUpdate struct {
	Modified bool
	Before   *Gateway
	After    *Gateway
}

// Update represents a gateway update.
type Update struct {
	GatewayV4 *GatewayUpdate
	GatewayV6 *GatewayUpdate
}

// Equal returns true if two Gateway objects are equivalent.
func (g *Gateway) Equal(other *Gateway) bool {
	return g.Interface == other.Interface &&
		g.Address == other.Address &&
		g.OK == other.OK
}
