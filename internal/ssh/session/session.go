package session

import (
	"net"
)

type SessionHandler interface {
	Proxy(conn net.Conn)
}
