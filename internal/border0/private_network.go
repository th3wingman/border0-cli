package border0

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/borderzero/border0-cli/internal/api/models"
	"github.com/borderzero/border0-cli/internal/device/state"
	"github.com/borderzero/border0-cli/internal/device/wgmgr"
	"github.com/borderzero/border0-go/lib/types/syncmap"
	"github.com/borderzero/border0-go/types/service"
	"go.uber.org/zap"
)

const (
	policyEvalCacheJanitorInterval = 5 * time.Minute
	policyEvalCacheTTL             = 1 * time.Minute
	sessionCacheTTL                = 8 * time.Hour
	continuousEvaluatorInterval    = 1 * time.Minute
)

type PrivateNetworkListener struct {
	logger              *zap.Logger
	ipv4Listener        net.Listener
	ipv6Listener        net.Listener
	connCh              chan net.Conn
	errCh               chan error
	border0API          Border0API
	socket              *models.Socket
	privateNetworkState state.State
	context             context.Context
	evaluator           policyEvaluator
	sessions            *syncmap.Map[string, *sessionConns]
	wgmr                wgmgr.WireGuardManager
}

type PrivateNetworkConn struct {
	net.Conn
	Metadata *ConnMetadata
	Listener *PrivateNetworkListener
}

type authorizePeerResult struct {
	email          string
	entityUUID     string
	sessionKey     string
	sshTicket      []byte
	allowedActions []any
	peerIP         string
	publicKey      string
}

type sessionConns struct {
	sync.Mutex
	peerIP      string
	userEmail   string
	publicKey   string
	activeConns map[string]*PrivateNetworkConn
}

// NewPrivateNetworkListener creates a PrivateNetworkListener with both IPv4 and IPv6 listeners
func NewPrivateNetworkListener(logger *zap.Logger, border0API Border0API, wgmr wgmgr.WireGuardManager, state state.State, socket *Socket) (*PrivateNetworkListener, error) {
	ipv4Listener, ipv6Listener, err := startPrivateNetworkListener(wgmr, socket)
	if err != nil {
		return nil, err
	}

	if ipv4Listener == nil && ipv6Listener == nil {
		return nil, fmt.Errorf("both IPv4 and IPv6 listeners are nil")
	}

	l := &PrivateNetworkListener{
		logger:              logger,
		ipv4Listener:        ipv4Listener,
		ipv6Listener:        ipv6Listener,
		connCh:              make(chan net.Conn),
		errCh:               make(chan error),
		border0API:          border0API,
		socket:              socket.Socket,
		privateNetworkState: state,
		context:             socket.GetContext(),
		evaluator:           newCachedPolicyEvaluator(border0API, policyEvalCacheJanitorInterval, policyEvalCacheTTL, sessionCacheTTL),
		sessions:            syncmap.New[string, *sessionConns](),
		wgmr:                wgmr,
	}

	socket.listener = l

	go l.continuousEvaluator()
	go l.acceptConnections()
	return l, nil
}

func startPrivateNetworkListener(wgmr wgmgr.WireGuardManager, socket *Socket) (net.Listener, net.Listener, error) {
	if socket.Socket.TargetPort == 0 {
		switch socket.SocketType {
		case service.ServiceTypeDatabase:
			switch socket.Socket.UpstreamType {
			case service.DatabaseProtocolPostgres:
				socket.Socket.TargetPort = 5432
			case service.DatabaseProtocolMySql:
				socket.Socket.TargetPort = 3306
			case service.DatabaseProtocolSqlserver:
				socket.Socket.TargetPort = 1433
			default:
				return nil, nil, fmt.Errorf("no default port for database type: %s", socket.Socket.UpstreamType)
			}
		case service.ServiceTypeSsh:
			socket.Socket.TargetPort = 22
		case service.ServiceTypeKubernetes:
			socket.Socket.TargetPort = 80
		default:
			return nil, nil, fmt.Errorf("no default port for service type: %s", socket.SocketType)
		}
	} else {
		if socket.SocketType == service.ServiceTypeHttp {
			socket.Socket.TargetPort = 80
		}
	}

	// create a listener for the private network
	var privateNetworkListenerIPv4 net.Listener
	var privateNetworkListenerIPv6 net.Listener
	var err error

	if socket.PrivateNetworkIPv4 != nil {
		privateNetworkListenerIPv4, err = wgmr.SocketListener(fmt.Sprintf("%s:%d", socket.PrivateNetworkIPv4.String(), socket.Socket.TargetPort))
		if err != nil {
			return nil, nil, fmt.Errorf("failed to create private network listener: %v", err)
		}
	}

	if socket.PrivateNetworkIPv6 != nil {
		privateNetworkListenerIPv6, err = wgmr.SocketListener(fmt.Sprintf("[%s]:%d", socket.PrivateNetworkIPv6.String(), socket.Socket.TargetPort))
		if err != nil {
			return nil, nil, fmt.Errorf("failed to create private network listener: %v", err)
		}
	}

	return privateNetworkListenerIPv4, privateNetworkListenerIPv6, nil
}

func (l *PrivateNetworkListener) acceptConnections() {
	ctx, cancel := context.WithCancel(l.context)
	defer cancel()
	l.context = ctx

	var wg sync.WaitGroup

	acceptFunc := func(listener net.Listener) {
		defer wg.Done()

		for {
			select {
			case <-l.context.Done():
				return
			default:
			}

			conn, err := listener.Accept()
			select {
			case <-l.context.Done():
				return
			default:
			}

			if err != nil {
				l.errCh <- err
			}
			l.connCh <- conn

		}
	}

	if l.ipv4Listener != nil {
		wg.Add(1)
		go acceptFunc(l.ipv4Listener)
	}

	if l.ipv6Listener != nil {
		wg.Add(1)
		go acceptFunc(l.ipv6Listener)
	}

	wg.Wait()
	close(l.connCh)
	close(l.errCh)
}

func (l *PrivateNetworkListener) Accept() (net.Conn, error) {
	for {
		select {
		case conn := <-l.connCh:
			if conn == nil {
				return nil, fmt.Errorf("connection is nil")
			}

			result, err := l.authorizePeer(conn)
			if err != nil {
				conn.Close()
				l.logger.Warn("failed to authorize peer", zap.Error(err))
				continue
			}

			pnConn := PrivateNetworkConn{
				Conn:     conn,
				Listener: l,
				Metadata: &ConnMetadata{
					ClientIP:       result.peerIP,
					UserEmail:      result.email,
					SessionKey:     result.sessionKey,
					AllowedActions: result.allowedActions,
					SshTicket:      result.sshTicket,
				},
			}

			if conns, ok := l.sessions.LoadOrStore(result.sessionKey, &sessionConns{
				peerIP:      result.peerIP,
				userEmail:   result.email,
				publicKey:   result.publicKey,
				activeConns: map[string]*PrivateNetworkConn{conn.RemoteAddr().String(): &pnConn},
			}); ok {
				conns.Lock()
				conns.activeConns[conn.RemoteAddr().String()] = &pnConn
				conns.Unlock()
			}

			return &pnConn, nil
		case err := <-l.errCh:
			return nil, err
		case <-l.context.Done():
			return nil, l.context.Err()
		}
	}
}

// Close closes both the IPv4 and IPv6 listeners
func (l *PrivateNetworkListener) Close() error {
	// close all active connections otherwise netstack won't release the port
	l.sessions.Range(func(key string, conns *sessionConns) bool {
		conns.Lock()
		defer conns.Unlock()
		for _, conn := range conns.activeConns {
			conn.Conn.Close()
		}
		l.sessions.Delete(key)
		return true
	})

	var ipv4CloseErr, ipv6CloseErr, err error

	if l.ipv4Listener != nil {
		ipv4CloseErr = l.ipv4Listener.Close()
		l.ipv4Listener = nil
	}

	if l.ipv6Listener != nil {
		ipv6CloseErr = l.ipv6Listener.Close()
		l.ipv6Listener = nil
	}

	if ipv4CloseErr != nil || ipv6CloseErr != nil {
		err = fmt.Errorf("ipv4: %w, ipv6: %v", ipv4CloseErr, ipv6CloseErr)
	}

	return err
}

// Addr returns the address of the IPv4 listener (or IPv6 if you prefer)
func (l *PrivateNetworkListener) Addr() net.Addr {
	return l.ipv4Listener.Addr()
}

func (l *PrivateNetworkListener) authorizePeer(conn net.Conn) (*authorizePeerResult, error) {
	tcpAddr, ok := conn.RemoteAddr().(*net.TCPAddr)
	if !ok {
		return nil, fmt.Errorf("remote address is not a TCP address")
	}

	peer := l.privateNetworkState.GetPeerByIP(tcpAddr.IP)
	if peer == nil {
		return nil, fmt.Errorf("peer not found for IP %s", tcpAddr.IP.String())
	}

	endpoint, err := l.wgmr.GetPeerIP(peer.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to get peer IP: %w", err)
	}

	var sessionKey string
	switch l.socket.SocketType {
	case service.ServiceTypeKubernetes, service.ServiceTypeHttp:
		sessionKey = deterministicUUIDv4(l.socket.SocketID, tcpAddr.IP.String(), time.Now().Format("20060102")).String()
	}

	email, entityUUID, sessionID, sshTicket, action, err := l.evaluator.EvaluatePeer(l.context, l.socket, tcpAddr, endpoint.String(), peer.PublicKey, sessionKey)
	if err != nil {
		return nil, fmt.Errorf("failed to evaluate peer: %w", err)
	}

	if len(action) == 0 {
		return nil, fmt.Errorf("authorization denied")
	}

	return &authorizePeerResult{
		peerIP:         endpoint.String(),
		email:          email,
		entityUUID:     entityUUID,
		sessionKey:     sessionID,
		sshTicket:      sshTicket,
		allowedActions: action,
		publicKey:      peer.PublicKey,
	}, nil
}

func (l *PrivateNetworkListener) continuousEvaluator() {
	for {
		select {
		case <-l.context.Done():
			return
		case <-time.After(continuousEvaluatorInterval):

			toDelete := []string{}
			l.sessions.Range(func(sessionKey string, conns *sessionConns) bool {
				conns.Lock()
				defer conns.Unlock()

				endpoint, err := l.wgmr.GetPeerIP(conns.publicKey)
				if err != nil {
					l.logger.Warn(
						"failed to get peer IP by public key",
						zap.Error(err),
						zap.String("session_id", sessionKey),
						zap.String("socket_id", l.socket.SocketID),
					)
					l.sessions.Delete(sessionKey)
					return true
				}

				actions, auditInfo, err := l.evaluator.Evaluate(l.context, l.socket, endpoint.String(), conns.userEmail, sessionKey)
				if err != nil {
					l.logger.Error("failed to evaluate", zap.Error(err), zap.String("session_id", sessionKey), zap.String("socket_id", l.socket.SocketID))
					return true
				}

				if len(actions) == 0 {
					toDelete = append(toDelete, sessionKey)
					eventSend := false
					for _, conn := range conns.activeConns {
						if !eventSend {
							metadata, err := json.Marshal(struct {
								AuditInfo map[string][]string `json:"audit_info"`
								ClientIP  string              `json:"client_ip"`
							}{auditInfo, endpoint.String()})
							if err != nil {
								l.logger.Error("failed to marshal metadata", zap.Error(err), zap.String("session_id", sessionKey), zap.String("socket_id", l.socket.SocketID))
							} else {
								if err := l.border0API.CreateSessionEvent(models.SessionEvent{
									SessionKey: sessionKey,
									Socket:     l.socket,
									Type:       "session_no_longer_allowed",
									Status:     "denied",
									Metadata:   string(metadata),
								}); err != nil {
									l.logger.Error("failed to send session event", zap.Error(err), zap.String("session_id", sessionKey), zap.String("socket_id", l.socket.SocketID))
								}
							}

							eventSend = true
						}

						delete(conns.activeConns, conn.RemoteAddr().String())
						if err := conn.Conn.Close(); err != nil {
							l.logger.Error("failed to close connection", zap.Error(err), zap.String("session_id", sessionKey), zap.String("socket_id", l.socket.SocketID))
						}
					}
				}

				return true
			})

			for _, key := range toDelete {
				l.sessions.Delete(key)
			}
		}
	}
}

func (c *PrivateNetworkConn) Close() error {
	ra := c.RemoteAddr()

	if conns, ok := c.Listener.sessions.Load(c.Metadata.SessionKey); ok {
		conns.Lock()
		defer conns.Unlock()

		if ra != nil {
			delete(conns.activeConns, ra.String())
		}
		if len(conns.activeConns) == 0 {
			c.Listener.sessions.Delete(c.Metadata.SessionKey)
		}
	}

	return c.Conn.Close()
}

func (c *PrivateNetworkConn) GetPeerIP() (string, error) {
	remoteAddr := c.RemoteAddr()
	if remoteAddr == nil {
		return "", fmt.Errorf("remote address is nil")
	}

	tcpAddr, ok := remoteAddr.(*net.TCPAddr)
	if !ok {
		return "", fmt.Errorf("remote address is not a TCP address")
	}

	peer := c.Listener.privateNetworkState.GetPeerByIP(tcpAddr.IP)
	if peer == nil {
		return "", fmt.Errorf("peer not found for IP %s", tcpAddr.IP.String())
	}

	endpoint, err := c.Listener.wgmr.GetPeerIP(peer.PublicKey)
	if err != nil {
		return "", fmt.Errorf("failed to get peer IP: %w", err)
	}

	return endpoint.String(), nil

}
