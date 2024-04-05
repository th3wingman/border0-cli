package sqlclientproxy

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/borderzero/border0-cli/internal/api/models"
	"github.com/borderzero/border0-cli/internal/border0"
	"github.com/borderzero/border0-cli/internal/client"
	"github.com/jackc/pgconn"
	"github.com/jackc/pgproto3/v2"
	"go.uber.org/zap"
)

type postgresClientProxy struct {
	sqlClientProxy
	upstreamConfig *pgconn.Config
}

func newPostgresClientProxy(logger *zap.Logger, port int, resource models.ClientResource, useWsProxy bool) (*postgresClientProxy, error) {
	info, err := client.GetResourceInfo(logger, resource.Hostname())
	if err != nil {
		return nil, fmt.Errorf("failed to get resource info")
	}

	systemCertPool, err := x509.SystemCertPool()
	if err != nil {
		return nil, fmt.Errorf("failed to get system cert pool: %v", err.Error())
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{info.SetupTLSCertificate()},
		RootCAs:      systemCertPool,
		ServerName:   resource.Hostname(),
	}

	var sslmode string
	if info.EndToEndEncryptionEnabled {
		sslmode = "?sslmode=disable"
	}

	upstreamConfig, err := pgconn.ParseConfig(fmt.Sprintf("postgres://%s:%d/%s", resource.Hostname(), info.Port, sslmode))
	if err != nil {
		return nil, fmt.Errorf("failed to parse upstream config: %s", err)
	}

	if !info.EndToEndEncryptionEnabled {
		upstreamConfig.TLSConfig = tlsConfig
	}

	return &postgresClientProxy{
		sqlClientProxy: sqlClientProxy{
			port:       port,
			info:       info,
			resource:   resource,
			tlsConfig:  tlsConfig,
			useWsProxy: useWsProxy,
		},
		upstreamConfig: upstreamConfig,
	}, nil
}

func (p *postgresClientProxy) Listen() error {
	l, err := net.Listen("tcp", fmt.Sprintf("localhost:%d", p.port))
	if err != nil {
		return fmt.Errorf("failed to listen on port: %s", err)
	}

	defer l.Close()

	fmt.Println("listening on", l.Addr().String())

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	connCh := make(chan net.Conn)

	go func() {
		defer close(connCh)
		for {
			conn, err := l.Accept()
			if err != nil {
				if opErr, ok := err.(*net.OpError); ok && opErr.Err.Error() == "use of closed network connection" {
					return
				}

				fmt.Printf("failed to accept connection: %s\n", err)
				return
			}

			connCh <- conn
		}
	}()

	for {
		select {
		case <-ctx.Done():
			return nil
		case conn := <-connCh:
			go p.handleConnection(ctx, conn)
		}
	}
}

func (p *postgresClientProxy) handleConnection(ctx context.Context, conn net.Conn) {
	defer conn.Close()

	clientConn := pgproto3.NewBackend(pgproto3.NewChunkReader(conn), conn)

	startupMessage, err := p.handleClientStartup(clientConn, conn)
	if err != nil {
		fmt.Println("failed to handle client startup:", err)
		return
	}

	if startupMessage == nil {
		fmt.Println("failed to handle client startup: nil startup message")
		return
	}

	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	if db, ok := startupMessage.Parameters["database"]; ok {
		p.upstreamConfig.Database = db
	}

	if user, ok := startupMessage.Parameters["user"]; ok {
		p.upstreamConfig.User = user
	}

	p.upstreamConfig.DialFunc = p.Dialer

	proxyConn, err := pgconn.ConnectConfig(ctx, p.upstreamConfig)
	if err != nil {
		fmt.Println("failed to connect to upstream:", err)
		return
	}

	pgconn, err := proxyConn.Hijack()
	if err != nil {
		fmt.Println("failed to connect to upstream:", err)
		return
	}

	if err = p.handleClientAuthRequest(clientConn, pgconn.ParameterStatuses); err != nil {
		fmt.Println("failed to handle client authentication:", err)
		return
	}

	fmt.Printf("client %s connected to server\n", conn.RemoteAddr().String())
	border0.ProxyConnection(conn, pgconn.Conn)
}

func (p *postgresClientProxy) handleClientStartup(c *pgproto3.Backend, conn net.Conn) (*pgproto3.StartupMessage, error) {
	message, err := c.ReceiveStartupMessage()
	if err != nil {
		return nil, nil
	}

	switch msg := message.(type) {
	case *pgproto3.StartupMessage:
		return msg, nil
	case *pgproto3.SSLRequest:
		_, err = conn.Write([]byte("N"))
		if err != nil {
			return nil, err
		}

		return p.handleClientStartup(c, conn)
	case *pgproto3.CancelRequest:
		conn.Close()
		return nil, nil
	default:
		return nil, fmt.Errorf("invalid startup message (%T)", msg)
	}
}

func (p *postgresClientProxy) Dialer(ctx context.Context, network, addr string) (net.Conn, error) {
	return client.Connect(addr, false, p.tlsConfig, p.tlsConfig.Certificates[0], p.info.CaCertificate, p.info.ConnectorAuthenticationEnabled, p.info.EndToEndEncryptionEnabled, p.useWsProxy)
}

func (p *postgresClientProxy) handleClientAuthRequest(serverSession *pgproto3.Backend, serverParams map[string]string) error {
	err := serverSession.Send(&pgproto3.AuthenticationOk{})
	if err != nil {
		return err
	}

	for name, value := range serverParams {
		err = serverSession.Send(&pgproto3.ParameterStatus{
			Name:  name,
			Value: value,
		})
		if err != nil {
			return err
		}
	}

	err = serverSession.Send(&pgproto3.ReadyForQuery{TxStatus: 'I'})
	if err != nil {
		return err
	}

	return nil
}
