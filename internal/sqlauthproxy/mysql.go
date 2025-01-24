package sqlauthproxy

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/feature/rds/auth"
	"github.com/borderzero/border0-cli/internal/api/models"
	"github.com/borderzero/border0-cli/internal/border0"
	"github.com/borderzero/border0-cli/internal/util"
	"github.com/borderzero/border0-go/lib/types/pointer"
	"github.com/go-mysql-org/go-mysql/client"
	"github.com/go-mysql-org/go-mysql/mysql"
	"github.com/go-mysql-org/go-mysql/server"
	"go.uber.org/zap"
	"k8s.io/client-go/util/cert"

	pe "github.com/pingcap/errors"
)

const (
	serverVersion = "5.7.0"
)

type mysqlServerHandler interface {
	server.Handler
	Database() string
	HandleConnection(serverConn *server.Conn)
	ErrorEvent(eventType, message string) error
	ClientConn(clientConn *client.Conn)
	CreateSessionEvent(models.SessionEvent) error
}

type mysqlHandler struct {
	Config
	logger          *zap.Logger
	options         []client.Option
	awsCredentials  aws.CredentialsProvider
	server          *server.Server
	upstreamAddress string
}

type dummyProvider struct{}

func (p *dummyProvider) CheckUsername(username string) (found bool, err error) {
	return true, nil
}

func (p *dummyProvider) GetCredential(username string) (password string, found bool, err error) {
	return "", true, nil
}

func newMysqlHandler(c Config) (*mysqlHandler, error) {
	upstreamAddress := net.JoinHostPort(c.Hostname, fmt.Sprintf("%d", c.Port))
	var options []client.Option
	var awsCredentials aws.CredentialsProvider
	if c.RdsIam {
		cfg, err := util.GetAwsConfig(context.Background(), c.AwsRegion, c.AwsCredentials)
		if err != nil {
			return nil, fmt.Errorf("failed to initialize AWS client: %v", err)
		}
		awsCredentials = cfg.Credentials
	}

	if c.UpstreamTLS && c.DialerFunc == nil {
		tlsConfig := &tls.Config{}

		if len(c.UpstreamCABlock) > 0 {
			caPool, err := cert.NewPoolFromBytes(c.UpstreamCABlock)
			if err != nil {
				return nil, fmt.Errorf("failed to load upstream CA: %s", err)
			}
			tlsConfig.RootCAs = caPool
			tlsConfig.ServerName = c.Hostname
		} else if c.UpstreamCAFile != "" {
			caPool, err := cert.NewPool(c.UpstreamCAFile)
			if err != nil {
				return nil, fmt.Errorf("failed to load upstream CA: %s", err)
			}
			tlsConfig.RootCAs = caPool
			tlsConfig.ServerName = c.Hostname
		} else {
			tlsConfig.InsecureSkipVerify = true
		}

		if len(c.UpstreamCertBlock) > 0 && len(c.UpstreamKeyBlock) > 0 {
			cert, err := tls.X509KeyPair(c.UpstreamCertBlock, c.UpstreamKeyBlock)
			if err != nil {
				return nil, fmt.Errorf("failed to load upstream cert: %s", err)
			}
			tlsConfig.Certificates = []tls.Certificate{cert}
		} else if c.UpstreamCertFile != "" && c.UpstreamKeyFile != "" {
			cert, err := tls.LoadX509KeyPair(c.UpstreamCertFile, c.UpstreamKeyFile)
			if err != nil {
				return nil, fmt.Errorf("failed to load upstream cert: %s", err)
			}
			tlsConfig.Certificates = []tls.Certificate{cert}
		} else if c.UpstreamCertFile != "" || c.UpstreamKeyFile != "" {
			return nil, fmt.Errorf("upstream cert and key must both be provided")
		}

		options = append(options, func(c *client.Conn) error {
			c.SetTLSConfig(tlsConfig)
			return nil
		})
	}

	var mysqlServer *server.Server
	if c.Socket.IsPrimaryProxy() {
		mysqlServer = server.NewServer(serverVersion, mysql.DEFAULT_COLLATION_ID, mysql.AUTH_NATIVE_PASSWORD, nil, nil)
	} else {
		mysqlServer = server.NewDefaultServer()
	}

	mysqlHandler := &mysqlHandler{
		Config:          c,
		logger:          c.Logger,
		server:          mysqlServer,
		upstreamAddress: upstreamAddress,
		awsCredentials:  awsCredentials,
		options:         options,
	}

	return mysqlHandler, nil
}

func (h mysqlHandler) handleClient(c net.Conn) {
	defer c.Close()

	var serverHandler mysqlServerHandler
	var metadata *border0.ConnMetadata

	switch {
	case h.Socket.PrivateNetworkEnabled:
		pnConn, ok := c.(*border0.PrivateNetworkConn)
		if !ok {
			h.logger.Error("failed to cast connection to private network")
			return
		}

		if pnConn.Metadata == nil {
			h.logger.Error("invalid private network metadata")
			return
		}

		defer func() {
			if err := h.Config.Border0API.EndSession(models.Session{
				SessionKey: pnConn.Metadata.SessionKey,
				SocketID:   h.Config.Socket.SocketID,
				EndTime:    pointer.To(time.Now()),
			}); err != nil {
				h.logger.Error("failed to end session", zap.Error(err))
			}
		}()

		metadata = pnConn.Metadata
		serverHandler = &mysqlLocalHandler{
			logger:          h.logger.With(zap.String("session_key", pnConn.Metadata.SessionKey)),
			metadata:        pnConn.Metadata,
			statements:      make(map[int64]*client.Stmt),
			preparedQueries: make(map[int64]string),
			border0API:      h.Border0API,
			socket:          h.Socket,
			lastAuth:        time.Now(),
			recordingChan:   make(chan message, 100),
			variables:       make(map[string]string),
		}
	case h.Config.E2eEncryptionEnabled:
		e2EEncryptionConn, ok := c.(border0.E2EEncryptionConn)
		if !ok {
			h.logger.Error("failed to cast connection to e2eencryption")
			return
		}

		if e2EEncryptionConn.Metadata == nil {
			h.logger.Error("invalid e2e metadata")
			return
		}

		metadata = e2EEncryptionConn.Metadata
		serverHandler = &mysqlLocalHandler{
			logger:          h.logger.With(zap.String("session_key", e2EEncryptionConn.Metadata.SessionKey)),
			metadata:        e2EEncryptionConn.Metadata,
			statements:      make(map[int64]*client.Stmt),
			preparedQueries: make(map[int64]string),
			border0API:      h.Border0API,
			socket:          h.Socket,
			lastAuth:        time.Now(),
			recordingChan:   make(chan message, 100),
			variables:       make(map[string]string),
		}
	default:
		serverHandler = &mysqlEmptyHandler{
			logger:     h.logger,
			border0API: h.Border0API,
		}
	}

	password := h.Password
	if h.RdsIam {
		authenticationToken, err := auth.BuildAuthToken(context.TODO(), h.upstreamAddress, h.AwsRegion, h.Username, h.awsCredentials)
		if err != nil {
			if err := serverHandler.ErrorEvent("database_rds_iam", fmt.Sprintf("failed to create authentication token: %s", err)); err != nil {
				h.logger.Error("failed to create session event", zap.Error(err))
			}

			return
		}

		password = authenticationToken
	}

	if h.DialerFunc == nil {
		h.DialerFunc = func(ctx context.Context, network, addr string) (net.Conn, error) {
			return net.DialTimeout(network, addr, 5*time.Second)
		}
	}

	var options []client.Option
	options = append(options, h.options...)
	options = append(options, func(c *client.Conn) error {
		c.SetCapability(mysql.CLIENT_MULTI_RESULTS)
		c.SetCapability(mysql.CLIENT_MULTI_STATEMENTS)
		c.SetCapability(mysql.CLIENT_PS_MULTI_RESULTS)
		c.SetAttributes(map[string]string{
			"_client_name": "border0-sql-proxy",
		})

		return nil
	})

	clientConn, err := client.ConnectWithDialer(context.Background(), "tcp", h.upstreamAddress, h.Username, password, "", h.DialerFunc, options...)
	if err != nil {
		if err := serverHandler.ErrorEvent("database_connection", fmt.Sprintf("upstream mysql connection failed: %s", pe.Unwrap(err))); err != nil {
			h.logger.Error("failed to create session event", zap.Error(err))
		}
		return
	}

	defer func() {
		if clientConn != nil {
			if err := clientConn.Quit(); err != nil {
				clientConn.Close()
			}
		}
	}()

	serverHandler.ClientConn(clientConn)

	serverConn, err := server.NewCustomizedConn(c, h.server, &dummyProvider{}, serverHandler)
	if err != nil {
		if metadata != nil {
			var mysqlErr *mysql.MyError
			if errors.As(err, &mysqlErr) {
				if mysqlErr.Code == mysql.ER_DBACCESS_DENIED_ERROR {
					if err := h.Border0API.UpdateSession(models.SessionUpdate{
						SessionKey:     metadata.SessionKey,
						Socket:         &h.Socket,
						Result:         models.ResultDenied,
						AuthInfoFailed: mysqlErr.Message,
					}); err != nil {
						h.logger.Error("failed to update session", zap.Error(err))
					}

					return
				}
			}
		}
		if err := serverHandler.ErrorEvent("database_connection", fmt.Sprintf("failed to accept connection: %s", err)); err != nil {
			h.logger.Error("failed to create session event", zap.Error(err))
		}
		return
	}

	defer func() {
		if serverConn != nil && !serverConn.Closed() {
			serverConn.Close()
		}
	}()

	// workaround: if the client does not support CLIENT_MULTI_RESULTS or CLIENT_MULTI_STATEMENTS, we will reconnect without those capabilities
	// we should check this during the handshake between client and connector, but this is a quick fix
	// note: we do want an upstream connection before the handshake so we can check if the database exists and return an proper error
	// the real fix requires a custom handshake implementation which requires a fork of go-mysql
	if serverConn.Capability()&mysql.CLIENT_MULTI_RESULTS == 0 || serverConn.Capability()&mysql.CLIENT_MULTI_STATEMENTS == 0 {
		clientConn.Close()

		var options []client.Option
		options = append(options, h.options...)
		if serverConn.Capability()&mysql.CLIENT_MULTI_RESULTS > 0 {
			options = append(options, func(c *client.Conn) error {
				c.SetCapability(mysql.CLIENT_MULTI_RESULTS)
				return nil
			})
		}
		if serverConn.Capability()&mysql.CLIENT_MULTI_STATEMENTS > 0 {
			options = append(options, func(c *client.Conn) error {
				c.SetCapability(mysql.CLIENT_MULTI_STATEMENTS)
				return nil
			})
		}
		if serverConn.Capability()&mysql.CLIENT_PS_MULTI_RESULTS > 0 {
			options = append(options, func(c *client.Conn) error {
				c.SetCapability(mysql.CLIENT_PS_MULTI_RESULTS)
				return nil
			})
		}

		options = append(options, func(c *client.Conn) error {
			c.SetAttributes(map[string]string{
				"_client_name": "border0-sql-proxy",
			})
			return nil
		})

		newClientConn, err := client.ConnectWithDialer(context.Background(), "tcp", h.upstreamAddress, h.Username, password, serverHandler.Database(), h.DialerFunc, options...)
		if err != nil {
			if err := serverHandler.ErrorEvent("database_connection", fmt.Sprintf("upstream mysql connection failed: %s", pe.Unwrap(err))); err != nil {
				h.logger.Error("failed to create session event", zap.Error(err))
			}
			return
		}

		clientConn = newClientConn
		serverHandler.ClientConn(clientConn)
	}

	if metadata != nil {
		charset, _, _ := getCharsetInfoByID(int(serverConn.Charset()))
		sessionMetadata, err := json.Marshal(struct {
			ClientUser   string            `json:"client_user"`
			Attributes   map[string]string `json:"attributes"`
			Charset      string            `json:"charset"`
			Capabilities []string          `json:"capabilities"`
			Database     string            `json:"database"`
		}{serverConn.GetUser(), serverConn.Attributes(), charset, capabilitySlice(serverConn.Capability()), serverHandler.Database()})
		if err != nil {
			h.logger.Error("failed to create session metadata", zap.Error(err))
			return
		}

		if err := serverHandler.CreateSessionEvent(models.SessionEvent{
			SessionKey: metadata.SessionKey,
			Socket:     &h.Socket,
			Type:       "database_connection",
			Status:     "success",
			Metadata:   string(sessionMetadata),
		}); err != nil {
			h.logger.Error("failed to create session event", zap.Error(err))
		}
	}

	serverHandler.HandleConnection(serverConn)
}

func capabilitySlice(capability uint32) []string {
	var caps []string
	for i := 0; capability != 0; i++ {
		field := uint32(1 << i)
		if capability&field == 0 {
			continue
		}
		capability ^= field

		switch field {
		case mysql.CLIENT_LONG_PASSWORD:
			caps = append(caps, "CLIENT_LONG_PASSWORD")
		case mysql.CLIENT_FOUND_ROWS:
			caps = append(caps, "CLIENT_FOUND_ROWS")
		case mysql.CLIENT_LONG_FLAG:
			caps = append(caps, "CLIENT_LONG_FLAG")
		case mysql.CLIENT_CONNECT_WITH_DB:
			caps = append(caps, "CLIENT_CONNECT_WITH_DB")
		case mysql.CLIENT_NO_SCHEMA:
			caps = append(caps, "CLIENT_NO_SCHEMA")
		case mysql.CLIENT_COMPRESS:
			caps = append(caps, "CLIENT_COMPRESS")
		case mysql.CLIENT_ODBC:
			caps = append(caps, "CLIENT_ODBC")
		case mysql.CLIENT_LOCAL_FILES:
			caps = append(caps, "CLIENT_LOCAL_FILES")
		case mysql.CLIENT_IGNORE_SPACE:
			caps = append(caps, "CLIENT_IGNORE_SPACE")
		case mysql.CLIENT_PROTOCOL_41:
			caps = append(caps, "CLIENT_PROTOCOL_41")
		case mysql.CLIENT_INTERACTIVE:
			caps = append(caps, "CLIENT_INTERACTIVE")
		case mysql.CLIENT_SSL:
			caps = append(caps, "CLIENT_SSL")
		case mysql.CLIENT_IGNORE_SIGPIPE:
			caps = append(caps, "CLIENT_IGNORE_SIGPIPE")
		case mysql.CLIENT_TRANSACTIONS:
			caps = append(caps, "CLIENT_TRANSACTIONS")
		case mysql.CLIENT_RESERVED:
			caps = append(caps, "CLIENT_RESERVED")
		case mysql.CLIENT_SECURE_CONNECTION:
			caps = append(caps, "CLIENT_SECURE_CONNECTION")
		case mysql.CLIENT_MULTI_STATEMENTS:
			caps = append(caps, "CLIENT_MULTI_STATEMENTS")
		case mysql.CLIENT_MULTI_RESULTS:
			caps = append(caps, "CLIENT_MULTI_RESULTS")
		case mysql.CLIENT_PS_MULTI_RESULTS:
			caps = append(caps, "CLIENT_PS_MULTI_RESULTS")
		case mysql.CLIENT_PLUGIN_AUTH:
			caps = append(caps, "CLIENT_PLUGIN_AUTH")
		case mysql.CLIENT_CONNECT_ATTRS:
			caps = append(caps, "CLIENT_CONNECT_ATTRS")
		case mysql.CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA:
			caps = append(caps, "CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA")
		default:
			caps = append(caps, fmt.Sprintf("(%d)", field))
		}
	}

	return caps
}
