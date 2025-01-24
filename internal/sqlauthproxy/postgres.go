package sqlauthproxy

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/feature/rds/auth"
	"github.com/borderzero/border0-cli/internal/api/models"
	"github.com/borderzero/border0-cli/internal/border0"
	"github.com/borderzero/border0-cli/internal/util"
	"github.com/borderzero/border0-go/lib/types/pointer"
	"github.com/jackc/pgconn"
	"github.com/jackc/pgproto3/v2"
	"go.uber.org/zap"
	"k8s.io/client-go/util/cert"
)

type postgresHandler struct {
	Config
	UpstreamConfig *pgconn.Config
	awsCredentials aws.CredentialsProvider
	tlsConfig      *tls.Config
}

type postgresServerHandler interface {
	HandleConnection(*pgconn.HijackedConn)
	ErrorEvent(eventType, message string) error
}

func newPostgresHandler(c Config) (*postgresHandler, error) {
	var awsCredentials aws.CredentialsProvider
	if c.RdsIam {
		cfg, err := util.GetAwsConfig(context.Background(), c.AwsRegion, c.AwsCredentials)
		if err != nil {
			return nil, fmt.Errorf("failed to initialize AWS client: %v", err)
		}
		awsCredentials = cfg.Credentials
	}

	var tlsConfig *tls.Config
	if !c.Socket.IsPrimaryProxy() {
		generatedCert, err := generateX509KeyPair()
		if err != nil {
			return nil, fmt.Errorf("failed to generate tls certificate: %s", err)
		}

		tlsConfig = &tls.Config{
			Certificates: []tls.Certificate{generatedCert},
		}
	}

	var (
		sslSettings       []string
		upstreamTLSConfig *tls.Config
	)
	if c.UpstreamTLS && c.DialerFunc == nil {
		if len(c.UpstreamCABlock) > 0 {
			upstreamTLSConfig = &tls.Config{}
			caPool, err := cert.NewPoolFromBytes(c.UpstreamCABlock)
			if err != nil {
				return nil, fmt.Errorf("failed to load upstream CA: %s", err)
			}
			upstreamTLSConfig.RootCAs = caPool
			upstreamTLSConfig.ServerName = c.Hostname
		} else if c.UpstreamCAFile != "" {
			sslSettings = append(sslSettings, fmt.Sprintf("sslrootcert=%s", c.UpstreamCAFile))
			sslSettings = append(sslSettings, "sslmode=verify-ca")
		} else {
			sslSettings = append(sslSettings, "sslmode=require")
		}

		if len(c.UpstreamCertBlock) > 0 && len(c.UpstreamKeyBlock) > 0 {
			if upstreamTLSConfig == nil {
				upstreamTLSConfig = &tls.Config{}
			}
			cert, err := tls.X509KeyPair(c.UpstreamCertBlock, c.UpstreamKeyBlock)
			if err != nil {
				return nil, fmt.Errorf("failed to load upstream certificate: %s", err)
			}
			upstreamTLSConfig.Certificates = []tls.Certificate{cert}
		}
		if c.UpstreamCertFile != "" {
			sslSettings = append(sslSettings, fmt.Sprintf("sslcert=%s", c.UpstreamCertFile))
		}
		if c.UpstreamKeyFile != "" {
			sslSettings = append(sslSettings, fmt.Sprintf("sslkey=%s", c.UpstreamKeyFile))
		}
	} else {
		sslSettings = append(sslSettings, "sslmode=prefer")
	}

	var strSslSettings string
	if len(sslSettings) > 0 {
		strSslSettings = "?" + strings.Join(sslSettings, "&")
	}

	config, err := pgconn.ParseConfig(
		fmt.Sprintf(
			"postgres://%s:%s@%s:%d%s",
			url.QueryEscape(c.Username),
			url.QueryEscape(c.Password),
			c.Hostname,
			c.Port,
			strSslSettings,
		),
	)
	if err != nil {
		return nil, err
	}
	if upstreamTLSConfig != nil {
		config.TLSConfig = upstreamTLSConfig
	}

	if c.DialerFunc != nil {
		config.DialFunc = c.DialerFunc
	}

	return &postgresHandler{
		Config:         c,
		UpstreamConfig: config,
		awsCredentials: awsCredentials,
		tlsConfig:      tlsConfig,
	}, nil
}

func (h postgresHandler) handleClient(c net.Conn) {
	defer c.Close()

	startupMessage, c, err := h.handleClientStartup(c)
	if err != nil {
		h.Logger.Error("sqlauthproxy: failed to handle client startup", zap.Error(err))
		return
	}

	clientConn := pgproto3.NewBackend(pgproto3.NewChunkReader(c), c)

	if startupMessage == nil {
		h.Logger.Error("sqlauthproxy: failed to handle client startup")
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if db, ok := startupMessage.Parameters["database"]; ok {
		h.UpstreamConfig.Database = db
	}

	var metadata *border0.ConnMetadata

	switch {
	case h.Socket.PrivateNetworkEnabled:
		pnConn, ok := c.(*border0.PrivateNetworkConn)
		if !ok {
			h.Logger.Error("failed to cast connection to private network")
			return
		}

		if pnConn.Metadata == nil {
			h.Logger.Error("invalid private network metadata")
			return
		}

		defer func() {
			if err := h.Config.Border0API.EndSession(models.Session{
				SessionKey: pnConn.Metadata.SessionKey,
				SocketID:   h.Config.Socket.SocketID,
				EndTime:    pointer.To(time.Now()),
			}); err != nil {
				h.Logger.Error("failed to end session", zap.Error(err))
			}
		}()

		metadata = pnConn.Metadata
	case h.Config.E2eEncryptionEnabled:
		e2eeConn, ok := c.(border0.E2EEncryptionConn)
		if !ok {
			c.Close()
			h.Logger.Error("failed to cast connection to e2eencryption")
			return
		}

		if e2eeConn.Metadata == nil {
			h.Logger.Error("invalid e2e metadata")
			return
		}

		metadata = e2eeConn.Metadata
	}

	var serverHandler postgresServerHandler

	if h.Config.Socket.IsPrimaryProxy() {
		if !isDatabaseAllowed(metadata.AllowedActions, h.UpstreamConfig.Database) {
			if err := h.Border0API.UpdateSession(models.SessionUpdate{
				SessionKey:     metadata.SessionKey,
				Socket:         &h.Socket,
				Result:         models.ResultDenied,
				AuthInfoFailed: "database access denied by policy",
			}); err != nil {
				h.Logger.Error("failed to update session", zap.Error(err))
			}

			clientConn.Send(&pgproto3.ErrorResponse{
				Severity: "ERROR",
				Code:     "28000",
				Message:  "User not authorized to access database",
				Detail:   fmt.Sprintf("User \"%s\" is not allowed to access database %s.", metadata.UserEmail, h.UpstreamConfig.Database),
			})

			return
		}

		serverHandler = &postgresLocalHandler{
			logger:          h.Logger.With(zap.String("session_key", metadata.SessionKey)),
			metadata:        metadata,
			border0API:      h.Border0API,
			socket:          h.Socket,
			lastAuth:        time.Now(),
			recordingChan:   make(chan message, 100),
			serverConn:      c,
			serverBackend:   clientConn,
			preparedQueries: make(map[string]string),
			binds:           make(map[string]bind),
			database:        h.UpstreamConfig.Database,
		}
	} else {
		serverHandler = &postgresCopyyHandler{
			serverConn: c,
			logger:     h.Logger,
		}
	}

	if h.RdsIam {
		authenticationToken, err := auth.BuildAuthToken(context.TODO(), net.JoinHostPort(h.Hostname, strconv.Itoa(h.Port)), h.AwsRegion, h.Username, h.awsCredentials)
		if err != nil {
			if err := serverHandler.ErrorEvent("database_rds_iam", fmt.Sprintf("failed to create authentication token: %s", err)); err != nil {
				h.Logger.Error("failed to create session event", zap.Error(err))
			}

			return
		}

		h.UpstreamConfig.Password = authenticationToken
	}

	conn, err := pgconn.ConnectConfig(ctx, h.UpstreamConfig)
	if err != nil {
		var e *pgconn.PgError
		if errors.As(err, &e) {
			clientConn.Send(&pgproto3.ErrorResponse{
				Severity: e.Severity,
				Code:     e.Code,
				Message:  e.Message,
				Detail:   e.Detail,
			})
		} else {
			clientConn.Send(&pgproto3.ErrorResponse{
				Severity: "ERROR",
				Code:     "08006",
				Message:  "Connection error",
				Detail:   err.Error(),
			})
		}

		if err := serverHandler.ErrorEvent("database_connection", fmt.Sprintf("failed to connect to upstream: %s", err)); err != nil {
			h.Logger.Error("failed to create session event", zap.Error(err))
		}

		return
	}

	defer conn.Close(ctx)

	pgconn, err := conn.Hijack()
	if err != nil {
		if err := serverHandler.ErrorEvent("database_connection", fmt.Sprintf("failed to connect to upstream: %s", err)); err != nil {
			h.Logger.Error("failed to create session event", zap.Error(err))
		}

		return
	}

	if err = h.handleClientAuthRequest(clientConn, pgconn.ParameterStatuses); err != nil {
		if err := serverHandler.ErrorEvent("database_connection", fmt.Sprintf("failed to handle client authentication: %s", err)); err != nil {
			h.Logger.Error("failed to create session event", zap.Error(err))
		}

		return
	}

	serverHandler.HandleConnection(pgconn)
}

func (h postgresHandler) handleClientStartup(conn net.Conn) (*pgproto3.StartupMessage, net.Conn, error) {
	c := pgproto3.NewBackend(pgproto3.NewChunkReader(conn), conn)

	message, err := c.ReceiveStartupMessage()
	if err != nil {
		return nil, nil, err
	}

	switch msg := message.(type) {
	case *pgproto3.StartupMessage:
		if !h.E2eEncryptionEnabled {
			_, ok := conn.(*tls.Conn)
			if !ok {
				return nil, nil, fmt.Errorf("failed to get TLS connection info")
			}
		}

		return msg, conn, nil
	case *pgproto3.SSLRequest:
		if h.E2eEncryptionEnabled {
			_, err := conn.Write([]byte("N"))
			if err != nil {
				return nil, nil, err
			}

			return h.handleClientStartup(conn)
		} else {
			_, err = conn.Write([]byte("S"))
			if err != nil {
				return nil, nil, err
			}

			conn = tls.Server(conn, h.tlsConfig)
			return h.handleClientStartup(conn)
		}
	case *pgproto3.CancelRequest:
		conn.Close()
		return nil, nil, nil
	default:
		return nil, nil, fmt.Errorf("invalid startup message (%T)", msg)
	}
}

func (h postgresHandler) handleClientAuthRequest(serverSession *pgproto3.Backend, serverParams map[string]string) error {
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

func generateX509KeyPair() (tls.Certificate, error) {
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(now.Unix()),
		Subject: pkix.Name{
			CommonName:   "sqlauthproxy",
			Organization: []string{"border.com"},
		},
		NotBefore: now,
		NotAfter:  now.AddDate(10, 0, 0),
	}

	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("failed to generate private key: %s", err)
	}

	cert, err := x509.CreateCertificate(rand.Reader, template, template, priv.Public(), priv)
	if err != nil {
		return tls.Certificate{}, err
	}

	return tls.Certificate{
		Certificate: [][]byte{cert},
		PrivateKey:  priv,
	}, nil
}
