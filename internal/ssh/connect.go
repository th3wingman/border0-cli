package ssh

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/url"
	"os"
	"regexp"
	"time"

	"github.com/borderzero/border0-cli/internal/api"
	"github.com/borderzero/border0-cli/internal/api/models"
	border0_http "github.com/borderzero/border0-cli/internal/http"
	"github.com/cenkalti/backoff/v4"
	gssh "github.com/gliderlabs/ssh"
	"go.uber.org/zap"
	"golang.org/x/crypto/ssh"
	"golang.org/x/net/proxy"
)

var ErrListenOnPort = errors.New("failed to listen on tcp port")
var ErrSessionDisconnected = errors.New("session disconnected")

type ConnectionOption func(*Connection)

func WithRetry(numOfRetry int) ConnectionOption {
	return func(h *Connection) {
		h.numOfRetry = numOfRetry
	}
}

type Connection struct {
	session    *ssh.Session
	logger     *zap.Logger
	socketID   string
	tunnelID   string
	closed     bool
	numOfRetry int
}

func NewConnection(logger *zap.Logger, opts ...ConnectionOption) *Connection {
	connection := &Connection{logger: logger}

	for _, opt := range opts {
		opt(connection)
	}

	return connection
}

func (c *Connection) Connect(ctx context.Context, userID string, socketID string, tunnelID string, port int, targethost string, identityFile string, proxyHost string, version string, localssh, httpserver bool, sshCa string, accessToken, httpdir string, connectorAuthRequired bool, caCertPool *x509.CertPool) error {
	c.socketID = socketID
	c.tunnelID = tunnelID

	tunnel, err := api.NewAPI(api.WithAccessToken(accessToken)).GetTunnel(context.Background(), socketID, tunnelID)
	if err != nil {
		return fmt.Errorf("error getting tunnel: %v", err)
	}

	sshConfig := &ssh.ClientConfig{
		User:            userID,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         defaultTimeout,
		ClientVersion:   fmt.Sprintf("SSH-2.0-Border0-%s", version),
	}
	var keyFiles []string
	var signers []ssh.Signer

	if identityFile != "" {
		f := []string{identityFile}
		if auth, err := authWithPrivateKeys(f, true); err == nil {
			signers = append(signers, auth...)
		}
	}

	if auth, err := authWithAgent(); err == nil {
		signers = append(signers, auth...)
	}

	home, err := os.UserHomeDir()
	if err == nil {
		for _, k := range defaultKeyFiles {
			f := home + "/.ssh/" + k
			if _, err := os.Stat(f); err == nil {
				keyFiles = append(keyFiles, f)
			}
		}
	}

	if auth, err := authWithPrivateKeys(keyFiles, false); err == nil {
		signers = append(signers, auth...)
	}

	// Start a thread that refreshes the token
	// refresh every hour, 3600secs
	go func() {
		for {
			time.Sleep(3600 * time.Second)
			_, err := border0_http.RefreshLogin()
			if err != nil {
				fmt.Println(err)
			}
		}
	}()

	proxyMatch, _ := regexp.Compile("^http(s)?://")
	var proxyDialer proxy.Dialer
	if proxyMatch.MatchString(proxyHost) {
		proxyURL, err := url.Parse(proxyHost)
		if err != nil {
			log.Fatalf("Invalid proxy URL: %s", err)
		}
		proxy.RegisterDialerType("http", newHttpProxy)
		proxy.RegisterDialerType("https", newHttpProxy)
		proxyDialer, _ = proxy.FromURL(proxyURL, proxy.Direct)
	} else {
		proxyDialer = proxy.Direct
	}

	retriesThreeTimesEveryTwoSeconds := backoff.WithMaxRetries(backoff.NewConstantBackOff(2*time.Second), uint64(c.numOfRetry))
	err = backoff.Retry(func() error {
		// Let's fetch a short lived signed cert from api.border0.com
		// We'll use that to authenticate. This returns a signer object.
		// for now we'll just add it to the signers list.
		// In future, this is the only auth method we should use.
		sshCert, err := getSshCert(userID, socketID, accessToken, 1)
		if err != nil {
			return ErrFailedToGetSshCert
		}
		// If we got a cert, we use that for auth method. Otherwise use static keys
		if sshCert != nil {
			sshConfig.Auth = []ssh.AuthMethod{ssh.PublicKeys(sshCert)}
		} else if signers != nil {
			sshConfig.Auth = []ssh.AuthMethod{ssh.PublicKeys(signers...)}
		} else {
			return errors.New("no ssh keys found for authenticating")
		}

		c.logger.Info("Connecting to Server", zap.String("server", sshServer()))
		time.Sleep(1 * time.Second)

		err = c.connect(ctx, proxyDialer, sshConfig, tunnel, port, targethost, localssh, httpserver, sshCa, httpdir, connectorAuthRequired, c.socketID, caCertPool)
		if err != nil {
			// abort retry when session is disconnected or it's already connected in the tcp port
			if errors.Is(err, ErrListenOnPort) || errors.Is(err, ErrSessionDisconnected) {
				return nil
			}
		}

		return err
	}, retriesThreeTimesEveryTwoSeconds)

	if err != nil {
		return fmt.Errorf("error connecting to server: %v", err)
	}

	return errors.New("ssh session disconnected")
}

func (c *Connection) connect(ctx context.Context, proxyDialer proxy.Dialer, sshConfig *ssh.ClientConfig, tunnel *models.Tunnel, port int, targethost string, localssh, httpserver bool, sshCa, httpdir string, connectorAuthRequired bool, socketID string, caCertPool *x509.CertPool) error {
	remoteHost := net.JoinHostPort(sshServer(), "22")

	defer c.Close()
	conn, err := proxyDialer.Dial("tcp", remoteHost)
	if err != nil {
		c.logger.Error("dial into remote server error", zap.Error(err))
		return err
	}

	defer conn.Close()

	sshCon, channel, req, err := ssh.NewClientConn(conn, remoteHost, sshConfig)
	if err != nil {
		c.logger.Error("dial into remote server error", zap.Error(err))
		return err
	}
	defer sshCon.Close()

	sshClient := ssh.NewClient(sshCon, channel, req)
	defer sshClient.Close()

	listener, err := sshClient.Listen("tcp", fmt.Sprintf("localhost:%d", tunnel.LocalPort))
	if err != nil {
		c.logger.Error("Listen open port ON remote server error", zap.Int("port", tunnel.LocalPort), zap.Error(err))
		return ErrListenOnPort
	}
	defer listener.Close()

	session, err := sshClient.NewSession()
	if err != nil {
		c.logger.Error("Failed to create session: %v", zap.Error(err))
		return err
	}
	defer session.Close()

	session.Stdout = os.Stdout
	modes := ssh.TerminalModes{}

	if err := session.RequestPty("xterm-256color", 80, 40, modes); err != nil {
		c.logger.Error("request for pseudo terminal failed", zap.Error(err))
		return err
	}

	if err := session.Shell(); err != nil {
		log.Print(err)
		return err
	}

	var tlsConfig *tls.Config

	if connectorAuthRequired {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			c.logger.Error("Failed to generate private key", zap.Error(err))
			return err
		}

		keyDer, err := x509.MarshalECPrivateKey(key)
		if err != nil {
			c.logger.Error("Failed to serialize private key", zap.Error(err))
			return err
		}

		template := x509.Certificate{
			SerialNumber: big.NewInt(1),
			Subject: pkix.Name{
				CommonName:   socketID,
				Organization: []string{"Border0 Connector"},
			},
			IsCA:                  true,
			NotBefore:             time.Now().Add(-time.Hour * 24 * 365),
			NotAfter:              time.Now().Add(time.Hour * 24 * 365 * 10),
			ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
			KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
			BasicConstraintsValid: true,
			DNSNames:              []string{socketID},
		}

		certDer, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
		if err != nil {
			c.logger.Error("failed to create certificate", zap.Error(err))
			return err
		}

		certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDer})
		keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDer})

		cert, err := tls.X509KeyPair([]byte(certPEM), []byte(keyPEM))
		if err != nil {
			c.logger.Error("failed to create certificate", zap.Error(err))
			return err
		}

		tlsConfig = &tls.Config{
			Certificates: []tls.Certificate{cert},
			ClientAuth:   tls.RequireAndVerifyClientCert,
			ClientCAs:    caCertPool,
		}
	}

	var sshServer *gssh.Server
	if localssh {
		sshServer = newServer(sshCa)
	}

	if httpserver {
		go border0_http.StartLocalHTTPServer(httpdir, listener)
	} else {
		go func() {
			for {
				client, err := listener.Accept()
				if err != nil {
					c.logger.Error("Tunnel Connection accept error", zap.Error(err))
					return
				}

				go func() {
					if connectorAuthRequired {
						tlsConn := tls.Server(client, tlsConfig)
						if err = tlsConn.Handshake(); err != nil {
							log.Printf("client tls handshake failed: %s", err)
							return
						}

						_, err = client.Write([]byte("BORDER0-CLIENT-CONNECTOR-AUTHENTICATED"))
						if err != nil {
							log.Printf("Failed to complete handshake: %s", err)
							return
						}
						log.Printf("client %s authenticated", tlsConn.ConnectionState().PeerCertificates[0].Subject.CommonName)
						time.Sleep(200 * time.Millisecond)
					}

					if localssh {
						go sshServer.HandleConn(client)
					} else {
						local, err := net.Dial("tcp", fmt.Sprintf("%s:%d", targethost, port))
						if err != nil {
							c.logger.Error("Dial INTO local service error", zap.Error(err))
							return
						}

						go handleClient(client, local)
					}
				}()
			}
		}()
	}

	done := make(chan bool, 1)
	defer func() { done <- true }()
	go KeepAlive(sshClient, done)

	go func(context.Context) {
		<-ctx.Done()
		session.Close()
	}(ctx)

	c.session = session

	if err := session.Wait(); err != nil {
		c.logger.Info("Session exited", zap.String("error", err.Error()))
		return ErrSessionDisconnected
	}

	return nil
}

func (c *Connection) Close() {
	if c.session != nil {
		if err := c.session.Close(); err != nil {
			if err != io.EOF {
				c.logger.Info("ssh session close error", zap.String("error", err.Error()))
			}
		}
	}

	c.closed = true
}

func (c *Connection) IsClosed() bool {
	return c.closed
}
