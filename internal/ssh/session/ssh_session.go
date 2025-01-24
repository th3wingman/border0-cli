package session

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/ec2instanceconnect"
	"github.com/borderzero/border0-cli/internal/api/models"
	"github.com/borderzero/border0-cli/internal/border0"
	"github.com/borderzero/border0-cli/internal/ssh/config"
	"github.com/borderzero/border0-cli/internal/ssh/session/common"
	"github.com/borderzero/border0-cli/internal/util/recorder"
	"github.com/borderzero/border0-go/lib/types/pointer"
	"go.uber.org/zap"
	"golang.org/x/crypto/ssh"
)

type sshSessionHandler struct {
	logger *zap.Logger
	config *config.ProxyConfig
}

// ensure sshSessionHandler implements SessionHandler.
var _ SessionHandler = (*sshSessionHandler)(nil)

type sshSession struct {
	config             *config.ProxyConfig
	logger             *zap.Logger
	metadata           *border0.ConnMetadata
	sshServerConfig    *ssh.ServerConfig
	sshClientConfig    *ssh.ClientConfig
	downstreamSshConn  *ssh.ServerConn
	downstreamSshChans <-chan ssh.NewChannel
	downstreamSshReqs  <-chan *ssh.Request
	upstreamSshConn    ssh.Conn
	upstreamSshChans   <-chan ssh.NewChannel
	upstreamSshReqs    <-chan *ssh.Request
	upstreamSshClient  *ssh.Client
	sessionWriter      io.WriteCloser
}

type sshChannel struct {
	*sshSession
	upstreamSession   *ssh.Session
	downstreamChannel ssh.Channel
	width             int
	height            int
	pty               bool
}

func NewSshSessionHandler(logger *zap.Logger, config *config.ProxyConfig) (*sshSessionHandler, error) {
	var authMethods []ssh.AuthMethod
	if config.IdentityFile != "" {
		bytes, err := os.ReadFile(config.IdentityFile)
		if err != nil {
			return nil, fmt.Errorf("failed to read identity file: %s", err)
		}

		signer, err := ssh.ParsePrivateKey(bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse identity file: %s", err)
		}

		authMethods = append(authMethods, ssh.PublicKeys(signer))
	}

	if config.IdentityPrivateKeyVar != "" {
		signer, err := newVariableSourceSigner(logger, config.IdentityPrivateKeyVar)
		if err != nil {
			return nil, fmt.Errorf("failed to initialize private key signer: %v", err)
		}

		authMethods = append(authMethods, ssh.PublicKeys(signer))
	}

	if config.Password != "" {
		authMethods = append(authMethods, ssh.Password(config.Password))
	}

	if len(authMethods) == 0 {
		if !config.Socket.IsPrimaryProxy() {
			return nil, fmt.Errorf("no authentication methods provided")
		} else {
			config.Border0CertAuth = true
		}
	}

	config.SshClientConfig = &ssh.ClientConfig{
		User:            config.Username,
		Auth:            authMethods,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         5 * time.Second,
	}

	return &sshSessionHandler{
		config: config,
		logger: logger,
	}, nil
}

func NewEc2InstanceConnectSessionHandler(logger *zap.Logger, config *config.ProxyConfig) *sshSessionHandler {
	config.SshClientConfig = &ssh.ClientConfig{
		User:            config.Username,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         5 * time.Second,
	}

	return &sshSessionHandler{
		config: config,
		logger: logger,
	}
}

func (s *sshSessionHandler) Proxy(conn net.Conn) {
	defer conn.Close()

	session := &sshSession{
		logger:          s.logger,
		config:          s.config,
		sshServerConfig: s.config.SshServerConfig,
		sshClientConfig: s.config.SshClientConfig,
	}

	var lastError error
	switch {
	case s.config.Socket.PrivateNetworkEnabled:
		pnConn, ok := conn.(*border0.PrivateNetworkConn)
		if !ok {
			s.logger.Error("failed to cast connection to private network")
			return
		}

		if pnConn.Metadata == nil {
			s.logger.Error("invalid private network metadata")
			return
		}

		defer func() {
			if err := s.config.Border0API.EndSession(models.Session{
				SessionKey: pnConn.Metadata.SessionKey,
				SocketID:   s.config.Socket.SocketID,
				EndTime:    pointer.To(time.Now()),
			}); err != nil {
				session.logger.Error("failed to end session", zap.Error(err))
			}
		}()

		session.metadata = pnConn.Metadata
		session.logger = session.logger.With(zap.String("session_key", session.metadata.SessionKey))
		session.sshServerConfig.NoClientAuthCallback = common.GetNoClientAuthCallback(
			s.config.Border0API,
			s.config.Socket,
			pnConn.Metadata,
			true,
			&lastError,
		)

		if s.config.Border0CertAuth {
			session.sshClientConfig.Auth = []ssh.AuthMethod{ssh.
				PublicKeysCallback(session.userPublicKeyCallback)}
		}
	case s.config.EndToEndEncryption:
		e2EEncryptionConn, ok := conn.(border0.E2EEncryptionConn)
		if !ok {
			conn.Close()
			s.logger.Error("failed to cast connection to e2eencryption")
			return
		}

		if e2EEncryptionConn.Metadata == nil {
			s.logger.Error("invalid e2e metadata")
			return
		}

		session.metadata = e2EEncryptionConn.Metadata
		session.logger = session.logger.With(zap.String("session_key", session.metadata.SessionKey))
		session.sshServerConfig.PublicKeyCallback = common.GetPublicKeyCallback(
			s.config.OrgSshCA,
			s.config.Border0API,
			s.config.Socket,
			e2EEncryptionConn.Metadata,
			true,
		)

		if s.config.Border0CertAuth {
			session.sshClientConfig.Auth = []ssh.AuthMethod{ssh.
				PublicKeysCallback(session.userPublicKeyCallback)}
		}
	default:
		session.metadata = &border0.ConnMetadata{}
	}

	var err error
	session.downstreamSshConn, session.downstreamSshChans, session.downstreamSshReqs, err = ssh.NewServerConn(conn, session.config.SshServerConfig)
	if err != nil {
		if sshErr, ok := err.(*ssh.ServerAuthError); ok && session.config.Socket.IsPrimaryProxy() {
			if err := s.config.Border0API.UpdateSession(models.SessionUpdate{
				SessionKey:     session.metadata.SessionKey,
				Socket:         session.config.Socket,
				Result:         models.ResultDenied,
				AuthInfoFailed: sshErr.Error(),
			}); err != nil {
				session.logger.Error("failed to update session", zap.Error(err))
			}

			return
		}

		if err := session.errorEvent("ssh_connection", fmt.Sprintf("failed to accept connection: %s", err)); err != nil {
			session.logger.Error("failed to create session event", zap.Error(err))
		}
		return
	}

	if session.config.Socket.IsPrimaryProxy() {
		if err := session.config.Border0API.UpdateSession(models.SessionUpdate{
			SessionKey: session.metadata.SessionKey,
			Socket:     session.config.Socket,
			UserData:   ",sshuser=" + session.downstreamSshConn.User(),
		}); err != nil {
			session.logger.Error("failed to update session", zap.Error(err))
			return
		}
	}

	if session.config.AwsUpstreamType == "aws-ec2connect" {
		if err := session.setupEc2InstanceConnect(); err != nil {
			if err := session.errorEvent("ssh_ec2_connect", fmt.Sprintf("failed to setup ec2 connect: %s", err)); err != nil {
				session.logger.Error("failed to create session event", zap.Error(err))
			}

			return
		}
	}

	sshConnUser := session.downstreamSshConn.User()

	// We only use the user from the ssh connection if
	// the ssh client config does not have a user defined.
	// If the user in the ssh client config at this point
	// is not empty string, then it came from the socket's
	// upstream configuration (so we use that).
	if session.sshClientConfig.User == "" {
		session.sshClientConfig.User = sshConnUser
	}

	// we don't support global requests (yet)
	// so we can disregard the reqs channel
	go ssh.DiscardRequests(session.downstreamSshReqs)
	if err := session.handleChannels(); err != nil {
		if err := session.errorEvent("ssh_session", err.Error()); err != nil {
			session.logger.Error("failed to create session event", zap.Error(err))
		}
		return
	}
}

func (s *sshSession) setupPipes(session *ssh.Session) (clientStdin io.WriteCloser, clientStdout io.Reader, clientStderr io.Reader, err error) {
	clientStdin, err = session.StdinPipe()
	if err != nil {
		return
	}

	clientStdout, err = session.StdoutPipe()
	if err != nil {
		return
	}

	clientStderr, err = session.StderrPipe()
	if err != nil {
		return
	}

	return
}

func (s *sshSession) setupEc2InstanceConnect() error {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return fmt.Errorf("failed to generate key: %s", err)
	}

	privateKeyBytes := x509.MarshalPKCS1PrivateKey(privateKey)
	privateKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privateKeyBytes,
	})

	signer, err := ssh.ParsePrivateKey(privateKeyPEM)
	if err != nil {
		return fmt.Errorf("unable to parse private key: %s", err)
	}

	s.sshClientConfig.Auth = []ssh.AuthMethod{
		ssh.PublicKeys(signer),
	}

	sshConnUser := s.downstreamSshConn.User()

	// We only use the user from the ssh connection if
	// the ssh client config does not have a user defined.
	// If the user in the ssh client config at this point
	// is not empty string, then it came from the socket's
	// upstream configuration (so we use that).
	if s.sshClientConfig.User == "" {
		s.sshClientConfig.User = sshConnUser
	}

	publicKey, err := ssh.NewPublicKey(&privateKey.PublicKey)
	if err != nil {
		return fmt.Errorf("unable to generate public key: %s", err)
	}

	publicKeyBytes := ssh.MarshalAuthorizedKey(publicKey)
	publicKeyString := string(publicKeyBytes)

	ec2ConnectClient := ec2instanceconnect.NewFromConfig(s.config.AwsConfig)
	_, err = ec2ConnectClient.SendSSHPublicKey(context.TODO(), &ec2instanceconnect.SendSSHPublicKeyInput{
		InstanceId:     &s.config.AwsEC2InstanceId,
		InstanceOSUser: &s.sshClientConfig.User,
		SSHPublicKey:   &publicKeyString,
	})

	if err != nil {
		return fmt.Errorf("failed to send ssh public key: %s", err)
	}

	return nil
}

func (s *sshSession) handleChannels() error {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	defer s.downstreamSshConn.Close()

	var max_session_duration int
	if s.config.Socket.IsPrimaryProxy() {
		for _, action := range s.metadata.AllowedActions {
			switch permission := action.(type) {
			case models.Permissions:
				if permission.SSH != nil && permission.SSH.MaxSessionDurationSeconds != nil {
					if *permission.SSH.MaxSessionDurationSeconds > max_session_duration {
						max_session_duration = *permission.SSH.MaxSessionDurationSeconds
					}
				}
			}
		}

		if max_session_duration > 0 {
			go func() {
				select {
				case <-time.After(time.Duration(max_session_duration) * time.Second):
					metadata, err := json.Marshal(struct {
						SessionDuration int    `json:"session_duration"`
						User            string `json:"user"`
					}{max_session_duration, s.sshClientConfig.User})

					if err != nil {
						s.logger.Error("failed to create session event", zap.Error(err))
					} else {
						if err := s.config.Border0API.CreateSessionEvent(models.SessionEvent{
							SessionKey: s.metadata.SessionKey,
							Socket:     s.config.Socket,
							Type:       "ssh_session_duration",
							Status:     "denied",
							Metadata:   string(metadata),
						}); err != nil {
							s.logger.Error("failed to create session event", zap.Error(err))
						}

						cancel()
					}
				case <-ctx.Done():
				}
			}()
		}
	}

	upstreamConn, err := net.DialTimeout("tcp", net.JoinHostPort(s.config.Hostname, strconv.Itoa(s.config.Port)), 5*time.Second)
	if err != nil {
		return fmt.Errorf("unable to connect to upstream host: %s", err)
	}

	s.upstreamSshConn, s.upstreamSshChans, s.upstreamSshReqs, err = ssh.NewClientConn(upstreamConn, "", s.sshClientConfig)
	if err != nil {
		return fmt.Errorf("unable to create ssh connection: %s", err)
	}

	s.upstreamSshClient = ssh.NewClient(s.upstreamSshConn, s.upstreamSshChans, s.upstreamSshReqs)

	defer s.upstreamSshConn.Close()
	go ssh.DiscardRequests(s.upstreamSshReqs)
	go s.keepAlive(ctx)

	for {
		select {
		case newChannel := <-s.downstreamSshChans:
			if newChannel == nil {
				return nil
			}

			switch newChannel.ChannelType() {
			case "session":
				go s.handleSessionChannel(ctx, newChannel)
			case "direct-tcpip":
				go s.handleDirectTcpipChannel(newChannel)
			default:
				newChannel.Reject(ssh.UnknownChannelType, fmt.Sprintf("unknown channel type: %s", newChannel.ChannelType()))
				if err := s.errorEvent("ssh_channel", fmt.Sprintf("unknown channel type: %s", newChannel.ChannelType())); err != nil {
					s.logger.Error("failed to create session event", zap.Error(err))
				}
			}
		case newChannel := <-s.upstreamSshChans:
			if newChannel == nil {
				return nil
			}

			switch newChannel.ChannelType() {
			default:
				if err := s.errorEvent("ssh_channel", fmt.Sprintf("unknown unknown server type: %s", newChannel.ChannelType())); err != nil {
					s.logger.Error("failed to create session event", zap.Error(err))
				}
				if err := newChannel.Reject(ssh.UnknownChannelType, fmt.Sprintf("unknown channel type: %s", newChannel.ChannelType())); err != nil {
					return err
				}

			}
		case <-ctx.Done():
			return nil
		}
	}
}

func (s *sshSession) keepAlive(ctx context.Context) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if _, _, err := s.upstreamSshConn.SendRequest("keepalive@openssh.com", true, nil); err != nil {
				if err := s.errorEvent("ssh_session", fmt.Sprintf("failed to send keepalive request: %s", err)); err != nil {
					s.logger.Error("failed to create session event", zap.Error(err))
				}

				return
			}
		}
	}
}

func (s *sshSession) handleDirectTcpipChannel(newChannel ssh.NewChannel) {
	var localForwardData localForwardChannel

	if err := ssh.Unmarshal(newChannel.ExtraData(), &localForwardData); err != nil {
		newChannel.Reject(ssh.ConnectionFailed, "failed to parse data")
		if err := s.errorEvent("ssh_tcpforward", fmt.Sprintf("failed to parse payload: %s", err)); err != nil {
			s.logger.Error("failed to create session event", zap.Error(err))
		}

		return
	}

	if s.config.Socket.IsPrimaryProxy() && !isAllowed("tcp_forwarding", "", &localForwardData, s.metadata.AllowedActions, s.logger) {
		newChannel.Reject(ssh.ConnectionFailed, "tcp_forwarding access denied by policy")

		metadata, err := json.Marshal(localForwardData)
		if err != nil {
			s.logger.Error("failed to create session event", zap.Error(err))
			return
		}

		if err := s.config.Border0API.CreateSessionEvent(models.SessionEvent{
			SessionKey: s.metadata.SessionKey,
			Socket:     s.config.Socket,
			Type:       "ssh_tcpforward",
			Status:     "denied",
			Metadata:   string(metadata),
		}); err != nil {
			s.logger.Error("failed to create session event", zap.Error(err))
		}

		return
	}
	upstreamChannel, _, err := s.upstreamSshConn.OpenChannel("direct-tcpip", newChannel.ExtraData())
	if err != nil {
		if sshErr, ok := err.(*ssh.OpenChannelError); ok {
			newChannel.Reject(sshErr.Reason, sshErr.Message)
			metadata, err := json.Marshal(struct {
				Error   string              `json:"error"`
				Payload localForwardChannel `json:"payload"`
			}{fmt.Sprintf("failed to open channel %s: %s", sshErr.Reason, sshErr.Message), localForwardData})
			if err != nil {
				s.logger.Error("failed to create session event", zap.Error(err))
				return
			}

			if err := s.config.Border0API.CreateSessionEvent(models.SessionEvent{
				SessionKey: s.metadata.SessionKey,
				Socket:     s.config.Socket,
				Type:       "ssh_tcpforward",
				Status:     "error",
				Metadata:   string(metadata),
			}); err != nil {
				s.logger.Error("failed to create session event", zap.Error(err))
			}
		} else {
			newChannel.Reject(ssh.ConnectionFailed, fmt.Sprintf("Could not connect to destination host: %s", err))
			metadata, err := json.Marshal(struct {
				Error   string              `json:"error"`
				Payload localForwardChannel `json:"payload"`
			}{fmt.Sprintf("failed to open channel %s", err), localForwardData})
			if err != nil {
				s.logger.Error("failed to create session event", zap.Error(err))
				return
			}

			if err := s.config.Border0API.CreateSessionEvent(models.SessionEvent{
				SessionKey: s.metadata.SessionKey,
				Socket:     s.config.Socket,
				Type:       "ssh_tcpforward",
				Status:     "error",
				Metadata:   string(metadata),
			}); err != nil {
				s.logger.Error("failed to create session event", zap.Error(err))
			}
		}
		return
	}

	defer upstreamChannel.Close()

	sshChannel, _, err := newChannel.Accept()
	if err != nil {
		metadata, err := json.Marshal(struct {
			Error   string              `json:"error"`
			Payload localForwardChannel `json:"payload"`
		}{fmt.Errorf("failed to accept channel: %w", err).Error(), localForwardData})
		if err != nil {
			s.logger.Error("failed to create session event", zap.Error(err))
			return
		}

		if err := s.config.Border0API.CreateSessionEvent(models.SessionEvent{
			SessionKey: s.metadata.SessionKey,
			Socket:     s.config.Socket,
			Type:       "ssh_tcpforward",
			Status:     "error",
			Metadata:   string(metadata),
		}); err != nil {
			s.logger.Error("failed to create session event", zap.Error(err))
		}

		return
	}
	defer sshChannel.Close()

	metadata, err := json.Marshal(localForwardData)
	if err != nil {
		s.logger.Error("failed to create session event", zap.Error(err))
	} else {
		if err := s.config.Border0API.CreateSessionEvent(models.SessionEvent{
			SessionKey: s.metadata.SessionKey,
			Socket:     s.config.Socket,
			Type:       "ssh_tcpforward",
			Status:     "success",
			Metadata:   string(metadata),
		}); err != nil {
			s.logger.Error("failed to create session event", zap.Error(err))
		}
	}

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer sshChannel.CloseWrite()
		defer wg.Done()
		io.Copy(sshChannel, upstreamChannel)
	}()

	go func() {
		defer upstreamChannel.Close()
		defer wg.Done()
		io.Copy(upstreamChannel, sshChannel)
	}()

	wg.Wait()
}

func (s *sshSession) handleSessionChannel(ctx context.Context, newChannel ssh.NewChannel) {
	channel := &sshChannel{
		sshSession: s,
		width:      80,
		height:     24,
	}

	upstreamSession, err := s.upstreamSshClient.NewSession()
	if err != nil {
		newChannel.Reject(ssh.ConnectionFailed, fmt.Sprintf("failed to open upstream channel (%s)", err))
		if err := s.errorEvent("ssh_session", fmt.Sprintf("failed to open upstream session: %s", err)); err != nil {
			s.logger.Error("failed to create session event", zap.Error(err))
		}

		return
	}

	channel.upstreamSession = upstreamSession
	defer upstreamSession.Close()

	downstreamChannel, downstreamChannelRequests, err := newChannel.Accept()
	if err != nil {
		if err := s.errorEvent("ssh_session", fmt.Sprintf("failed to accept channel: %s", err)); err != nil {
			s.logger.Error("failed to create session event", zap.Error(err))
		}
		return
	}

	metadata, err := json.Marshal(struct {
		ChannelType   string `json:"channel_type"`
		User          string `json:"user"`
		ClientVersion string `json:"client_version"`
	}{newChannel.ChannelType(), s.sshClientConfig.User, string(s.downstreamSshConn.ClientVersion())})
	if err != nil {
		s.logger.Error("failed to create session event", zap.Error(err))
		return
	}

	if err := s.config.Border0API.CreateSessionEvent(models.SessionEvent{
		SessionKey: s.metadata.SessionKey,
		Socket:     s.config.Socket,
		Type:       "ssh_session",
		Status:     "success",
		Metadata:   string(metadata),
	}); err != nil {
		s.logger.Error("failed to create session event", zap.Error(err))
	}

	channel.downstreamChannel = downstreamChannel
	defer downstreamChannel.Close()

	for {
		select {
		case <-ctx.Done():
			return
		case req := <-downstreamChannelRequests:
			if req == nil {
				return
			}

			channel.handleRequest(req)
		}
	}
}

func (s *sshChannel) handleRequest(req *ssh.Request) {
	switch req.Type {
	case "env":
		if _, err := s.upstreamSession.SendRequest(req.Type, req.WantReply, req.Payload); err != nil {
			s.logger.Error("failed to send request", zap.Error(err))
			req.Reply(false, nil)
			return
		}

		if req.WantReply {
			req.Reply(true, nil)
		}
	case "pty-req":
		if _, err := s.upstreamSession.SendRequest(req.Type, req.WantReply, req.Payload); err != nil {
			s.logger.Error("failed to send request", zap.Error(err))
			req.Reply(false, nil)
			return
		}

		termLen := req.Payload[3]
		w, h := common.ParseDims(req.Payload[termLen+4:])
		s.width = int(w)
		s.height = int(h)

		if req.WantReply {
			req.Reply(true, nil)
		}
		s.pty = true
	case "window-change":
		if _, err := s.upstreamSession.SendRequest(req.Type, req.WantReply, req.Payload); err != nil {
			s.logger.Error("failed to send request", zap.Error(err))
			req.Reply(false, nil)
			return
		}
		w, h := common.ParseDims(req.Payload)
		s.width = int(w)
		s.height = int(h)

		if req.WantReply {
			req.Reply(true, nil)
		}
	case "subsystem":
		if string(req.Payload[4:]) == "sftp" {
			go s.handleSftp(req)
		} else {
			req.Reply(false, nil)
			if err := s.errorEvent("ssh_subsystem", fmt.Sprintf("unknown subsystem: %s", string(req.Payload[4:]))); err != nil {
				s.logger.Error("failed to create session event", zap.Error(err))
			}
		}
	case "exec":
		go s.handleExec(req)
	case "shell":
		go s.handleShell(req)
	default:
		if req.WantReply {
			req.Reply(false, nil)
		}
	}
}

func (s *sshChannel) handleSftp(req *ssh.Request) {
	if s.config.Socket.IsPrimaryProxy() && !isAllowed("sftp", "", nil, s.metadata.AllowedActions, s.logger) {
		if err := req.Reply(false, nil); err != nil {
			s.logger.Error("failed to reply to request", zap.Error(err))
		}

		s.downstreamChannel.Stderr().Write([]byte("Request not allowed\n"))

		metadata, err := json.Marshal(struct {
			User          string `json:"user"`
			ClientVersion string `json:"client_version"`
		}{s.sshClientConfig.User, string(s.downstreamSshConn.ClientVersion())})
		if err != nil {
			s.logger.Error("failed to create session event", zap.Error(err))
			return
		}

		if err := s.config.Border0API.CreateSessionEvent(models.SessionEvent{
			SessionKey: s.metadata.SessionKey,
			Socket:     s.config.Socket,
			Type:       "ssh_sftp",
			Status:     "denied",
			Metadata:   string(metadata),
		}); err != nil {
			s.logger.Error("failed to create session event", zap.Error(err))
		}

		return
	}

	defer s.upstreamSession.Close()

	upstreamStdin, upstreamStdout, upstreamStderr, err := s.setupPipes(s.upstreamSession)
	if err != nil {
		req.Reply(false, []byte(fmt.Sprint(err)))
		return
	}

	metadata, err := json.Marshal(struct {
		User          string `json:"user"`
		ClientVersion string `json:"client_version"`
	}{s.sshClientConfig.User, string(s.downstreamSshConn.ClientVersion())})
	if err != nil {
		s.logger.Error("failed to create session event", zap.Error(err))
	} else {
		if err := s.config.Border0API.CreateSessionEvent(models.SessionEvent{
			SessionKey: s.metadata.SessionKey,
			Socket:     s.config.Socket,
			Type:       "ssh_sftp",
			Status:     "success",
			Metadata:   string(metadata),
		}); err != nil {
			s.logger.Error("failed to create session event", zap.Error(err))
		}
	}

	if s.config.IsRecordingEnabled() {
		r, err := s.record(nil)
		if err != nil {
			if err := s.errorEvent("ssh_recording", fmt.Sprintf("failed to record session: %s", err)); err != nil {
				s.logger.Error("failed to create session event", zap.Error(err))
			}
			return
		}

		s.sessionWriter.Write([]byte(fmt.Sprintf("starting a %s session\n", string(req.Payload[4:]))))
		defer r.Stop()
	}

	var wg sync.WaitGroup
	wg.Add(3)

	go func() {
		defer wg.Done()
		defer upstreamStdin.Close()
		io.Copy(upstreamStdin, s.downstreamChannel)
	}()

	go func() {
		defer wg.Done()
		defer closeChannel(s.downstreamChannel, err)
		io.Copy(s.downstreamChannel, upstreamStdout)
	}()

	go func() {
		defer wg.Done()
		io.Copy(s.downstreamChannel.Stderr(), upstreamStderr)
	}()

	var ok bool
	ok, err = s.upstreamSession.SendRequest(req.Type, req.WantReply, req.Payload)
	if err != nil {
		if err := s.errorEvent("ssh_sftp", fmt.Sprintf("failed to start sftp session: %s", err)); err != nil {
			s.logger.Error("failed to create session event", zap.Error(err))
		}

		req.Reply(false, []byte(fmt.Sprint(err)))
		return
	}

	if req.WantReply {
		req.Reply(ok, nil)
	}

	wg.Wait()
}

func (s *sshChannel) handleExec(req *ssh.Request) {
	command := string(req.Payload[4:])

	if s.config.Socket.IsPrimaryProxy() && !isAllowed(req.Type, command, nil, s.metadata.AllowedActions, s.logger) {
		if err := req.Reply(false, nil); err != nil {
			s.logger.Error("failed to reply to request", zap.Error(err))
		}

		s.downstreamChannel.Stderr().Write([]byte("Request not allowed\n"))

		metadata, err := json.Marshal(struct {
			User          string `json:"user"`
			ClientVersion string `json:"client_version"`
			Command       string `json:"command,omitempty"`
		}{s.sshClientConfig.User, string(s.downstreamSshConn.ClientVersion()), command})
		if err != nil {
			s.logger.Error("failed to create session event", zap.Error(err))
			return
		}

		if err := s.config.Border0API.CreateSessionEvent(models.SessionEvent{
			SessionKey: s.metadata.SessionKey,
			Socket:     s.config.Socket,
			Type:       fmt.Sprintf("ssh_%s", req.Type),
			Status:     "denied",
			Metadata:   string(metadata),
		}); err != nil {
			s.logger.Error("failed to create session event", zap.Error(err))
		}

		return
	}

	defer s.upstreamSession.Close()

	upstreamStdin, upstreamStdout, upstreamStderr, err := s.setupPipes(s.upstreamSession)
	if err != nil {
		req.Reply(false, []byte(fmt.Sprint(err)))
		return
	}

	metadata, err := json.Marshal(struct {
		Username      string `json:"username"`
		Pty           bool   `json:"pty"`
		Command       string `json:"command,omitempty"`
		ClientVersion string `json:"client_version"`
	}{Username: s.sshClientConfig.User, Pty: s.pty, Command: command, ClientVersion: string(s.downstreamSshConn.ClientVersion())})
	if err != nil {
		s.logger.Error("failed to create session event", zap.Error(err))
	} else {
		if err := s.config.Border0API.CreateSessionEvent(models.SessionEvent{
			SessionKey: s.metadata.SessionKey,
			Socket:     s.config.Socket,
			Type:       fmt.Sprintf("ssh_%s", req.Type),
			Status:     "success",
			Metadata:   string(metadata),
		}); err != nil {
			s.logger.Error("failed to create session event", zap.Error(err))
		}
	}

	if s.config.IsRecordingEnabled() {
		r, err := s.record(&upstreamStdout)
		if err != nil {
			if err := s.errorEvent("ssh_recording", fmt.Sprintf("failed to record session: %s", err)); err != nil {
				s.logger.Error("failed to create session event", zap.Error(err))
			}
			return
		}

		s.sessionWriter.Write([]byte(fmt.Sprintf("%s\n", command)))
		defer r.Stop()
	}

	var wg sync.WaitGroup
	wg.Add(3)

	go func() {
		defer wg.Done()
		defer upstreamStdin.Close()
		io.Copy(upstreamStdin, s.downstreamChannel)
	}()

	go func() {
		defer wg.Done()
		defer closeChannel(s.downstreamChannel, err)
		io.Copy(s.downstreamChannel, upstreamStdout)
	}()

	go func() {
		defer wg.Done()
		io.Copy(s.downstreamChannel.Stderr(), upstreamStderr)
	}()

	runErr := s.upstreamSession.Run(command)
	if runErr != nil {
		if err := s.errorEvent("ssh_shell", fmt.Sprintf("failed to request exec: %s", runErr)); err != nil {
			s.logger.Error("failed to create session event", zap.Error(err))
		}
	}

	wg.Wait()
}

func (s *sshChannel) handleShell(req *ssh.Request) {
	if s.config.Socket.IsPrimaryProxy() && !isAllowed(req.Type, "", nil, s.metadata.AllowedActions, s.logger) {
		if err := req.Reply(false, nil); err != nil {
			s.logger.Error("failed to reply to request", zap.Error(err))
		}

		s.downstreamChannel.Stderr().Write([]byte("Request not allowed\n"))

		metadata, err := json.Marshal(struct {
			User          string `json:"user"`
			ClientVersion string `json:"client_version"`
		}{s.sshClientConfig.User, string(s.downstreamSshConn.ClientVersion())})
		if err != nil {
			s.logger.Error("failed to create session event", zap.Error(err))
			return
		}

		if err := s.config.Border0API.CreateSessionEvent(models.SessionEvent{
			SessionKey: s.metadata.SessionKey,
			Socket:     s.config.Socket,
			Type:       fmt.Sprintf("ssh_%s", req.Type),
			Status:     "denied",
			Metadata:   string(metadata),
		}); err != nil {
			s.logger.Error("failed to create session event", zap.Error(err))
		}

		return
	}

	defer s.upstreamSession.Close()

	metadata, err := json.Marshal(struct {
		Username      string `json:"username"`
		Pty           bool   `json:"pty"`
		Command       string `json:"command,omitempty"`
		ClientVersion string `json:"client_version"`
	}{Username: s.sshClientConfig.User, Pty: s.pty, ClientVersion: string(s.downstreamSshConn.ClientVersion())})
	if err != nil {
		s.logger.Error("failed to create session event", zap.Error(err))
	} else {
		if err := s.config.Border0API.CreateSessionEvent(models.SessionEvent{
			SessionKey: s.metadata.SessionKey,
			Socket:     s.config.Socket,
			Type:       fmt.Sprintf("ssh_%s", req.Type),
			Status:     "success",
			Metadata:   string(metadata),
		}); err != nil {
			s.logger.Error("failed to create session event", zap.Error(err))
		}
	}

	upstreamStdin, upstreamStdout, upstreamStderr, err := s.setupPipes(s.upstreamSession)
	if err != nil {
		req.Reply(false, []byte(fmt.Sprint(err)))
		return
	}

	if s.config.IsRecordingEnabled() {
		r, err := s.record(&upstreamStdout)
		if err != nil {
			if err := s.errorEvent("ssh_recording", fmt.Sprintf("failed to record session: %s", err)); err != nil {
				s.logger.Error("failed to create session event", zap.Error(err))
			}
			return
		}

		defer r.Stop()
	}

	var wg sync.WaitGroup
	wg.Add(3)

	go func() {
		defer wg.Done()
		defer upstreamStdin.Close()
		io.Copy(upstreamStdin, s.downstreamChannel)
	}()

	go func() {
		defer wg.Done()
		defer closeChannel(s.downstreamChannel, err)
		io.Copy(s.downstreamChannel, upstreamStdout)
	}()

	go func() {
		defer wg.Done()
		io.Copy(s.downstreamChannel.Stderr(), upstreamStderr)
	}()

	var ok bool
	ok, err = s.upstreamSession.SendRequest(req.Type, req.WantReply, req.Payload)
	if err != nil {
		if err := s.errorEvent("ssh_shell", fmt.Sprintf("failed to request shell: %s", err)); err != nil {
			s.logger.Error("failed to create session event", zap.Error(err))
		}

		req.Reply(false, []byte(fmt.Sprint(err)))
		return
	}

	if req.WantReply {
		req.Reply(ok, nil)
	}

	wg.Wait()
}

func closeChannel(downstreamChannel ssh.Channel, err error) {
	var exitStatus int
	if err != nil {
		if sshErr, ok := err.(*ssh.ExitError); ok {
			exitStatus = sshErr.ExitStatus()
		} else {
			if err != io.EOF {
				exitStatus = -1
			}
		}
	}

	status := struct {
		Status uint32
	}{
		Status: uint32(exitStatus),
	}

	downstreamChannel.SendRequest("exit-status", false, ssh.Marshal(&status))
	downstreamChannel.Close()
}

func (s *sshChannel) record(reader *io.Reader) (*recorder.AsciinemaRecorder, error) {
	pr, pw := io.Pipe()
	s.sessionWriter = pw

	if reader != nil {
		*reader = io.TeeReader(*reader, pw)
	}

	recorderOpts := []recorder.AsciinemaRecorderOption{
		recorder.WithAsciinemaHeight(s.height),
		recorder.WithAsciinemaWidth(s.width),
	}
	r := recorder.NewAsciinemaRecorder(s.logger, s.config.Border0API, pr, s.config.Socket.SocketID, s.metadata.SessionKey, recorderOpts...)

	if err := r.Record(); err != nil {
		return nil, err
	}

	return r, nil
}

func (s *sshSession) userPublicKeyCallback() ([]ssh.Signer, error) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate private key: %s", err)
	}

	sshPublicKey, err := ssh.NewPublicKey(privateKey.Public())
	if err != nil {
		return nil, fmt.Errorf("failed to generate public key: %s", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	signedSshCert, err := s.config.Border0API.SignSshOrgCertificate(ctx, s.config.Socket.SocketID, s.metadata.SessionKey, s.metadata.UserEmail, s.metadata.SshTicket, ssh.MarshalAuthorizedKey(sshPublicKey))
	if err != nil {
		return nil, fmt.Errorf("failed to fetch signed ssh org certificate %s", err)
	}

	pubcert, _, _, _, err := ssh.ParseAuthorizedKey([]byte(signedSshCert))
	if err != nil {
		return nil, fmt.Errorf("failed to parse authorized key: %s", err)
	}

	sshCert, ok := pubcert.(*ssh.Certificate)
	if !ok {
		return nil, fmt.Errorf("failed to cast to ssh certificate")
	}

	signer, err := ssh.NewSignerFromKey(privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to generate signer: %s", err)
	}

	certSigner, err := ssh.NewCertSigner(sshCert, signer)
	if err != nil {
		return nil, fmt.Errorf("failed to generate cert signer: %s", err)
	}

	return []ssh.Signer{certSigner}, nil
}

func (s *sshSession) errorEvent(eventType string, message string) error {
	var clientVersion string
	if s.downstreamSshConn != nil {
		clientVersion = string(s.downstreamSshConn.ClientVersion())
	}

	metadata, err := json.Marshal(struct {
		User          string `json:"user,omitempty"`
		ClientVersion string `json:"client_version,omitempty"`
		Error         string `json:"error"`
	}{s.sshClientConfig.User, clientVersion, message})
	if err != nil {
		return err
	}

	return s.config.Border0API.CreateSessionEvent(models.SessionEvent{
		SessionKey: s.metadata.SessionKey,
		Socket:     s.config.Socket,
		Type:       eventType,
		Status:     "error",
		Metadata:   string(metadata),
	})
}
