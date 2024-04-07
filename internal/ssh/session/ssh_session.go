package session

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/ec2instanceconnect"
	"github.com/borderzero/border0-cli/internal/api/models"
	"github.com/borderzero/border0-cli/internal/border0"
	"github.com/borderzero/border0-cli/internal/ssh/config"
	"github.com/borderzero/border0-cli/internal/ssh/session/common"
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
	metadata           *border0.E2EEncryptionMetadata
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

	if len(config.IdentityPrivateKey) > 0 {
		signer, err := ssh.ParsePrivateKey(config.IdentityPrivateKey)
		if err != nil {
			return nil, fmt.Errorf("failed to parse identity private key: %s", err)
		}

		authMethods = append(authMethods, ssh.PublicKeys(signer))
	}

	if config.Password != "" {
		authMethods = append(authMethods, ssh.Password(config.Password))
	}

	if len(authMethods) == 0 {
		if !config.EndToEndEncryption {
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

	if s.config.EndToEndEncryption {
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
		)

		if s.config.Border0CertAuth {
			session.sshClientConfig.Auth = []ssh.AuthMethod{ssh.
				PublicKeysCallback(session.userPublicKeyCallback)}
		}
	}

	var err error
	session.downstreamSshConn, session.downstreamSshChans, session.downstreamSshReqs, err = ssh.NewServerConn(conn, session.config.SshServerConfig)
	if err != nil {
		session.logger.Error("failed to accept ssh connection", zap.Error(err))
		return
	}

	if session.config.EndToEndEncryption {
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
			session.logger.Error("failed to setup ec2 connect", zap.Error(err))
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
		session.logger.Error("failed to handle channels", zap.Error(err))
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

	upstreamConn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", s.config.Hostname, s.config.Port), 5*time.Second)
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
				go s.handleSessionChannel(ctx, cancel, newChannel)
			case "direct-tcpip":
				go s.handleDirectTcpipChannel(ctx, cancel, newChannel)
			default:
				s.logger.Error("unknown client channel type", zap.String("channel_type", newChannel.ChannelType()))
				if err := newChannel.Reject(ssh.UnknownChannelType, fmt.Sprintf("unknown channel type: %s", newChannel.ChannelType())); err != nil {
					return err
				}
			}
		case newChannel := <-s.upstreamSshChans:
			if newChannel == nil {
				return nil
			}

			switch newChannel.ChannelType() {
			default:
				s.logger.Error("unknown server channel type", zap.String("channel_type", newChannel.ChannelType()))
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
				s.logger.Error("failed to send keepalive request", zap.Error(err))
				return
			}
		}
	}
}

func (s *sshSession) handleDirectTcpipChannel(ctx context.Context, cancel context.CancelFunc, newChannel ssh.NewChannel) {
	upstreamChannel, _, err := s.upstreamSshConn.OpenChannel("direct-tcpip", newChannel.ExtraData())
	if err != nil {
		if sshErr, ok := err.(*ssh.OpenChannelError); ok {
			newChannel.Reject(sshErr.Reason, sshErr.Message)
		} else {
			newChannel.Reject(ssh.ConnectionFailed, fmt.Sprintf("Could not connect to destination host: %s", err))
		}
	}

	defer upstreamChannel.Close()

	sshChannel, _, err := newChannel.Accept()
	if err != nil {
		log.Printf("Could not accept channel: %v", err)
		return
	}
	defer sshChannel.Close()

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

func (s *sshSession) handleSessionChannel(ctx context.Context, cancel context.CancelFunc, newChannel ssh.NewChannel) {
	channel := &sshChannel{
		sshSession: s,
		width:      80,
		height:     24,
	}

	upstreamSession, err := s.upstreamSshClient.NewSession()
	if err != nil {
		s.logger.Error("failed to open upstream session", zap.Error(err))
		newChannel.Reject(ssh.ConnectionFailed, fmt.Sprintf("failed to open upstream channel (%s)", err))
		return
	}

	channel.upstreamSession = upstreamSession
	defer upstreamSession.Close()

	downstreamChannel, downstreamChannelRequests, err := newChannel.Accept()
	if err != nil {
		s.logger.Error("failed to accept channel", zap.Error(err))
		return
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
			s.logger.Error("unknown subsystem", zap.String("subsystem", string(req.Payload[4:])))
			req.Reply(false, nil)
		}
	case "exec":
		go s.handleExec(req)
	case "shell":
		go s.handleShell(req)
	default:
		s.logger.Error("unknown request type", zap.String("request_type", req.Type))
		req.Reply(false, nil)
	}
}

func (s *sshChannel) handleSftp(req *ssh.Request) {
	defer s.upstreamSession.Close()

	upstreamStdin, upstreamStdout, upstreamStderr, err := s.setupPipes(s.upstreamSession)
	if err != nil {
		req.Reply(false, []byte(fmt.Sprint(err)))
		return
	}

	if s.config.IsRecordingEnabled() {
		r, err := s.record(nil)
		if err != nil {
			s.logger.Error("failed to record session", zap.Error(err))
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
		req.Reply(false, []byte(fmt.Sprint(err)))
		return
	}

	if req.WantReply {
		req.Reply(ok, nil)
	}

	wg.Wait()
}

func (s *sshChannel) handleExec(req *ssh.Request) {
	defer s.upstreamSession.Close()

	upstreamStdin, upstreamStdout, upstreamStderr, err := s.setupPipes(s.upstreamSession)
	if err != nil {
		req.Reply(false, []byte(fmt.Sprint(err)))
		return
	}

	command := string(req.Payload[4:])

	if s.config.IsRecordingEnabled() {
		r, err := s.record(&upstreamStdout)
		if err != nil {
			s.logger.Error("failed to record session", zap.Error(err))
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

	err = s.upstreamSession.Run(command)

	wg.Wait()
}

func (s *sshChannel) handleShell(req *ssh.Request) {
	defer s.upstreamSession.Close()

	upstreamStdin, upstreamStdout, upstreamStderr, err := s.setupPipes(s.upstreamSession)
	if err != nil {
		req.Reply(false, []byte(fmt.Sprint(err)))
		return
	}

	if s.config.IsRecordingEnabled() {
		r, err := s.record(&upstreamStdout)
		if err != nil {
			s.logger.Error("failed to record session", zap.Error(err))
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

func (s *sshChannel) record(reader *io.Reader) (*common.Recording, error) {
	pr, pw := io.Pipe()
	s.sessionWriter = pw

	if reader != nil {
		*reader = io.TeeReader(*reader, pw)
	}

	r := common.NewRecording(s.logger, pr, s.config.Socket.SocketID, s.metadata.SessionKey, s.config.Border0API, s.width, s.height)

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
