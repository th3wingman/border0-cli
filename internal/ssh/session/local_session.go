package session

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"os/user"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/borderzero/border0-cli/internal/api/models"
	"github.com/borderzero/border0-cli/internal/border0"
	"github.com/borderzero/border0-cli/internal/ssh/config"
	"github.com/borderzero/border0-cli/internal/ssh/server"
	"github.com/borderzero/border0-cli/internal/ssh/session/common"
	"github.com/borderzero/border0-cli/internal/util/recorder"
	"github.com/borderzero/border0-go/lib/types/pointer"
	gliderlabs_ssh "github.com/gliderlabs/ssh"
	"go.uber.org/zap"
	"golang.org/x/crypto/ssh"
)

type localSessionHandler struct {
	logger *zap.Logger
	config *config.ProxyConfig
}

type localForwardChannel struct {
	DestAddr   string `json:"dest_addr"`
	DestPort   uint32 `json:"dest_port"`
	OriginAddr string `json:"origin_addr"`
	OriginPort uint32 `json:"origin_port"`
}

// ensure localSessionHandler implements SessionHandler.
var _ SessionHandler = (*localSessionHandler)(nil)

type localSession struct {
	config             *config.ProxyConfig
	metadata           *border0.ConnMetadata
	sshServerConfig    *ssh.ServerConfig
	logger             *zap.Logger
	username           string
	downstreamSshConn  *ssh.ServerConn
	downstreamSshChans <-chan ssh.NewChannel
	downstreamSshReqs  <-chan *ssh.Request
}

type localChannel struct {
	*localSession
	downstreamChannel ssh.Channel
	window            gliderlabs_ssh.Window
	env               []string
	pty               bool
	ptyTerm           string
	winch             chan gliderlabs_ssh.Window
}

func NewLocalSessionHandler(logger *zap.Logger, config *config.ProxyConfig) *localSessionHandler {
	return &localSessionHandler{
		config: config,
		logger: logger,
	}
}

func (s *localSessionHandler) Proxy(conn net.Conn) {
	defer conn.Close()

	session := &localSession{
		logger:          s.logger,
		config:          s.config,
		sshServerConfig: s.config.SshServerConfig,
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
	case s.config.EndToEndEncryption:
		e2EEncryptionConn, ok := conn.(border0.E2EEncryptionConn)
		if !ok {
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
	default:
		session.metadata = &border0.ConnMetadata{}
	}

	var err error
	session.downstreamSshConn, session.downstreamSshChans, session.downstreamSshReqs, err = ssh.NewServerConn(conn, session.config.SshServerConfig)
	if err != nil {
		if lastError != nil {
			err = lastError
		}
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

	if s.config.Username != "" {
		session.username = s.config.Username
	} else {
		session.username = session.downstreamSshConn.User()
	}

	if session.config.Socket.IsPrimaryProxy() {
		if err := session.config.Border0API.UpdateSession(models.SessionUpdate{
			SessionKey: session.metadata.SessionKey,
			Socket:     session.config.Socket,
			UserData:   ",sshuser=" + session.username,
		}); err != nil {
			session.logger.Error("failed to update session", zap.Error(err))
			return
		}
	}

	go ssh.DiscardRequests(session.downstreamSshReqs)

	session.handleChannels()
}

func (s *localSession) handleChannels() {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	defer s.downstreamSshConn.Close()

	var max_session_duration int
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
				}{max_session_duration, s.username})

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

	for {
		select {
		case newChannel, ok := <-s.downstreamSshChans:
			if !ok {
				return
			}

			switch newChannel.ChannelType() {
			case "session":
				go s.handleSessionChannel(ctx, newChannel)
			case "direct-tcpip":
				go s.handleDirectTcpipChannel(ctx, newChannel)
			default:
				newChannel.Reject(ssh.UnknownChannelType, fmt.Sprintf("unknown channel type: %s", newChannel.ChannelType()))
				if err := s.errorEvent("ssh_channel", fmt.Sprintf("unknown channel type: %s", newChannel.ChannelType())); err != nil {
					s.logger.Error("failed to create session event", zap.Error(err))
				}
			}
		case <-ctx.Done():
			return
		}
	}
}

func (s *localSession) handleDirectTcpipChannel(ctx context.Context, newChannel ssh.NewChannel) {
	var localForwardData localForwardChannel

	if err := ssh.Unmarshal(newChannel.ExtraData(), &localForwardData); err != nil {
		newChannel.Reject(ssh.ConnectionFailed, "failed to parse payload")

		if err := s.errorEvent("ssh_tcpforward", fmt.Sprintf("failed to parse payload: %s", err)); err != nil {
			s.logger.Error("failed to create session event", zap.Error(err))
		}

		return
	}

	if s.config.EndToEndEncryption && !isAllowed("tcp_forwarding", "", &localForwardData, s.metadata.AllowedActions, s.logger) {
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

	var dialer net.Dialer
	dialer.Timeout = time.Second * 5
	conn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(localForwardData.DestAddr, strconv.Itoa(int(localForwardData.DestPort))))
	if err != nil {
		newChannel.Reject(ssh.ConnectionFailed, err.Error())

		metadata, err := json.Marshal(struct {
			Error   string              `json:"error"`
			Payload localForwardChannel `json:"payload"`
		}{fmt.Errorf("connection failed: %w", err).Error(), localForwardData})
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

	defer conn.Close()

	sshChannel, reqs, err := newChannel.Accept()
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

	go ssh.DiscardRequests(reqs)

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		defer sshChannel.Close()
		defer conn.Close()

		io.Copy(sshChannel, conn)
	}()

	go func() {
		defer wg.Done()
		defer sshChannel.Close()
		defer conn.Close()

		io.Copy(conn, sshChannel)
	}()

	wg.Wait()
}

func (s *localSession) handleSessionChannel(ctx context.Context, newChannel ssh.NewChannel) {
	channel := &localChannel{
		localSession: s,
	}

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
	}{newChannel.ChannelType(), s.username, string(s.downstreamSshConn.ClientVersion())})
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

			channel.handleRequest(ctx, req)
		}
	}
}

func (c *localChannel) handleRequest(ctx context.Context, req *ssh.Request) {
	switch req.Type {
	case "env":
		var env struct{ Key, Value string }
		ssh.Unmarshal(req.Payload, &env)
		c.env = append(c.env, fmt.Sprintf("%s=%s", env.Key, env.Value))
		req.Reply(true, nil)
	case "pty-req":
		if c.pty {
			req.Reply(false, nil)
			return
		}

		if len(req.Payload) < 4 {
			req.Reply(false, nil)
			return
		}

		length := binary.BigEndian.Uint32(req.Payload)
		if uint32(len(req.Payload)) < 4+length {
			req.Reply(false, nil)
			return
		}

		c.ptyTerm = string(req.Payload[4 : 4+length])
		w, h := common.ParseDims(req.Payload[length+4:])
		c.window.Width = int(w)
		c.window.Height = int(h)
		c.winch = make(chan gliderlabs_ssh.Window, 1)
		c.winch <- c.window
		c.pty = true
		req.Reply(true, nil)
	case "window-change":
		if !c.pty {
			req.Reply(false, nil)
			return
		}

		w, h := common.ParseDims(req.Payload)
		c.window.Width = int(w)
		c.window.Height = int(h)
		c.winch <- c.window
		if req.WantReply {
			req.Reply(true, nil)
		}
	case "subsystem":
		if string(req.Payload[4:]) == "sftp" {
			go c.handleSftp(req)
		} else {
			req.Reply(false, nil)
			if err := c.errorEvent("ssh_subsystem", fmt.Sprintf("unknown subsystem: %s", string(req.Payload[4:]))); err != nil {
				c.logger.Error("failed to create session event", zap.Error(err))
			}
		}
	case "exec", "shell":
		go c.handleExec(ctx, req)
	default:
		if req.WantReply {
			req.Reply(false, nil)
		}
	}
}

func (c *localChannel) handleSftp(req *ssh.Request) {
	if c.config.EndToEndEncryption && !isAllowed("sftp", "", nil, c.metadata.AllowedActions, c.logger) {
		req.Reply(false, nil)
		c.downstreamChannel.Stderr().Write([]byte("Request not allowed\n"))

		metadata, err := json.Marshal(struct {
			User          string `json:"user"`
			ClientVersion string `json:"client_version"`
		}{c.username, string(c.downstreamSshConn.ClientVersion())})
		if err != nil {
			c.logger.Error("failed to create session event", zap.Error(err))
			return
		}

		if err := c.config.Border0API.CreateSessionEvent(models.SessionEvent{
			SessionKey: c.metadata.SessionKey,
			Socket:     c.config.Socket,
			Type:       "ssh_sftp",
			Status:     "denied",
			Metadata:   string(metadata),
		}); err != nil {
			c.logger.Error("failed to create session event", zap.Error(err))
		}

		return
	}

	defer c.downstreamChannel.Close()

	if req.WantReply {
		if err := req.Reply(true, nil); err != nil {
			return
		}
	}

	metadata, err := json.Marshal(struct {
		User          string `json:"user"`
		ClientVersion string `json:"client_version"`
	}{c.username, string(c.downstreamSshConn.ClientVersion())})
	if err != nil {
		c.logger.Error("failed to create session event", zap.Error(err))
	} else {
		if err := c.config.Border0API.CreateSessionEvent(models.SessionEvent{
			SessionKey: c.metadata.SessionKey,
			Socket:     c.config.Socket,
			Type:       "ssh_sftp",
			Status:     "success",
			Metadata:   string(metadata),
		}); err != nil {
			c.logger.Error("failed to create session event", zap.Error(err))
		}
	}

	if c.config.IsRecordingEnabled() {
		pr, pw := io.Pipe()

		recorderOpts := []recorder.AsciinemaRecorderOption{
			recorder.WithAsciinemaHeight(c.window.Height),
			recorder.WithAsciinemaWidth(c.window.Width),
		}
		r := recorder.NewAsciinemaRecorder(c.logger, c.config.Border0API, pr, c.config.Socket.SocketID, c.metadata.SessionKey, recorderOpts...)
		if err := r.Record(); err != nil {
			if err := c.errorEvent("ssh_recording", fmt.Sprintf("failed to record session: %s", err)); err != nil {
				c.logger.Error("failed to create session event", zap.Error(err))
			}

			return
		}

		pw.Write([]byte(fmt.Sprintf("starting a %s session\n", string(req.Payload[4:]))))
		defer r.Stop()
	}

	ctx := context.Background()
	processErr := server.StartChildProcess(ctx, c.downstreamChannel, "sftp", c.username)
	if processErr != nil {
		if err := c.errorEvent("ssh_sftp", fmt.Sprintf("failed to start sftp child process: %s", processErr)); err != nil {
			c.logger.Error("failed to create session event", zap.Error(err))
		}
	}

	closeChannel(c.downstreamChannel, processErr)
}

func (c *localChannel) handleExec(ctx context.Context, req *ssh.Request) {
	var payload = struct{ Value string }{}
	ssh.Unmarshal(req.Payload, &payload)
	command := payload.Value

	if c.config.Socket.IsPrimaryProxy() && !isAllowed(req.Type, command, nil, c.metadata.AllowedActions, c.logger) {
		if err := req.Reply(false, nil); err != nil {
			c.logger.Error("failed to reply to request", zap.Error(err))
		}

		c.downstreamChannel.Stderr().Write([]byte("Request not allowed\n"))

		metadata, err := json.Marshal(struct {
			User          string `json:"user"`
			ClientVersion string `json:"client_version"`
			Command       string `json:"command,omitempty"`
		}{c.username, string(c.downstreamSshConn.ClientVersion()), command})
		if err != nil {
			c.logger.Error("failed to create session event", zap.Error(err))
			return
		}

		if err := c.config.Border0API.CreateSessionEvent(models.SessionEvent{
			SessionKey: c.metadata.SessionKey,
			Socket:     c.config.Socket,
			Type:       fmt.Sprintf("ssh_%s", req.Type),
			Status:     "denied",
			Metadata:   string(metadata),
		}); err != nil {
			c.logger.Error("failed to create session event", zap.Error(err))
		}
		return
	}

	defer c.downstreamChannel.Close()

	if req.WantReply {
		if err := req.Reply(true, nil); err != nil {
			return
		}
	}

	if c.config.IsRecordingEnabled() {
		pwc := NewPipeWriteChannel(c.downstreamChannel)
		c.downstreamChannel = pwc

		recorderOpts := []recorder.AsciinemaRecorderOption{
			recorder.WithAsciinemaHeight(c.window.Height),
			recorder.WithAsciinemaWidth(c.window.Width),
		}
		r := recorder.NewAsciinemaRecorder(c.logger, c.config.Border0API, pwc.reader, c.config.Socket.SocketID, c.metadata.SessionKey, recorderOpts...)
		if err := r.Record(); err != nil {
			if err := c.errorEvent("ssh_recording", fmt.Sprintf("failed to record session: %s", err)); err != nil {
				c.logger.Error("failed to create session event", zap.Error(err))
			}

			return
		}

		if command != "" {
			pwc.logWriter.Write([]byte(fmt.Sprintf("%s\n", command)))
		}

		defer r.Stop()
	}

	user, err := user.Lookup(c.username)
	if err != nil {
		if err := c.errorEvent(fmt.Sprintf("ssh_%s", req.Type), fmt.Errorf("could not find user %s: %w", c.username, err).Error()); err != nil {
			c.logger.Error("failed to create session event", zap.Error(err))
		}

		return
	}

	shell, err := server.GetShell(user)
	if err != nil {
		if err := c.errorEvent(fmt.Sprintf("ssh_%s", req.Type), fmt.Errorf("could not get user shell: %w", err).Error()); err != nil {
			c.logger.Error("failed to create session event", zap.Error(err))
		}

		return
	}

	var cmd exec.Cmd
	cmd.Path = shell
	cmd.Args = []string{shell}

	uid, _ := strconv.ParseUint(user.Uid, 10, 32)
	gid, _ := strconv.ParseUint(user.Gid, 10, 32)

	cmd.Env = []string{
		"LANG=en_US.UTF-8",
		"HOME=" + user.HomeDir,
		"USER=" + user.Username,
		"SHELL=" + shell,
		"PATH=" + os.Getenv("PATH"),
	}

	cmd.Env = append(cmd.Env, c.env...)
	cmd.Dir = user.HomeDir

	defer func() {
		if c.winch != nil {
			close(c.winch)
		}
	}()

	metadata, err := json.Marshal(struct {
		Username      string `json:"username"`
		Pty           bool   `json:"pty"`
		Command       string `json:"command,omitempty"`
		ClientVersion string `json:"client_version"`
	}{Username: c.username, Pty: c.pty, Command: command, ClientVersion: string(c.downstreamSshConn.ClientVersion())})
	if err != nil {
		c.logger.Error("failed to create session event", zap.Error(err))
	} else {
		if err := c.config.Border0API.CreateSessionEvent(models.SessionEvent{
			SessionKey: c.metadata.SessionKey,
			Socket:     c.config.Socket,
			Type:       fmt.Sprintf("ssh_%s", req.Type),
			Status:     "success",
			Metadata:   string(metadata),
		}); err != nil {
			c.logger.Error("failed to create session event", zap.Error(err))
		}
	}

	exitStatus := server.ExecCmd(ctx, c.downstreamChannel, command, c.ptyTerm, c.pty, c.winch, cmd, uid, gid, c.username)
	status := struct{ Status uint32 }{Status: uint32(exitStatus)}
	c.downstreamChannel.SendRequest("exit-status", false, ssh.Marshal(&status))
}

func isAllowed(reqType, command string, localForward *localForwardChannel, allowedActions []any, logger *zap.Logger) bool {
	for _, allowedAction := range allowedActions {
		switch permission := allowedAction.(type) {
		case string:
			return true
		case models.Permissions:
			if permission.SSH == nil {
				continue
			}

			switch reqType {
			case "shell":
				if permission.SSH.Shell != nil {
					return true
				}
			case "sftp":
				if permission.SSH.SFTP != nil {
					return true
				}
			case "exec":
				if permission.SSH.Exec != nil {
					if permission.SSH.Exec.Commands == nil {
						return true
					}
					for _, allowedCommand := range *permission.SSH.Exec.Commands {
						re, err := regexp.Compile(allowedCommand)
						if err != nil {
							logger.Error("failed to compile allowed command regex", zap.Error(err))
							continue
						}
						if re.MatchString(command) {
							return true
						}
					}
				}
			case "tcp_forwarding":
				if permission.SSH.TCPForwarding != nil {
					if permission.SSH.TCPForwarding.AllowedConnections == nil {
						return true
					}

					if localForward == nil {
						logger.Error("localForward is nil")
						return false
					}

					for _, allowedConnection := range *permission.SSH.TCPForwarding.AllowedConnections {
						if isAllowedAddress(allowedConnection.DestinationAddress, localForward.DestAddr) &&
							isAllowedPort(allowedConnection.DestinationPort, localForward.DestPort) {
							return true
						}
					}
				}
			}
		default:
			logger.Error("unknown action type", zap.String("type", fmt.Sprintf("%T", allowedAction)))
			continue
		}
	}

	return false
}

func isAllowedAddress(addressFromPolicy *string, address string) bool {
	if addressFromPolicy == nil || *addressFromPolicy == "*" {
		return true
	}

	return strings.EqualFold(*addressFromPolicy, address)
}

func isAllowedPort(portFromPolicy *string, port uint32) bool {
	if portFromPolicy == nil || *portFromPolicy == "*" {
		return true
	}

	return *portFromPolicy == strconv.FormatUint(uint64(port), 10)
}

func (s *localSession) errorEvent(eventType string, message string) error {
	var clientVersion string
	if s.downstreamSshConn != nil {
		clientVersion = string(s.downstreamSshConn.ClientVersion())
	}

	metadata, err := json.Marshal(struct {
		User          string `json:"user,omitempty"`
		ClientVersion string `json:"client_version,omitempty"`
		Error         string `json:"error"`
	}{s.username, clientVersion, message})
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
