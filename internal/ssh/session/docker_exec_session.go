package session

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/anmitsu/go-shlex"
	"github.com/borderzero/border0-cli/internal/api/models"
	"github.com/borderzero/border0-cli/internal/border0"
	sshConfig "github.com/borderzero/border0-cli/internal/ssh/config"
	"github.com/borderzero/border0-cli/internal/ssh/session/common"
	"github.com/borderzero/border0-cli/internal/util/recorder"
	"github.com/borderzero/border0-go/lib/types/pointer"
	"github.com/borderzero/border0-go/lib/types/set"
	"github.com/borderzero/border0-go/lib/types/slice"
	"github.com/borderzero/border0-go/lib/types/wildcard"
	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/client"
	"github.com/manifoldco/promptui"
	"go.uber.org/zap"
	"golang.org/x/crypto/ssh"
)

type dockerExecSessionHandler struct {
	logger *zap.Logger
	config *sshConfig.ProxyConfig
}

// ensure dockerExecSessionHandler implements SessionHandler.
var _ SessionHandler = (*dockerExecSessionHandler)(nil)

type dockerExecSession struct {
	logger *zap.Logger
	config *sshConfig.ProxyConfig

	metadata *border0.ConnMetadata
	username string

	sshServerConfig *ssh.ServerConfig
	sshHeight       int
	sshWidth        int
	pty             bool
	// active channels
	downstreamSshConn  *ssh.ServerConn
	downstreamSshChans <-chan ssh.NewChannel
}

func NewDockerExecSessionHandler(
	logger *zap.Logger,
	config *sshConfig.ProxyConfig,
) *dockerExecSessionHandler {
	return &dockerExecSessionHandler{
		logger: logger,
		config: config,
	}
}

// Proxy runs the local proxying function between the connection to the
// remote Border0 proxy and the origin service (in this case the origin
// service is a connection to a remote docker executor / docker engine).
func (s *dockerExecSessionHandler) Proxy(conn net.Conn) {
	defer conn.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	session := &dockerExecSession{
		logger:          s.logger,
		config:          s.config,
		sshServerConfig: s.config.SshServerConfig,
		sshWidth:        80,
		sshHeight:       24,
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

	// accept SSH connection from Border0 proxy
	dsConn, dsChanns, dsReqs, err := ssh.NewServerConn(conn, session.config.SshServerConfig)
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
	session.downstreamSshConn = dsConn
	session.downstreamSshChans = dsChanns

	// we don't support global requests (yet)
	// so we can disregard the reqs channel
	go ssh.DiscardRequests(dsReqs)

	if session.config.Socket.IsPrimaryProxy() {
		session.username = session.downstreamSshConn.User()

		if s.config.Username != "" {
			session.username = s.config.Username
		}

		if err := session.config.Border0API.UpdateSession(models.SessionUpdate{
			SessionKey: session.metadata.SessionKey,
			Socket:     session.config.Socket,
			UserData:   ",sshuser=" + session.username,
		}); err != nil {
			session.logger.Error("failed to update session", zap.Error(err))
			return
		}
	}

	if session.config.Socket.IsPrimaryProxy() {
		var max_session_duration int
		for _, permission := range session.metadata.AllowedActions {
			switch permission := permission.(type) {
			case models.Permissions:
				if permission.SSH != nil {
					if permission.SSH.MaxSessionDurationSeconds != nil && *permission.SSH.MaxSessionDurationSeconds > max_session_duration {
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
					}{max_session_duration, session.username})

					if err != nil {
						s.logger.Error("failed to create session event", zap.Error(err))
					} else {
						if err := s.config.Border0API.CreateSessionEvent(models.SessionEvent{
							SessionKey: session.metadata.SessionKey,
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

	session.handleChannels(ctx)
}

func (s *dockerExecSession) handleChannels(ctx context.Context) {
	defer s.downstreamSshConn.Close()

	channelCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	for {
		select {
		case newChannel, ok := <-s.downstreamSshChans:
			if !ok {
				return
			}

			if newChannel.ChannelType() != "session" {
				if err := s.errorEvent("ssh_channel", fmt.Sprintf("unknown channel type: %s", newChannel.ChannelType())); err != nil {
					s.logger.Error("failed to create session event", zap.Error(err))
				}

				continue
			}

			channel, requests, err := newChannel.Accept()
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
				continue
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

			go func(in <-chan *ssh.Request) {
				for req := range in {
					switch {
					case req == nil:
						continue
					// handled mostly for the benefit of session recordings
					case req.Type == "pty-req":
						termLen := req.Payload[3]
						w, h := common.ParseDims(req.Payload[termLen+4:])
						s.sshWidth = int(w)
						s.sshHeight = int(h)
						if req.WantReply {
							req.Reply(true, nil)
						}
						s.pty = true
					// handled mostly for the benefit of session recordings
					case req.Type == "window-change":
						w, h := common.ParseDims(req.Payload)
						s.sshWidth = int(w)
						s.sshHeight = int(h)
						if req.WantReply {
							req.Reply(true, nil)
						}
					case req.Type == "shell", req.Type == "exec":
						if req.WantReply {
							req.Reply(true, nil)
						}
						go s.handleChannel(channelCtx, channel, s.downstreamSshConn.User(), req)
					default:
						if req.WantReply {
							req.Reply(false, nil)
						}
					}
				}
			}(requests)
		case <-ctx.Done():
			return
		}
	}
}

func (s *dockerExecSession) handleChannel(
	ctx context.Context,
	channel ssh.Channel,
	user string,
	req *ssh.Request,
) {
	defer channel.Close()

	var permissions []models.Permissions
	var allAllowed bool

	if s.config.Socket.IsPrimaryProxy() {
		var allowed bool
		for _, allowedAction := range s.metadata.AllowedActions {
			switch permission := allowedAction.(type) {
			case string:
				allowed = true
				allAllowed = true
			case models.Permissions:
				if permission.SSH != nil && permission.SSH.DockerExec != nil {
					allowed = true
					permissions = append(permissions, permission)
				}
			default:
				s.logger.Warn("unknown action type", zap.String("type", fmt.Sprintf("%T", allowedAction)))
			}
		}

		if !allowed {
			channel.Stderr().Write([]byte("docker exec access denied by policy\r\n"))
			channel.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{Status: 1}))

			if err := s.config.Border0API.UpdateSession(models.SessionUpdate{
				SessionKey:     s.metadata.SessionKey,
				Socket:         s.config.Socket,
				Result:         models.ResultDenied,
				AuthInfoFailed: "docker exec access denied by policy",
			}); err != nil {
				s.logger.Error("failed to update session", zap.Error(err))
			}

			return
		}

		if allAllowed {
			permissions = nil
		}
	}

	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		channel.Write([]byte("An error occured. Try again later..."))
		if err := s.errorEvent("ssh_docker_exec", fmt.Sprintf("failed to initialize new docker client: %s", err)); err != nil {
			s.logger.Error("failed to create session event", zap.Error(err))
		}

		return
	}

	var payload = struct{ Value string }{}
	ssh.Unmarshal(req.Payload, &payload)
	command := payload.Value

	if s.config.IsRecordingEnabled() {
		pwc := NewPipeWriteChannel(channel)
		channel = pwc

		recorderOpts := []recorder.AsciinemaRecorderOption{
			recorder.WithAsciinemaHeight(s.sshHeight),
			recorder.WithAsciinemaWidth(s.sshWidth),
		}
		r := recorder.NewAsciinemaRecorder(s.logger, s.config.Border0API, pwc.reader, s.config.Socket.SocketID, s.metadata.SessionKey, recorderOpts...)
		if err := r.Record(); err != nil {
			channel.Write([]byte("An error occured. Try again later..."))
			channel.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{Status: 1}))
			if err := s.errorEvent("ssh_recording", fmt.Sprintf("failed to initialize new docker client: %s", err)); err != nil {
				s.logger.Error("failed to create session event", zap.Error(err))
			}

			return
		}

		if command != "" {
			pwc.logWriter.Write([]byte(fmt.Sprintf("%s\n", command)))
		}
		defer r.Stop()
	}

	var clientTarget string
	userSlice := strings.SplitN(user, "/", 2)
	if len(userSlice) == 2 { // format is container/user
		clientTarget = userSlice[0]
		user = userSlice[1]
	}

	container, err := s.askForTarget(ctx, channel, cli, clientTarget, permissions)
	if err != nil {
		channel.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{Status: 1}))
		if err := s.errorEvent("ssh_docker_exec", fmt.Sprintf("failed to determine target for docker exec: %s", err)); err != nil {
			s.logger.Error("failed to create session event", zap.Error(err))
		}

		return
	}

	if container == "" {
		return // no containers available or user cancelled operation
	}

	metadata, err := json.Marshal(struct {
		SessionType   string `json:"session_type"`
		ClientVersion string `json:"client_version"`
		Command       string `json:"command,omitempty"`
		ContainerID   string `json:"container_id,omitempty"`
	}{req.Type, string(s.downstreamSshConn.ClientVersion()), command, container})
	if err != nil {
		s.logger.Error("failed to create session event", zap.Error(err))
		return
	}

	if err := s.config.Border0API.CreateSessionEvent(models.SessionEvent{
		SessionKey: s.metadata.SessionKey,
		Socket:     s.config.Socket,
		Type:       "ssh_kubectl_exec",
		Status:     "success",
		Metadata:   string(metadata),
	}); err != nil {
		s.logger.Error("failed to create session event", zap.Error(err))
	}

	switch req.Type {
	case "shell":
		// we iterate over the slice and not the set
		// because order is not maintained for the set
		shells := []string{"bash", "zsh", "ash", "sh"}
		shellSet := set.New(shells...)
		for _, shell := range shells {
			if shellSet.Size() == 0 {
				channel.Write([]byte("No shells available in the target container :("))
				if err := s.errorEventWithContainer("ssh_docker_exec", fmt.Sprintf("no shells available in the target container: %s", err), container, ""); err != nil {
					s.logger.Error("failed to create session event", zap.Error(err))
				}

				return
			}

			if err := s.exec(ctx, cli, channel, container, user, []string{shell}, true); err != nil {
				if err.Error() == "shell not found in container" {
					shellSet.Remove(shell)
					continue
				}

				channel.Stderr().Write([]byte("An error occured. Try again later...\r\n"))
				channel.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{Status: 1}))
				if err := s.errorEventWithContainer("ssh_docker_exec", err.Error(), container, shell); err != nil {
					s.logger.Error("failed to create session event", zap.Error(err))
				}
			}
			break
		}
	case "exec":
		commandArgs, err := shlex.Split(command, true)
		if err != nil {
			channel.Stderr().Write([]byte("failed to parse command\r\n"))
			if err := s.errorEventWithContainer("ssh_docker_exec", fmt.Sprintf("failed to parse command: %s", err), container, command); err != nil {
				s.logger.Error("failed to create session event", zap.Error(err))
			}

			return
		}

		if err := s.exec(ctx, cli, channel, container, user, commandArgs, false); err != nil {
			channel.Stderr().Write([]byte("An error occured. Try again later...\r\n"))
			channel.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{Status: 1}))
			if err := s.errorEventWithContainer("ssh_docker_exec", fmt.Sprintf("exec error: %s", err), container, command); err != nil {
				s.logger.Error("failed to create session event", zap.Error(err))
			}

			return
		}
	}

	channel.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{Status: 0}))
}

func (s *dockerExecSession) exec(ctx context.Context, cli *client.Client, channel ssh.Channel, container, user string, command []string, returnOnNotFound bool) error {
	exec, err := cli.ContainerExecCreate(ctx, container, types.ExecConfig{
		User:       user, // User that will run the command
		Privileged: true, // Is the container in privileged mode
		Tty:        s.pty,
		// ConsoleSize  *[2]uint `json:",omitempty"` // Initial console size [height, width]
		AttachStdin:  true,
		AttachStderr: true,
		AttachStdout: true,
		Detach:       false, // Execute in detach mode
		// DetachKeys   string   // Escape keys for detach
		// Env          []string // Environment variables
		// WorkingDir   string   // Working directory
		Cmd: command, // Execution commands and args
	})
	if err != nil {
		return fmt.Errorf("failed to perform ContainerExecCreate operation against docker container %s: %w", container, err)
	}

	hijackedResponse, err := cli.ContainerExecAttach(ctx, exec.ID, types.ExecStartCheck{
		Detach: false, // ExecStart will first check if it's detached
		Tty:    true,  // Check if there's a tty
		// ConsoleSize  *[2]uint `json:",omitempty"`// Terminal size [height, width], unused if Tty == false
	})
	if err != nil {
		return fmt.Errorf("failed to perform ContainerExecAttach operation against docker container %s: %w", container, err)
	}
	defer hijackedResponse.Close()

	if returnOnNotFound {
		// perform one read to check whether the container
		// errored in finding shell in binaries path
		buf := make([]byte, 256)
		n, err := hijackedResponse.Conn.Read(buf)
		if err != nil {
			channel.Write([]byte("An error occured. Try again later..."))
			if err := s.errorEventWithContainer("ssh_docker_exec", fmt.Sprintf("failed to perform first-read on connection to docker remote executor: %s", err), container, strings.Join(command, " ")); err != nil {
				s.logger.Error("failed to create session event", zap.Error(err))
			}

		}

		if strings.Contains(string(buf[:n]), "executable file not found") ||
			strings.Contains(string(buf[:n]), "command terminated with exit code 127") {
			return fmt.Errorf("shell not found in container")
		}

		// if no error, we need to write that first read back to the ssh channel
		channel.Write(buf[:n])
	}

	// stitch together connection to proxy and connection to executor
	errs := make(chan error, 2)
	var wg sync.WaitGroup // wait group is for channel closure

	go func() { wg.Wait(); close(errs) }()
	wg.Add(2)
	go func() { defer wg.Done(); _, e := io.Copy(channel, hijackedResponse.Conn); errs <- e }()
	go func() { defer wg.Done(); _, e := io.Copy(hijackedResponse.Conn, channel); errs <- e }()

	if err = <-errs; err != nil {
		if !errors.Is(err, io.EOF) {
			channel.SendRequest("exit-status", false, []byte{1, 0, 0, 0})
			return fmt.Errorf("failed to proxy between border0 proxy and docker remote executor: %w", err)
		}
	}

	channel.SendRequest("exit-status", false, []byte{0, 0, 0, 0})
	return nil
}

func (s *dockerExecSession) askForTarget(ctx context.Context, channel ssh.Channel, cli *client.Client, clientTarget string, permissions []models.Permissions) (string, error) {
	containerListCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	containers, err := cli.ContainerList(containerListCtx, container.ListOptions{})
	if err != nil {
		return "", fmt.Errorf("failed to list Docker containers: %v", err)
	}

	if len(containers) == 0 {
		channel.Stderr().Write([]byte("No containers available to you - sorry :(\r\n"))
		return "", nil
	}

	type containerPrompt struct {
		ID               string
		PromptIdentifier string
	}
	containerPrompts := []containerPrompt{}

	for _, container := range containers {
		// if there's an allowlist present, process it
		if len(s.config.DockerExecProxy.ContainerNameAllowlist) > 0 {
			include := false
			for _, name := range container.Names {
				for _, template := range s.config.DockerExecProxy.ContainerNameAllowlist {
					// match, ignoring leading slash
					if wildcard.Match(template, name) || wildcard.Match(template, strings.TrimPrefix(name, "/")) {
						include = true
						break
					}
				}
			}
			if !include {
				continue // won't include this one, move on to next container
			}
		}

		if len(permissions) > 0 {
			include := false
			for _, name := range container.Names {
				for _, permission := range permissions {
					if permission.SSH.DockerExec.AllowedContainers != nil {
						for _, allowedContainer := range *permission.SSH.DockerExec.AllowedContainers {
							if wildcard.Match(allowedContainer, name) || wildcard.Match(allowedContainer, strings.TrimPrefix(name, "/")) {
								include = true
								break
							}
						}
					} else {
						include = true
					}
				}
			}

			if !include {
				continue // won't include this one, move on to next container
			}
		}

		include := false
		if clientTarget != "" {
			for _, name := range container.Names {
				if strings.EqualFold(strings.TrimPrefix(name, "/"), clientTarget) {
					include = true
					break
				}
			}

			if !include {
				continue // won't include this one, move on to next container
			}
		}

		friendlyName := container.ID
		if len(container.Names) > 0 {
			friendlyName = strings.Join(
				// strip leading slashes
				slice.Transform(
					container.Names,
					func(name string) string { return strings.TrimPrefix(name, "/") },
				),
				// use comma as join delimeter
				", ",
			)
		}

		containerPrompts = append(containerPrompts, containerPrompt{
			ID:               container.ID,
			PromptIdentifier: fmt.Sprintf("%s (%s)", friendlyName, container.Image),
		})
	}

	if len(containerPrompts) == 0 {
		channel.Stderr().Write([]byte("No containers available to you - sorry :(\r\n"))
		return "", errors.New("no allowlisted containers available")
	}
	if len(containerPrompts) == 1 {
		return containerPrompts[0].ID, nil
	}

	// sorting by alphanumeric order of prompt identifiers
	sort.Slice(containerPrompts, func(i, j int) bool {
		return containerPrompts[i].PromptIdentifier < containerPrompts[j].PromptIdentifier
	})

	conatinerPrompt := promptui.Select{
		Label:             "Choose a container",
		Items:             slice.Transform(containerPrompts, func(c containerPrompt) string { return c.PromptIdentifier }),
		Stdout:            channel,
		Stdin:             channel,
		StartInSearchMode: true,
		Searcher: func(input string, index int) bool {
			return strings.Contains(strings.ToLower(containerPrompts[index].PromptIdentifier), strings.ToLower(input))
		},
		Size: 10, // default is 5
	}
	index, _, err := conatinerPrompt.Run()
	if err != nil {
		// handle cancellation by user (e.g. ^C or ^D)
		if errors.Is(err, promptui.ErrInterrupt) || errors.Is(err, promptui.ErrEOF) {
			return "", nil
		}
		return "", fmt.Errorf("unable to select container: %v", err)
	}

	return containerPrompts[index].ID, nil
}

func (s *dockerExecSession) errorEvent(eventType, message string) error {
	return s.errorEventWithContainer(eventType, message, "", "")
}

func (s *dockerExecSession) errorEventWithContainer(eventType, message, container, command string) error {
	var clientVersion string
	if s.downstreamSshConn != nil {
		clientVersion = string(s.downstreamSshConn.ClientVersion())
	}

	metadata, err := json.Marshal(struct {
		User          string `json:"user,omitempty"`
		ClientVersion string `json:"client_version,omitempty"`
		Error         string `json:"error"`
		Container     string `json:"container,omitempty"`
		Command       string `json:"command,omitempty"`
	}{s.username, clientVersion, message, container, command})
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
