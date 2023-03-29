package ssh

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"os"
	"time"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	"github.com/aws/session-manager-plugin/src/datachannel"
	"github.com/aws/session-manager-plugin/src/log"
	"github.com/aws/session-manager-plugin/src/message"
	"github.com/borderzero/border0-cli/internal/api/models"
	"golang.org/x/crypto/ssh"
)

const ResizeSleepInterval = 500 * time.Millisecond

type ProxyConfig struct {
	Username        string
	Password        string
	IdentityFile    string
	Hostname        string
	Port            int
	sshClientConfig *ssh.ClientConfig
	sshServerConfig *ssh.ServerConfig
	AwsEC2Target    string
	ssmClient       *ssm.Client
	windowWidth     int
	windowHeight    int
	session         *ShellSession
}

func BuildProxyConfig(socket models.Socket) *ProxyConfig {
	if socket.ConnectorLocalData.UpstreamUsername == "" && socket.ConnectorLocalData.UpstreamPassword == "" &&
		socket.ConnectorLocalData.UpstreamIdentifyFile == "" && socket.ConnectorLocalData.AWSEC2Target == "" {
		return nil
	}

	return &ProxyConfig{
		Hostname:     socket.ConnectorData.TargetHostname,
		Port:         socket.ConnectorData.Port,
		Username:     socket.ConnectorLocalData.UpstreamUsername,
		Password:     socket.ConnectorLocalData.UpstreamPassword,
		IdentityFile: socket.ConnectorLocalData.UpstreamIdentifyFile,
		AwsEC2Target: socket.ConnectorLocalData.AWSEC2Target,
	}
}

func Proxy(l net.Listener, c ProxyConfig) error {
	var handler func(net.Conn, ProxyConfig)

	if c.AwsEC2Target != "" {
		awsConfig, err := config.LoadDefaultConfig(context.TODO())
		if err != nil {
			return fmt.Errorf("failed to load aws config: %s", err)
		}
		c.ssmClient = ssm.NewFromConfig(awsConfig)
		handler = handelSSMclient
	} else {
		var authMethods []ssh.AuthMethod
		if c.IdentityFile != "" {
			bytes, err := os.ReadFile(c.IdentityFile)
			if err != nil {
				return fmt.Errorf("sshauthproxy: failed to read identity file: %s", err)
			}

			signer, err := ssh.ParsePrivateKey(bytes)
			if err != nil {
				return fmt.Errorf("sshauthproxy: failed to parse identity file: %s", err)
			}

			authMethods = append(authMethods, ssh.PublicKeys(signer))
		}

		if c.Password != "" {
			authMethods = append(authMethods, ssh.Password(c.Password))
		}

		if len(authMethods) == 0 {
			return fmt.Errorf("sshauthproxy: no authentication methods provided")
		}

		c.sshClientConfig = &ssh.ClientConfig{
			User:            c.Username,
			Auth:            authMethods,
			HostKeyCallback: ssh.InsecureIgnoreHostKey(),
			Timeout:         5 * time.Second,
		}

		handler = handleSSHclient
	}

	c.sshServerConfig = &ssh.ServerConfig{
		NoClientAuth: true,
	}

	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return fmt.Errorf("sshauthproxy: failed to generate private key: %s", err)
	}

	signer, err := ssh.NewSignerFromKey(privateKey)
	if err != nil {
		return fmt.Errorf("sshauthproxy: failed to generate signer: %s", err)
	}
	c.sshServerConfig.AddHostKey(signer)

	for {
		conn, err := l.Accept()
		if err != nil {
			return fmt.Errorf("sshauthproxy: failed to accept connection: %s", err)
		}

		go handler(conn, c)
	}
}

func handelSSMclient(conn net.Conn, config ProxyConfig) {
	defer conn.Close()

	sshConn, chans, reqs, err := ssh.NewServerConn(conn, config.sshServerConfig)
	if err != nil {
		fmt.Printf("sshauthproxy: failed to accept ssh connection: %s", err)
		return
	}

	defer sshConn.Close()

	go ssh.DiscardRequests(reqs)

	for newChannel := range chans {
		if newChannel == nil {
			fmt.Printf("sshauthproxy: proxy channel closed")
			return
		}

		if newChannel.ChannelType() != "session" {
			newChannel.Reject(ssh.UnknownChannelType, "unknown channel type")
			continue
		}

		channel, requests, err := newChannel.Accept()
		if err != nil {
			fmt.Printf("sshauthproxy: failed to accept channel: %s", err)
			return
		}

		go func(in <-chan *ssh.Request) {
			for req := range in {
				switch {
				case req == nil:
					continue
				case req.Type == "pty-req":
					termLen := req.Payload[3]
					w, h := parseDims(req.Payload[termLen+4:])
					config.windowWidth = int(w)
					config.windowHeight = int(h)
					req.Reply(true, nil)
				case req.Type == "window-change":
					w, h := parseDims(req.Payload)
					config.session.handleWindowChange(int(w), int(h))
					req.Reply(true, nil)
				case req.Type == "shell":
					go handleSSMShell(channel, &config)
					req.Reply(true, nil)
				default:
					req.Reply(false, nil)
				}
			}
		}(requests)
	}

}

type ssmDataChannel struct {
	datachannel.DataChannel
}

func (s ssmDataChannel) HandleChannelClosedMessage(log log.T, stopHandler datachannel.Stop, sessionId string, outputMessage message.ClientMessage) {
	stopHandler()
}

func (dataChannel *ssmDataChannel) OutputMessageHandler(log log.T, stopHandler datachannel.Stop, sessionID string, rawMessage []byte) error {
	outputMessage := &message.ClientMessage{}
	err := outputMessage.DeserializeClientMessage(log, rawMessage)
	if err != nil {
		log.Errorf("Cannot deserialize raw message: %s, err: %v.", string(rawMessage), err)
		return err
	}
	if err = outputMessage.Validate(); err != nil {
		log.Errorf("Invalid outputMessage: %v, err: %v.", *outputMessage, err)
		return err
	}

	switch outputMessage.MessageType {
	case message.OutputStreamMessage:
		return dataChannel.HandleOutputMessage(log, *outputMessage, rawMessage)
	case message.AcknowledgeMessage:
		return dataChannel.HandleAcknowledgeMessage(log, *outputMessage)
	case message.ChannelClosedMessage:
		dataChannel.HandleChannelClosedMessage(log, stopHandler, sessionID, *outputMessage)
	case message.StartPublicationMessage, message.PausePublicationMessage:
		return nil
	default:
		log.Warn("Invalid message type received: %s", outputMessage.MessageType)
	}

	return nil
}

func handleSSMShell(channel ssh.Channel, config *ProxyConfig) {
	defer channel.Close()

	var s ShellSession
	sessionOutput, err := config.ssmClient.StartSession(context.TODO(), &ssm.StartSessionInput{
		Target: &config.AwsEC2Target,
	})
	if err != nil {
		fmt.Printf("sshauthproxy: failed to start ssm session: %s", err)
		return
	}

	datachannel := ssmDataChannel{
		DataChannel: datachannel.DataChannel{},
	}

	s.SessionId = *sessionOutput.SessionId
	s.StreamUrl = *sessionOutput.StreamUrl
	s.TokenValue = *sessionOutput.TokenValue
	s.DataChannel = &datachannel
	config.session = &s
	s.handleWindowChange(config.windowWidth, config.windowHeight)
	sessionLogger := log.Logger(false, "border0")

	if err = s.OpenDataChannel(sessionLogger); err != nil {
		fmt.Printf("sshauthproxy: failed to execute ssm session: %s", err)
		return
	}

	defer s.TerminateSession(sessionLogger)

	s.SessionType = "border0"
	s.sshChannel = channel

	s.Initialize(sessionLogger, &s)
	if s.SetSessionHandlers(sessionLogger); err != nil {
		fmt.Printf("sshauthproxy: failed to execute ssm session: %s", err)
	}
}

func handleSSHclient(conn net.Conn, config ProxyConfig) {
	defer conn.Close()

	sshConn, chans, reqs, err := ssh.NewServerConn(conn, config.sshServerConfig)
	if err != nil {
		fmt.Printf("sshauthproxy: failed to accept ssh connection: %s", err)
		return
	}

	go ssh.DiscardRequests(reqs)
	if err := handleChannels(sshConn, chans, config); err != nil {
		fmt.Printf("sshauthproxy: failed to handle channels: %s", err)
		return
	}
}

func handleChannels(sshConn *ssh.ServerConn, chans <-chan ssh.NewChannel, config ProxyConfig) error {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	defer sshConn.Close()

	upstreamConn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", config.Hostname, config.Port), 5*time.Second)
	if err != nil {
		return fmt.Errorf("unable to connect to upstream host: %s", err)
	}

	sshClientConn, clientChans, req, err := ssh.NewClientConn(upstreamConn, "", config.sshClientConfig)
	if err != nil {
		return fmt.Errorf("unable to connect to upstream host: %s", err)
	}

	go ssh.DiscardRequests(req)

	defer sshClientConn.Close()

	for {
		select {
		case newChannel := <-chans:
			if newChannel == nil {
				return fmt.Errorf("proxy channel closed")
			}

			go handleChannel(ctx, cancel, newChannel, sshClientConn)
		case newChannel := <-clientChans:
			if newChannel == nil {
				return fmt.Errorf("upstream channel closed")
			}

			go handleChannel(ctx, cancel, newChannel, sshConn.Conn)
		case <-ctx.Done():
			return nil
		}
	}
}

func handleChannel(ctx context.Context, cancel context.CancelFunc, newChannel ssh.NewChannel, sshConn ssh.Conn) {
	clientChannel, clientReq, err := sshConn.OpenChannel(newChannel.ChannelType(), newChannel.ExtraData())
	if err != nil {
		if chanErr, ok := err.(*ssh.OpenChannelError); ok {
			if err := newChannel.Reject(chanErr.Reason, chanErr.Message); err != nil {
				return
			}
		} else {
			if err = newChannel.Reject(ssh.ConnectionFailed, fmt.Sprintf("error connecting to backend (%s)", err)); err != nil {
				return
			}
		}
		return
	}

	serverChannel, serverReq, err := newChannel.Accept()
	if err != nil {
		return
	}

	defer clientChannel.Close()
	defer serverChannel.Close()

	go func() {
		io.Copy(clientChannel, serverChannel)
		cancel()
	}()

	go func() {
		io.Copy(serverChannel, clientChannel)
		cancel()
	}()

	for {
		select {
		case <-ctx.Done():
			return
		case req := <-clientReq:
			if req == nil {
				return
			}

			handleRequest(serverChannel, req)
		case req := <-serverReq:
			if req == nil {
				return
			}

			handleRequest(clientChannel, req)
		}
	}
}

func handleRequest(channel ssh.Channel, req *ssh.Request) {
	ok, _ := channel.SendRequest(req.Type, req.WantReply, req.Payload)

	if req.WantReply {
		req.Reply(ok, nil)
	}
}

func parseDims(b []byte) (uint32, uint32) {
	w := binary.BigEndian.Uint32(b)
	h := binary.BigEndian.Uint32(b[4:])
	return w, h
}
