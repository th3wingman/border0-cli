package session

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/anmitsu/go-shlex"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/eks"
	awsv1 "github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	sessionv1 "github.com/aws/aws-sdk-go/aws/session"
	"github.com/borderzero/border0-cli/internal/api/models"
	"github.com/borderzero/border0-cli/internal/border0"
	"github.com/borderzero/border0-cli/internal/ssh/config"
	"github.com/borderzero/border0-cli/internal/ssh/session/common"
	"github.com/borderzero/border0-cli/internal/util/recorder"
	"github.com/borderzero/border0-go/lib/types/maps"
	"github.com/borderzero/border0-go/lib/types/pointer"
	"github.com/borderzero/border0-go/lib/types/set"
	"github.com/manifoldco/promptui"
	"go.uber.org/zap"
	"golang.org/x/crypto/ssh"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/tools/remotecommand"
	"sigs.k8s.io/aws-iam-authenticator/pkg/token"
)

type kubectlExecSessionHandler struct {
	logger *zap.Logger
	config *config.ProxyConfig
}

// ensure kubectlExecSessionHandler implements SessionHandler.
var _ SessionHandler = (*kubectlExecSessionHandler)(nil)

type kubectlExecSession struct {
	logger          *zap.Logger
	config          *config.ProxyConfig
	metadata        *border0.ConnMetadata
	sshServerConfig *ssh.ServerConfig
	sshHeight       int
	sshWidth        int
	pty             bool

	// active channels
	downstreamSshConn  *ssh.ServerConn
	downstreamSshChans <-chan ssh.NewChannel
}

type kubeTarget struct {
	namespace string
	pod       string
	container string
}

func NewKubectlExecSessionHandler(
	logger *zap.Logger,
	config *config.ProxyConfig,
) *kubectlExecSessionHandler {
	return &kubectlExecSessionHandler{
		logger: logger,
		config: config,
	}
}

// Proxy runs the local proxying function between the connection to the remote Border0 proxy and
// the origin service (in this case the origin service is a connection to a remote kubectl executor).
func (s *kubectlExecSessionHandler) Proxy(conn net.Conn) {
	defer conn.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	session := &kubectlExecSession{
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

		if err := session.errorEvent("ssh_connection", fmt.Sprintf("failed to accept connection: %s", err), "", nil); err != nil {
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
		if err := session.config.Border0API.UpdateSession(models.SessionUpdate{
			SessionKey: session.metadata.SessionKey,
			Socket:     session.config.Socket,
		}); err != nil {
			session.logger.Error("failed to update session", zap.Error(err))
			return
		}

		var max_session_duration int
		for _, action := range session.metadata.AllowedActions {
			switch permission := action.(type) {
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
						SessionDuration int `json:"session_duration"`
					}{max_session_duration})

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

func (s *kubectlExecSession) handleChannels(ctx context.Context) {
	defer s.downstreamSshConn.Close()

	channelCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	for newChannel := range s.downstreamSshChans {
		if newChannel == nil {
			if err := s.errorEvent("ssh_channel", "proxy channel closed", "", nil); err != nil {
				s.logger.Error("failed to create session event", zap.Error(err))
			}
			return
		}

		if newChannel.ChannelType() != "session" {
			if err := s.errorEvent("ssh_channel", fmt.Sprintf("unknown channel type: %s", newChannel.ChannelType()), "", nil); err != nil {
				s.logger.Error("failed to create session event", zap.Error(err))
			}
			continue
		}

		channel, requests, err := newChannel.Accept()
		if err != nil {
			if err := s.errorEvent("ssh_session", fmt.Sprintf("failed to accept channel: %s", err), "", nil); err != nil {
				s.logger.Error("failed to create session event", zap.Error(err))
			}
			return
		}

		metadata, err := json.Marshal(struct {
			ChannelType   string `json:"channel_type"`
			ClientVersion string `json:"client_version"`
		}{newChannel.ChannelType(), string(s.downstreamSshConn.ClientVersion())})
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

		termSizeQueue := newTerminalWindowSizeQueue(ctx)

		go func(in <-chan *ssh.Request) {
			for req := range in {
				switch {
				case req == nil:
					continue
				// handled mostly for the benefit of session recordings
				case req.Type == "pty-req":
					s.pty = true
					termLen := req.Payload[3]
					w, h := common.ParseDims(req.Payload[termLen+4:])
					s.sshWidth = int(w)
					s.sshHeight = int(h)
					termSizeQueue.push(&remotecommand.TerminalSize{
						Width:  uint16(w),
						Height: uint16(h),
					})
					if req.WantReply {
						req.Reply(true, nil)
					}
				// handled mostly for the benefit of session recordings
				case req.Type == "window-change":
					w, h := common.ParseDims(req.Payload)
					s.sshWidth = int(w)
					s.sshHeight = int(h)
					termSizeQueue.push(&remotecommand.TerminalSize{
						Width:  uint16(w),
						Height: uint16(h),
					})
					if req.WantReply {
						req.Reply(true, nil)
					}
				case req.Type == "shell", req.Type == "exec":
					if req.WantReply {
						req.Reply(true, nil)
					}

					go s.handleChannel(channelCtx, channel, termSizeQueue, s.downstreamSshConn.User(), req)
				default:
					if req.WantReply {
						req.Reply(false, nil)
					}
				}
			}
		}(requests)
	}
}

func (s *kubectlExecSession) getKubeconfig(ctx context.Context) (*rest.Config, error) {
	// if its an AWS EKS cluster, we use aws credentials to get kubeconfig
	if s.config.KubectlExecProxy.IsAwsEks {
		// get cluster details
		eksClient := eks.NewFromConfig(s.config.AwsConfig)
		describeClusterCtx, cancel := context.WithTimeout(ctx, time.Second*5)
		defer cancel()
		describeClusterOutput, err := eksClient.DescribeCluster(describeClusterCtx, &eks.DescribeClusterInput{
			Name: aws.String(s.config.KubectlExecProxy.AwsEksClusterName),
		})
		if err != nil {
			return nil, fmt.Errorf("failed to describe eks cluster \"%s\": %v", s.config.KubectlExecProxy.AwsEksClusterName, err)
		}

		// initialize new token generator
		iamAuthTokenGenerator, err := token.NewGenerator(true, false)
		if err != nil {
			return nil, fmt.Errorf("failed to initialize aws iam authenticator token generator: %v", err)
		}

		// retrieve credentials to use with the aws go sdk v1. we have to do this because
		// the aws iam authenticator for k8s only interfaces with the legacy aws go sdk (v1).
		retrieveCredsCtx, cancel := context.WithTimeout(ctx, time.Second*5)
		defer cancel()
		v2creds, err := s.config.AwsConfig.Credentials.Retrieve(retrieveCredsCtx)
		if err != nil {
			return nil, fmt.Errorf("failed to retrieve temporary aws credentials: %v", err)
		}

		// use legacy credentials object to init new session object
		session, err := sessionv1.NewSession(&awsv1.Config{
			Credentials: credentials.NewStaticCredentials(
				v2creds.AccessKeyID,
				v2creds.SecretAccessKey,
				v2creds.SessionToken,
			),
		})
		if err != nil {
			return nil, fmt.Errorf("failed to initialize new aws session: %v", err)
		}

		// retrieve k8s bearer token
		token, err := iamAuthTokenGenerator.GetWithOptions(&token.GetTokenOptions{
			ClusterID:   s.config.KubectlExecProxy.AwsEksClusterName,
			Region:      s.config.AwsConfig.Region, // OK if empty
			Session:     session,                   // have to pass it or else default credential chain is used
			SessionName: fmt.Sprintf("border0-k8s-%d", time.Now().UnixNano()),
		})
		if err != nil {
			return nil, fmt.Errorf("failed to generate k8s token with aws iam authenticator token generator: %v", err)
		}

		// decode CA data
		ca, err := base64.StdEncoding.DecodeString(aws.ToString(describeClusterOutput.Cluster.CertificateAuthority.Data))
		if err != nil {
			return nil, fmt.Errorf("failed to decode base64-encoded kubernetes cluster CA data: %v", err)
		}

		// build kubeconfig
		kubeConfig := &rest.Config{
			Host:            aws.ToString(describeClusterOutput.Cluster.Endpoint),
			BearerToken:     token.Token,
			TLSClientConfig: rest.TLSClientConfig{CAData: ca},
		}
		return kubeConfig, nil
	}

	// if kubeconfig path is defined, use it
	if s.config.KubectlExecProxy.KubeconfigPath != "" {
		kubeConfig, err := clientcmd.BuildConfigFromFlags(
			s.config.KubectlExecProxy.MasterUrl, // OK if empty
			s.config.KubectlExecProxy.KubeconfigPath,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to build kubeconfig from the given path: %v", err)
		}
		return kubeConfig, nil
	}

	// otherwise use k8s default config loading rules
	kubeConfig, err := clientcmd.BuildConfigFromKubeconfigGetter(
		s.config.KubectlExecProxy.MasterUrl, // OK if empty
		clientcmd.NewDefaultClientConfigLoadingRules().GetStartingConfig,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to build kubeconfig: %v", err)
	}
	return kubeConfig, nil

}

func (s *kubectlExecSession) handleChannel(
	ctx context.Context,
	channel ssh.Channel,
	terminalSizeQ remotecommand.TerminalSizeQueue,
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
				if permission.SSH != nil && permission.SSH.KubectlExec != nil {
					allowed = true
					permissions = append(permissions, permission)
				}
			default:
				s.logger.Warn("unknown action type", zap.String("type", fmt.Sprintf("%T", allowedAction)))
			}
		}

		if !allowed {
			channel.Stderr().Write([]byte("kubectl exec access denied by policy\r\n"))
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

	kubeconfig, err := s.getKubeconfig(ctx)
	if err != nil {
		channel.Stderr().Write([]byte("failed to get kubeconfig\r\n"))

		if err := s.errorEvent("ssh_docker_exec", fmt.Sprintf("failed to get kubeconfig: %s", err), "", nil); err != nil {
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
			if err := s.errorEvent("ssh_recording", fmt.Sprintf("failed to initialize new docker client: %s", err), "", nil); err != nil {
				s.logger.Error("failed to create session event", zap.Error(err))
			}

			return
		}

		if command != "" {
			pwc.logWriter.Write([]byte(fmt.Sprintf("%s\n", command)))
		}
		defer r.Stop()
	}

	var clientTarget *kubeTarget
	userSlice := strings.SplitN(user, "/", 3)
	if len(userSlice) > 1 {
		switch len(userSlice) {
		case 2: // format is namespace/pod
			clientTarget = &kubeTarget{
				namespace: userSlice[0],
				pod:       userSlice[1],
			}
		case 3: // format is namespace/container/pod
			clientTarget = &kubeTarget{
				namespace: userSlice[0],
				pod:       userSlice[1],
				container: userSlice[2],
			}
		}
	}

	target, err := s.askForTarget(ctx, channel, kubeconfig, clientTarget, permissions)
	if err != nil {
		if err := s.errorEvent("ssh_recording", fmt.Sprintf("failed to determine target for remote command executor: %s", err), "", nil); err != nil {
			s.logger.Error("failed to create session event", zap.Error(err))
		}

		return
	}
	if target == nil {
		return // user cancelled operation
	}

	metadata, err := json.Marshal(struct {
		SessionType   string `json:"session_type"`
		ClientVersion string `json:"client_version"`
		Command       string `json:"command,omitempty"`
		Namespace     string `json:"namespace"`
		Pod           string `json:"pod"`
		Container     string `json:"container,omitempty"`
	}{req.Type, string(s.downstreamSshConn.ClientVersion()), command, target.namespace, target.pod, target.container})
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
		channel.Write([]byte("\r\n"))

		// we iterate over the slice and not the set
		// because order is not maintained for the set
		shells := []string{"bash", "zsh", "ash", "sh"}
		shellSet := set.New(shells...)
		for _, shell := range shells {
			if shellSet.Size() == 0 {
				channel.Write([]byte("No shells available in the target container :("))
				if err := s.errorEvent("ssh_kubectl_exec", fmt.Sprintf("no shells available in the target container: %s", err), "", target); err != nil {
					s.logger.Error("failed to create session event", zap.Error(err))
				}

				return
			}

			s.pty = true
			if err := s.exec(ctx, channel, terminalSizeQ, kubeconfig, shell, target); err != nil {
				if strings.Contains(err.Error(), "executable file not found") ||
					strings.Contains(err.Error(), "command terminated with exit code 127") {
					shellSet.Remove(shell)
					continue // try next shell
				}

				if !errors.Is(err, io.EOF) && !errors.Is(err, context.Canceled) {
					if err := s.errorEvent("ssh_kubectl_exec", fmt.Sprintf("failed to stream between ssh channel and target container: %s", err), shell, target); err != nil {
						s.logger.Error("failed to create session event", zap.Error(err))
					}
				}
				channel.SendRequest("exit-status", false, []byte{0, 0, 0, 1})
				return
			}
			break
		}
	case "exec":
		var payload = struct{ Value string }{}
		ssh.Unmarshal(req.Payload, &payload)
		command := payload.Value

		if err := s.exec(ctx, channel, terminalSizeQ, kubeconfig, command, target); err != nil {
			if !errors.Is(err, io.EOF) && !errors.Is(err, context.Canceled) {
				if err := s.errorEvent("ssh_kubectl_exec", fmt.Sprintf("failed to stream between ssh channel and target container: %s", err), command, target); err != nil {
					s.logger.Error("failed to create session event", zap.Error(err))
				}
			}

			channel.SendRequest("exit-status", false, []byte{0, 0, 0, 1})
			return
		}
	}

	channel.SendRequest("exit-status", false, []byte{0, 0, 0, 0})
}

func (s *kubectlExecSession) exec(ctx context.Context, channel ssh.Channel, terminalSizeQ remotecommand.TerminalSizeQueue, kubeconfig *rest.Config, command string, target *kubectlExecTarget) error {
	exec, err := getRemoteCommandExecutor(
		kubeconfig,
		command,
		target,
		s.pty,
	)
	if err != nil {
		return err
	}

	streamOptions := remotecommand.StreamOptions{
		Stdin:  channel,
		Stdout: channel,
		Stderr: channel.Stderr(),
	}

	if s.pty {
		streamOptions.Tty = true
		streamOptions.TerminalSizeQueue = terminalSizeQ
	}

	return exec.StreamWithContext(ctx, streamOptions)
}

type kubectlExecTarget struct {
	namespace string
	pod       string
	container string
}

func (s *kubectlExecSession) askForTarget(ctx context.Context, channel ssh.Channel, kubeconfig *rest.Config, clientTarget *kubeTarget, permissions []models.Permissions) (*kubectlExecTarget, error) {
	clientset, err := kubernetes.NewForConfig(kubeconfig)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize new k8s clientset to query the cluster: %v", err)
	}

	// get namespaces from k8s api
	listNsCtx, cancel := context.WithTimeout(ctx, time.Second*5)
	defer cancel()
	namespaceList, err := clientset.CoreV1().Namespaces().List(listNsCtx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to list namespaces in cluster: %v", err)
	}

	// filter namespaces if there with allowlist *iff* provided, otherwise all are available
	namespaces := []string{}
	for _, ns := range namespaceList.Items {
		if len(s.config.KubectlExecProxy.NamespaceAllowlist) > 0 && !slices.Contains(s.config.KubectlExecProxy.NamespaceAllowlist, ns.Name) {
			continue
		}

		if len(permissions) > 0 {
			var allowed bool
			for _, permission := range permissions {
				if permission.SSH != nil && permission.SSH.KubectlExec != nil && permission.SSH.KubectlExec.AllowedNamespaces != nil {
					for _, allowedNamespace := range *permission.SSH.KubectlExec.AllowedNamespaces {
						if strings.EqualFold(ns.Name, allowedNamespace.Namespace) || allowedNamespace.Namespace == "*" {
							allowed = true
							break
						}
					}
				} else {
					allowed = true
					break
				}
			}

			if !allowed {
				continue
			}
		}

		if clientTarget != nil {
			if ns.Name != clientTarget.namespace {
				continue
			}
		}

		namespaces = append(namespaces, ns.Name)
	}

	if len(namespaces) == 0 {
		channel.Write([]byte("\r\nNo targets available to you - sorry :("))
		return nil, fmt.Errorf("no (allowlisted) namespaces found in cluster")
	}

	// identify namespace to use
	namespace := ""
	if len(namespaces) == 1 {
		namespace = namespaces[0]
	} else {
		namespacePrompt := promptui.Select{
			Label:             "Choose a namespace",
			Items:             namespaces,
			Stdout:            channel,
			Stdin:             channel,
			StartInSearchMode: true,
			Searcher: func(input string, index int) bool {
				return strings.Contains(strings.ToLower(namespaces[index]), strings.ToLower(input))
			},
		}
		_, selectedNamespace, err := namespacePrompt.Run()
		if err != nil {
			// handle cancellation by user (e.g. ^C or ^D)
			if errors.Is(err, promptui.ErrInterrupt) || errors.Is(err, promptui.ErrEOF) {
				return nil, nil
			}
			return nil, fmt.Errorf("unable to select namespace: %v", err)
		}
		namespace = selectedNamespace
	}

	// if there is a selectors allowlist for this namespace
	compareChosenPodAgainstSelectors := false
	selectors := map[string][]string{}

	if namespaceSelectors, ok := s.config.KubectlExecProxy.NamespaceSelectorsAllowlist[namespace]; ok && len(namespaceSelectors) != 0 {
		compareChosenPodAgainstSelectors = true
		selectors = namespaceSelectors
	}

	// get pods from k8s api
	listPodsCtx, cancel := context.WithTimeout(ctx, time.Second*5)
	defer cancel()
	podList, err := clientset.CoreV1().Pods(namespace).List(listPodsCtx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to list pods in namespace \"%s\": %v", namespace, err)
	}

	// filter them if needed based on selectors. Otherwise just extract the name.
	pods := []string{}
	for _, pod := range podList.Items {
		if compareChosenPodAgainstSelectors {
			if !maps.MatchesFilters(pod.ObjectMeta.Labels, selectors, nil) {
				continue
			}
		}

		if !isPodAllowed(pod, namespace, permissions) {
			continue
		}

		if clientTarget != nil {
			if pod.Name != clientTarget.pod {
				continue
			}
		}

		pods = append(pods, pod.Name)
	}

	if len(pods) == 0 {
		channel.Write([]byte("\r\nNo targets available to you - sorry :("))
		return nil, fmt.Errorf("no (allowlisted) pods found in namespace \"%s\"", namespace)
	}

	// identify pod to use
	pod := ""
	if len(pods) == 1 {
		pod = pods[0]
	} else {
		// pick a pod
		podPrompt := promptui.Select{
			Label:             "Choose a pod",
			Items:             pods,
			Stdout:            channel,
			Stdin:             channel,
			StartInSearchMode: true,
			Searcher: func(input string, index int) bool {
				return strings.Contains(strings.ToLower(pods[index]), strings.ToLower(input))
			},
		}
		_, selectedPod, err := podPrompt.Run()
		if err != nil {
			// handle cancellation by user (e.g. ^C or ^D)
			if errors.Is(err, promptui.ErrInterrupt) || errors.Is(err, promptui.ErrEOF) {
				return nil, nil
			}
			return nil, fmt.Errorf("unable to select pod: %v", err)
		}
		pod = selectedPod
	}

	// describe selected pod via k8s api
	getPodCtx, cancel := context.WithTimeout(ctx, time.Second*5)
	defer cancel()
	describedPod, err := clientset.CoreV1().Pods(namespace).Get(getPodCtx, pod, metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to get containers in pod %s of namespace %s: %v", pod, namespace, err)
	}

	containers := []string{}
	for _, container := range describedPod.Spec.Containers {
		if clientTarget != nil && clientTarget.container != "" && clientTarget.container != container.Name {
			continue
		}

		containers = append(containers, container.Name)
	}

	if len(containers) == 0 {
		channel.Write([]byte("\r\nNo targets available to you - sorry :("))
		return nil, fmt.Errorf("no containers available in pod \"%s\" of namespace \"%s\"", pod, namespace)
	}

	container := ""
	if len(containers) == 1 {
		container = containers[0]
	} else {
		// pick a container
		containerPrompt := promptui.Select{
			Label:             "Choose a container",
			Items:             containers,
			Stdout:            channel,
			Stdin:             channel,
			StartInSearchMode: true,
			Searcher: func(input string, index int) bool {
				return strings.Contains(strings.ToLower(containers[index]), strings.ToLower(input))
			},
		}
		_, selectedContainer, err := containerPrompt.Run()
		if err != nil {
			// handle cancellation by user (e.g. ^C or ^D)
			if errors.Is(err, promptui.ErrInterrupt) || errors.Is(err, promptui.ErrEOF) {
				return nil, nil
			}
			return nil, fmt.Errorf("unable to select container: %v", err)
		}
		container = selectedContainer
	}

	return &kubectlExecTarget{
		namespace: namespace,
		pod:       pod,
		container: container,
	}, nil
}

// getRemoteCommandExecutor returns an abstraction for a multiplexed bidirectional
// stream of a TTY on a given namespace and pod based on the given command.
func getRemoteCommandExecutor(
	config *rest.Config,
	command string,
	target *kubectlExecTarget,
	tty bool,
) (remotecommand.Executor, error) {
	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, err
	}

	commandArgs, err := shlex.Split(command, true)
	if err != nil {
		return nil, err
	}

	req := clientset.
		CoreV1().
		RESTClient().
		Post().
		Resource("pods").
		Name(target.pod).
		Namespace(target.namespace).
		SubResource("exec")

	option := &v1.PodExecOptions{
		Container: target.container,
		Command:   commandArgs,
		Stdin:     true,
		Stdout:    true,
		Stderr:    true,
	}

	if tty {
		option.TTY = true
	}

	req = req.VersionedParams(option, scheme.ParameterCodec)

	exec, err := remotecommand.NewSPDYExecutor(config, http.MethodPost, req.URL())
	if err != nil {
		return nil, err
	}

	return exec, nil
}

type terminalWindowSizeQueue struct {
	ctx  context.Context
	c    chan *remotecommand.TerminalSize
	done bool
}

// ensure terminalWindowSizeQueue implements remotecommand.TerminalSizeQueue.
var _ remotecommand.TerminalSizeQueue = (*terminalWindowSizeQueue)(nil)

func newTerminalWindowSizeQueue(ctx context.Context) *terminalWindowSizeQueue {
	return &terminalWindowSizeQueue{
		ctx: ctx,
		c:   make(chan *remotecommand.TerminalSize, 50),
	}
}

func (q *terminalWindowSizeQueue) Next() *remotecommand.TerminalSize {
	if q.done {
		return nil
	}
	select {
	case size := <-q.c:
		return size
	case <-q.ctx.Done():
		if q.done {
			return nil
		}
		q.done = true
		defer close(q.c)
		return nil
	}
}

func (q *terminalWindowSizeQueue) push(ts *remotecommand.TerminalSize) {
	q.c <- ts
}

func isPodAllowed(pod v1.Pod, namespace string, permissions []models.Permissions) bool {
	if len(permissions) == 0 {
		return true
	}

	for _, permission := range permissions {
		if permission.SSH == nil || permission.SSH.KubectlExec == nil {
			continue
		}

		if permission.SSH.KubectlExec.AllowedNamespaces == nil {
			return true
		}

		for _, ns := range *permission.SSH.KubectlExec.AllowedNamespaces {
			if strings.EqualFold(ns.Namespace, namespace) || ns.Namespace == "*" {
				if labelMatchesPod(ns.PodSelector, pod) {
					return true
				}
			}
		}
	}

	return false
}

func labelMatchesPod(podSelector *map[string]string, pod v1.Pod) bool {
	if podSelector == nil {
		return true
	}

	if len(*podSelector) == 0 {
		return false
	}

	for label, value := range *podSelector {
		if labelValue, ok := pod.ObjectMeta.Labels[label]; !ok || !strings.EqualFold(labelValue, value) {
			return false
		}
	}

	return true
}

func (s *kubectlExecSession) errorEvent(eventType, message, command string, target *kubectlExecTarget) error {
	var clientVersion string
	if s.downstreamSshConn != nil {
		clientVersion = string(s.downstreamSshConn.ClientVersion())
	}

	metadataStruct := struct {
		ClientVersion string `json:"client_version,omitempty"`
		Error         string `json:"error"`
		Namespace     string `json:"namespace,omitempty"`
		Pod           string `json:"pod,omitempty"`
		Container     string `json:"container,omitempty"`
		Command       string `json:"command,omitempty"`
	}{
		ClientVersion: clientVersion,
		Error:         message,
		Command:       command,
	}

	if target != nil {
		metadataStruct.Namespace = target.namespace
		metadataStruct.Pod = target.pod
		metadataStruct.Container = target.container
	}

	metadata, err := json.Marshal(metadataStruct)
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
