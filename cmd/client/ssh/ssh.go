package ssh

import (
	"archive/tar"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/AlecAivazis/survey/v2"
	"github.com/borderzero/border0-cli/client/preference"
	"github.com/borderzero/border0-cli/cmd/logger"
	"github.com/borderzero/border0-cli/internal"
	"github.com/borderzero/border0-cli/internal/client"
	"github.com/borderzero/border0-cli/internal/enum"
	"github.com/borderzero/border0-cli/internal/util"
	"github.com/moby/term"
	"github.com/spf13/cobra"
	"golang.org/x/crypto/ssh"
)

var (
	hostname     string
	sshLoginName string
	useWsProxy   bool
	noPreserve   bool
)

type HostDB struct {
	Hosts []Host `json:"hosts"`
}

type Host struct {
	DNSname    string    `json:"dnsname"`
	Username   string    `json:"username"`
	LastUsed   time.Time `json:"lastused"`
	SocketType string    `json:"sockettype"`
}

func AddCommandsTo(client *cobra.Command) {
	client.AddCommand(sshCmd)
	sshCmd.Flags().StringVarP(&hostname, "host", "", "", "The ssh border0 target host")
	sshCmd.Flags().StringVarP(&sshLoginName, "username", "u", "", "Specifies the user to log in as on the remote machine(deprecated)")
	sshCmd.Flags().StringVarP(&sshLoginName, "login", "l", "", "Same as username, specifies the user login to use on remote machine")
	sshCmd.Flags().BoolVarP(&useWsProxy, "wsproxy", "w", false, "Use websocket proxy")

	sshCPCmd.Flags().StringVarP(&hostname, "host", "", "", "The ssh border0 target host")
	sshCPCmd.Flags().StringVarP(&sshLoginName, "login", "l", "", "Same as username, specifies the user login to use on remote machine")
	sshCPCmd.Flags().BoolVarP(&useWsProxy, "wsproxy", "w", false, "Use websocket proxy")
	sshCPCmd.Flags().BoolVarP(&noPreserve, "no-preserve", "", false, "Do not preserve file attributes")
	sshCmd.AddCommand(sshCPCmd)

	client.AddCommand(keySignCmd)
	keySignCmd.Flags().StringVarP(&hostname, "host", "", "", "The border0 target host")
	keySignCmd.MarkFlagRequired("host")
}

// sshCmd represents the client ssh keysign command
var sshCPCmd = &cobra.Command{
	Use:               "cp <file-spec-src> <file-spec-dest>",
	Short:             "copy from/to a border0 ssh service",
	ValidArgsFunction: client.AutocompleteHost,
	RunE: func(cmd *cobra.Command, args []string) error {
		if len(args) != 2 {
			return errors.New("source and destination are required")
		}

		srcSpec, err := extractFileSpec(args[0])
		if err != nil {
			return err
		}
		destSpec, err := extractFileSpec(args[1])
		if err != nil {
			return err
		}

		if len(srcSpec.PodName) != 0 && len(destSpec.PodName) != 0 {
			return fmt.Errorf("one of src or dest must be a local file specification")
		}
		if len(srcSpec.File.String()) == 0 || len(destSpec.File.String()) == 0 {
			return errors.New("filepath can not be empty")
		}

		if len(srcSpec.PodName) == 0 && len(destSpec.PodName) == 0 {
			return fmt.Errorf("one of src or dest must be a remote file specification")
		}

		var hostname string
		if len(srcSpec.PodName) != 0 {
			hostname = srcSpec.Socket
		} else {
			hostname = destSpec.Socket
		}

		token, claims, err := client.MTLSLogin(logger.Logger, hostname)
		if err != nil {
			return err
		}
		orgID := fmt.Sprint(claims["org_id"])

		sshCert, err := client.GenSSHKey(token, orgID, hostname)
		if err != nil {
			return fmt.Errorf("unable to create ssh key: %w", err)
		}

		info, err := client.GetResourceInfo(logger.Logger, hostname)
		if err != nil {
			log.Fatalf("failed to get certificate: %v", err.Error())
		}

		certificate := tls.Certificate{
			Certificate: [][]byte{info.Certficate.Raw},
			PrivateKey:  info.PrivateKey,
		}

		systemCertPool, err := x509.SystemCertPool()
		if err != nil {
			return fmt.Errorf("failed to load system cert pool: %w", err)
		}

		tlsConfig := tls.Config{
			Certificates: []tls.Certificate{certificate},
			ServerName:   hostname,
			RootCAs:      systemCertPool,
		}

		conn, err := client.Connect(net.JoinHostPort(hostname, strconv.Itoa(info.Port)), true, &tlsConfig, certificate, info.CaCertificate, info.ConnectorAuthenticationEnabled, info.EndToEndEncryptionEnabled, useWsProxy)
		if err != nil {
			if errors.Is(err, client.ErrConnectorHandshakeFailed) || errors.Is(err, client.ErrProxyHandshakeFailed) {
				return fmt.Errorf("failed to connect: %s. You may not be authorized for this socket. Speak to your Border0 administrator", err)
			}
			return fmt.Errorf("failed to connect: %w", err)
		}

		home, err := util.GetUserHomeDir()
		if err != nil {
			return fmt.Errorf("failed to write ssh key: %w", err)
		}

		buffer, err := os.ReadFile(fmt.Sprintf("%s/.ssh/%s", home, claims["org_id"]))
		if err != nil {
			return err
		}

		k, err := ssh.ParsePrivateKey(buffer)
		if err != nil {
			return err
		}

		certData := []byte(sshCert.SSHCertSigned)
		pubcert, _, _, _, err := ssh.ParseAuthorizedKey(certData)
		if err != nil {
			return err
		}
		cert1, ok := pubcert.(*ssh.Certificate)
		if !ok {
			return fmt.Errorf("failed to cast to certificate: %w", err)
		}

		certSigner, err := ssh.NewCertSigner(cert1, k)
		if err != nil {
			return fmt.Errorf("NewCertSigner: %w", err)
		}

		var remoteSpec fileSpec
		if len(srcSpec.PodName) != 0 {
			remoteSpec = srcSpec
		} else {
			remoteSpec = destSpec
		}

		user := fmt.Sprintf("%s/%s", remoteSpec.PodNamespace, remoteSpec.PodName)
		if len(remoteSpec.PodContainer) != 0 {
			user = fmt.Sprintf("%s/%s", user, remoteSpec.PodContainer)
		}

		sshConfig := &ssh.ClientConfig{
			User:            user,
			HostKeyCallback: ssh.InsecureIgnoreHostKey(),
			Timeout:         10 * time.Second,
			Auth:            []ssh.AuthMethod{ssh.PublicKeys(certSigner)},
			ClientVersion:   "SSH-2.0-Border0-" + internal.Version,
		}

		serverConn, chans, reqs, err := ssh.NewClientConn(conn, hostname, sshConfig)
		if err != nil {
			if err.Error() == "ssh: handshake failed: EOF" {
				return fmt.Errorf("ssh handshake failed (EOF): you might be unauthorized for this server")
			}
			return fmt.Errorf("dial into remote server error: %s", err)
		}
		defer serverConn.Close()

		sshClient := ssh.NewClient(serverConn, chans, reqs)

		session, err := sshClient.NewSession()
		if err != nil {
			return fmt.Errorf("failed to create session: %w", err)
		}
		defer session.Close()

		if len(srcSpec.PodName) != 0 {
			cmd := fmt.Sprintf("tar cf - %s", srcSpec.File.String())
			stdin, err := session.StdinPipe()
			if err != nil {
				return fmt.Errorf("failed to get stdin pipe: %w", err)
			}

			stdoutPipe, err := session.StdoutPipe()
			if err != nil {
				return fmt.Errorf("failed to get stdout pipe: %w", err)
			}

			stderrPipe, err := session.StderrPipe()
			if err != nil {
				return fmt.Errorf("failed to get stderr pipe: %w", err)
			}

			if err := session.Start(cmd); err != nil {
				return fmt.Errorf("failed to start session: %w", err)
			}

			go io.Copy(stdin, os.Stdin)
			go io.Copy(os.Stderr, stderrPipe)

			srcFile := srcSpec.File.(remotePath)
			prefix := stripPathShortcuts(srcFile.StripSlashes().Clean().String())
			destFile := destSpec.File.(localPath)

			tr := tar.NewReader(stdoutPipe)
			for {
				header, err := tr.Next()
				if err != nil {
					if err != io.EOF {
						return err
					}

					break
				}

				if !strings.HasPrefix(header.Name, prefix) {
					return fmt.Errorf("tar contents corrupted")
				}

				mode := header.FileInfo().Mode()
				destFileName := destFile.Join(newRemotePath(header.Name[len(prefix):]))

				if !isRelative(destFile, destFileName) {
					session.Stderr.Write([]byte(fmt.Sprintf("warning: file %q is outside target destination, skipping\n", destFileName)))
					continue
				}

				if err := os.MkdirAll(destFileName.Dir().String(), 0755); err != nil {
					return err
				}
				if header.FileInfo().IsDir() {
					if err := os.MkdirAll(destFileName.String(), 0755); err != nil {
						return err
					}
					continue
				}

				if mode&os.ModeSymlink != 0 {
					session.Stderr.Write([]byte(fmt.Sprintf("warning: skipping symlink: %q -> %q\n", destFileName, header.Linkname)))
					continue
				}
				outFile, err := os.Create(destFileName.String())
				if err != nil {
					return err
				}
				defer outFile.Close()
				if _, err := io.Copy(outFile, tr); err != nil {
					return err
				}
				if err := outFile.Close(); err != nil {
					return err
				}
			}

			if err := session.Wait(); err != nil {
				return fmt.Errorf("failed to complete session: %w", err)
			}
		}

		if len(destSpec.PodName) != 0 {
			if _, err := os.Stat(srcSpec.File.String()); err != nil {
				return fmt.Errorf("%s doesn't exist in local filesystem", srcSpec.File)
			}

			stdinPipe, err := session.StdinPipe()
			if err != nil {
				return fmt.Errorf("failed to get stdin pipe: %w", err)
			}

			stdoutPipe, err := session.StdoutPipe()
			if err != nil {
				return fmt.Errorf("failed to get stdout pipe: %w", err)
			}

			stderrPipe, err := session.StderrPipe()
			if err != nil {
				return fmt.Errorf("failed to get stdin pipe: %w", err)
			}

			go io.Copy(os.Stderr, stderrPipe)
			go io.Copy(os.Stdout, stdoutPipe)

			srcFile := srcSpec.File.(localPath)
			destFile := destSpec.File.(remotePath)

			if err := checkDestinationIsDir(destSpec, sshClient); err == nil {
				// If no error, dest.File was found to be a directory.
				// Copy specified src into it
				destFile = destFile.Join(srcFile.Base())
			}

			go func(src localPath, dest remotePath, writer io.WriteCloser) {
				defer writer.Close()

				tarWriter := tar.NewWriter(writer)
				defer tarWriter.Close()

				srcPath := src.Clean()
				destPath := dest.Clean()

				if err := recursiveTar(srcPath.Dir(), srcPath.Base(), destPath.Dir(), destPath.Base(), tarWriter); err != nil {
					fmt.Printf("failed to create tar archive: %v\n", err)
				}
			}(srcFile, destFile, stdinPipe)

			var cmd string

			if noPreserve {
				cmd = "tar --no-same-permissions --no-same-owner -xmf -"
			} else {
				cmd = "tar -xmf -"
			}

			destFileDir := destFile.Dir().String()
			if len(destFileDir) > 0 {
				cmd = fmt.Sprintf("%s -C %s", cmd, destFileDir)
			}

			if err := session.Start(cmd); err != nil {
				return fmt.Errorf("failed to start session: %w", err)
			}

			if err := session.Wait(); err != nil {
				return fmt.Errorf("failed to complete session: %w", err)
			}
		}

		return nil
	},
}

// sshCmd represents the client ssh keysign command
var sshCmd = &cobra.Command{
	Use:               "ssh [flags] [destination] [command]",
	Short:             "Connect to a border0 ssh service",
	Example:           "border0 client ssh user@socket whoami",
	ValidArgsFunction: client.AutocompleteHost,
	RunE: func(cmd *cobra.Command, args []string) error {
		var commands []string

		if hostname == "" {
			if len(args) > 0 {
				hostnameSlice := strings.SplitN(args[0], "@", 2)
				switch len(hostnameSlice) {
				case 1:
					hostname = hostnameSlice[0]
				case 2:
					sshLoginName = hostnameSlice[0]
					hostname = hostnameSlice[1]
				}
			}

			if len(args) > 1 {
				commands = args[1:]
			}
		} else {
			if len(args) > 0 {
				commands = args
			}
		}

		var sshType string
		if hostname == "" {
			pickedHost, err := client.PickHost(hostname, enum.SSHSocket, enum.TLSSocket)
			if err != nil {
				return err
			}
			hostname = pickedHost.Hostname()
			sshType = pickedHost.SshType
		}

		token, claims, err := client.MTLSLogin(logger.Logger, hostname)
		if err != nil {
			return err
		}
		orgID := fmt.Sprint(claims["org_id"])

		pref, err := preference.Read()
		if err != nil {
			fmt.Println("WARNING: could not read preference file:", err)
		}
		socketPref := preference.NewSSHSocket(hostname)

		if sshType != "aws-ssm" {
			if sshLoginName == "" {
				suggestedSocket := pref.Socket(hostname)
				if preference.Found(suggestedSocket) {
					sshLoginName = suggestedSocket.Username
					socketPref = suggestedSocket
				} else {
					suggestedSocket = pref.SuggestSocket(hostname, enum.SSHSocket)
					if preference.Found(suggestedSocket) {
						sshLoginName = suggestedSocket.Username
						socketPref = suggestedSocket
					}
					if err = survey.AskOne(&survey.Input{
						Message: "SSH username:",
						Default: sshLoginName,
					}, &sshLoginName); err != nil {
						return errors.New("failed to get login/username, empty login not allowed")
					}
				}
			}

			// Now we should have the login name, so lets write back the data to the preference file
			socketPref.Username = sshLoginName
			pref.SetSocket(socketPref)
		}
		sshCert, err := client.GenSSHKey(token, orgID, hostname)
		if err != nil {
			return fmt.Errorf("unable to create ssh key: %w", err)
		}

		info, err := client.GetResourceInfo(logger.Logger, hostname)
		if err != nil {
			log.Fatalf("failed to get certificate: %v", err.Error())
		}

		certificate := tls.Certificate{
			Certificate: [][]byte{info.Certficate.Raw},
			PrivateKey:  info.PrivateKey,
		}

		systemCertPool, err := x509.SystemCertPool()
		if err != nil {
			return fmt.Errorf("failed to load system cert pool: %w", err)
		}

		tlsConfig := tls.Config{
			Certificates: []tls.Certificate{certificate},
			ServerName:   hostname,
			RootCAs:      systemCertPool,
		}

		conn, err := client.Connect(net.JoinHostPort(hostname, strconv.Itoa(info.Port)), true, &tlsConfig, certificate, info.CaCertificate, info.ConnectorAuthenticationEnabled, info.EndToEndEncryptionEnabled, useWsProxy)
		if err != nil {
			if errors.Is(err, client.ErrConnectorHandshakeFailed) || errors.Is(err, client.ErrProxyHandshakeFailed) {
				return fmt.Errorf("failed to connect: %s. You may not be authorized for this socket. Speak to your Border0 administrator", err)
			}
			return fmt.Errorf("failed to connect: %w", err)
		}

		home, err := util.GetUserHomeDir()
		if err != nil {
			return fmt.Errorf("failed to write ssh key: %w", err)
		}

		buffer, err := os.ReadFile(fmt.Sprintf("%s/.ssh/%s", home, claims["org_id"]))
		if err != nil {
			return err
		}

		k, err := ssh.ParsePrivateKey(buffer)
		if err != nil {
			return err
		}

		certData := []byte(sshCert.SSHCertSigned)
		pubcert, _, _, _, err := ssh.ParseAuthorizedKey(certData)
		if err != nil {
			return err
		}
		cert1, ok := pubcert.(*ssh.Certificate)
		if !ok {
			return fmt.Errorf("failed to cast to certificate: %w", err)
		}

		certSigner, err := ssh.NewCertSigner(cert1, k)
		if err != nil {
			return fmt.Errorf("NewCertSigner: %w", err)
		}

		sshConfig := &ssh.ClientConfig{
			User:            sshLoginName,
			HostKeyCallback: ssh.InsecureIgnoreHostKey(),
			Timeout:         10 * time.Second,
			Auth:            []ssh.AuthMethod{ssh.PublicKeys(certSigner)},
			ClientVersion:   "SSH-2.0-Border0-" + internal.Version,
		}

		if len(commands) == 0 {
			fmt.Printf("\nConnecting to Server: %s:%d as %s \n", hostname, info.Port, sshLoginName)
		}
		serverConn, chans, reqs, err := ssh.NewClientConn(conn, hostname, sshConfig)
		if err != nil {
			if err.Error() == "ssh: handshake failed: EOF" {
				return fmt.Errorf("ssh handshake failed (EOF): you might be unauthorized for this server")
			}
			return fmt.Errorf("dial into remote server error: %s", err)
		}
		defer serverConn.Close()

		sshClient := ssh.NewClient(serverConn, chans, reqs)

		session, err := sshClient.NewSession()
		if err != nil {
			return fmt.Errorf("failed to create session: %w", err)
		}
		defer session.Close()

		// persist logged in username
		if err := preference.Write(pref); err != nil {
			fmt.Println("WARNING: could not update preference file:", err)
		}

		fd := os.Stdin.Fd()

		var termWidth, termHeight = 80, 24

		if term.IsTerminal(fd) {
			oldState, err := term.MakeRaw(fd)
			if err != nil {
				log.Fatalf("%s", err)
			}

			defer term.RestoreTerminal(fd, oldState)

			winsize, err := term.GetWinsize(fd)
			if err == nil {
				termWidth = int(winsize.Width)
				termHeight = int(winsize.Height)
			}
		}

		modes := ssh.TerminalModes{
			ssh.ECHO:          1,
			ssh.TTY_OP_ISPEED: 14400,
			ssh.TTY_OP_OSPEED: 14400,
		}

		term := os.Getenv("TERM")
		if term == "" {
			term = "xterm-256color"
		}

		if err := session.RequestPty(term, termHeight, termWidth, modes); err != nil {
			return fmt.Errorf("session xterm: %w", err)
		}

		go client.MonWinCh(session, os.Stdout.Fd())

		session.Stdout = os.Stdout
		session.Stderr = os.Stderr
		session.Stdin = os.Stdin

		if len(commands) > 0 {
			if err := session.Run(strings.Join(commands, " ")); err != nil {
				return fmt.Errorf("session run: %w", err)
			}
		} else {
			if err := session.Shell(); err != nil {
				return fmt.Errorf("session shell: %w", err)
			}

			done := make(chan bool, 1)
			defer func() { done <- true }()

			go keepAlive(sshClient, done)
			if err := session.Wait(); err != nil {
				// gracefully handle ssh.ExitMissingError. It's returned if a session is torn down cleanly,
				// but the server sends no confirmation of the exit status
				if !errors.Is(err, new(ssh.ExitMissingError)) {
					return err
				}
			}
		}
		return nil
	},
}

func keepAlive(sshClient *ssh.Client, done chan bool) {
	t := time.NewTicker(10 * time.Second)
	max := 4
	n := 0

	defer t.Stop()

	for {
		select {
		case <-done:
			return
		case <-t.C:
			aliveChan := make(chan bool, 1)

			go func() {
				_, _, err := sshClient.SendRequest("keepalive@border0.com", true, nil)
				if err != nil {
					aliveChan <- false
				} else {
					aliveChan <- true
				}
			}()

			select {
			case <-time.After(5 * time.Second):
				n++
			case alive := <-aliveChan:
				if !alive {
					n++
				} else {
					n = 0
				}
			}

			if n >= max {
				log.Println("ssh keepalive timeout, disconnecting")
				sshClient.Close()
				return
			}
		}
	}
}

var (
	errFileSpecDoesntMatchFormat = errors.New("filespec must match the canonical format:\n\t kubernetes target: namespace/pod[/container]@socket:file/path\n\t docker target: container/root@socket:file/path\n\t ssh target: user@socket:file/path")
)

func extractFileSpec(arg string) (fileSpec, error) {
	i := strings.Index(arg, ":")

	// filespec starting with a semicolon is invalid
	if i == 0 {
		return fileSpec{}, errFileSpecDoesntMatchFormat
	}
	if i == -1 {
		return fileSpec{
			File: newLocalPath(arg),
		}, nil
	}

	pod, file := arg[:i], arg[i+1:]
	pieces := strings.Split(pod, "@")
	if len(pieces) != 2 {
		return fileSpec{}, errFileSpecDoesntMatchFormat
	}

	host := pieces[1]
	pieces = strings.Split(pieces[0], "/")
	switch len(pieces) {
	case 1:
		return fileSpec{
			PodName: pieces[0],
			Socket:  host,
			File:    newRemotePath(file),
		}, nil
	case 2:
		return fileSpec{
			PodNamespace: pieces[0],
			PodName:      pieces[1],
			Socket:       host,
			File:         newRemotePath(file),
		}, nil
	case 3:
		return fileSpec{
			PodNamespace: pieces[0],
			PodName:      pieces[1],
			PodContainer: pieces[2],
			Socket:       host,
			File:         newRemotePath(file),
		}, nil
	default:
		return fileSpec{}, errFileSpecDoesntMatchFormat
	}
}

func recursiveTar(srcDir, srcFile localPath, destDir, destFile remotePath, tw *tar.Writer) error {
	matchedPaths, err := srcDir.Join(srcFile).Glob()
	if err != nil {
		return err
	}
	for _, fpath := range matchedPaths {
		stat, err := os.Lstat(fpath)
		if err != nil {
			return err
		}
		if stat.IsDir() {
			files, err := os.ReadDir(fpath)
			if err != nil {
				return err
			}
			if len(files) == 0 {
				//case empty directory
				hdr, _ := tar.FileInfoHeader(stat, fpath)
				hdr.Name = destFile.String()
				if err := tw.WriteHeader(hdr); err != nil {
					return err
				}
			}
			for _, f := range files {
				if err := recursiveTar(srcDir, srcFile.Join(newLocalPath(f.Name())),
					destDir, destFile.Join(newRemotePath(f.Name())), tw); err != nil {
					return err
				}
			}
			return nil
		} else if stat.Mode()&os.ModeSymlink != 0 {
			//case soft link
			hdr, _ := tar.FileInfoHeader(stat, fpath)
			target, err := os.Readlink(fpath)
			if err != nil {
				return err
			}

			hdr.Linkname = target
			hdr.Name = destFile.String()
			if err := tw.WriteHeader(hdr); err != nil {
				return err
			}
		} else {
			//case regular file or other file type like pipe
			hdr, err := tar.FileInfoHeader(stat, fpath)
			if err != nil {
				return err
			}
			hdr.Name = destFile.String()

			if err := tw.WriteHeader(hdr); err != nil {
				return err
			}

			f, err := os.Open(fpath)
			if err != nil {
				return err
			}
			defer f.Close()

			if _, err := io.Copy(tw, f); err != nil {
				return err
			}
			return f.Close()
		}
	}
	return nil
}

// checkDestinationIsDir receives a destination fileSpec and
// determines if the provided destination path exists on the
// pod. If the destination path does not exist or is _not_ a
// directory, an error is returned with the exit code received.
func checkDestinationIsDir(dest fileSpec, sshClient *ssh.Client) error {
	session, err := sshClient.NewSession()
	if err != nil {
		return fmt.Errorf("failed to create session: %w", err)
	}
	defer session.Close()

	if err := session.Run(fmt.Sprintf("test -d %s", dest.File.String())); err != nil {
		return fmt.Errorf("destination is not a directory: %w", err)
	}

	return nil
}
