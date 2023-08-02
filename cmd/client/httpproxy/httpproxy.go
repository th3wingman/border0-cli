package httpproxy

import (
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"

	b0tls "github.com/borderzero/border0-cli/cmd/client/tls"
	"github.com/borderzero/border0-cli/cmd/logger"
	"github.com/borderzero/border0-cli/internal/client"
	"github.com/borderzero/border0-cli/internal/enum"
	"github.com/hashicorp/yamux"
	"github.com/spf13/cobra"
)

var (
	hostname      string
	httpProxyPort int
	numStreams    int
)

type SessionManager struct {
	sessions []*yamux.Session
}

// clientProxyCmd represents the client tls command
var clientProxyCmd = &cobra.Command{
	Use:               "proxy",
	Short:             "Connect a Border0 HTTP proxy",
	ValidArgsFunction: client.AutocompleteHost,
	RunE: func(cmd *cobra.Command, args []string) error {
		if len(args) > 0 {
			hostname = args[0]
		}

		if numStreams < 1 {
			return fmt.Errorf("number of streams must be greater than 0")
		}

		if httpProxyPort == 0 {
			return fmt.Errorf("port number is required")
		}

		if hostname == "" {
			pickedHost, err := client.PickHost(hostname, enum.TLSSocket)
			if err != nil {
				return fmt.Errorf("failed to pick host: %v", err)
			}
			hostname = pickedHost.Hostname()
		}

		info, err := client.GetResourceInfo(logger.Logger, hostname)
		if err != nil {
			return fmt.Errorf("failed to get certificate: %v", err)
		}

		certificate := tls.Certificate{
			Certificate: [][]byte{info.Certficate.Raw},
			PrivateKey:  info.PrivateKey,
		}

		tlsConfig := tls.Config{
			Certificates:       []tls.Certificate{certificate},
			InsecureSkipVerify: true,
		}

		// Create a multiplexed session over multiple TCP connections
		//sessions := make([]*yamux.Session, numStreams)
		sessionManager := &SessionManager{}

		for i := 0; i < numStreams; i++ {
			conn, err := b0tls.EstablishConnection(info.ConnectorAuthenticationEnabled, fmt.Sprintf("%s:%d", hostname, info.Port), &tlsConfig)
			if err != nil {
				log.Fatalf("Failed to connect to proxy: %v", err)
			}

			fmt.Printf("%d = Connected to %s:%d\n", i, hostname, info.Port)
			session, err := yamux.Client(conn, nil)
			if err != nil {
				log.Fatalf("Failed to create yamux session: %v", err)
			}
			fmt.Println("Created session number ", i)
			//sessions[i] = session
			sessionManager.addSession(session)
		}

		// Now start the local listener on which we accept the traffic
		l, err := net.Listen("tcp", fmt.Sprintf("localhost:%d", httpProxyPort))
		if err != nil {
			log.Fatalf("error: Unable to start tcp listener on port %d, %s\n", httpProxyPort, err)
		}
		defer l.Close()
		log.Printf("service started, listening for connections on port %d\n", httpProxyPort)

		sessionIndex := 0

		for {
			clientConn, err := l.Accept()
			if err != nil {
				log.Printf("Failed to accept connection: %v", err)
				continue
			}
			// Choose a session from the slice by using the index
			//selectedSession := sessions[sessionIndex]
			selectedSession := sessionManager.selectSession(sessionIndex)

			// Increment the index so that next time a different session is used
			sessionIndex++

			go handleClientConnection(clientConn, selectedSession)
		}

		return nil
	},
}

// SessionManager is a simple struct that holds a slice of yamux sessions
// here we can add and remove sessions as they are created and closed
func (sm *SessionManager) addSession(session *yamux.Session) {
	sm.sessions = append(sm.sessions, session)
	go func() {
		<-session.CloseChan() // Wait for the session to close
		sm.removeSession(session)
	}()
}

// removeSession is a simple function that removes a session from the slice
func (sm *SessionManager) removeSession(session *yamux.Session) {
	for i, s := range sm.sessions {
		if s == session {
			log.Printf("one of the upstream connections went down and has been removed. Pool size is now %d\n", len(sm.sessions))
			sm.sessions = append(sm.sessions[:i], sm.sessions[i+1:]...)

			// Todo, we could try to reconnect here and add one back to the pool
			break
		}
	}
	if len(sm.sessions) == 0 {
		log.Fatalf("All upstream sessions have been closed, no more upstream options available. Exiting.")
	}
}

// selectSession is a simple function that selects a session from the slice
func (sm *SessionManager) selectSession(index int) *yamux.Session {
	return sm.sessions[index%len(sm.sessions)]
}

// handleClientConnection is a function that handles the client connection
func handleClientConnection(clientConn net.Conn, session *yamux.Session) {
	defer clientConn.Close()
	fmt.Println("New connection accepted from ", clientConn.RemoteAddr())

	stream, err := session.OpenStream()
	if err != nil {
		log.Printf("Failed to open yamux stream: %v", err)
		return
	}
	defer stream.Close()

	go io.Copy(clientConn, stream)
	io.Copy(stream, clientConn)
}

func AddCommandsTo(client *cobra.Command) {
	client.AddCommand(clientProxyCmd)
	clientProxyCmd.Flags().IntVarP(&httpProxyPort, "port", "p", 8080, "port number to listen on")
	clientProxyCmd.Flags().IntVarP(&numStreams, "connections", "c", 1, "number of parallel connections to open to the Border0 service")
	clientProxyCmd.Flags().StringVarP(&hostname, "service", "", "", "The Border0 service identifier")
}
