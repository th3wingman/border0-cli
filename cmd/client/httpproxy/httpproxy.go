package httpproxy

import (
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"
	"strings"
	"time"

	b0tls "github.com/borderzero/border0-cli/cmd/client/tls"
	"github.com/borderzero/border0-cli/cmd/logger"
	"github.com/borderzero/border0-cli/internal/client"
	"github.com/borderzero/border0-cli/internal/enum"
	"github.com/hashicorp/yamux"
	"github.com/spf13/cobra"

	"github.com/rivo/tview"
)

var (
	hostname             string
	httpProxyPort        int
	numStreams           int
	connectionsPerSecond int
	connectionsPerMinute int
	tuiView              bool
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

		var updateTextView func(line string)

		if tuiView {
			textView, app := startTUI()
			logLines := make([]string, 0, 10)
			updateTextView = func(line string) {
				app.QueueUpdateDraw(func() {
					if len(logLines) >= 10 {
						logLines = logLines[len(logLines)-9:]
					}
					timestamp := time.Now().Format("2006-01-02 15:04:05")
					logLine := fmt.Sprintf("%s: %s", timestamp, line)
					logLines = append([]string{logLine}, logLines...) // Insert at the beginning

					textView.SetText(strings.Join(logLines, "\n"))
				})
			}
		} else {
			updateTextView = func(line string) {
				timestamp := time.Now().Format("2006-01-02 15:04:05")
				fmt.Printf("%s: %s\n", timestamp, line)
			}
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

			//fmt.Printf("%d = Connected to %s:%d\n", i, hostname, info.Port)
			updateTextView(fmt.Sprintf("%d = Connected to %s:%d\n", i, hostname, info.Port))

			session, err := yamux.Client(conn, nil)
			if err != nil {
				log.Fatalf("Failed to create yamux session: %v", err)
			}
			//fmt.Println("Created session number ", i)
			updateTextView(fmt.Sprintf("created session number %d ", i))
			//sessions[i] = session
			sessionManager.addSession(session)

		}

		// Now start the local listener on which we accept the traffic
		l, err := net.Listen("tcp", fmt.Sprintf("localhost:%d", httpProxyPort))
		if err != nil {
			log.Fatalf("error: Unable to start tcp listener on port %d, %s\n", httpProxyPort, err)
		}
		defer l.Close()
		//log.Printf("service started, listening for connections on port %d\n", httpProxyPort)
		updateTextView(fmt.Sprintf("service started, listening for connections on port %d\n", httpProxyPort))

		sessionIndex := 0

		// Reset the connections per second counter every second
		go func() {
			for {
				time.Sleep(time.Second)
				connectionsPerSecond = 0
			}
		}()

		// Reset the connections per minute counter every minute
		go func() {
			for {
				time.Sleep(time.Minute)
				connectionsPerMinute = 0
			}
		}()

		for {
			clientConn, err := l.Accept()
			if err != nil {
				log.Printf("Failed to accept connection: %v", err)
				continue
			}

			// Increment the counters
			connectionsPerSecond++
			connectionsPerMinute++

			// Choose a session from the slice by using the index
			//selectedSession := sessions[sessionIndex]
			selectedSession := sessionManager.selectSession(sessionIndex)

			// Increment the index so that next time a different session is used
			sessionIndex++

			go handleClientConnection(clientConn, selectedSession, updateTextView)
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
// func handleClientConnection(clientConn net.Conn, session *yamux.Session) {
func handleClientConnection(clientConn net.Conn, session *yamux.Session, updateTextView func(string)) {

	defer clientConn.Close()
	//fmt.Println("New connection accepted from ", clientConn.RemoteAddr())

	logLine := fmt.Sprintf("New connection accepted from %s", clientConn.RemoteAddr())
	updateTextView(logLine)

	stream, err := session.OpenStream()
	if err != nil {
		log.Printf("Failed to open yamux stream: %v", err)
		return
	}
	defer stream.Close()

	go io.Copy(clientConn, stream)
	io.Copy(stream, clientConn)
}

func startTUI() (*tview.TextView, *tview.Application) {
	if !tuiView {
		return nil, nil // If TUI view is not enabled, return nil
	}

	app := tview.NewApplication()

	// Stats view
	statsView := tview.NewTextView().
		SetDynamicColors(true).
		SetWrap(false)
	statsView.SetBorder(true).SetTitle("Statistics")

	// Log view
	textView := tview.NewTextView().
		SetDynamicColors(true).
		SetWrap(false)
	textView.SetBorder(true).SetTitle("Log")

	// Grid layout
	grid := tview.NewGrid().
		SetRows(5, 0). // 3 rows for stats, rest for logs
		SetColumns(0).
		AddItem(statsView, 0, 0, 1, 1, 0, 0, false).
		AddItem(textView, 1, 0, 1, 1, 0, 0, false)

	// Update stats every second

	go func() {
		for {
			stats := fmt.Sprintf(
				"Time: %s\nAverage Connections Per Second: %d\nAverage Connections Per Minute: %d",
				time.Now().Format(time.RFC1123), connectionsPerSecond, connectionsPerMinute)
			statsView.SetText(stats)
			time.Sleep(1 * time.Second)
		}
	}()

	go func() {
		if err := app.SetRoot(grid, true).Run(); err != nil {
			panic(err)
		}
	}()

	return textView, app
}

func AddCommandsTo(client *cobra.Command) {
	client.AddCommand(clientProxyCmd)
	clientProxyCmd.Flags().BoolVarP(&tuiView, "tui", "t", false, "Tui output")
	clientProxyCmd.Flags().IntVarP(&httpProxyPort, "port", "p", 8080, "port number to listen on")

	clientProxyCmd.Flags().IntVarP(&numStreams, "connections", "c", 1, "number of parallel connections to open to the Border0 service")
	clientProxyCmd.Flags().StringVarP(&hostname, "service", "", "", "The Border0 service identifier")
}
