package httpproxylib

import (
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/borderzero/border0-cli/internal/border0"
	"github.com/hashicorp/yamux"
)

// here we handle the https requests, ie. connect method
// IO copy after taking over the conn
func handleTunneling(w http.ResponseWriter, r *http.Request) int {
	if r.Host == "" {
		http.Error(w, "Not found", http.StatusNotFound)
		return http.StatusNotFound
	}

	destConn, err := net.DialTimeout("tcp", r.Host, 10*time.Second)
	if err != nil {
		log.Printf("Failed to connect to host %s: %v", r.Host, err)
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return http.StatusServiceUnavailable
	}
	// Write header before we take over the connection
	w.WriteHeader(http.StatusOK)

	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "Hijacking not supported", http.StatusInternalServerError)
		return http.StatusInternalServerError
	}

	clientConn, _, err := hijacker.Hijack()
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return http.StatusServiceUnavailable
	}

	// Now Copy from clientConn to destConn and vice versa
	border0.ProxyConnection(clientConn, destConn)
	return http.StatusOK
}

// Proxy HTTP proxy requests
func handleHTTP(w http.ResponseWriter, req *http.Request) int {
	if req.Host == "" {
		http.Error(w, "Not found", http.StatusNotFound)
		return http.StatusNotFound
	}
	req.URL.Host = req.Host
	req.URL.Scheme = "http" // You can also dynamically set the scheme based on the original request

	resp, err := http.DefaultTransport.RoundTrip(req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return http.StatusServiceUnavailable
	}

	defer resp.Body.Close()
	copyHeader(w.Header(), resp.Header)
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)
	return resp.StatusCode
}

// Make sure we copy all headers from the original request
// to the proxy request
func copyHeader(dst, src http.Header) {
	for k, vv := range src {
		for _, v := range vv {
			dst.Add(k, v)
		}
	}
}

// Function to check if the proxy request is allowed
// based on the hostname
func checkIfAllowed(host string, allowedHosts []string) bool {

	// if allowedHosts is empty, then all hosts are allowed
	if len(allowedHosts) == 0 {
		return true
	}
	// host may contain a colon and port number, so we should remove it
	// before checking if it is in the allowedHosts list
	if index := strings.LastIndex(host, ":"); index != -1 {
		host = host[:index]
	}

	for _, h := range allowedHosts {
		if h == host {
			return true
		}
	}
	log.Printf("Host %s not allowed to be proxied. Use allowed-host to add host.", host)
	return false
}

// Start the HTTP proxy server
func StartHttpProxy(listener net.Listener, allowedProxyHosts []string) error {

	// Ok let's accept connections and process them
	for {
		conn, err := listener.Accept()

		if err != nil {
			log.Fatalf("Failed to accept connection: %v", err)
		}

		go func(conn net.Conn) {

			yamuxSession, err := yamux.Server(conn, nil)
			if err != nil {
				log.Printf("Failed to create yamux session: %v", err)
			}

			// Open the first stream for logging
			//loggingStream, err := yamuxSession.AcceptStream()
			loggingStream, err := yamuxSession.OpenStream()

			if err != nil {
				log.Printf("Failed to accept logging stream: %v", err)
				return
			}
			defer loggingStream.Close()
			var logMutex sync.Mutex
			var statusCode int = 0

			handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				// Log to the loggingStream instead of stdout

				logMessage := fmt.Sprintf("Received request %s %s", r.Method, r.Host)
				fmt.Println(logMessage)

				// check if host is in allowedHosts
				if !checkIfAllowed(r.Host, allowedProxyHosts) {
					loggingStream.Write([]byte("Host not allowed"))
					http.Error(w, "Not found", http.StatusMethodNotAllowed)
					return
				}
				if r.Method == http.MethodConnect {
					statusCode = handleTunneling(w, r)
				} else {
					statusCode = handleHTTP(w, r)
				}
				// Log the status code to the control stream
				mgs := fmt.Sprintf("Completed request %d %s %s", statusCode, r.Method, r.Host)
				logMutex.Lock()
				loggingStream.Write([]byte(mgs))
				logMutex.Unlock()
			})

			server := &http.Server{Handler: handler}
			server.Serve(yamuxSession)
		}(conn)
	}
}
