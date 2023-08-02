package httpproxylib

import (
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/borderzero/border0-cli/internal/border0"
	"github.com/hashicorp/yamux"
)

// here we handle the https requests, ie. connect method
// IO copy after taking over the conn
func handleTunneling(w http.ResponseWriter, r *http.Request) {
	if r.Host == "" {
		http.Error(w, "Not found", http.StatusNotFound)
		return
	}

	destConn, err := net.DialTimeout("tcp", r.Host, 10*time.Second)
	if err != nil {
		log.Printf("Failed to connect to host %s: %v", r.Host, err)
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	// Write header before we take over the connection
	w.WriteHeader(http.StatusOK)

	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "Hijacking not supported", http.StatusInternalServerError)
		return
	}

	clientConn, _, err := hijacker.Hijack()
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}

	// Now Copy from clientConn to destConn and vice versa
	border0.ProxyConnection(clientConn, destConn)
}

// Proxy HTTP proxy requests
func handleHTTP(w http.ResponseWriter, req *http.Request) {
	if req.Host == "" {
		http.Error(w, "Not found", http.StatusNotFound)
		return
	}
	req.URL.Host = req.Host
	req.URL.Scheme = "http" // You can also dynamically set the scheme based on the original request

	resp, err := http.DefaultTransport.RoundTrip(req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	defer resp.Body.Close()
	copyHeader(w.Header(), resp.Header)
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)
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

func handleYamuxSession(conn net.Conn, handleStreamFunc func(net.Conn)) {
	session, err := yamux.Server(conn, nil)
	if err != nil {
		log.Printf("Failed to create yamux session: %v", err)
		return
	}
	for {
		stream, err := session.AcceptStream()
		if err != nil {
			log.Printf("Failed to accept yamux stream: %v", err)
			return
		}
		go handleStreamFunc(stream)
	}
}

// Start the HTTP proxy server
func StartHttpProxy(listener net.Listener, allowedProxyHosts []string) error {

	// create HTTP proxy handler function
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Printf("Received request %s %s\n", r.Method, r.Host)

		// check if host is in allowedHosts
		// if not return not allowed
		if !checkIfAllowed(r.Host, allowedProxyHosts) {
			http.Error(w, "Not found", http.StatusMethodNotAllowed)
			return
		}
		if r.Method == http.MethodConnect {
			handleTunneling(w, r)
		} else {
			handleHTTP(w, r)
		}
	})

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

			server := &http.Server{Handler: handler}
			server.Serve(yamuxSession)
		}(conn)
	}
}
