package httpproxylib

import (
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/borderzero/border0-cli/internal/border0"
)

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
	//log.Printf("Tunneling from %s to %s", r.RemoteAddr, r.Host)
	w.WriteHeader(http.StatusOK)
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "Hijacking not supported", http.StatusInternalServerError)
		return
	}
	clientConn, rw, err := hijacker.Hijack()
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}

	// for rw.Reader.Buffered() > 0 {
	// 	b := make([]byte, rw.Reader.Buffered())
	// 	n, err := rw.Read(b)
	// 	if err != nil {
	// 		fmt.Printf("Error reading from buffered reader: %v\n", err)
	// 		return
	// 	}

	// 	m, err := clientConn.Write(b[:n])
	// 	// check error
	// 	if err != nil {
	// 		fmt.Printf("Error writing to client: %v\n", err)
	// 		return
	// 	}
	// 	if m != n {
	// 		fmt.Printf("Byte mismatch: %d != %d\n", m, n)
	// 		return
	// 	}
	// }

	buf := make([]byte, 4096)
	n, err := rw.Read(buf)
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	m, err := destConn.Write(buf[:n])
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	if m != n {
		http.Error(w, "byte mismatch", http.StatusServiceUnavailable)
		return
	}

	border0.ProxyConnection(clientConn, destConn)
}

func handleHTTP(w http.ResponseWriter, req *http.Request) {
	//req.Host = mapHost(req.Host)
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

func copyHeader(dst, src http.Header) {
	for k, vv := range src {
		for _, v := range vv {
			dst.Add(k, v)
		}
	}
}

func checkIfAllowed(host string, allowedHosts []string) bool {
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
	return false
}

func StartHttpProxy(listener net.Listener, allowedProxyHosts []string) error {
	// print all enttries in allowedHosts
	for _, h := range allowedProxyHosts {
		fmt.Println("Allowed host: ", h)
	}
	server := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
		}),
	}
	return server.Serve(listener)
}
