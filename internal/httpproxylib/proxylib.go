package httpproxylib

import (
	"io"
	"log"
	"net"
	"net/http"
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
	log.Printf("Tunneling from %s to %s", r.RemoteAddr, r.Host)
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

	buf := make([]byte, 1024)
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

func StartHttpProxy(listener net.Listener) error {
	server := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			log.Printf("Received request %s %s %s\n", r.Method, r.Host, r.RemoteAddr)
			if r.Method == http.MethodConnect {
				handleTunneling(w, r)
			} else {
				handleHTTP(w, r)
			}
		}),
	}
	return server.Serve(listener)
}
