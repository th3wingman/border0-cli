package httpproxylib

import (
	"fmt"
	"net/http"
	"net/http/httputil"
	"time"

	"github.com/borderzero/border0-cli/internal/border0"
	"github.com/borderzero/border0-go/lib/types/syncmap"
	"github.com/google/uuid"

	"go.uber.org/zap"
)

type logResponseWriter struct {
	http.ResponseWriter
	statusCode    int
	bodyBytesSent int64
}

func getHandler(
	logger *zap.Logger,
	api border0.Border0API,
	socket *border0.Socket,
) (http.Handler, error) {
	recorders := syncmap.New[string, *expiringRecorder]()

	target, err := getTargetConfig(socket.Socket.TargetHostname, socket.Socket.TargetPort, socket.Socket.UpstreamHttpHostname)
	if err != nil {
		return nil, fmt.Errorf("failed to determine target http settings: %v", err)
	}

	// build single host reverse proxy
	proxy, err := getHttpProxy(target)
	if err != nil {
		return nil, fmt.Errorf("failed to build http reverse proxy for socket: %v", err)
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		startTime := time.Now()

		if target.hostHeader != nil {
			r.Host = *target.hostHeader
		}

		pnConn, ok := r.Context().Value(connContextKey).(*border0.PrivateNetworkConn)
		if !ok {
			logger.Error(
				"failed to get private network connection from request context for private network socket",
				zap.String("socket_id", socket.SocketID),
			)
			return
		}

		sessionID, err := uuid.Parse(pnConn.Metadata.SessionKey)
		if err != nil {
			logger.Error(
				"failed to parse session key from connection metadata for private network socket",
				zap.String("socket_id", socket.SocketID),
				zap.String("session_key", pnConn.Metadata.SessionKey),
				zap.Error(err),
			)
			return
		}

		logWriter := &logResponseWriter{
			ResponseWriter: w,
		}

		// foward the request
		proxy.ServeHTTP(logWriter, r)

		// record the request
		if err := recordOne(
			logger,
			api,
			recorders,
			socket.Socket,
			sessionID,
			r,
			startTime,
			logWriter.statusCode,
			logWriter.bodyBytesSent,
		); err != nil {
			logger.Error("failed to record request", zap.Error(err))
		}

	}), nil
}
func getHttpProxy(
	target *targetConfig,
) (*httputil.ReverseProxy, error) {
	// initialize reverse proxy
	proxy := httputil.NewSingleHostReverseProxy(target.url)

	// return as handler
	return proxy, nil
}

func (rw *logResponseWriter) WriteHeader(code int) {
	rw.statusCode = code
	rw.ResponseWriter.WriteHeader(code)
}

func (rw *logResponseWriter) Write(b []byte) (int, error) {
	bytesWritten, err := rw.ResponseWriter.Write(b)
	rw.bodyBytesSent += int64(bytesWritten) // Track the body bytes sent
	return bytesWritten, err
}
