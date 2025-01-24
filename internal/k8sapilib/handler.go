package k8sapilib

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"

	"github.com/borderzero/border0-cli/internal/api/models"
	"github.com/borderzero/border0-cli/internal/border0"
	"github.com/borderzero/border0-cli/internal/util/recorder"
	"github.com/borderzero/border0-go/lib/types/syncmap"

	"github.com/google/uuid"
	"go.uber.org/zap"
)

type kubernetesError struct {
	Message string `json:"message,omitempty"`
}

func getHandler(
	ctx context.Context,
	logger *zap.Logger,
	api border0.Border0API,
	socket *border0.Socket,
	policyEvalCacheJanitorInterval time.Duration,
	policyEvalCacheTTL time.Duration,
) (http.Handler, error) {
	// initialize recorders
	recorders := syncmap.New[string, *expiringRecorder]()

	// get target kubernetes configuration
	target, err := getTargetKubernetesApiConfig(ctx, socket.Socket.ConnectorLocalData.KubernetesAPISettings)
	if err != nil {
		return nil, fmt.Errorf("failed to determine target kubernetes api settings: %v", err)
	}

	// build single host reverse proxy
	proxy, err := getKubernetesProxy(logger, api, recorders, socket.Socket, target)
	if err != nil {
		return nil, fmt.Errorf("failed to build kubernetes reverse proxy for socket: %v", err)
	}

	// build evaluator that caches results
	evaluator := newCachedPolicyEvaluator(api, policyEvalCacheJanitorInterval, policyEvalCacheTTL)

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var userEmail string
		var sessionID uuid.UUID
		// set received at in request context
		r = withReceivedAt(r, time.Now())

		// for private netowrk sockets, we can get the identity from the connection
		// metadata. Otherweise we need to extract the client certificate from the request.
		if socket.PrivateNetworkEnabled {
			pnConn, ok := r.Context().Value(connContextKey).(*border0.PrivateNetworkConn)
			if !ok {
				logger.Error(
					"failed to get private network connection from request context for private network socket",
					zap.String("socket_id", socket.SocketID),
				)
				return
			}

			userEmail = pnConn.Metadata.UserEmail
			sessionID, err = uuid.Parse(pnConn.Metadata.SessionKey)
			if err != nil {
				logger.Error(
					"failed to parse session key from connection metadata for private network socket",
					zap.String("socket_id", socket.SocketID),
					zap.String("session_key", pnConn.Metadata.SessionKey),
					zap.Error(err),
				)
				return
			}
		} else {
			// having no certificates should not be possible given we require client
			// certificates in the HTTPS server's TLS configuration. However, we must
			// avoid nil pointer access at all costs, so we check it.
			if len(r.TLS.PeerCertificates) < 1 {
				logger.Error(
					"kubernetes socket got an HTTP request without client certificates",
					zap.String("socket_id", socket.SocketID),
					zap.String("method", r.Method),
					zap.String("path", r.URL.Path),
				)
				http.Error(w, "no client certificate presented", http.StatusForbidden)
				return
			}
			userEmail = r.TLS.PeerCertificates[0].Subject.CommonName

			// compute session key deterministically from socket id and client cert serial number.
			sessionID = deterministicUUIDv4(socket.SocketID, r.TLS.PeerCertificates[0].SerialNumber.String())
		}

		// retrieve authorization details for the current request
		rules, ok := getAuthorizationDetails(logger, evaluator, socket, userEmail, sessionID, w, r)
		if !ok {
			// getAuthorizationDetails takes care of writing responses
			// when the client is not authorized for kubernetes sockets.
			return
		}

		// filter out offending requests
		if err := evaluateAccess(logger, api, recorders, socket, sessionID, rules, r); err != nil {
			http.Error(w, err.Error(), http.StatusForbidden)
			return
		}

		// override the authorization header if applicable
		if target.getBearerToken != nil {
			bearerToken, err := target.getBearerToken()
			if err != nil {
				logger.Error(
					"failed to get bearer token for upstream kubernetes api for kubernetes socket",
					zap.String("socket_id", socket.SocketID),
					zap.Error(err),
				)
				http.Error(w, "an unknown error occurred... try again later.", http.StatusInternalServerError)
				return
			}
			r.Header.Set("Authorization", fmt.Sprintf("Bearer %s", bearerToken))
		}

		// foward the request
		proxy.ServeHTTP(w, r)
	}), nil
}

func deterministicUUIDv4(values ...string) uuid.UUID {
	hasher := sha256.New()
	for _, v := range values {
		hasher.Write([]byte(v))
	}
	hash := hasher.Sum(nil)
	uuidBytes := make([]byte, 16)
	copy(uuidBytes, hash[:16])
	uuidBytes[6] = (uuidBytes[6] & 0x0f) | 0x40 // Version 4
	uuidBytes[8] = (uuidBytes[8] & 0x3f) | 0x80 // Variant 10
	return uuid.UUID(uuidBytes)
}

func getKubernetesProxy(
	logger *zap.Logger,
	api border0.Border0API,
	recorders *syncmap.Map[string, *expiringRecorder],
	socket *models.Socket,
	target *targetKubernetesApiConfig,
) (*httputil.ReverseProxy, error) {
	// build target URL
	targetURL, err := url.Parse(target.host)
	if err != nil {
		return nil, fmt.Errorf("failed to build tunnel listener URL for socket: %v", err)
	}

	// initialize reverse proxy
	proxy := httputil.NewSingleHostReverseProxy(targetURL)

	// initialize non-default transport (to verify server's ca certificate
	// and provide client certificates for authentication if applicable)
	proxy.Transport, err = buildKubernetesProxyTransport(target)
	if err != nil {
		return nil, fmt.Errorf("failed to build kubernetes proxy transport: %v", err)
	}

	// set director function to record the exec TTY if applicable
	if socket.RecordingEnabled {
		proxy.ModifyResponse = getResponseModifierFunc(logger, api, recorders, socket)
	}

	// return as handler
	return proxy, nil
}

func getResponseModifierFunc(
	logger *zap.Logger,
	api border0.Border0API,
	recorders *syncmap.Map[string, *expiringRecorder],
	socket *models.Socket,
) func(*http.Response) error {
	return func(res *http.Response) error {
		var sessionID uuid.UUID
		// for private netowrk sockets, we can get the identity from the connection
		// metadata. Otherweise we need to extract the client certificate from the request.
		if socket.PrivateNetworkEnabled {
			pnConn, ok := res.Request.Context().Value(connContextKey).(*border0.PrivateNetworkConn)
			if !ok {
				return errors.New("failed to get private network connection from request context for private network socket")
			}

			sid, err := uuid.Parse(pnConn.Metadata.SessionKey)
			if err != nil {
				return fmt.Errorf("failed to parse session key from connection metadata for private network socket: %v", err)
			}
			sessionID = sid
		} else {
			if len(res.Request.TLS.PeerCertificates) < 1 {
				logger.Error("no client certificate found in response's original request", zap.String("socket_id", socket.SocketID))
				return errors.New("no client certificate found in response's original request")
			}
			clientCert := res.Request.TLS.PeerCertificates[0]

			sessionID = deterministicUUIDv4(socket.SocketID, clientCert.SerialNumber.String())
		}
		k8sreq, err := kubernetesRequestFromHTTPRequest(res.Request)
		if err != nil {
			logger.Error("failed to parse kubernetes request from http response's original request", zap.String("socket_id", socket.SocketID), zap.Error(err))
			return fmt.Errorf("failed to parse kubernetes request from http response's original request: %v", err)
		}

		// extract error message from body if present
		msg := ""
		if res.StatusCode >= 400 && res.StatusCode < 500 {
			var k8serr *kubernetesError
			if bodyBytes, err := preserveBodyRead(res); err == nil {
				if err = json.Unmarshal(bodyBytes, &k8serr); err == nil {
					msg = k8serr.Message
				}
			}
		}

		eventID, err := recordOne(logger, api, recorders, socket, sessionID, k8sreq, getReceivedAt(res.Request), res.StatusCode, msg)
		if err != nil {
			logger.Error("failed to record single kubernetes api request", zap.String("socket_id", socket.SocketID), zap.Error(err))
			return fmt.Errorf("failed to record single kubernetes api request: %v", err)
		}

		isResponseForExecRequest := strings.HasSuffix(strings.Split(res.Request.URL.Path, "?")[0], "/exec")
		is101Response := res.StatusCode == http.StatusSwitchingProtocols
		if !isResponseForExecRequest || !is101Response {
			return nil
		}

		pipeReader, pipeWriter := io.Pipe()

		rec := recorder.NewAsciinemaRecorder(logger, api, pipeReader, socket.SocketID, sessionID.String(), recorder.WithAsciinemaRecordingID(eventID))
		if err := rec.Record(); err != nil {
			logger.Error("failed to initialize exec recorder for socket", zap.String("socket_id", socket.SocketID), zap.Error(err))
			return fmt.Errorf("failed to initialize exec recorder for socket: %v", err)
		}

		backConn, ok := res.Body.(io.ReadWriteCloser)
		if !ok {
			rec.Stop()
			logger.Error("failed to retrieve connection to client from http response object for exec recording", zap.String("socket_id", socket.SocketID))
			return errors.New("failed to retrieve connection to client from http response object for exec recording")
		}

		// override the response Body implementation to a tee-wrapped read-write-closer
		// such that data read from the client connection is written to the pipe writer.
		res.Body = newTeeWrappedRWC(backConn, pipeWriter, func() { rec.Stop() })

		return nil
	}
}

// preserveBodyRead reads the body of an HTTP response, returns the data as a byte
// slice, and replaces the response body with a new reader that can be read again.
func preserveBodyRead(resp *http.Response) ([]byte, error) {
	old := resp.Body
	defer old.Close()

	bodyBytes, err := io.ReadAll(old)
	if err != nil {
		return nil, err
	}

	resp.Body = io.NopCloser(bytes.NewReader(bodyBytes))

	return bodyBytes, nil
}
