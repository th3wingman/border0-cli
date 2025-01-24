package httpproxylib

import (
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/borderzero/border0-cli/internal/api/models"
	"github.com/borderzero/border0-cli/internal/border0"
	"github.com/borderzero/border0-cli/internal/util/recorder"
	"github.com/borderzero/border0-go/lib/types/syncmap"
	"github.com/borderzero/border0-go/types/recordings"

	"github.com/google/uuid"
	"go.uber.org/zap"
)

const (
	expiringRecorderInactivityTimeout = time.Minute
)

type accessLogEntry struct {
	Timestamp     time.Time     `json:"timestamp"`       // Timestamp of the request
	RemoteAddr    string        `json:"remote_addr"`     // Client's IP address
	Method        string        `json:"method"`          // HTTP method (GET, POST, etc.)
	URL           string        `json:"url"`             // Request URL
	Protocol      string        `json:"protocol"`        // HTTP protocol version
	StatusCode    int           `json:"status_code"`     // HTTP response status code
	BodyBytesSent int64         `json:"body_bytes_sent"` // Number of bytes sent in the response body
	Referer       string        `json:"referer"`         // HTTP referer header
	UserAgent     string        `json:"user_agent"`      // User-Agent header
	Latency       time.Duration `json:"latency"`         // Time taken to serve the request
}

type expiringRecorder struct {
	mu            sync.Mutex
	ch            chan *accessLogEntry
	timer         *time.Timer
	maxInactivity time.Duration
}

func newExpiringRecorder(maxInactivity time.Duration, fn func()) (*expiringRecorder, chan *accessLogEntry) {
	var once sync.Once // make sure we don't close the channel more than once
	ch := make(chan *accessLogEntry)
	return &expiringRecorder{
		maxInactivity: maxInactivity,
		ch:            ch,
		timer:         time.AfterFunc(maxInactivity, func() { fn(); once.Do(func() { close(ch) }) }),
	}, ch
}

func (er *expiringRecorder) write(msg *accessLogEntry) bool {
	er.mu.Lock()
	defer er.mu.Unlock()

	if !er.timer.Stop() {
		select {
		case <-er.timer.C:
			// drain timer's channel (not strictly necessary... garbage collector will deal with it).
		default:
			// fallthrough
		}
		// timer already expired (this is very unlikely to happen because
		// we remove the recorder from the recorders map when it expires)
		return false
	}
	if er.timer.Reset(er.maxInactivity) {
		return false
	}
	er.ch <- msg
	return true
}

func recordOne(
	logger *zap.Logger,
	api border0.Border0API,
	recorders *syncmap.Map[string, *expiringRecorder],
	socket *models.Socket,
	sessionID uuid.UUID,
	req *http.Request,
	receivedAt time.Time,
	status int,
	bodyBytesSent int64,
) error {
	msg := &accessLogEntry{
		Timestamp:     receivedAt,
		RemoteAddr:    req.RemoteAddr,
		Method:        req.Method,
		URL:           req.URL.String(),
		Protocol:      req.Proto,
		StatusCode:    status,
		BodyBytesSent: bodyBytesSent,
		Referer:       req.Referer(),
		UserAgent:     req.UserAgent(),
		Latency:       time.Duration(time.Since(receivedAt).Milliseconds()),
	}

	recorderIdentifier := fmt.Sprintf("%s-%s", socket.SocketID, sessionID.String())

	if rec, ok := recorders.Load(recorderIdentifier); ok {
		if ok := rec.write(msg); ok {
			return nil
		}
	}

	reqRec, err := recorder.NewJSONLRecorder(
		logger,
		api,
		socket.SocketID,
		sessionID.String(),
		recordings.RecordingTypeHTTPAccessLog,
		recorder.WithJSONLRecordingID[*accessLogEntry](sessionID), // http sockets have only one recording per session
	)
	if err != nil {
		logger.Error("failed to initialize new JSONL recorder for http socket", zap.String("socket_id", socket.SocketID), zap.Error(err))
		return fmt.Errorf("failed to initialize new JSONL recorder for http socket: %v", err)
	}

	rec, ch := newExpiringRecorder(
		expiringRecorderInactivityTimeout,
		func() { recorders.Delete(recorderIdentifier) },
	)
	reqRec.Record(ch)
	recorders.Store(recorderIdentifier, rec)
	rec.write(msg)

	return nil
}
