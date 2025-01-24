package k8sapilib

import (
	"fmt"
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

type message struct {
	EventID      string `json:"event_id"`
	Time         int64  `json:"time"`
	Duration     int64  `json:"duration"`
	Verb         string `json:"verb"`
	APIGroup     string `json:"api_group"`
	Namespace    string `json:"namespace"`
	ResourceType string `json:"resource_type"`
	ResourceName string `json:"resource_name"`
	StatusCode   int    `json:"status_code"`
	Info         string `json:"info"`
}

type expiringRecorder struct {
	mu            sync.Mutex
	ch            chan *message
	timer         *time.Timer
	maxInactivity time.Duration
}

func newExpiringRecorder(maxInactivity time.Duration, fn func()) (*expiringRecorder, chan *message) {
	var once sync.Once // make sure we don't close the channel more than once
	ch := make(chan *message)
	return &expiringRecorder{
		maxInactivity: maxInactivity,
		ch:            ch,
		timer:         time.AfterFunc(maxInactivity, func() { fn(); once.Do(func() { close(ch) }) }),
	}, ch
}

func (er *expiringRecorder) write(msg *message) bool {
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
	k8sreq *kubernetesRequest,
	receivedAt *time.Time,
	status int,
	info string,
) (uuid.UUID, error) {

	eventID := uuid.New()
	msg := &message{
		EventID:      eventID.String(),
		Verb:         k8sreq.verb,
		APIGroup:     k8sreq.apigroup,
		Namespace:    k8sreq.namespace,
		ResourceType: k8sreq.resource,
		ResourceName: k8sreq.resourceName,
		StatusCode:   status,
		Info:         info,
	}
	if receivedAt != nil {
		msg.Time = int64(receivedAt.UnixMilli())
		msg.Duration = time.Since(*receivedAt).Milliseconds()
	}

	recorderIdentifier := fmt.Sprintf("%s-%s", socket.SocketID, sessionID.String())

	if rec, ok := recorders.Load(recorderIdentifier); ok {
		if ok := rec.write(msg); ok {
			return eventID, nil
		}
	}

	reqRec, err := recorder.NewJSONLRecorder(
		logger,
		api,
		socket.SocketID,
		sessionID.String(),
		recordings.RecordingTypeKubernetesAPIRequestLog,
		recorder.WithJSONLRecordingID[*message](sessionID), // kubernetes sockets have only one recording per session
	)
	if err != nil {
		logger.Error("failed to initialize new JSONL recorder for kubernetes socket", zap.String("socket_id", socket.SocketID), zap.Error(err))
		return uuid.Nil, fmt.Errorf("failed to initialize new JSONL recorder for kubernetes socket: %v", err)
	}

	rec, ch := newExpiringRecorder(
		expiringRecorderInactivityTimeout,
		func() { recorders.Delete(recorderIdentifier) },
	)
	reqRec.Record(ch)
	recorders.Store(recorderIdentifier, rec)
	rec.write(msg)

	return eventID, nil
}
