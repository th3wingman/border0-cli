package recorder

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/borderzero/border0-cli/internal/border0"
	"github.com/borderzero/border0-go/lib/types/set"
	"github.com/borderzero/border0-go/types/recordings"
	"github.com/google/uuid"
	"go.uber.org/zap"
)

const (
	jsonlUploadBufferThreshold = 1024 * 1024
	jsonlUploadInterval        = 30 * time.Second
)

var (
	allowedJSONLRecordingTypes = set.New(
		recordings.RecordingTypeDatabaseQueryLog,
		recordings.RecordingTypeKubernetesAPIRequestLog,
		recordings.RecordingTypeHTTPAccessLog,
	)
)

type JSONLRecorder[T any] struct {
	logger        *zap.Logger
	api           border0.Border0API
	sessionKey    string
	socketID      string
	recordingType string
	recordingID   string
	zipWriter     *gzip.Writer
	buf           bytes.Buffer
	uploadLock    sync.Mutex
}

type JSONLRecorderOption[T any] func(*JSONLRecorder[T])

func WithJSONLRecordingID[T any](id uuid.UUID) JSONLRecorderOption[T] {
	return func(recorder *JSONLRecorder[T]) { recorder.recordingID = id.String() }
}

func NewJSONLRecorder[T any](
	logger *zap.Logger,
	api border0.Border0API,
	socketID string,
	sessionKey string,
	recordingType string,
	opts ...JSONLRecorderOption[T],
) (*JSONLRecorder[T], error) {
	if !allowedJSONLRecordingTypes.Has(recordingType) {
		return nil, fmt.Errorf(
			"invalid recording type \"%s\" for JSONL recorder, must be one of [ %s ]",
			recordingType,
			strings.Join(allowedJSONLRecordingTypes.Slice(), ", "),
		)
	}
	recorder := &JSONLRecorder[T]{
		logger:        logger,
		api:           api,
		sessionKey:    sessionKey,
		socketID:      socketID,
		recordingType: recordingType,
		recordingID:   uuid.NewString(),
	}
	for _, opt := range opts {
		opt(recorder)
	}
	return recorder, nil
}

func (r *JSONLRecorder[T]) Record(messageChan chan T) {
	r.zipWriter = gzip.NewWriter(&r.buf)

	go func() {
		shouldUpload := true
		dataWritten := false

		defer func() {
			if shouldUpload && dataWritten {
				if err := r.upload(); err != nil {
					r.logger.Error("failed to upload recording", zap.Error(err))
					return
				}
			}
		}()

		timer := time.NewTimer(jsonlUploadInterval)

		for {
			select {
			case message, open := <-messageChan:
				if !open {
					// flush the buffer on channel closure
					if r.buf.Len() > 0 {
						if err := r.upload(); err != nil {
							r.logger.Error("failed to upload recording", zap.Error(err))
							shouldUpload = false
							return
						}
						timer.Reset(jsonlUploadInterval)
						dataWritten = false
					}
					return
				}

				logJson, err := json.Marshal(message)
				if err != nil {
					r.logger.Error("failed to marshal message", zap.Error(err))
					shouldUpload = false
					return
				}

				logJson = append([]byte(logJson), "\n"...)

				if _, err := r.zipWriter.Write([]byte(logJson)); err != nil {
					r.logger.Error("failed to write to recording", zap.Error(err))
					shouldUpload = false
					return
				}

				dataWritten = true

				if r.buf.Len() > jsonlUploadBufferThreshold {
					if err := r.upload(); err != nil {
						r.logger.Error("failed to upload recording", zap.Error(err))
						shouldUpload = false
						return
					}

					timer.Reset(jsonlUploadInterval)
					dataWritten = false
				}
			case <-timer.C:
				if dataWritten {
					if err := r.upload(); err != nil {
						r.logger.Error("failed to upload recording", zap.Error(err))
						shouldUpload = false
						return
					}

					dataWritten = false
				}

				timer.Reset(jsonlUploadInterval)
			}
		}
	}()
}

func (r *JSONLRecorder[T]) upload() error {
	r.uploadLock.Lock()
	defer r.uploadLock.Unlock()

	if err := r.zipWriter.Flush(); err != nil {
		return fmt.Errorf("failed to flush session log file: %s", err)
	}

	if err := r.zipWriter.Close(); err != nil {
		return fmt.Errorf("failed to close session log file: %s", err)
	}

	uploadBuffer := make([]byte, r.buf.Len())
	copy(uploadBuffer, r.buf.Bytes())
	r.buf.Reset()
	r.zipWriter = gzip.NewWriter(&r.buf)

	go func(uploadBuffer []byte) {
		r.uploadLock.Lock()
		defer r.uploadLock.Unlock()

		if err := r.api.UploadRecording(uploadBuffer, r.socketID, r.sessionKey, r.recordingID, r.recordingType); err != nil {
			r.logger.Error("failed to upload recording", zap.Error(err))
			return
		}
	}(uploadBuffer)

	return nil
}
