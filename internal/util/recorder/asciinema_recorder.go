package recorder

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"

	"github.com/borderzero/border0-cli/internal/border0"
	"github.com/borderzero/border0-go/types/recordings"

	"github.com/google/uuid"
	"go.uber.org/zap"
)

const (
	asciinemaUploadBufferThreshold = 1024 * 1024
	asciinemaUploadInterval        = 30 * time.Second

	defaultWidth  = 80
	defaultHeight = 24
)

// asciinema v2 header
// https://github.com/asciinema/asciinema/blob/develop/doc/asciicast-v2.md
type logHeader struct {
	Version   int    `json:"version"`
	Width     int    `json:"width"`
	Height    int    `json:"height"`
	Timestamp int64  `json:"timestamp"`
	Title     string `json:"title"`
}

type AsciinemaRecorder struct {
	logger      *zap.Logger
	api         border0.Border0API
	sessionKey  string
	socketID    string
	recordingID string
	reader      io.ReadCloser
	start       time.Time
	width       int
	height      int
	zipWriter   *gzip.Writer
	buf         bytes.Buffer
	uploadLock  sync.Mutex
}

type AsciinemaRecorderOption func(*AsciinemaRecorder)

func WithAsciinemaWidth(width int) AsciinemaRecorderOption {
	return func(recorder *AsciinemaRecorder) { recorder.width = width }
}

func WithAsciinemaHeight(height int) AsciinemaRecorderOption {
	return func(recorder *AsciinemaRecorder) { recorder.height = height }
}

func WithAsciinemaRecordingID(id uuid.UUID) AsciinemaRecorderOption {
	return func(recorder *AsciinemaRecorder) { recorder.recordingID = id.String() }
}

func NewAsciinemaRecorder(
	logger *zap.Logger,
	api border0.Border0API,
	reader io.ReadCloser,
	socketID string,
	sessionKey string,
	opts ...AsciinemaRecorderOption,
) *AsciinemaRecorder {
	ar := &AsciinemaRecorder{
		logger:      logger,
		sessionKey:  sessionKey,
		socketID:    socketID,
		api:         api,
		reader:      reader,
		recordingID: uuid.NewString(),
		width:       defaultWidth,
		height:      defaultHeight,
	}
	for _, opt := range opts {
		opt(ar)
	}
	return ar
}

func (r *AsciinemaRecorder) Record() error {
	r.zipWriter = gzip.NewWriter(&r.buf)
	r.start = time.Now()

	if r.width == 0 {
		r.width = defaultWidth
	}

	if r.height == 0 {
		r.height = defaultHeight
	}

	newloghdr := &logHeader{
		Version:   2,
		Width:     r.width,
		Height:    r.height,
		Timestamp: time.Now().Unix(),
		Title:     fmt.Sprintf("Recording %s for Socket %s", r.recordingID, r.socketID),
	}

	headerJson, _ := json.Marshal(newloghdr)
	headerJson = append([]byte(headerJson), "\n"...)

	if _, err := r.zipWriter.Write(headerJson); err != nil {
		return fmt.Errorf("failed to write header to recording: %s", err)
	}

	go func() {
		shouldUpload := true
		dateWritten := false

		defer func() {
			if shouldUpload && dateWritten {
				if err := r.upload(); err != nil {
					r.logger.Error("failed to upload recording", zap.Error(err))
					return
				}
			}
		}()

		timer := time.NewTimer(asciinemaUploadInterval)
		readBuffer := make([]byte, 1024)
		readResult := make(chan int, 1)

		go func() {
			for {
				n, err := r.reader.Read(readBuffer)
				if err != nil && err != io.ErrClosedPipe {
					r.logger.Error("failed to read buffer", zap.Error(err))
					close(readResult)
					return
				}

				if n == 0 {
					close(readResult)
					return
				}

				readResult <- n
			}
		}()

		for {
			select {
			case n, open := <-readResult:
				if !open {
					return
				}

				elapsed := time.Since(r.start).Seconds()
				message := []interface{}{
					float64(elapsed),
					string("o"),
					strings.ReplaceAll(string(readBuffer[:n]), "\n", "\r\n"),
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
					return
				}

				dateWritten = true

				if r.buf.Len() > asciinemaUploadBufferThreshold {
					if err := r.upload(); err != nil {
						r.logger.Error("failed to upload recording", zap.Error(err))
						shouldUpload = false
						return
					}

					timer.Reset(asciinemaUploadInterval)
					dateWritten = false
				}

			case <-timer.C:
				if dateWritten {
					if err := r.upload(); err != nil {
						r.logger.Error("failed to upload recording", zap.Error(err))
						shouldUpload = false
						return
					}

					dateWritten = false
				}

				timer.Reset(asciinemaUploadInterval)
			}
		}
	}()

	return nil
}

func (r *AsciinemaRecorder) Stop() error {
	if err := r.reader.Close(); err != nil {
		return fmt.Errorf("failed to close session log file: %s", err)
	}
	return nil
}

func (r *AsciinemaRecorder) upload() error {
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

		if err := r.api.UploadRecording(uploadBuffer, r.socketID, r.sessionKey, r.recordingID, recordings.RecordingTypeAsciinema); err != nil {
			r.logger.Error("failed to upload recording", zap.Error(err))
			return
		}
	}(uploadBuffer)

	return nil
}
