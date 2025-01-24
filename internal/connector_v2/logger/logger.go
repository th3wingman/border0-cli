package logger

import (
	"io"
	"os"

	"github.com/borderzero/border0-cli/internal/connector_v2/errors"
	"github.com/borderzero/border0-cli/internal/logging"
	pb "github.com/borderzero/border0-proto/connector"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type connectorLogger struct {
	logger   *zap.Logger
	sendFunc func(*pb.ControlStreamRequest) error
	encoder  zapcore.Encoder
	level    zapcore.Level
	fields   []zapcore.Field

	pluginID string
	socketID string
}

func NewConnectorLogger(l *zap.Logger, sendFunc func(*pb.ControlStreamRequest) error) *zap.Logger {
	encoderConfig := zap.NewProductionEncoderConfig()
	encoderConfig.LevelKey = ""
	encoderConfig.TimeKey = ""
	encoder := zapcore.NewJSONEncoder(encoderConfig)

	minLevel := l.Level()

	// if BORDER0_CONNECTOR_LOG_LEVEL is set, use it, otherwise
	// use the same level as the underlying logger uses.
	connectorLogLevel := os.Getenv("BORDER0_CONNECTOR_LOG_LEVEL")
	if connectorLogLevel != "" {
		minLevel = logging.ParseLogLevel(connectorLogLevel)
	}

	core := &connectorLogger{
		logger:   l,
		encoder:  encoder,
		level:    minLevel,
		sendFunc: sendFunc,
	}

	return zap.New(core)
}

func (c *connectorLogger) Check(entry zapcore.Entry, checkedEntry *zapcore.CheckedEntry) *zapcore.CheckedEntry {
	if c.Enabled(entry.Level) {
		return checkedEntry.AddCore(entry, c)
	}
	return checkedEntry
}

func (c *connectorLogger) Sync() error {
	return nil
}

func (c *connectorLogger) With(fields []zapcore.Field) zapcore.Core {
	cloned := *c
	cloned.fields = append(cloned.fields, fields...)

	for _, field := range fields {
		switch field.Key {
		case "plugin_id":
			cloned.pluginID = field.String
		case "socket_id":
			cloned.socketID = field.String
		}
	}

	return &cloned
}

func (c *connectorLogger) Enabled(level zapcore.Level) bool {
	// We **must** return true here so that all levels result in a Write().
	// In the Write() we will pass logs of all levels downsteam to the inner
	// Logger, but only log the revelant ones.
	return true
}

func (c *connectorLogger) Write(entry zapcore.Entry, fields []zapcore.Field) error {
	allFields := append(c.fields, fields...)

	// pass all logs down to inner logger
	c.logger.Log(entry.Level, entry.Message, allFields...)

	// if this level is not enabled, return early
	if !c.level.Enabled(entry.Level) {
		return nil
	}

	// if the level is enabled, then we push the log to the api
	buffer, err := c.encoder.EncodeEntry(entry, allFields)
	if err != nil {
		return err
	}
	err = c.sendFunc(&pb.ControlStreamRequest{
		RequestType: &pb.ControlStreamRequest_Log{
			Log: &pb.Log{
				Timestamp: timestamppb.Now(),
				Severity:  entry.Level.String(),
				Message:   string(buffer.Bytes()),
				PluginId:  c.pluginID,
				SocketId:  c.socketID,
			},
		},
	})
	if err != nil && err.Error() != errors.ErrStreamNotConnected && err != io.EOF {
		c.logger.Error("failed to send log", zap.Error(err))
	}
	return nil
}
