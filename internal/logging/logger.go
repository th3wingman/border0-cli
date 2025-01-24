package logging

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

func BuildProduction() (*zap.Logger, error) {
	// fetch log level by env
	logLevel := zapcore.Level(ParseLogLevel(os.Getenv("BORDER0_LOG_LEVEL")))
	c := zap.NewProductionConfig()
	c.Level = zap.NewAtomicLevelAt(logLevel)
	c.EncoderConfig.StacktraceKey = ""
	c.EncoderConfig.CallerKey = ""
	c.EncoderConfig.EncodeTime = zapcore.TimeEncoderOfLayout(time.RFC3339)

	if runtime.GOOS == "windows" {
		// dump to a log file
		c.OutputPaths = []string{"stdout", filepath.Join(os.Getenv("PROGRAMDATA"), "border0-device-service.log")}
		c.ErrorOutputPaths = []string{"stderr", filepath.Join(os.Getenv("PROGRAMDATA"), "border0-device-service.log")}
	}

	log, err := c.Build()
	if err != nil {
		return nil, err
	}
	return log, nil
}

// ParseLogLevel returns the log level for a string
func ParseLogLevel(levelEnv string) zapcore.Level {
	level, err := zapcore.ParseLevel(strings.ToLower(levelEnv))
	if err != nil {
		return zapcore.InfoLevel
	}
	return level
}
