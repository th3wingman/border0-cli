package turtle

import (
	"context"
	"crypto/tls"

	"go.uber.org/zap"
)

// Config holds all configuration for the TURTLE client.
type Config struct {
	context   context.Context
	logger    *zap.Logger
	tlsConfig *tls.Config
}

// Option represents a configuration option for the TURTLE client.
type Option func(*Config)

// WithContext returns the configuration option that sets a non-default top-level context.
func WithContext(ctx context.Context) Option { return func(c *Config) { c.context = ctx } }

// WithLogger returns the configuration option that sets a non-default logger.
func WithLogger(logger *zap.Logger) Option { return func(c *Config) { c.logger = logger } }

// WithTlsConfig returns the configuration option that sets a non-default tls config.
func WithTlsConfig(config *tls.Config) Option { return func(c *Config) { c.tlsConfig = config } }
