package connectorv2

import (
	"context"

	"google.golang.org/grpc/credentials"
)

// FIXME: this should be exported as part of the Border0 Go SDK

// border0GrpcTunnelCredentials represents the authentication mechanism
// against the Border0 API's connector-control-plain (GRPC) server.
type border0GrpcTunnelCredentials struct {
	token    string
	insecure bool
}

// ensures border0GrpcTunnelCredentials implements credentials.PerRPCCredentials
// (the generic authentication interface for GRPC) at compile-time.
var _ credentials.PerRPCCredentials = (*border0GrpcTunnelCredentials)(nil)

// Border0GrpcTunnelCredentials constructor
func newBorder0GrpcTunnelCredentials(token string, insecure bool) *border0GrpcTunnelCredentials {
	return &border0GrpcTunnelCredentials{token: token, insecure: insecure}
}

// GetRequestMetadata gets the current request metadata, refreshing tokens
// if required. This should be called by the transport layer on each
// request, and the data should be populated in headers or other
// context. If a status code is returned, it will be used as the status for
// the RPC (restricted to an allowable set of codes as defined by gRFC
// A54). uri is the URI of the entry point for the request.  When supported
// by the underlying implementation, ctx can be used for timeout and
// cancellation. Additionally, RequestInfo data will be available via ctx
// to this call.
//
// ^ copied straight from the interface defintion.
func (c *border0GrpcTunnelCredentials) GetRequestMetadata(ctx context.Context, in ...string) (map[string]string, error) {
	return map[string]string{
		"authorization": c.token,
		"content-type":  "application/grpc",
	}, nil
}

// RequireTransportSecurity indicates whether the credentials requires
// transport security.
//
// ^ copied straight from the interface defintion.
func (c *border0GrpcTunnelCredentials) RequireTransportSecurity() bool {
	return !c.insecure
}
