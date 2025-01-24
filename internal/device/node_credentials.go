package device

import (
	"context"

	"github.com/borderzero/border0-go/types/connector"
	"google.golang.org/grpc/credentials"
)

const (
	// deviceManagementStreamMetadataKeyPublicKey is the GRPC
	// stream metadata key for the node's public key.
	deviceManagementStreamMetadataKeyPublicKey = "public_key"
	// deviceManagementStreamMetadataKeyClientVersion is the client app version.
	deviceManagementStreamMetadataKeyClientVersion = "client_version"
	// deviceManagementStreamMetadataKeyHostname is the hostname of the node.
	deviceManagementStreamMetadataKeyHostname = "hostname"
	// deviceManagementStreamMetadataKeyOS is the operating system of the node.
	deviceManagementStreamMetadataKeyOS = "os"
	// deviceManagementStreamMetadataKeyPlatform is the platform of the node.
	deviceManagementStreamMetadataKeyPlatform = "platform"
	// deviceManagementStreamMetadataKeyPlatformVersion is the platform version of the node.
	deviceManagementStreamMetadataKeyPlatformVersion = "platform_version"
	// deviceManagementStreamMetadataKeyKernelVersion is the kernel version of the node.
	deviceManagementStreamMetadataKeyKernelVersion = "kernel_version"
	// deviceManagementStreamMetadataKeyKernelArch is the kernel architecture of the node.
	deviceManagementStreamMetadataKeyKernelArch = "kernel_arch"
)

// deviceManagementStreamCredentials represents the authentication mechanism
// against the Border0 API's device-control-plain (GRPC) server.
type deviceManagementStreamCredentials struct {
	publicKey         string
	insecureTransport bool
	clientVersion     string
	HostMetadata      *connector.HostMetadata
}

// ensures deviceManagementStreamCredentials implements credentials.PerRPCCredentials
// (the generic authentication interface for GRPC) at compile-time.
var _ credentials.PerRPCCredentials = (*deviceManagementStreamCredentials)(nil)

// credentialOption is the constructor option type for deviceManagementStreamCredentials.
type credentialOption func(*deviceManagementStreamCredentials)

// withPublicKey is the CredentialOption to set the public key.
func withPublicKey(publicKey string) credentialOption {
	return func(d *deviceManagementStreamCredentials) { d.publicKey = publicKey }
}

// withInsecureTransport is the CredentialOption to toggle insecure transport.
func withInsecureTransport(insecureTransport bool) credentialOption {
	return func(d *deviceManagementStreamCredentials) { d.insecureTransport = insecureTransport }
}

// withVersion is the CredentialOption to set the version.
func withClientVersion(version string) credentialOption {
	return func(d *deviceManagementStreamCredentials) { d.clientVersion = version }
}

// withHostMetadata is the CredentialOption to set the host metadata.
func withHostMetadata(metadata *connector.HostMetadata) credentialOption {
	return func(d *deviceManagementStreamCredentials) { d.HostMetadata = metadata }
}

// newDeviceManagementStreamCredentials returns a new deviceManagementStreamCredentials
// object initialized with the given options.
func newDeviceManagementStreamCredentials(opts ...credentialOption) *deviceManagementStreamCredentials {
	creds := &deviceManagementStreamCredentials{}
	for _, opt := range opts {
		opt(creds)
	}
	return creds
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
func (d *deviceManagementStreamCredentials) GetRequestMetadata(ctx context.Context, in ...string) (map[string]string, error) {
	md := map[string]string{}
	if d.publicKey != "" {
		md[deviceManagementStreamMetadataKeyPublicKey] = d.publicKey
	}
	if d.clientVersion != "" {
		md[deviceManagementStreamMetadataKeyClientVersion] = d.clientVersion
	}

	if d.HostMetadata != nil {
		md[deviceManagementStreamMetadataKeyHostname] = d.HostMetadata.Hostname
		md[deviceManagementStreamMetadataKeyOS] = d.HostMetadata.OS
		md[deviceManagementStreamMetadataKeyPlatform] = d.HostMetadata.Platform
		md[deviceManagementStreamMetadataKeyPlatformVersion] = d.HostMetadata.PlatformVersion
		md[deviceManagementStreamMetadataKeyKernelVersion] = d.HostMetadata.KernelVersion
		md[deviceManagementStreamMetadataKeyKernelArch] = d.HostMetadata.KernelArch
	}

	return md, nil
}

// RequireTransportSecurity indicates whether the credentials requires
// transport security.
//
// ^ copied straight from the interface defintion.
func (d *deviceManagementStreamCredentials) RequireTransportSecurity() bool {
	return !d.insecureTransport
}
