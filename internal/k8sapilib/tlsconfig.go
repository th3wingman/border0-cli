package k8sapilib

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"

	"github.com/borderzero/border0-cli/internal/border0"
	"github.com/borderzero/border0-cli/internal/util/refresher"
)

func tlsConfig(
	socket *border0.Socket,
	refresher *refresher.Refresher,
) (*tls.Config, error) {
	if socket.Organization == nil {
		return nil, errors.New("no organization reference in socket object")
	}
	cert, ok := socket.Organization.Certificates["mtls_certificate"]
	if !ok {
		return nil, errors.New("no CA certificate found for socket")
	}
	block, _ := pem.Decode([]byte(cert))
	if block == nil {
		return nil, errors.New("failed to encode socket's CA certificate as PEM block")
	}
	caCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to encode socket's CA certificate as x509.Certificate: %v", err)
	}
	clientCaPool := x509.NewCertPool()
	clientCaPool.AddCert(caCert)

	return &tls.Config{
		GetCertificate: func(chi *tls.ClientHelloInfo) (*tls.Certificate, error) { return refresher.GetCurrent(), nil },
		ClientAuth:     tls.RequireAndVerifyClientCert,
		ClientCAs:      clientCaPool,
	}, nil
}
