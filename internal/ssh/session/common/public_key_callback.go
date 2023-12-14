package common

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/borderzero/border0-cli/internal/api/models"
	"github.com/borderzero/border0-cli/internal/border0"
	"golang.org/x/crypto/ssh"
)

// GetPublicKeyCallback returns a function to be provided as the PublicKeyCallback
// field of an ssh.ServerConfig object. This function is invoked by the ssh server
// in order to verify, among other things, that the certificate being provided by a
// given ssh client is issued by the correct organization-wide certificate authority.
func GetPublicKeyCallback(
	orgWideCACertificate ssh.PublicKey,
	border0ApiClient border0.Border0API,
	socket *models.Socket,
	e2eeMetadata *border0.E2EEncryptionMetadata,
) func(ssh.ConnMetadata, ssh.PublicKey) (*ssh.Permissions, error) {
	return func(metadata ssh.ConnMetadata, certificate ssh.PublicKey) (*ssh.Permissions, error) {
		cert, ok := certificate.(*ssh.Certificate)
		if !ok {
			return nil, errors.New("can not cast certificate")
		}

		if orgWideCACertificate == nil {
			return nil, errors.New("error: unable to validate certificate, no CA configured")
		}

		if !bytes.Equal(cert.SignatureKey.Marshal(), orgWideCACertificate.Marshal()) {
			return nil, errors.New("error: invalid client certificate")
		}

		if e2eeMetadata.UserEmail != cert.KeyId {
			return nil, errors.New("error: ssh certificate does not match tls certificate")
		}

		var certChecker ssh.CertChecker
		if err := certChecker.CheckCert("mysocket_ssh_signed", cert); err != nil {
			return nil, fmt.Errorf("error: invalid client certificate: %s", err)
		}

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		actions, _, err := border0ApiClient.Evaluate(ctx, socket, e2eeMetadata.ClientIP, e2eeMetadata.UserEmail, e2eeMetadata.SessionKey)
		if err != nil {
			return nil, fmt.Errorf("error: failed to authorize: %s", err)
		}

		if len(actions) == 0 {
			return nil, errors.New("error: authorization failed")
		}

		return &ssh.Permissions{}, nil
	}
}
