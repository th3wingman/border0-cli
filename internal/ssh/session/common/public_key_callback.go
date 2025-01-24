package common

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
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
	connMetadata *border0.ConnMetadata,
	checkAllowedUsernames bool,
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

		if connMetadata.UserEmail != cert.KeyId {
			return nil, errors.New("error: ssh certificate does not match tls certificate")
		}

		var certChecker ssh.CertChecker
		if err := certChecker.CheckCert("mysocket_ssh_signed", cert); err != nil {
			return nil, fmt.Errorf("error: invalid client certificate: %s", err)
		}

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		clientIP, _, err := net.SplitHostPort(connMetadata.ClientIP)
		if err != nil {
			return nil, fmt.Errorf("failed to parse client ip: %w", err)
		}

		actions, _, err := border0ApiClient.Evaluate(ctx, socket, clientIP, connMetadata.UserEmail, connMetadata.SessionKey)
		if err != nil {
			return nil, fmt.Errorf("error: failed to authorize: %s", err)
		}

		if checkAllowedUsernames {
			var allowed bool
			for _, action := range actions {
				switch permission := action.(type) {
				case string:
					allowed = true
				case models.Permissions:
					if permission.SSH != nil {
						if permission.SSH.AllowedUsernames == nil {
							allowed = true
						} else {
							for _, username := range *permission.SSH.AllowedUsernames {
								if strings.EqualFold(username, metadata.User()) {
									allowed = true
									break
								}
							}
						}
					}
				}
			}

			if !allowed {
				return nil, fmt.Errorf("error: authorization failed, no policy allowed SSH access for ssh user %s", metadata.User())
			}
		}

		return &ssh.Permissions{}, nil
	}
}

func GetNoClientAuthCallback(
	border0ApiClient border0.Border0API,
	socket *models.Socket,
	connMetadata *border0.ConnMetadata,
	checkAllowedUsernames bool,
	lastError *error,
) func(ssh.ConnMetadata) (*ssh.Permissions, error) {
	return func(metadata ssh.ConnMetadata) (*ssh.Permissions, error) {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		actions, _, err := border0ApiClient.Evaluate(ctx, socket, connMetadata.ClientIP, connMetadata.UserEmail, connMetadata.SessionKey)
		if err != nil {
			return nil, fmt.Errorf("error: failed to authorize: %s", err)
		}

		if checkAllowedUsernames {
			var allowed bool
			for _, action := range actions {
				switch permission := action.(type) {
				case string:
					allowed = true
				case models.Permissions:
					if permission.SSH != nil {
						if permission.SSH.AllowedUsernames == nil {
							allowed = true
						} else {
							for _, username := range *permission.SSH.AllowedUsernames {
								if strings.EqualFold(username, metadata.User()) {
									allowed = true
									break
								}
							}
						}
					}
				}
			}

			if !allowed {
				err := &ssh.ServerAuthError{
					Errors: []error{fmt.Errorf("error: authorization failed, no policy allowed SSH access for ssh user %s", metadata.User())},
				}
				*lastError = err
				return nil, err
			}
		}

		return &ssh.Permissions{}, nil
	}
}
