package k8sapilib

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/eks"
	awsv1 "github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	sessionv1 "github.com/aws/aws-sdk-go/aws/session"
	"github.com/borderzero/border0-cli/internal/util"
	"github.com/borderzero/border0-go/types/service"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"sigs.k8s.io/aws-iam-authenticator/pkg/token"
)

type targetKubernetesApiConfig struct {
	host                 string
	caCertificate        []byte
	clientCertificate    []byte
	clientCertificateKey []byte

	getBearerToken func() (string, error)
}

func getTargetKubernetesApiConfig(
	ctx context.Context,
	config *service.KubernetesServiceConfiguration,
) (*targetKubernetesApiConfig, error) {
	target := &targetKubernetesApiConfig{}

	if config.KubernetesServiceType == service.KubernetesServiceTypeStandard {
		standardConfig := config.StandardKubernetesServiceConfiguration

		// host from static service config
		if standardConfig.Server != "" {
			target.host = standardConfig.Server
		}

		// auth token from static service config
		if standardConfig.TokenFile != "" {
			target.getBearerToken = func() (string, error) {
				data, err := os.ReadFile(standardConfig.TokenFile)
				if err != nil {
					return "", fmt.Errorf("failed to read bearer token file referenced in service configuration: %v", err)
				}
				return string(data), nil
			}
		}
		if standardConfig.Token != "" {
			target.getBearerToken = func() (string, error) { return standardConfig.Token, nil }
		}

		// ca cert from static service config
		if standardConfig.CertificateAuthority != "" {
			data, err := os.ReadFile(standardConfig.CertificateAuthority)
			if err != nil {
				return nil, fmt.Errorf("failed to certificate authority file referenced in service configuration: %v", err)
			}
			target.caCertificate = data
		}
		if standardConfig.CertificateAuthorityData != "" {
			data, err := base64.StdEncoding.DecodeString(standardConfig.CertificateAuthorityData)
			if err != nil {
				return nil, fmt.Errorf("failed to base64 decode certificate authority data referenced in service configuration: %v", err)
			}
			target.caCertificate = data
		}

		// client cert from static service config
		if standardConfig.ClientCertificate != "" {
			data, err := os.ReadFile(standardConfig.ClientCertificate)
			if err != nil {
				return nil, fmt.Errorf("failed to client certificate file referenced in service configuration: %v", err)
			}
			target.clientCertificate = data
		}
		if standardConfig.ClientCertificateData != "" {
			data, err := base64.StdEncoding.DecodeString(standardConfig.ClientCertificateData)
			if err != nil {
				return nil, fmt.Errorf("failed to base64 decode client certificate data referenced in service configuration: %v", err)
			}
			target.clientCertificate = data
		}

		// client cert key from static service config
		if standardConfig.ClientKey != "" {
			data, err := os.ReadFile(standardConfig.ClientKey)
			if err != nil {
				return nil, fmt.Errorf("failed to client key file referenced in service configuration: %v", err)
			}
			target.clientCertificateKey = data
		}
		if standardConfig.ClientKeyData != "" {
			data, err := base64.StdEncoding.DecodeString(standardConfig.ClientKeyData)
			if err != nil {
				return nil, fmt.Errorf("failed to base64 decode client certificate key data referenced in service configuration: %v", err)
			}
			target.clientCertificateKey = data
		}

		if target.host == "" || ((len(target.clientCertificate) == 0 || len(target.clientCertificateKey) == 0) && target.getBearerToken == nil) {
			loadingRules := clientcmd.NewDefaultClientConfigLoadingRules()
			configOverrides := &clientcmd.ConfigOverrides{}

			var kubeconfig *rest.Config
			if standardConfig.KubeconfigPath != "" {
				loadingRules.ExplicitPath = standardConfig.KubeconfigPath
				if standardConfig.Context != "" {
					configOverrides.CurrentContext = standardConfig.Context
				}
				loadedKubeconfig, err := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(loadingRules, configOverrides).ClientConfig()
				if err != nil {
					return nil, fmt.Errorf("failed to build kubeconfig from the given path: %v", err)
				}
				kubeconfig = loadedKubeconfig
			} else {
				if standardConfig.Context != "" {
					configOverrides.CurrentContext = standardConfig.Context
				}
				loadedKubeconfig, err := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(loadingRules, configOverrides).ClientConfig()
				if err != nil {
					return nil, fmt.Errorf("failed to build kubeconfig from default config loading rules: %v", err)
				}
				kubeconfig = loadedKubeconfig
			}

			// host from kubeconfig
			if target.host == "" {
				target.host = kubeconfig.Host
			}

			// auth token from kubeconfig
			if target.getBearerToken == nil {
				if kubeconfig.BearerTokenFile != "" {
					target.getBearerToken = func() (string, error) {
						data, err := os.ReadFile(kubeconfig.BearerTokenFile)
						if err != nil {
							return "", fmt.Errorf("failed to read bearer token file referenced in kubeconfig: %v", err)
						}
						return string(data), nil
					}
				}
				if kubeconfig.BearerToken != "" {
					target.getBearerToken = func() (string, error) { return kubeconfig.BearerToken, nil }
				}
			}

			// ca cert from kubeconfig
			if len(target.caCertificate) == 0 {
				if kubeconfig.CAFile != "" {
					data, err := os.ReadFile(kubeconfig.CAFile)
					if err != nil {
						return nil, fmt.Errorf("failed to ca certificate file referenced in kubeconfig: %v", err)
					}
					target.caCertificate = data
				}
				if len(kubeconfig.CAData) > 0 {
					target.caCertificate = kubeconfig.CAData
				}
			}

			// client cert from kubeconfig
			if len(target.clientCertificate) == 0 {
				if kubeconfig.CertFile != "" {
					data, err := os.ReadFile(kubeconfig.CertFile)
					if err != nil {
						return nil, fmt.Errorf("failed to client certificate file referenced in kubeconfig: %v", err)
					}
					target.clientCertificate = data
				}
				if len(kubeconfig.CertData) > 0 {
					target.clientCertificate = kubeconfig.CertData
				}
			}

			// client cert key from kubeconfig
			if len(target.clientCertificateKey) == 0 {
				if kubeconfig.KeyFile != "" {
					data, err := os.ReadFile(kubeconfig.KeyFile)
					if err != nil {
						return nil, fmt.Errorf("failed to client certificate key file referenced in kubeconfig: %v", err)
					}
					target.clientCertificateKey = data
				}
				if len(kubeconfig.KeyData) > 0 {
					target.clientCertificateKey = kubeconfig.KeyData
				}
			}
		}
	}

	if config.KubernetesServiceType == service.KubernetesServiceTypeAwsEks {
		eksConfig := config.AwsEksKubernetesServiceConfiguration

		// initialize aws config for the cluster's region
		cfg, err := util.GetAwsConfig(ctx, eksConfig.EksClusterRegion, eksConfig.AwsCredentials)
		if err != nil {
			return nil, fmt.Errorf("failed to initialize AWS configuration for AWS EKS Kubernetes service: %v", err)
		}

		// need to describe the cluster to get server and CA certificate
		eksClient := eks.NewFromConfig(*cfg)
		describeClusterCtx, cancel := context.WithTimeout(ctx, time.Second*5)
		defer cancel()
		describeClusterOutput, err := eksClient.DescribeCluster(describeClusterCtx, &eks.DescribeClusterInput{
			Name: aws.String(eksConfig.EksClusterName),
		})
		if err != nil {
			return nil, fmt.Errorf("failed to describe eks cluster \"%s\": %v", eksConfig.EksClusterName, err)
		}

		// decode the ca certificate data
		caCertPEM, err := base64.StdEncoding.DecodeString(aws.ToString(describeClusterOutput.Cluster.CertificateAuthority.Data))
		if err != nil {
			return nil, fmt.Errorf("failed to base64 decode CA certificate data for eks cluster \"%s\": %v", eksConfig.EksClusterName, err)
		}

		// initialize new token generator
		iamAuthTokenGenerator, err := token.NewGenerator(true, false)
		if err != nil {
			return nil, fmt.Errorf("failed to initialize aws iam authenticator token generator: %v", err)
		}

		// initialize current token object to expired token
		var tkmutex sync.RWMutex
		tk := &token.Token{Expiration: time.Now().Add(-1 * time.Hour)}

		// define getBearerTokenFunc
		getBearerTokenFunc := func() (string, error) {

			// This locking scheme is known as a double-checked locking.
			//
			// - we acquire the read-lock to check the expiry.
			// - if we need to update the token we release the read-lock and acquire the write-lock
			// - with the write-lock held, we check the token still needs refreshing (because it is
			//   possible that another go routine / thread already refreshed it while the current go
			//   routine / thread was waiting to acquire the write-lock after releasing the read-lock.
			// - if we still need to refresh, we do it.
			tkmutex.RLock()
			if tk.Expiration.After(time.Now().Add(-5 * time.Minute)) {
				defer tkmutex.RUnlock()
				return tk.Token, nil
			}

			tkmutex.RUnlock()

			tkmutex.Lock()
			defer tkmutex.Unlock()

			// check again while holding lock
			if !tk.Expiration.After(time.Now().Add(-5 * time.Minute)) {

				// retrieve credentials to use with the aws go sdk v1. we have to do this because
				// the aws iam authenticator for k8s only interfaces with the legacy aws go sdk (v1).
				retrieveCredsCtx, cancel := context.WithTimeout(ctx, time.Second*5)
				defer cancel()
				v2creds, err := cfg.Credentials.Retrieve(retrieveCredsCtx)
				if err != nil {
					return "", fmt.Errorf("failed to retrieve temporary aws credentials: %v", err)
				}

				// use legacy credentials object to init new session object
				session, err := sessionv1.NewSession(&awsv1.Config{
					Credentials: credentials.NewStaticCredentials(
						v2creds.AccessKeyID,
						v2creds.SecretAccessKey,
						v2creds.SessionToken,
					),
				})
				if err != nil {
					return "", fmt.Errorf("failed to initialize new aws session: %v", err)
				}

				// retrieve k8s bearer token
				newToken, err := iamAuthTokenGenerator.GetWithOptions(&token.GetTokenOptions{
					ClusterID:   eksConfig.EksClusterName,
					Region:      eksConfig.EksClusterRegion,
					Session:     session, // have to pass it or else default credential chain is used
					SessionName: fmt.Sprintf("border0-kubernetes-%d", time.Now().UnixNano()),
				})
				if err != nil {
					return "", fmt.Errorf("failed to generate k8s token with aws iam authenticator token generator: %v", err)
				}
				tk = &newToken
			}

			return tk.Token, nil
		}

		// override config above
		target.host = aws.ToString(describeClusterOutput.Cluster.Endpoint)
		target.caCertificate = caCertPEM
		target.getBearerToken = getBearerTokenFunc
	}

	return target, nil
}

func buildKubernetesProxyTransport(target *targetKubernetesApiConfig) (http.RoundTripper, error) {
	tlsClientConfig := &tls.Config{}

	// set non-default ca certificate for server if applicable
	if target.caCertificate != nil {
		caCertPool := x509.NewCertPool()
		if ok := caCertPool.AppendCertsFromPEM(target.caCertificate); !ok {
			return nil, errors.New("failed to append CA certificate (PEM) to cert pool")
		}
		tlsClientConfig.RootCAs = caCertPool
	}

	// use client certficate authentication if applicable
	if target.clientCertificate != nil && target.clientCertificateKey != nil {
		materializedClientCert, err := tls.X509KeyPair(target.clientCertificate, target.clientCertificateKey)
		if err != nil {
			return nil, fmt.Errorf("failed to materialize client certificate: %v", err)
		}
		tlsClientConfig.Certificates = []tls.Certificate{materializedClientCert}
	}

	return &http.Transport{TLSClientConfig: tlsClientConfig}, nil
}
