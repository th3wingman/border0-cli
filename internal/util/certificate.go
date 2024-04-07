package util

import (
	"crypto/sha256"
	"crypto/tls"
	"fmt"
	"os"
	"os/user"
)

func GetEndToEndEncryptionCertificate(orgID, connectorID string) (*tls.Certificate, error) {
	privateKeyFile, certificateFile, err := generateNames(orgID, connectorID)
	if err != nil {
		return nil, fmt.Errorf("failed to generate names: %s", err)
	}

	var keyFilePath, certFilePath string
	var errors []error

	if _, err := os.Stat(serviceConfigPath + privateKeyFile); err == nil {
		keyFilePath = serviceConfigPath + privateKeyFile
	}

	if _, err := os.Stat(serviceConfigPath + certificateFile); err == nil {
		certFilePath = serviceConfigPath + certificateFile
	}

	if keyFilePath != "" && certFilePath != "" {
		certificate, err := readCertificate(keyFilePath, certFilePath)
		if err != nil {
			errors = append(errors, err)
		} else {
			return certificate, nil
		}
	}

	var userKeyFilePath, userCertFilePath string
	u, err := user.Current()
	if err == nil {
		if _, err := os.Stat(u.HomeDir + "/.border0/" + privateKeyFile); err == nil {
			userKeyFilePath = u.HomeDir + "/.border0/" + privateKeyFile
		}

		if _, err := os.Stat(u.HomeDir + "/.border0/" + certificateFile); err == nil {
			userCertFilePath = u.HomeDir + "/.border0/" + certificateFile
		}
	}

	if userKeyFilePath != "" && userCertFilePath != "" {
		certificate, err := readCertificate(userKeyFilePath, userCertFilePath)
		if err != nil {
			errors = append(errors, err)
		} else {
			return certificate, nil
		}
	}

	if len(errors) > 0 {
		return nil, fmt.Errorf("failed to load certificate: %s", errors)
	} else {
		return nil, nil
	}
}

func readCertificate(keyFilePath, certFilePath string) (*tls.Certificate, error) {
	certificate, err := tls.LoadX509KeyPair(certFilePath, keyFilePath)
	if err != nil {
		return nil, fmt.Errorf("failed to load certificate: %s", err)
	}

	return &certificate, nil
}

func generateNames(orgID, connectorID string) (string, string, error) {
	name := orgID
	if connectorID != "" {
		name = fmt.Sprintf("%s%s", orgID, connectorID)
	} else {
		hostname, err := os.Hostname()
		if err == nil {
			name = fmt.Sprintf("%s%s", orgID, hostname)
		}
	}

	hasher := sha256.New()
	_, err := hasher.Write([]byte(name))
	if err != nil {
		return "", "", fmt.Errorf("failed to hash name: %s", err)
	}

	hashBytes := hasher.Sum(nil)
	shortHash := fmt.Sprintf("%x", hashBytes)[:8]
	privateKeyFile := fmt.Sprintf("connector-%s.key", shortHash)
	certificateFile := fmt.Sprintf("connector-%s.crt", shortHash)

	return privateKeyFile, certificateFile, nil
}

func StoreCertificateFiles(key []byte, certficate []byte, path, keyFileName, certificateFileName string) error {
	if _, err := os.Stat(path); os.IsNotExist(err) {
		if err := os.MkdirAll(path, 0700); err != nil {
			return fmt.Errorf("failed to create directory %s: %w", path, err)
		}
	} else if err != nil {
		return fmt.Errorf("failed to check directory %s: %w", path, err)
	}
	if err := os.WriteFile(path+keyFileName, key, 0600); err != nil {
		return fmt.Errorf("failed to write key file: %w", err)
	}

	if err := os.WriteFile(path+certificateFileName, certficate, 0600); err != nil {
		return fmt.Errorf("failed to write certificate file: %w", err)
	}
	return nil
}

func StoreConnectorCertifcate(privateKey []byte, certificate []byte, orgID, connectorID string) error {
	privateKeyFile, certificateFile, err := generateNames(orgID, connectorID)
	if err != nil {
		return fmt.Errorf("failed to generate names: %s", err)
	}

	serviceConfigPathErr := StoreCertificateFiles(privateKey, certificate, serviceConfigPath, privateKeyFile, certificateFile)
	if serviceConfigPathErr != nil {
		u, err := user.Current()
		if err != nil {
			return fmt.Errorf("failed to store the certifcate files %s %s", err, serviceConfigPathErr)
		}

		err = StoreCertificateFiles(privateKey, certificate, u.HomeDir+"/.border0/", privateKeyFile, certificateFile)
		if err != nil {
			return fmt.Errorf("failed to store the certifcate files %s %s", err, serviceConfigPathErr)
		}
	}

	return nil
}
