package session

import (
	"context"
	"fmt"
	"io"

	"github.com/borderzero/border0-cli/lib/varsource"
	"go.uber.org/zap"
	"golang.org/x/crypto/ssh"
)

type varsourceSigner struct {
	logger *zap.Logger

	variableSource varsource.VariableSource
	variableDefn   string

	fallback ssh.MultiAlgorithmSigner
}

func newVariableSourceSigner(logger *zap.Logger, variableDefn string) (ssh.MultiAlgorithmSigner, error) {
	vs := &varsourceSigner{
		logger:         logger,
		variableSource: varsource.NewDefaultVariableSource(),
		variableDefn:   variableDefn,
	}

	// the PublicKey method of the ssh.Signer interface
	// cannot return nil, so we maintain a fallback value
	// to return in the PublicKey method here just in case...
	priv, err := vs.fetchValue()
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve initial private key value: %v", err)
	}
	signer, err := ssh.ParsePrivateKey([]byte(priv))
	if err != nil {
		return nil, fmt.Errorf("failed to parse initial value for identity private key: %v", err)
	}

	if multiSigner, ok := signer.(ssh.MultiAlgorithmSigner); ok {
		vs.fallback = multiSigner
		return vs, nil
	}

	return nil, fmt.Errorf("signer is not a MultiAlgorithmSigner, got %T", signer)
}

func (vs *varsourceSigner) fetchValue() (string, error) {
	return vs.variableSource.GetVariable(context.Background(), vs.variableDefn)
}

func (vs *varsourceSigner) PublicKey() ssh.PublicKey {
	priv, err := vs.fetchValue()
	if err != nil {
		vs.logger.Error("failed to retrieve identity private key from variable source", zap.Error(err))
		return vs.fallback.PublicKey()
	}
	signer, err := ssh.ParsePrivateKey([]byte(priv))
	if err != nil {
		vs.logger.Error("failed to retrieve identity private key", zap.Error(err))
		return vs.fallback.PublicKey()
	}
	return signer.PublicKey()
}

func (vs *varsourceSigner) Sign(rand io.Reader, data []byte) (*ssh.Signature, error) {
	priv, err := vs.fetchValue()
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve private key variable value: %v", err)
	}
	signer, err := ssh.ParsePrivateKey([]byte(priv))
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key from retrieved variable value: %v", err)
	}
	return signer.Sign(rand, data)
}

func (vs *varsourceSigner) Algorithms() []string {
	priv, err := vs.fetchValue()
	if err != nil {
		vs.logger.Error("failed to retrieve identity private key from variable source", zap.Error(err))
		return vs.fallback.Algorithms()
	}
	signer, err := ssh.ParsePrivateKey([]byte(priv))
	if err != nil {
		vs.logger.Error("failed to retrieve identity private key", zap.Error(err))
		return vs.fallback.Algorithms()
	}

	if multiSigner, ok := signer.(ssh.MultiAlgorithmSigner); ok {
		return multiSigner.Algorithms()
	}

	vs.logger.Error("signer is not a MultiAlgorithmSigner", zap.String("signer", fmt.Sprintf("%T", signer)))
	return vs.fallback.Algorithms()
}

func (vs *varsourceSigner) SignWithAlgorithm(rand io.Reader, data []byte, algorithm string) (*ssh.Signature, error) {
	priv, err := vs.fetchValue()
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve private key variable value: %v", err)
	}
	signer, err := ssh.ParsePrivateKey([]byte(priv))
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key from retrieved variable value: %v", err)
	}

	if multiSigner, ok := signer.(ssh.MultiAlgorithmSigner); ok {
		return multiSigner.SignWithAlgorithm(rand, data, algorithm)
	}
	return nil, fmt.Errorf("signer is not a MultiAlgorithmSigner, got %T", signer)
}
