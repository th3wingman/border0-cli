package state

import (
	"fmt"
	"time"

	"github.com/borderzero/border0-go/lib/nacl"
)

const keyLen = 32

type key struct {
	PrivateKey string     `yaml:"private_key" json:"-"`
	PublicKey  string     `yaml:"public_key" json:"public_key"`
	ExpiresAt  *time.Time `yaml:"expires_at,omitempty" json:"expires_at,omitempty"`

	// below are runtime objects which should not be serialized
	RuntimeKey *nacl.PrivateKey `yaml:"-" json:"-"`
}

func (k *key) decodeAndValidate() error {
	privateKey, err := nacl.ParsePrivateKeyB64(k.PrivateKey)
	if err != nil {
		return fmt.Errorf("failed to base64-decode private key: %v", err)
	}
	k.RuntimeKey = privateKey
	return nil
}
