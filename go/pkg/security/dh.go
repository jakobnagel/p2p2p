package security

import (
	"crypto/ecdh"
	"crypto/rand"
	"fmt"
)

func generateDhKey() (*ecdh.PrivateKey, error) {
	dhPrivate, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("could not generate DH key: %s", err)
	}
	return dhPrivate, nil
}
