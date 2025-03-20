package security

import (
	"crypto/aes"
	"crypto/cipher"
	"fmt"
)

func encrypt(data []byte, key []byte, nonce []byte) ([]byte, error) {
	// encrypt
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("could not create AES cipher: %s", err)
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("could not create GCM: %s", err)
	}

	ciphertext := aesgcm.Seal(nil, nonce, data, nil)
	return ciphertext, nil
}

func decrypt(ciphertext, key, nonce []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("could not create AES cipher: %s", err)
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("could not create GCM: %s", err)
	}

	plaintext, err := aesgcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("could not decrypt message: %s", err)
	}

	return plaintext, nil
}
