package security

import (
	"crypto/rand"
	"testing"
)

func TestInvalidKey(t *testing.T) {
	validKey := make([]byte, 32)
	rand.Read(validKey)

	invalidKey := make([]byte, 32)
	rand.Read(invalidKey)

	nonce := make([]byte, 12)
	rand.Read(nonce)

	// Encrypt a message
	message := []byte("Hello, World!")
	encryptedMessage, _ := Encrypt(message, validKey, nonce)

	// decrypt the message with the valid key
	decryptedMessage, err := Decrypt(encryptedMessage, validKey, nonce)
	if err != nil || string(decryptedMessage) != string(message) {
		t.Fatalf("could not decrypt message: %v", err)
	}

	// Decrypt the message with the invalid key
	decryptedMessage, err = Decrypt(encryptedMessage, invalidKey, nonce)
	if err == nil || string(decryptedMessage) == string(message) {
		t.Fatalf("decrypted message successfully: %v", err)
	}
}

func TestInvalidNonce(t *testing.T) {
	key := make([]byte, 32)
	rand.Read(key)

	validNonce := make([]byte, 12)
	rand.Read(validNonce)

	invalidNonce := make([]byte, 12)
	rand.Read(invalidNonce)

	// Encrypt a message
	message := []byte("Hello, World!")
	encryptedMessage, _ := Encrypt(message, key, validNonce)

	// decrypt the message with the valid nonce
	decryptedMessage, err := Decrypt(encryptedMessage, key, validNonce)
	if err != nil || string(decryptedMessage) != string(message) {
		t.Fatalf("could not decrypt message: %v", err)
	}

	// Decrypt the message with the invalid key
	decryptedMessage, err = Decrypt(encryptedMessage, key, invalidNonce)
	if err == nil || string(decryptedMessage) == string(message) {
		t.Fatalf("decrypted message successfully: %v", err)
	}
}
