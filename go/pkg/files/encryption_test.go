package files

import (
	"testing"
)

func TestFileEncryption(t *testing.T) {
	password := "password"
	plaintext := "Hello, World!"
	ciphertext, _ := encryptFileData([]byte(plaintext), password)
	decrypted, _ := decryptFileData(ciphertext, password)

	if string(decrypted) != plaintext {
		t.Errorf("Decrypted text does not match plaintext")
	}
}

func TestInvalidPassword(t *testing.T) {
	password := "password"
	plaintext := "Hello, World!"
	ciphertext, _ := encryptFileData([]byte(plaintext), password)
	_, err := decryptFileData(ciphertext, "INVALID_PASSWORD")

	if err == nil {
		t.Errorf("Expected error when decrypting with invalid password")
	}
}
