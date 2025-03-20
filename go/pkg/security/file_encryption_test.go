package security

import (
	"fmt"
	"os"
	"testing"
)

func TestFileEncryption(t *testing.T) {
	password := "password"
	plaintext := "Hello, World!"
	ciphertext, _ := encrypt([]byte(plaintext), generateKeyFromPassword(password), nonce)
	inputFile, _ := os.CreateTemp("", "plaintext_*.txt")
	defer os.Remove(inputFile.Name())

	inputFile.WriteString(plaintext)
	inputFile.Close()

	outputFile, _ := os.CreateTemp("", "encrypted_*.txt")
	defer os.Remove(outputFile.Name())
	outputFile.Close()

	EncryptFile(inputFile.Name(), outputFile.Name(), password)

	fileContents, _ := os.ReadFile(outputFile.Name())
	if fmt.Sprintf("%x", fileContents) != fmt.Sprintf("%x", ciphertext) {
		t.Errorf("File contents do not match ciphertext")
	}

	decryptedFile, _ := os.CreateTemp("", "decrypted_*.txt")
	defer os.Remove(decryptedFile.Name())
	decryptedFile.Close()

	DecryptFile(outputFile.Name(), decryptedFile.Name(), password)
	decryptedContents, _ := os.ReadFile(decryptedFile.Name())
	if string(decryptedContents) != plaintext {
		t.Errorf("Decrypted contents do not match plaintext")
	}
}

func TestInvalidPassword(t *testing.T) {
	password := "password"
	plaintext := "Hello, World!"
	inputFile, _ := os.CreateTemp("", "plaintext_*.txt")
	defer os.Remove(inputFile.Name())

	inputFile.WriteString(plaintext)
	inputFile.Close()

	outputFile, _ := os.CreateTemp("", "encrypted_*.txt")
	defer os.Remove(outputFile.Name())
	outputFile.Close()

	EncryptFile(inputFile.Name(), outputFile.Name(), password)

	err := DecryptFile(outputFile.Name(), "decrypted.txt", "wrongpassword")
	if err == nil {
		t.Errorf("Expected error due to wrong password")
	}

}
