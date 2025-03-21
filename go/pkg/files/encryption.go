package files

import (
	"crypto/sha1"
	"fmt"
	"os"

	"golang.org/x/crypto/pbkdf2"
	"nagelbros.com/p2p2p/pkg/security"
)

var salt = make([]byte, 8)
var nonce = make([]byte, 12)

func decryptFileData(ciphertext []byte, password string) ([]byte, error) {
	// generate key
	key := generateKeyFromPassword(password)

	// decrypt input file
	plaintext, err := security.Decrypt(ciphertext, key, nonce)
	if err != nil {
		return nil, fmt.Errorf("could not decrypt file: %s", err)
	}

	return plaintext, nil
}

func encryptFileData(plaintext []byte, password string) ([]byte, error) {
	// generate key
	key := generateKeyFromPassword(password)

	// encrypt input file
	ciphertext, err := security.Encrypt(plaintext, key, nonce)
	if err != nil {
		return nil, fmt.Errorf("could not encrypt file: %s", err)
	}

	return ciphertext, nil
}

func EncryptToFile(plaintext []byte, outFile, password string) error {
	ciphertext, err := encryptFileData(plaintext, password)
	if err != nil {
		return fmt.Errorf("could not encrypt file: %s", err)
	}

	// create output file
	outF, err := os.Create(outFile)
	if err != nil {
		return fmt.Errorf("could not create output file: %s", err)
	}
	defer outF.Close()

	// write encrypted data to output file
	outF.Write(ciphertext)

	return nil
}

func EncryptFromFileToFile(inFile, outFile, password string) error {
	// read input file
	plaintext, err := os.ReadFile(inFile)
	if err != nil {
		return fmt.Errorf("could not open input file: %s", err)
	}

	ciphertext, err := encryptFileData(plaintext, password)
	if err != nil {
		return fmt.Errorf("could not encrypt file: %s", err)
	}

	// create output file
	outF, err := os.Create(outFile)
	if err != nil {
		return fmt.Errorf("could not create output file: %s", err)
	}
	defer outF.Close()

	// write encrypted data to output file
	outF.Write(ciphertext)

	return nil
}

func DecryptFromFile(inFile, password string) ([]byte, error) {
	// read input file
	ciphertext, err := os.ReadFile(inFile)
	if err != nil {
		return nil, fmt.Errorf("could not open input file: %s", err)
	}

	// decrypt input file
	plaintext, err := decryptFileData(ciphertext, password)
	if err != nil {
		return nil, fmt.Errorf("could not decrypt file: %s", err)
	}

	return plaintext, nil
}

func DecryptFromFileToFile(inFile, outFile, password string) error {
	// read input file
	ciphertext, err := os.ReadFile(inFile)
	if err != nil {
		return fmt.Errorf("could not open input file: %s", err)
	}

	// decrypt input file
	plaintext, err := decryptFileData(ciphertext, password)
	if err != nil {
		return fmt.Errorf("could not decrypt file: %s", err)
	}

	// create output file
	outF, err := os.Create(outFile)
	if err != nil {
		return fmt.Errorf("could not create output file: %s", err)
	}
	defer outF.Close()

	// write decrypted data to output file
	outF.Write(plaintext)

	return nil
}

func generateKeyFromPassword(password string) []byte {
	return pbkdf2.Key([]byte(password), salt, 4096, 32, sha1.New)
}
