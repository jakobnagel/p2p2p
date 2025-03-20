package security

import (
	"crypto/sha1"
	"fmt"
	"os"
	"path"

	"golang.org/x/crypto/pbkdf2"
)

var salt = make([]byte, 8)
var nonce = make([]byte, 12)

func EncryptFile(inFile, outFile, password string) error {
	// generate key
	key := generateKeyFromPassword(password)

	// read input file
	inFileData, err := os.ReadFile(inFile)
	if err != nil {
		return fmt.Errorf("could not open input file: %s", err)
	}

	// encrypt input file
	ciphertext, err := encrypt(inFileData, key, nonce)
	if err != nil {
		return fmt.Errorf("could not encrypt file: %s", err)
	}

	// create output file
	os.MkdirAll(path.Dir(outFile), 0755)
	outF, err := os.Create(outFile)
	if err != nil {
		return fmt.Errorf("could not create output file: %s", err)
	}
	defer outF.Close()

	// write encrypted data to output file
	outF.Write(ciphertext)

	return nil
}

func DecryptFile(inFile, outFile, password string) error {
	// generate key
	key := generateKeyFromPassword(password)

	// read input file
	inFileData, err := os.ReadFile(inFile)
	if err != nil {
		return fmt.Errorf("could not open input file: %s", err)
	}

	// decrypt input file
	plaintext, err := decrypt(inFileData, key, nonce)
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
