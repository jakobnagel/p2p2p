package security

import (
	"crypto/rand"
	"crypto/rsa"
)

func sign(data []byte, key *rsa.PrivateKey) ([]byte, error) {
	hash := Hash.New()
	hash.Write(data)
	return rsa.SignPKCS1v15(rand.Reader, key, Hash, hash.Sum(nil))
}

func verify(data, signature []byte, key *rsa.PublicKey) error {
	hash := Hash.New()
	hash.Write(data)
	return rsa.VerifyPKCS1v15(key, Hash, hash.Sum(nil), signature)
}
