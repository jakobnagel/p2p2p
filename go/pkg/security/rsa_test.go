package security

import (
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"math/big"
	"net"
	"os"
	"testing"
)

// Tests the contact verification process, ensuring an attacker can not pretend to be a contact
func TestVerifyServiceKey(t *testing.T) {
	addr := net.Addr(&net.TCPAddr{IP: net.IPv4(1, 2, 3, 4), Port: 1234})

	f, err := os.CreateTemp(".", "known_services_*.txt")
	if err != nil {
		t.Errorf("could not create known services file: %s", err)
	}
	defer os.Remove(f.Name())

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Errorf("could not generate RSA key: %s", err)
	}
	hash := hashRsaKey(&privateKey.PublicKey)
	_, err = f.WriteString(fmt.Sprintf("%s %x\n", addr, hash))

	if err != nil {
		t.Errorf("could not write to known services file: %s", err)
	}

	valid := verifyKnownRsaKey(f.Name(), addr, &privateKey.PublicKey)
	if valid != nil {
		t.Errorf("service key not verified: %s", valid)
	}

	invalid := verifyKnownRsaKey(f.Name(), addr, &rsa.PublicKey{N: big.NewInt(1234), E: 3})
	if invalid == nil {
		t.Errorf("service key verified with invalid key")
	}
}

// test if verifying RSA key works
// passing test indicates a MITM wouldn't be able to forge a signature
func TestRsaVerify(t *testing.T) {
	realPrivateKey, _ := generateRsaKey()
	realPublicKey := &realPrivateKey.PublicKey
	fakePrivateKey, _ := generateRsaKey()

	message := []byte("Hello, world!")

	signature, _ := sign(message, realPrivateKey)

	err := verify(message, signature, realPublicKey)
	if err != nil {
		t.Errorf("failed to verify valid signature: %s", err)
	}
	err = verify(message, signature, &fakePrivateKey.PublicKey)
	if err == nil {
		t.Errorf("verified signature with fake key")
	}
}
