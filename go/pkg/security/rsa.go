package security

import (
	"bufio"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/binary"
	"encoding/pem"
	"fmt"
	"net"
	"os"
	"strings"

	"nagelbros.com/p2p2p/pkg/config"
)

func readOrGeneratePrivateRsaKey() (*rsa.PrivateKey, error) {
	privateKeyData, err := os.ReadFile(config.Cfg.PrivateKeyFile)
	if os.IsNotExist(err) {
		fmt.Printf("Could not read private key: %s\n", err)
		fmt.Printf("Generating new RSA key\n")

		privateKey, err := generateRsaKey()
		if err != nil {
			return nil, fmt.Errorf("could not generate RSA key: %s", err)
		}
		fmt.Println("FILE: ", config.Cfg.PrivateKeyFile)
		privateKeyFile, err := os.Create(config.Cfg.PrivateKeyFile)
		if err != nil {
			return nil, fmt.Errorf("could not create private key file: %s", err)
		}
		defer privateKeyFile.Close()

		privateKeyPEM := &pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
		}
		if err := pem.Encode(privateKeyFile, privateKeyPEM); err != nil {
			return nil, fmt.Errorf("could not encode private key: %s", err)
		}

		return privateKey, nil
	}

	block, _ := pem.Decode(privateKeyData)
	if block == nil || block.Type != "RSA PRIVATE KEY" {
		return nil, fmt.Errorf("could not decode private key")
	}

	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("could not parse private key: %s", err)
	}

	return privateKey, nil
}

func generateRsaKey() (*rsa.PrivateKey, error) {
	return rsa.GenerateKey(rand.Reader, 2048)
}

func verifyKnownRsaKey(fname string, addr net.Addr, key *rsa.PublicKey) error {
	f, err := os.Open(fname)
	if err != nil {
		if os.IsNotExist(err) {
			f, err = os.Create(fname)
			if err != nil {
				return fmt.Errorf("could not create known services file: %s", err)
			}
		} else {
			return fmt.Errorf("could not open known services file: %s", err)
		}
	}
	defer f.Close()

	r := bufio.NewReader(f)

	for {
		line, err := r.ReadString('\n')
		line = strings.TrimSpace(line)
		if err != nil { // EOF
			f.Close()
			break
		}

		addr2, hash, found := strings.Cut(line, " ")
		if !found {
			return fmt.Errorf("could not parse known services file")
		}

		if addr2 == addr.String() {
			if fmt.Sprintf("%x", hashRsaKey(key)) == hash {
				return nil
			} else {
				return fmt.Errorf("RSA key does not match address: %s", addr2)
			}
		}
	}

	// add key to file
	f, err = os.OpenFile(fname, os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		return fmt.Errorf("could not open known services file: %s", err)
	}
	defer f.Close()

	_, err = f.WriteString(fmt.Sprintf("%s %x\n", addr.String(), hashRsaKey(key)))
	if err != nil {
		return fmt.Errorf("could not write to known services file: %s", err)
	}

	return nil
}

func hashRsaKey(key *rsa.PublicKey) []byte {
	hash := crypto.SHA224.New()

	e := make([]byte, 8)
	binary.BigEndian.PutUint64(e, uint64(key.E))

	hash.Write(append(key.N.Bytes(), e...))
	return hash.Sum(nil)
}

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
