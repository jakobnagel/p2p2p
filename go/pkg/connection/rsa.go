package connection

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"

	"google.golang.org/protobuf/proto"
	pb "nagelbros.com/p2p2p/pb/security"
)

func readOrGeneratePrivateRsaKey() (*rsa.PrivateKey, error) {
	privateKeyData, err := os.ReadFile("private.pem")
	if err != nil {
		fmt.Printf("Could not read private key: %s\n", err)
		fmt.Printf("Generating new RSA key\n")

		privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return nil, fmt.Errorf("could not generate RSA key: %s", err)
		}

		privateKeyFile, err := os.Create("private.pem")
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

func acceptRsa(conn net.Conn) (*rsa.PublicKey, error) {
	buffer := make([]byte, 1024)

	bufSize, err := conn.Read(buffer)
	if err != nil {
		return nil, fmt.Errorf("could not read from connection: %s", err)
	}

	var clientRsaKeyMsg pb.RsaPublicKey
	err = proto.Unmarshal(buffer[:bufSize], &clientRsaKeyMsg)
	if err != nil {
		return nil, fmt.Errorf("could unmarshal RSA key: %s", err)
	}

	n := big.NewInt(0)
	n.SetBytes(clientRsaKeyMsg.N)

	clientRsaKey := rsa.PublicKey{
		N: n,
		E: int(clientRsaKeyMsg.E),
	}

	return &clientRsaKey, nil
}

func sendRsa(conn net.Conn, key *rsa.PublicKey) error {
	publicKeyMsg := pb.RsaPublicKey{
		N: key.N.Bytes(),
		E: uint32(key.E),
	}

	publicKeyMsgBytes, err := proto.Marshal(&publicKeyMsg)
	if err != nil {
		return fmt.Errorf("could not marshal RSA key: %s", err)
	}

	_, err = conn.Write(publicKeyMsgBytes)
	return err
}
