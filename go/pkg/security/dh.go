package security

import (
	"crypto/ecdh"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"net"

	"google.golang.org/protobuf/proto"
	mesPb "nagelbros.com/p2p2p/pb/message"
	secPb "nagelbros.com/p2p2p/pb/security"
)

func sendDh(conn net.Conn, dhKey *ecdh.PrivateKey, rsaKey *rsa.PrivateKey) error {
	dhMessage := &secPb.DiffeHellman{DhPublicKey: dhKey.PublicKey().Bytes()}

	// sign dh public key
	dhMessageHash := Hash.New()
	dhMessageHash.Write(dhMessage.DhPublicKey)
	signature, err := rsa.SignPKCS1v15(rand.Reader, rsaKey, Hash, dhMessageHash.Sum(nil))
	if err != nil {
		return fmt.Errorf("could not sign DH public key: %s", err)
	}

	// wrap dh public key and signature
	wrappedMessage := &mesPb.MessageWrapper{
		Message:   dhMessage.DhPublicKey,
		Signature: signature,
	}
	msgBytes, err := proto.Marshal(wrappedMessage)
	if err != nil {
		return fmt.Errorf("could not marshal DH public key: %s", err)
	}
	conn.Write(msgBytes)

	return nil
}

func acceptDh(conn net.Conn, remoteRsaKey *rsa.PublicKey) (*ecdh.PublicKey, error) {
	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil {
		return nil, fmt.Errorf("could not read DH public key: %s", err)
	}

	// parse and verify dh public key
	var dhPublicMsg mesPb.MessageWrapper
	dhPublicHash := Hash.New()
	err = proto.Unmarshal(buf[:n], &dhPublicMsg)
	if err != nil {
		return nil, fmt.Errorf("could not unmarshal DH public key: %s", err)
	}
	dhPublicHash.Write(dhPublicMsg.Message)
	err = rsa.VerifyPKCS1v15(remoteRsaKey, Hash, dhPublicHash.Sum(nil), dhPublicMsg.Signature)
	if err != nil {
		return nil, fmt.Errorf("could not verify DH public key: %s", err)
	}

	remoteDhPublic, err := ecdh.P256().NewPublicKey(dhPublicMsg.Message)
	if err != nil {
		return nil, fmt.Errorf("could not create DH public key from remote: %s", err)
	}

	return remoteDhPublic, nil
}
