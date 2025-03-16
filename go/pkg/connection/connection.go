package connection

import (
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"net"

	"google.golang.org/protobuf/proto"
	pb "nagelbros.com/p2p2p/pb/message"
)

type SecureConnection struct {
	conn         net.Conn
	remoteRsaKey *rsa.PublicKey
	localRsaKey  *rsa.PrivateKey
	sharedSecret []byte
}

const Hash = crypto.SHA256

func EstablishSecureConnection(conn net.Conn, initiator bool) (*SecureConnection, error) {

	// RSA key exchange
	localRsaKey, err := readOrGeneratePrivateRsaKey()
	if err != nil {
		return nil, fmt.Errorf("could not get private key: %s", err)
	}
	sendRsa(conn, &localRsaKey.PublicKey)

	remoteRsaKey, err := acceptRsa(conn)
	if err != nil {
		return nil, fmt.Errorf("could not accept RSA key: %s", err)
	}

	// diffie-hellman key exchange
	localDhPrivate, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("could not generate DH key: %s", err)
	}

	// share DH public key
	sendDh(conn, localDhPrivate, localRsaKey)

	// accept remote DH public key
	remoteDhPublic, err := acceptDh(conn, remoteRsaKey)
	if err != nil {
		return nil, fmt.Errorf("could not accept DH key: %s", err)
	}

	// compute shared secret
	sharedSecret, err := localDhPrivate.ECDH(remoteDhPublic)
	if err != nil {
		return nil, fmt.Errorf("could not compute shared secret: %s", err)
	}

	return &SecureConnection{
		conn:         conn,
		remoteRsaKey: remoteRsaKey,
		localRsaKey:  localRsaKey,
		sharedSecret: sharedSecret,
	}, nil
}

func (sc *SecureConnection) Send(data []byte) error {
	// encrypt
	block, err := aes.NewCipher(sc.sharedSecret)
	if err != nil {
		return fmt.Errorf("could not create AES cipher: %s", err)
	}
	nonce := make([]byte, 12)
	if _, err := rand.Read(nonce); err != nil {
		return fmt.Errorf("could not generate nonce: %s", err)
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return fmt.Errorf("could not create GCM: %s", err)
	}

	ciphertext := aesgcm.Seal(nil, nonce, data, nil)

	// sign
	hash := Hash.New()
	hash.Write(ciphertext)
	signature, err := rsa.SignPKCS1v15(rand.Reader, sc.localRsaKey, Hash, hash.Sum(nil))
	if err != nil {
		return fmt.Errorf("could not sign message: %s", err)
	}

	// wrap
	wrappedMessage := &pb.MessageWrapper{
		Message:   ciphertext,
		Signature: signature,
		Nonce:     nonce,
	}

	// encode
	data, err = proto.Marshal(wrappedMessage)
	if err != nil {
		return fmt.Errorf("could not marshal message: %s", err)
	}

	// send
	sc.conn.Write(data)
	return nil
}

func (sc *SecureConnection) Receive() ([]byte, error) {
	buf := make([]byte, 1024)
	n, err := sc.conn.Read(buf)
	if err != nil {
		return nil, fmt.Errorf("could not read from connection: %s", err)
	}

	var msg pb.MessageWrapper
	err = proto.Unmarshal(buf[:n], &msg)
	if err != nil {
		return nil, fmt.Errorf("could not unmarshal message: %s", err)
	}

	signature := msg.Signature
	ciphertext := msg.Message
	nonce := msg.Nonce

	// verify
	hash := Hash.New()
	hash.Write(ciphertext)
	err = rsa.VerifyPKCS1v15(sc.remoteRsaKey, Hash, hash.Sum(nil), signature)
	if err != nil {
		return nil, fmt.Errorf("could not verify message: %s", err)
	}

	// decrypt
	block, err := aes.NewCipher(sc.sharedSecret)
	if err != nil {
		return nil, fmt.Errorf("could not create AES cipher: %s", err)
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("could not create GCM: %s", err)
	}

	data, err := aesgcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("could not decrypt message: %s", err)
	}

	return data, nil
}
