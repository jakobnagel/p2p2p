package security

import (
	"crypto"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"net"

	"google.golang.org/protobuf/proto"
	"nagelbros.com/p2p2p/pkg/config"
	pb "nagelbros.com/p2p2p/types/message"
)

type SecConn struct {
	conn         net.Conn
	remoteRsaKey *rsa.PublicKey
	localRsaKey  *rsa.PrivateKey
	sharedSecret []byte
}

const Hash = crypto.SHA256

func EstablishSecureConnection(conn net.Conn) (*SecConn, error) {
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

	valid := verifyRsaKey(config.Cfg.KnownKeysFile, conn.RemoteAddr(), remoteRsaKey)
	if valid != nil {
		return nil, fmt.Errorf("could not verify RSA key: %s", valid)
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

	return &SecConn{
		conn:         conn,
		remoteRsaKey: remoteRsaKey,
		localRsaKey:  localRsaKey,
		sharedSecret: sharedSecret,
	}, nil
}

func (sc *SecConn) Send(message *pb.Message) error {
	data, err := proto.Marshal(message)
	if err != nil {
		return fmt.Errorf("could not marshal message: %s", err)
	}

	nonce := make([]byte, 12)
	if _, err := rand.Read(nonce); err != nil {
		return fmt.Errorf("could not generate nonce: %s", err)
	}

	ciphertext, err := Encrypt(data, sc.sharedSecret, nonce)
	if err != nil {
		return fmt.Errorf("could not encrypt message: %s", err)
	}

	// sign
	signature, err := sign(ciphertext, sc.localRsaKey)
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

func (sc *SecConn) Receive() (*pb.Message, error) {
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
	err = verify(ciphertext, signature, sc.remoteRsaKey)
	if err != nil {
		return nil, fmt.Errorf("could not verify message: %s", err)
	}

	// decrypt
	data, err := Decrypt(ciphertext, sc.sharedSecret, nonce)
	if err != nil {
		return nil, fmt.Errorf("could not decrypt message: %s", err)
	}

	// unmarshal
	message := &pb.Message{}
	err = proto.Unmarshal(data, message)
	if err != nil {
		return nil, fmt.Errorf("could not unmarshal message: %s", err)
	}

	return message, nil
}

func (sc *SecConn) Addr() net.Addr {
	return sc.conn.RemoteAddr()
}
