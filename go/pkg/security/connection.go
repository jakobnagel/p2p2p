package security

import (
	"crypto"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"math/big"
	"net"

	"google.golang.org/protobuf/proto"
	"nagelbros.com/p2p2p/pkg/config"
	pb "nagelbros.com/p2p2p/types/message"
	secPb "nagelbros.com/p2p2p/types/security"
)

type SecConn struct {
	conn         net.Conn
	remoteRsaKey *rsa.PublicKey
	localRsaKey  *rsa.PrivateKey
	sharedSecret []byte
}

const Hash = crypto.SHA256

func EstablishSecureConnection(conn net.Conn) (*SecConn, error) {
	// Send introduction
	localRsaKey, err := readOrGeneratePrivateRsaKey()
	if err != nil {
		return nil, fmt.Errorf("could not get private key: %s", err)
	}
	localDhKey, err := generateDhKey()
	if err != nil {
		return nil, fmt.Errorf("could not generate DH key: %s", err)
	}

	introMsg, err := createIntroMessage(localRsaKey, localDhKey)
	if err != nil {
		return nil, fmt.Errorf("could not create introduction message: %s", err)
	}
	introMsgBytes, err := proto.Marshal(introMsg)
	if err != nil {
		return nil, fmt.Errorf("could not marshal introduction message: %s", err)
	}
	_, err = conn.Write(introMsgBytes)
	if err != nil {
		return nil, fmt.Errorf("could not send introduction message: %s", err)
	}

	// Accept introduction
	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil {
		return nil, fmt.Errorf("could not read introduction message: %s", err)
	}

	var signedMessage pb.SignedMessage
	var wrappedMessage pb.WrappedMessage
	err = proto.Unmarshal(buf[:n], &signedMessage)
	if err != nil {
		return nil, fmt.Errorf("could not unmarshal introduction message: %s", err)
	}
	err = proto.Unmarshal(signedMessage.SignedPayload, &wrappedMessage)
	if err != nil {
		return nil, fmt.Errorf("could not unmarshal introduction message: %s", err)
	}

	signature := signedMessage.RsaSignature
	introduction := wrappedMessage.GetIntroduction()
	remoteRsaKey := &rsa.PublicKey{
		N: new(big.Int).SetBytes(introduction.RsaPublicKey.N),
		E: int(introduction.RsaPublicKey.E),
	}
	remoteDhKey, err := ecdh.P256().NewPublicKey(introduction.DiffeHellman.DhPublicKey)
	if err != nil {
		return nil, fmt.Errorf("could not create remote DH public key: %s", err)
	}

	// check if we already know this host
	valid := verifyKnownRsaKey(config.Cfg.KnownKeysFile, conn.RemoteAddr(), remoteRsaKey)
	if valid != nil {
		return nil, fmt.Errorf("could not verify RSA key: %s", valid)
	}

	// verify introduction message
	err = verify(signedMessage.SignedPayload, signature, remoteRsaKey)
	if err != nil {
		return nil, fmt.Errorf("could not verify introduction message: %s", err)
	}

	// compute shared secret
	sharedSecret, err := localDhKey.ECDH(remoteDhKey)
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

func (sc *SecConn) Send(message *pb.WrappedMessage) error {
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

	// wrap
	encryptedMessage := &pb.EncryptedMessage{
		EncryptedPayload: ciphertext,
		AesNonce:         nonce,
	}

	signedPayload, err := proto.Marshal(encryptedMessage)
	if err != nil {
		return fmt.Errorf("could not marshal encrypted message: %s", err)
	}

	// sign
	signature, err := sign(signedPayload, sc.localRsaKey)
	if err != nil {
		return fmt.Errorf("could not sign message: %s", err)
	}

	signedMessage := &pb.SignedMessage{
		EncryptedMessage: pb.SignedMessage_ENCRYPTED_WRAPPED_MESSAGE,
		SignedPayload:    signedPayload,
		RsaSignature:     signature,
	}

	// encode
	data, err = proto.Marshal(signedMessage)
	if err != nil {
		return fmt.Errorf("could not marshal message: %s", err)
	}

	// send
	sc.conn.Write(data)
	return nil
}

func (sc *SecConn) Receive() (*pb.WrappedMessage, error) {
	buf := make([]byte, 1024)
	n, err := sc.conn.Read(buf)
	if err != nil {
		return nil, fmt.Errorf("could not read from connection: %s", err)
	}

	var msg pb.SignedMessage
	err = proto.Unmarshal(buf[:n], &msg)
	if err != nil {
		return nil, fmt.Errorf("could not unmarshal message: %s", err)
	}

	signature := msg.RsaSignature
	signedPayload := msg.SignedPayload

	// verify
	err = verify(signedPayload, signature, sc.remoteRsaKey)
	if err != nil {
		return nil, fmt.Errorf("could not verify message: %s", err)
	}

	// decrypt
	var encryptedMessage pb.EncryptedMessage
	err = proto.Unmarshal(signedPayload, &encryptedMessage)
	if err != nil {
		return nil, fmt.Errorf("could not unmarshal encrypted message: %s", err)
	}

	ciphertext := encryptedMessage.EncryptedPayload
	nonce := encryptedMessage.AesNonce
	data, err := Decrypt(ciphertext, sc.sharedSecret, nonce)
	if err != nil {
		return nil, fmt.Errorf("could not decrypt message: %s", err)
	}

	// unmarshal
	message := pb.WrappedMessage{}
	err = proto.Unmarshal(data, &message)
	if err != nil {
		return nil, fmt.Errorf("could not unmarshal message: %s", err)
	}

	return &message, nil
}

func (sc *SecConn) Addr() net.Addr {
	return sc.conn.RemoteAddr()
}

func createIntroMessage(rsaKey *rsa.PrivateKey, dhKey *ecdh.PrivateKey) (*pb.SignedMessage, error) {
	rsaPublicKeyMsg := &secPb.RsaPublicKey{
		N: rsaKey.PublicKey.N.Bytes(),
		E: uint32(rsaKey.PublicKey.E),
	}
	dhPublicMsg := &secPb.DiffeHellman{
		DhPublicKey: dhKey.PublicKey().Bytes(),
	}

	introMsg := &pb.Introduction{
		RsaPublicKey: rsaPublicKeyMsg,
		DiffeHellman: dhPublicMsg,
	}

	wrappedMessage := &pb.WrappedMessage{
		Payload: &pb.WrappedMessage_Introduction{
			Introduction: introMsg,
		},
	}
	msgBytes, err := proto.Marshal(wrappedMessage)
	if err != nil {
		return nil, fmt.Errorf("could not marshal introduction message: %s", err)
	}

	// sign the introduction message
	signature, err := sign(msgBytes, rsaKey)
	if err != nil {
		return nil, fmt.Errorf("could not sign introduction message: %s", err)
	}

	signedMessage := &pb.SignedMessage{
		EncryptedMessage: pb.SignedMessage_WRAPPED_MESSAGE,
		SignedPayload:    msgBytes,
		RsaSignature:     signature,
	}

	return signedMessage, nil
}
