import message_pb2
import security_pb2
from util.rsa import get_RSA_signature, verify_RSA_signature
from cryptography.hazmat.primitives import serialization as crypto_serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.asymmetric import rsa, ec

def client_introduce(sock, privkey, pubkey):
    rsa_key = security_pb2.RsaPublicKey()
    rsa_key.n = pubkey.public_numbers().n.to_bytes(256, 'big')
    rsa_key.e = pubkey.public_numbers().e

    # generate a private key for DHKE, pack public key
    dh = security_pb2.DiffeHellman()
    dh_private_key = ec.generate_private_key(
        ec.SECP256R1()
    )
    dh_public_key = dh_private_key.public_key().public_bytes(
        crypto_serialization.Encoding.PEM,
        crypto_serialization.PublicFormat.SubjectPublicKeyInfo
    )
    dh.dh_public_key = dh_public_key

    introduction = message_pb2.Introduction()
    introduction.rsa_public_key.CopyFrom(rsa_key)
    introduction.diffe_hellman.CopyFrom(dh)

    wrapped_msg = message_pb2.WrappedMessage()
    wrapped_msg.introduction.CopyFrom(introduction)

    signed_msg = message_pb2.SignedMessage()
    signed_msg.encrypted_message = message_pb2.SignedMessage.Encrypted_Message.WRAPPED_MESSAGE
    signed_msg.signed_payload = wrapped_msg.SerializeToString()

    signature = get_RSA_signature(privkey, signed_msg.signed_payload)
    signed_msg.rsa_signature = signature

    verify_RSA_signature(pubkey, signature, signed_msg.signed_payload)
    sock.sendall(signed_msg.SerializeToString())

    serialized_msg = sock.recv(1024)

    # receive and veryify message
    received_msg = message_pb2.SignedMessage()
    received_msg.ParseFromString(serialized_msg)

    received_msg.ParseFromString(serialized_msg)
    received_payload = message_pb2.WrappedMessage()

    received_payload.ParseFromString(received_msg.signed_payload)
    n = int.from_bytes(received_payload.introduction.rsa_public_key.n, 'big')
    e = received_payload.introduction.rsa_public_key.e
    received_key = rsa.RSAPublicNumbers(e, n).public_key()

    try:
        verify_RSA_signature(received_key, received_msg.rsa_signature, received_msg.signed_payload)
    except:
        print("Bad signature")
        conn.close()
        exit()

    received_dh_public_key = crypto_serialization.load_pem_public_key(received_payload.introduction.diffe_hellman.dh_public_key)

    # derive DH shared key
    dh_key = dh_private_key.exchange(
        ec.ECDH(), received_dh_public_key
    )

    return received_key, dh_key



def server_introduce(conn, privkey, pubkey):
    # receive the rsa pub key and dhke params
    serialized_msg = conn.recv(1024)
    received_msg = message_pb2.SignedMessage()
    received_msg.ParseFromString(serialized_msg)
    received_payload = message_pb2.WrappedMessage()

    received_payload.ParseFromString(received_msg.signed_payload)
    n = int.from_bytes(received_payload.introduction.rsa_public_key.n, 'big')
    e = received_payload.introduction.rsa_public_key.e
    received_key = rsa.RSAPublicNumbers(e, n).public_key()

    try:
        verify_RSA_signature(received_key, received_msg.rsa_signature, received_msg.signed_payload)
    except:
        print("Bad signature")
        conn.close()
        exit()

    # create and send response
    rsa_key = security_pb2.RsaPublicKey()
    rsa_key.n = pubkey.public_numbers().n.to_bytes(256, 'big')
    rsa_key.e = pubkey.public_numbers().e

    dh = security_pb2.DiffeHellman()
    # generate a private key for DHKE, pack public key
    dh = security_pb2.DiffeHellman()
    dh_private_key = ec.generate_private_key(
        ec.SECP256R1()
    )
    dh_public_key = dh_private_key.public_key().public_bytes(
        crypto_serialization.Encoding.PEM,
        crypto_serialization.PublicFormat.SubjectPublicKeyInfo
    )
    dh.dh_public_key = dh_public_key

    introduction = message_pb2.Introduction()
    introduction.rsa_public_key.CopyFrom(rsa_key)
    introduction.diffe_hellman.CopyFrom(dh)

    wrapped_msg = message_pb2.WrappedMessage()
    wrapped_msg.introduction.CopyFrom(introduction)

    signed_msg = message_pb2.SignedMessage()
    signed_msg.encrypted_message = message_pb2.SignedMessage.Encrypted_Message.WRAPPED_MESSAGE
    signed_msg.signed_payload = wrapped_msg.SerializeToString()

    signature = get_RSA_signature(privkey, signed_msg.signed_payload)
    signed_msg.rsa_signature = signature

    conn.sendall(signed_msg.SerializeToString())

    received_dh_public_key = crypto_serialization.load_pem_public_key(received_payload.introduction.diffe_hellman.dh_public_key)
    # derive DH shared key
    dh_key = dh_private_key.exchange(
        ec.ECDH(), received_dh_public_key
    )

    return received_key, dh_key

