from os import listdir, getcwd
from os.path import isfile, join
import message_pb2
from util.hash import hash_data
from util.encryption import encrypt, decrypt
from util.rsa import get_RSA_signature, verify_RSA_signature

def create_file_list_request(local_rsa_priv_key, aes_key):
    payload = message_pb2.FileListRequest()

    wrapped_msg = message_pb2.WrappedMessage()
    wrapped_msg.file_list_request.CopyFrom(payload)

    signed_msg_bytes = build_and_serialize_signed_msg(local_rsa_priv_key, aes_key, wrapped_msg)
    return signed_msg_bytes

def create_file_list(local_rsa_priv_key, aes_key):
    fpath = join(getcwd(), "files")
    files = [f for f in listdir(fpath) if isfile(join(fpath, f))]
    file_list = message_pb2.FileList()
    for file in files:
        fpath = join(join(getcwd(), "files"), file)
        with open(fpath, 'rb') as f:
            file_metadata = message_pb2.FileMetadata()
            file_metadata.hash = hash_data(f.read())
            file_metadata.name = file
            file_list.files.append(file_metadata)

    wrapped_msg = message_pb2.WrappedMessage()
    wrapped_msg.file_list.CopyFrom(file_list)

    signed_msg_bytes = build_and_serialize_signed_msg(local_rsa_priv_key, aes_key, wrapped_msg)
    return signed_msg_bytes

def consume_message(local_rsa_priv_key, peer_rsa_pub_key, aes_key, serialized_msg):
    received_msg = message_pb2.SignedMessage()
    received_msg.ParseFromString(serialized_msg)

    received_signed_payload = message_pb2.WrappedMessage()
    verify_incoming_payload(peer_rsa_pub_key, received_msg.rsa_signature, received_msg.signed_payload)

    encrypted_message = message_pb2.EncryptedMessage()
    encrypted_message.ParseFromString(received_msg.signed_payload)

    aes_nonce = encrypted_message.aes_nonce
    plain_request = decrypt(encrypted_message.encrypted_payload, aes_key, aes_nonce)
    plain_payload = message_pb2.WrappedMessage()
    plain_payload.ParseFromString(plain_request)

    if plain_payload.HasField("file_list_request"):
        print('file_list_request received')
        file_list = create_file_list(local_rsa_priv_key, aes_key)
        return file_list
    elif plain_payload.HasField("file_list"):
        print('file_list received')
        print(plain_payload.file_list)
    elif plain_payload.HasField("file_download_request"):
        print('file_download_request received')
    elif plain_payload.HasField("file_download"):
        print('file_download received')
    elif plain_payload.HasField("file_upload_request"):
        print('file_upload_request received')
    elif plain_payload.HasField("error"):
        print('Error message received')
    else:
        print('unknown request type')


def build_and_serialize_signed_msg(rsa_priv_key, aes_key, wrapped_msg):
    ctxt, nonce = encrypt(wrapped_msg.SerializeToString(), rsa_priv_key, aes_key)
    encrypted_message = message_pb2.EncryptedMessage()
    encrypted_message.encrypted_payload = ctxt
    encrypted_message.aes_nonce = nonce

    signed_msg = message_pb2.SignedMessage()
    signed_msg.encrypted_message = message_pb2.SignedMessage.Encrypted_Message.ENCRYPTED_WRAPPED_MESSAGE

    signed_msg.signed_payload = encrypted_message.SerializeToString()

    signature = get_RSA_signature(rsa_priv_key, signed_msg.signed_payload)
    signed_msg.rsa_signature = signature

    final_msg_bytes = signed_msg.SerializeToString()

    return final_msg_bytes

def verify_incoming_payload(key, sig, payload):
    try:
        verify_RSA_signature(key, sig, payload)
    except:
        print("Bad signature")
        conn.close()
        exit()
