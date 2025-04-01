from os import listdir, getcwd
from os.path import isfile, join
import message_pb2
import random
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

def create_file_download_request(local_rsa_priv_key, aes_key):
    file_download_request = message_pb2.FileDownloadRequest()
    file_download_request.file_name = pick_peer_file()

    wrapped_msg = message_pb2.WrappedMessage()
    wrapped_msg.file_download_request.CopyFrom(file_download_request)

    signed_msg_bytes = build_and_serialize_signed_msg(local_rsa_priv_key, aes_key, wrapped_msg)
    return signed_msg_bytes

def create_file_download(local_rsa_priv_key, aes_key, fname):
    consent = input(f"Client requested file: {fname}, allow? (y/n)")
    response = None
    wrapped_msg = message_pb2.WrappedMessage()
    if consent == 'y':
        full_fpath = join(join(getcwd(), "files"), fname)
        if isfile(full_fpath):
            response = message_pb2.FileDownload()
            response.file_name = fname
            with open(full_fpath, 'rb') as f:
                response.file_data = f.read()
            wrapped_msg.file_download.CopyFrom(response)
        else:
            response = message_pb2.Error()
            response.message = f"file {full_fpath} not found"
            wrapped_msg.error.CopyFrom(response)
    else:
        response = message_pb2.Error()
        response.message = "Peer denied request."
        wrapped_msg.error.CopyFrom(response)


    signed_msg_bytes = build_and_serialize_signed_msg(local_rsa_priv_key, aes_key, wrapped_msg)
    return signed_msg_bytes

def complete_file_download(fname, fdata):
    full_fpath = join(join(getcwd(), "files"), fname)
    if isfile(full_fpath):
        new_fname = fname + str(random.randint(0,100000))
        print(f"File {fname} already exists. Saving new file as {new_fname}")
        complete_file_download(new_fname, fdata)
    else:
        with open(full_fpath, 'wb') as f:
            f.write(fdata)
        print(f"File {fname} saved.\n")


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

    response = None
    if plain_payload.HasField("file_list_request"):
        print('file_list_request received')
        response = create_file_list(local_rsa_priv_key, aes_key)

    elif plain_payload.HasField("file_list"):
        print('file_list received')
        print(plain_payload.file_list)

    elif plain_payload.HasField("file_download_request"):
        print('file_download_request received')
        fname = plain_payload.file_download_request.file_name
        response = create_file_download(local_rsa_priv_key, aes_key, fname)

    elif plain_payload.HasField("file_download"):
        print('file_download received')
        fname = plain_payload.file_download.file_name
        fdata = plain_payload.file_download.file_data
        complete_file_download(fname, fdata)

    elif plain_payload.HasField("file_upload_request"):
        print('file_upload_request received')

    elif plain_payload.HasField("error"):
        print('Error message received')

    else:
        print('unknown request type')
    return response


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

def pick_peer_file():
    fname = input("What file would you like to request?\n")
    return fname

