import pytest
import os
from ..util import message, rsa
import message_pb2

# --- Message Creation Tests ---
def test_create_file_list_request():
    privkey = rsa.get_RSA_private_key()
    aes_key = os.urandom(32)
    request = message.create_file_list_request(privkey, aes_key)
    assert isinstance(request, bytes)

def test_create_file_list():
    # This test might require mocking file system interactions
    privkey = rsa.get_RSA_private_key()
    aes_key = os.urandom(32)
    file_list = message.create_file_list(privkey, aes_key)
    assert isinstance(file_list, bytes)

def test_create_file_download_request():
    privkey = rsa.get_RSA_private_key()
    aes_key = os.urandom(32)
    request = message.create_file_download_request(privkey, aes_key)
    assert isinstance(request, bytes)

def test_create_file_download():
    # This test requires mocking user input and file operations
    privkey = rsa.get_RSA_private_key()
    aes_key = os.urandom(32)
    fname = "test_file.txt" #create a dummy file
    with open(fname, 'w') as f:
        f.write("test content")
    download = message.create_file_download(privkey, aes_key, fname)
    assert isinstance(download, bytes)
    os.remove(fname)

def test_create_file_upload_request():
    # This test requires mocking file operations
    privkey = rsa.get_RSA_private_key()
    aes_key = os.urandom(32)
    fname = "test_file.txt" #create a dummy file
    with open(fname, 'w') as f:
        f.write("test content")
    request = message.create_file_upload_request(privkey, aes_key)
    assert isinstance(request, bytes)
    os.remove(fname)

# --- Message Consumption Tests ---
def test_consume_message():
    # This test is complex and requires mocking the entire message flow
    # It would be best to break this down into smaller testable units if possible
    privkey = rsa.get_RSA_private_key()
    pubkey = rsa.get_RSA_public_key()
    aes_key = os.urandom(32)
    # Create a dummy serialized message. This is where mocking protobufs is important
    # For example, create a WrappedMessage, encrypt it, sign it, and serialize it.
    wrapped_msg = message_pb2.WrappedMessage()
    wrapped_msg.file_list_request.CopyFrom(message_pb2.FileListRequest())
    signed_msg_bytes = message.build_and_serialize_signed_msg(privkey, aes_key, wrapped_msg)

    response = message.consume_message(privkey, pubkey, aes_key, signed_msg_bytes)
    # Assert based on the expected behavior for the given message type
    assert response is not None
