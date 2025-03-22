import message_pb2
import security_pb2

def client_introduce(sock, privkey, pubkey):
    pass


def server_introduce(conn, privkey, pubkey):
    # receive the rsa pub key and dhke params
    serialized_msg = conn.recv(1024)
    received_msg = message_pb2.SignedMessage()
    received_msg.ParseFromString(serialized_msg)

    print(received_msg)  # Prints the parsed message

