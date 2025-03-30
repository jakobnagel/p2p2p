#!/usr/bin/env python

from util.browser import browse
from util.rsa import get_RSA_private_key, get_RSA_public_key, get_RSA_signature, verify_RSA_signature
from util.intro import client_introduce
from util.message import create_file_list_request, consume_message
import socket

TYPE = "_ppp._tcp.local."
NAME = socket.gethostname()

if __name__ == "__main__":
    privkey = get_RSA_private_key()
    pubkey = get_RSA_public_key()

    peer = browse()
    addr, port = peer[1][0].split(":")

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((addr, int(port)))
        peer_rsa_pubkey, shared_dh_key = client_introduce(s, privkey, pubkey)
        msg = create_file_list_request(privkey, shared_dh_key)
        print("sending msg")
        s.sendall(msg)
        print("getting msg")
        data = s.recv(1024)
        print("consuming msg")
        reply = consume_message(privkey, peer_rsa_pubkey, shared_dh_key, data)

