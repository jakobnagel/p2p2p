#!/usr/bin/env python

from util.browser import browse
from util.rsa import get_RSA_private_key, get_RSA_public_key, get_RSA_signature, verify_RSA_signature
import socket

TYPE = "_ppp._tcp.local."
NAME = socket.gethostname()

if __name__ == "__main__":
    privkey = get_RSA_private_key()
    print(privkey)
    pubkey = get_RSA_public_key()
    print(pubkey)
    message = b"A message I want to sign"

    signature = get_RSA_signature(privkey, message)
    print(signature)
    verify_RSA_signature(pubkey, signature, message)
    peer = browse()
    while peer:
        addr, port = peer[1][0].split(":")
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((addr, int(port)))
            s.sendall(b"Hello, world")
            data = s.recv(1024)

            print(f"Received {data!r}")
        peer = None

