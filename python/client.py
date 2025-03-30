#!/usr/bin/env python

from util.browser import browse
from util.rsa import get_RSA_private_key, get_RSA_public_key, get_RSA_signature, verify_RSA_signature
from util.intro import client_introduce
from util.message import create_file_list_request, consume_message, create_file_list
import socket

TYPE = "_ppp._tcp.local."
NAME = socket.gethostname()

def main():
    privkey = get_RSA_private_key()
    pubkey = get_RSA_public_key()

    peer = browse()
    addr, port = peer[1][0].split(":")

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((addr, int(port)))
        peer_rsa_pubkey, shared_dh_key = client_introduce(s, privkey, pubkey)

        action = pick_action()
        msg = action(privkey, shared_dh_key)
        s.sendall(msg)
        data = s.recv(1024)
        if data:
            reply = consume_message(privkey, peer_rsa_pubkey, shared_dh_key, data)

def pick_action():
    options = [
        ("Request list of files", create_file_list_request),
        ("Send your file list", create_file_list),
    ]

    cmd = -1
    while cmd not in range(len(options)):
        for i, x in enumerate(options):
            print(f"{i}: {x[0]}")

        try:
            cmd = int(input("Select an action by entering the corresponding number. \n"))
            if cmd not in range(len(options)):
                print("Invalid number")
        except:
            print("Invalid number")

    return options[cmd][1]

if __name__ == "__main__":
    main()
