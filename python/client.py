#!/usr/bin/env python

from util.browser import browse
from util.rsa import get_RSA_private_key, get_RSA_public_key, get_RSA_signature, verify_RSA_signature
from util.intro import client_introduce
from util.message import create_file_list_request, consume_message, create_file_download_request, create_file_upload_request
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

        while True:
            try:
                print("\nCtrl+c to quit\n")
                action = pick_action()
                msg = action(privkey, shared_dh_key)
                s.sendall(msg)
                if action not in [create_file_upload_request]:
                    data = s.recv(1024)
                    reply = consume_message(privkey, peer_rsa_pubkey, shared_dh_key, data)
                    if reply:
                        print("probably shouldnt be here")
            except KeyboardInterrupt:
                break


def pick_action():
    options = [
        ("Request list of files", create_file_list_request),
        ("Request a file for download", create_file_download_request),
        ("Upload a file", create_file_upload_request),
    ]

    cmd = -1
    while cmd not in range(len(options)):
        for i, x in enumerate(options):
            print(f"{i}: {x[0]}")

        try:
            cmd = int(input("Select an action by entering the corresponding number. \n"))
            if cmd not in range(len(options)):
                print("Invalid number")
        except ValueError:
            print("Invalid number")

    return options[cmd][1]

if __name__ == "__main__":
    main()
