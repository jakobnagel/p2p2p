#!/usr/bin/env python
from __future__ import annotations

import socket
import logging
import socket
import sys
import time

from zeroconf import ServiceInfo, Zeroconf, __version__


TYPE="_ppp._tcp.local."
NAME = socket.gethostname()

def main():
    r = Zeroconf()

    # create and bind socket
    s = socket.socket()
    ip = socket.gethostbyname(NAME)
    port = 12345
    s.bind((NAME, port))

    addresses = [socket.inet_aton(ip)]
    info = ServiceInfo(
        f"{TYPE}",
        f"{NAME}.{TYPE}",
        addresses=addresses,
        port=port,
    )

    r.register_service(info)
    print("Registered as peer.")

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind((ip, port))
    s.listen()
    print("Listening for connections. Ctrl+c to quit.")
    try:
        while True:
            conn, addr = s.accept()
            with conn:
                print(f"Connected by {addr}")
                while True:
                    data = conn.recv(1024)
                    if not data:
                        break
                    print("got", data.decode())
                    data = input("what to send back?").encode()
                    conn.sendall(data)
    except KeyboardInterrupt:
        pass
    finally:
        s.close()
        # unregister and close
        r.unregister_service(info)
        r.close()

if __name__ == "__main__":
    main()

