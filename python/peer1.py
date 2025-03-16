#!/usr/bin/env python
from __future__ import annotations

import socket
import logging
import socket
import sys
import time

from zeroconf import ServiceInfo, Zeroconf, __version__

def main():
    r = Zeroconf()

    # create and bind socket
    s = socket.socket()
    host = socket.gethostname()
    ip = socket.gethostbyname(socket.gethostname())
    print(ip)
    port = 12345
    s.bind((host, port))

    addresses = [socket.inet_aton(ip)]
    expected = {ip}
    if socket.has_ipv6:
        addresses.append(socket.inet_pton(socket.AF_INET6, "::1"))
        expected.add("::1")

    desc = {"version": "0.10", "a": "test value", "b": "another value"}
    info = ServiceInfo(
        "_http._tcp.local.",
        "FileSharing._http._tcp.local.",
        addresses=addresses,
        port=12345,
        properties=desc,
    )

    r.register_service(info)

    s.listen(5)
    while True:
        c, addr = s.accept()
        print('Got connection from', addr)
        c.send('Thank you for connecting'.encode())
        time.sleep(5)
        c.close()

        # unregister and close
        r.unregister_service(info)
        r.close()

if __name__ == "__main__":
    main()



