#!/usr/bin/env python

from __future__ import annotations

import logging
import sys
import socket

from zeroconf import Zeroconf

TYPE = "_p2p._tcp.local."
NAME = socket.gethostname()

if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)
    if len(sys.argv) > 1:
        assert sys.argv[1:] == ["--debug"]
        logging.getLogger("zeroconf").setLevel(logging.DEBUG)

    zeroconf = Zeroconf()

    try:
        print(zeroconf.get_service_info(TYPE, NAME + "." + TYPE))
        print(zeroconf.get_service_info(TYPE, NAME + "." + TYPE))
    finally:
        zeroconf.close()
