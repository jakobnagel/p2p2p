#!/usr/bin/env python

from __future__ import annotations

import logging
import sys

from zeroconf import Zeroconf

TYPE = "_http._tcp.local."
NAME = "FileSharing"

if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)
    if len(sys.argv) > 1:
        assert sys.argv[1:] == ["--debug"]
        logging.getLogger("zeroconf").setLevel(logging.DEBUG)

    zeroconf = Zeroconf()

    try:
        print(zeroconf.get_service_info(TYPE, NAME + "." + TYPE))
    finally:
        zeroconf.close()
