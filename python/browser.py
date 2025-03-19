#!/usr/bin/env python

from __future__ import annotations

import argparse
import logging
from time import sleep
from typing import cast

from zeroconf import (
    ServiceBrowser,
    ServiceStateChange,
    Zeroconf
)


servers = []
TYPE = "_ppp._tcp.local."

def on_service_state_change(
    zeroconf: Zeroconf, service_type: str, name: str, state_change: ServiceStateChange
) -> None:
    if state_change is ServiceStateChange.Added:
        info = zeroconf.get_service_info(service_type, name)

        if info:
            addresses = [f"{addr}:{info.port}" for addr in info.parsed_scoped_addresses()]
            servers.append((info.server, addresses))
        else:
            print("  No info")

if __name__ == "__main__":
    zeroconf = Zeroconf()
    num_servers = 0

    browser = ServiceBrowser(zeroconf, TYPE, handlers=[on_service_state_change])

    choice = -1
    peer = None
    try:
        while True:
            if len(servers) == num_servers:
                continue
            else:
                num_servers = len(servers)

                for i, p in enumerate(servers):
                    print(f"{i}: {p[0][:-1 * (len(TYPE) + 1)]}")
                while choice not in range(len(servers)):
                    try:
                        choice = int(input("Select a peer by entering the corresponding number:\n"))
                        if choice not in range(len(servers)):
                            print("Invalid number")
                    except:
                        print("Invalid number")

                peer = servers[choice]
                break
        print(f"connecting to {peer}")

    except KeyboardInterrupt:
        pass
    finally:
        zeroconf.close()

