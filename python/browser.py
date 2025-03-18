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


def on_service_state_change(
    zeroconf: Zeroconf, service_type: str, name: str, state_change: ServiceStateChange
) -> None:

    if state_change is ServiceStateChange.Added:
        info = zeroconf.get_service_info(service_type, name)

        if info:
            addresses = [f"{addr}:{cast(int, info.port)}" for addr in info.parsed_scoped_addresses()]
            print(f"  Addresses: {', '.join(addresses)}")
            print(f"  Server: {info.server}")
            if info.properties:
                print("  Properties are:")
                for key, value in info.properties.items():
                    print(f"    {key!r}: {value!r}")
            else:
                print("  No properties")
        else:
            print("  No info")
        print("\n")


if __name__ == "__main__":
    zeroconf = Zeroconf()

    browser = ServiceBrowser(zeroconf, "_ppp._tcp.local.", handlers=[on_service_state_change])

    try:
        while True:
            sleep(0.1)
    except KeyboardInterrupt:
        pass
    finally:
        zeroconf.close()
