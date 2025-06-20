# Copyright (c) 2024 Patrik
# See the COPYRIGHT file for more information

from __future__ import annotations

import random

from cowrie.shell.command import HoneyPotCommand

commands = {}

class Command_ip(HoneyPotCommand):
    def call(self) -> None:
        args = list(self.args)

        # Check if user asked "ip a" or "ip addr" or anything else
        if len(args) >= 1 and args[0] in ("a", "addr", "address"):
            self.show_ip_address()
        else:
            # Always show same output for simplicity
            self.show_ip_address()

    def show_ip_address(self) -> None:
        hwaddr = f"{random.randint(0, 255):02x}:{random.randint(0, 255):02x}:{random.randint(0, 255):02x}:{random.randint(0, 255):02x}:{random.randint(0, 255):02x}:{random.randint(0, 255):02x}"
        ipv4 = self.protocol.kippoIP
        ipv4_prefix = ipv4.rsplit(".", 1)[0]
        ipv6 = f"fe{random.randint(0, 255):02x}::{random.randint(111, 999)}:abcd:{random.randint(0, 9999):04x}:1234/64"

        result = f"""1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host noprefixroute
       valid_lft forever preferred_lft forever
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP group default qlen 1000
    link/ether {hwaddr} brd ff:ff:ff:ff:ff:ff
    inet {ipv4}/24 brd {ipv4_prefix}.255 scope global dynamic eth0
       valid_lft 86399sec preferred_lft 86399sec
    inet6 {ipv6} scope link 
       valid_lft forever preferred_lft forever"""
        self.write(f"{result}\n")

# Register commands
commands["/sbin/ip"] = Command_ip
commands["/bin/ip"] = Command_ip
commands["ip"] = Command_ip
