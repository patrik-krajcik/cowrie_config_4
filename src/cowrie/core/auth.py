# Copyright (c) 2009-2014 Upi Tamminen <desaster@gmail.com>
# See the COPYRIGHT file for more information

"""
This module contains authentication code
"""

from __future__ import annotations

import configparser
import json
import re
from collections import OrderedDict
from os import path
from random import randint
from typing import Any
from re import Pattern
from pathlib import Path
import random

from twisted.python import log

from cowrie.core.config import CowrieConfig # Configuracia

_USERDB_DEFAULTS: list[str] = [
    "root:x:!root",
    "root:x:!123456",
    "root:x:!/honeypot/i",
    "root:x:*",
    "phil:x:*",
    "phil:x:fout",
]


class UserDB:
    """
    By Walter de Jong <walter@sara.nl>
    """

    def __init__(self) -> None:
        self.userdb: dict[
            tuple[Pattern[bytes] | bytes, Pattern[bytes] | bytes], bool
        ] = OrderedDict()
        self.load()

    def load(self) -> None:
        """
        load the user db
        """

        dblines: list[str]
        try:
            with open(
                "{}/userdb.txt".format(CowrieConfig.get("honeypot", "etc_path")), # Directory for config files
                encoding="ascii",
            ) as db:
                dblines = db.readlines()
        except OSError:
            log.msg("Could not read etc/userdb.txt, default database activated")
            dblines = _USERDB_DEFAULTS

        for user in dblines:
            if not user.startswith("#"):
                try:
                    login = user.split(":")[0].encode("utf8")
                    password = user.split(":")[2].strip().encode("utf8")
                except IndexError:
                    continue
                else:
                    self.adduser(login, password)

    def checklogin(
        self, thelogin: bytes, thepasswd: bytes, src_ip: str = "0.0.0.0"
    ) -> bool:
        for credentials, policy in self.userdb.items():
            login: bytes | Pattern[bytes]
            passwd: bytes | Pattern[bytes]
            login, passwd = credentials

            if self.match_rule(login, thelogin):
                if self.match_rule(passwd, thepasswd):
                    return policy

        return False

    def match_rule(self, rule: bytes | Pattern[bytes], data: bytes) -> bool | bytes:
        if isinstance(rule, bytes):
            return rule in [b"*", data]
        return bool(rule.search(data))

    def re_or_bytes(self, rule: bytes) -> Pattern[bytes] | bytes:
        """
        Convert a /.../ type rule to a regex, otherwise return the string as-is

        @param login: rule
        @type login: bytes
        """
        res = re.match(rb"/(.+)/(i)?$", rule)
        if res:
            return re.compile(res.group(1), re.IGNORECASE if res.group(2) else 0)

        return rule

    def adduser(self, login: bytes, passwd: bytes) -> None:
        """
        All arguments are bytes

        @param login: user id
        @type login: bytes
        @param passwd: password
        @type passwd: bytes
        """
        user = self.re_or_bytes(login)

        if passwd[0] == ord("!"):
            policy = False
            passwd = passwd[1:]
        else:
            policy = True

        p = self.re_or_bytes(passwd)
        self.userdb[(user, p)] = policy




class AuthPerIP:
    """
    Authentication that tracks username/password combos per source IP.
    Each IP can have multiple unlocked combinations.
    Attacker must try DIFFERENT passwords for the same username to progress.
    """

    def __init__(self) -> None:
        try:
            params = CowrieConfig.get("honeypot", "auth_class_parameters").split(",")
            self.mintry = int(params[0])
            self.maxtry = int(params[1])
        except (configparser.Error, ValueError):
            self.mintry = 2
            self.maxtry = 3

        if self.maxtry < self.mintry:
            self.maxtry = self.mintry + 1
            log.msg(f"Adjusted maxtry to: {self.maxtry}")

        self.state_file = f"{CowrieConfig.get('honeypot', 'state_path')}/auth_perip.json"
        self.uservar: dict[str, dict] = {}  # { "src_ip": { "combos": {username: password}, "attempts": {username: {"tried": set(), "try": x, "max": y}} } }
        self.load_state()

    def load_state(self) -> None:
        """Load saved IP credential mappings"""
        if Path(self.state_file).is_file():
            try:
                with open(self.state_file, "r", encoding="utf-8") as f:
                    self.uservar = json.load(f)
            except Exception as e:
                log.msg(f"Failed to load state: {e}")

    def save_state(self) -> None:
        """Persist current mappings"""
        try:
            with open(self.state_file, "w", encoding="utf-8") as f:
                json.dump(self.uservar, f)
        except Exception as e:
            log.msg(f"Failed to save state: {e}")

    def checklogin(self, username: bytes, password: bytes, src_ip: str) -> bool:
        """Main login logic per IP"""
        user = username.decode("utf-8", errors="replace")
        pw = password.decode("utf-8", errors="replace")

        if src_ip not in self.uservar:
            self.uservar[src_ip] = {
                "combos": {},  # {username: password}
                "attempts": {}  # {username: {"tried": [passwords], "try": x, "max": y}}
            }

        ipdata = self.uservar[src_ip]

        # Already unlocked for this IP?
        if user in ipdata["combos"]:
            locked_pw = ipdata["combos"][user]
            if pw == locked_pw:
                log.msg(f"Successful login for '{user}' from {src_ip} (already unlocked)")
                return True
            else:
                log.msg(f"Failed login for '{user}' from {src_ip} (wrong password after unlock)")
                return False  # <<<< FORCE FAIL if wrong password after unlock

        # Initialize attempt tracking for new username
        if user not in ipdata["attempts"]:
            ipdata["attempts"][user] = {
                "tried": [],
                "try": 0,
                "max": random.randint(self.mintry, self.maxtry)
            }
            log.msg(f"New username '{user}' for {src_ip} - need {ipdata['attempts'][user]['max']} different passwords")

        user_attempt = ipdata["attempts"][user]

        # Check if password was already tried
        if pw in user_attempt["tried"]:
            log.msg(f"Password '{pw}' already tried for user '{user}' from {src_ip} - not counting again")
            self.save_state()
            return False

        # First time trying this password -> count attempt
        user_attempt["tried"].append(pw)
        user_attempt["try"] += 1

        attempts = user_attempt["try"]
        needed = user_attempt["max"]

        log.msg(f"Attempt {attempts}/{needed} for user '{user}' from {src_ip}")

        if attempts >= needed:
            # Success: unlock username/password combo for this IP
            ipdata["combos"][user] = pw
            log.msg(f"Unlocked '{user}' with password '{pw}' for {src_ip}")
            # Delete the attempt tracking after unlock
            if user in ipdata["attempts"]:
                del ipdata["attempts"][user]
            self.save_state()
            return True

        self.save_state()
        return False





class AuthGlobal:
    """
    Authentication that locks the first successful password per username.
    New usernames require random attempts (between mintry/maxtry) before access.
    IP addresses are NOT tracked.
    Must try different passwords to progress.
    """

    def __init__(self) -> None:
        try:
            params = CowrieConfig.get("honeypot", "auth_class_parameters_user").split(",")
            self.mintry = int(params[0])
            self.maxtry = int(params[1])
        except (configparser.Error, ValueError):
            self.mintry = 2
            self.maxtry = 3

        if self.maxtry < self.mintry:
            self.maxtry = self.mintry + 1
            log.msg(f"Adjusted maxtry to: {self.maxtry}")

        self.uservar: dict = {
            "user_locks": {},   # {"username": "password"}
            "attempts": {}      # {"username": {"tried": [passwords], "try": X, "max": Y}}
        }
        self.state_file = f"{CowrieConfig.get('honeypot', 'state_path')}/auth_global.json"
        self.load_state()

    def load_state(self) -> None:
        """Load saved state from JSON"""
        if Path(self.state_file).is_file():
            try:
                with open(self.state_file, 'r', encoding='utf-8') as f:
                    self.uservar = json.load(f)
            except Exception as e:
                log.msg(f"State load error: {e}")

    def save_state(self) -> None:
        """Persist current state"""
        try:
            with open(self.state_file, 'w', encoding='utf-8') as f:
                json.dump(self.uservar, f)
        except Exception as e:
            log.msg(f"State save error: {e}")

    def checklogin(self, username: bytes, password: bytes, src_ip: str) -> bool:
        """
        Authentication flow:
        1. Known username ? Only allow its locked password
        2. New username ? Must try different passwords until unlocked
        """
        user = username.decode('utf-8', errors='replace')
        pw = password.decode('utf-8', errors='replace')
        # Known user: Check against locked password
        if user in self.uservar["user_locks"]:
            if pw == self.uservar["user_locks"][user]:
                log.msg(f"Successful login for locked user '{user}'")
                return True
            log.msg(f"Failed login - wrong password for '{user}'")
            return False

        # Initialize tracking for new user
        if user not in self.uservar["attempts"]:
            self.uservar["attempts"][user] = {
                "tried": [],
                "try": 0,
                "max": random.randint(self.mintry, self.maxtry)
            }
            log.msg(f"New user '{user}' - need {self.uservar['attempts'][user]['max']} different passwords")

        user_attempt = self.uservar["attempts"][user]

        # If password already tried, don't count again
        if pw in user_attempt["tried"]:
            log.msg(f"Password '{pw}' already tried for user '{user}' - not counting again")
            self.save_state()
            return False

        # New password for this user ? count it
        user_attempt["tried"].append(pw)
        user_attempt["try"] += 1

        attempts = user_attempt["try"]
        needed = user_attempt["max"]

        log.msg(f"Attempt {attempts}/{needed} for user '{user}'")

        if attempts >= needed:
            # Lock this password for the user
            self.uservar["user_locks"][user] = pw
            log.msg(f"Locked password '{pw}' for user '{user}'")
            self.save_state()
            return True

        self.save_state()
        return False