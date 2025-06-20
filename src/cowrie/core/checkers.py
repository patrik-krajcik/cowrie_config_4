# Copyright (c) 2009-2014 Upi Tamminen <desaster@gmail.com>
# See the COPYRIGHT file for more information

"""
This module contains ...
"""

from __future__ import annotations

from sys import modules

from zope.interface import implementer

import os

from twisted.conch import error
from twisted.conch.ssh import keys
from twisted.cred.checkers import ICredentialsChecker
from twisted.cred.error import UnauthorizedLogin, UnhandledCredentials
from twisted.internet import defer
from twisted.python import failure, log

from cowrie.core import credentials as conchcredentials
from cowrie.core.config import CowrieConfig
import cowrie.core.auth  # noqa: F401


@implementer(ICredentialsChecker)
class HoneypotPublicKeyChecker:
    """
    Checker that accepts, logs and denies public key authentication attempts
    """

    credentialInterfaces = (conchcredentials.ISSHPrivateKeyIP,)

    def requestAvatarId(self, credentials):
        _pubKey = keys.Key.fromString(credentials.blob)

        log.msg(
            eventid="cowrie.client.fingerprint",
            format="public key attempt for user %(username)s of type %(type)s with fingerprint %(fingerprint)s",
            username=credentials.username,
            fingerprint=_pubKey.fingerprint(),
            key=_pubKey.toString("OPENSSH"),
            type=_pubKey.sshType(),
        )

        log.msg(f"[DEBUG][checkers.py][requestAvatarId] KEY: {_pubKey.toString('OPENSSH')}", system="cowrie")

        # Determine mode
        persistent_global = CowrieConfig.getboolean("shell", "persistent_global", fallback=False)
        persistent_perip = CowrieConfig.getboolean("shell", "persistent_per_ip", fallback=False)

        log.msg(f"[DEBUG][checkers.py][requestAvatarId] Determined modes - Global: {persistent_global}, PerIP: {persistent_perip}", system="cowrie")

        if not (persistent_global or persistent_perip):
            log.msg("[DEBUG][checkers.py][requestAvatarId] No persistent mode enabled, denying access", system="cowrie")
            log.msg( 
                eventid="cowrie.login.failed",
                format="public key login attempt for [%(username)s] failed",
                username=credentials.username,
                fingerprint=_pubKey.fingerprint(),
                key=_pubKey.toString("OPENSSH"),
                type=_pubKey.sshType(),
            )
            return failure.Failure(error.ConchError("Incorrect signature"))

        state_path = CowrieConfig.get("honeypot", "state_path", fallback=".")
        if persistent_global:
            auth_dir = os.path.join(state_path, "filesystems", "global")
        else:
            cleaned_ip = credentials.ip.replace('.', '_')
            auth_dir = os.path.join(state_path, "filesystems", cleaned_ip)

        auth_file = os.path.join(auth_dir, f"{credentials.username.decode(errors='ignore')}_authorized_keys")
        key = f"{_pubKey.toString('OPENSSH').decode(errors='ignore')}"

        log.msg(f"[DEBUG][checkers.py][requestAvatarId] Checking authorized keys file: {auth_file}", system="cowrie")
        log.msg(f"[DEBUG][checkers.py][requestAvatarId] Loaded CLIENT key: {key}",system="cowrie")


        try:
            with open(auth_file) as f:
                authorized_keys = []
                for line in f:
                    clean_line = line.strip()
                    if clean_line:
                        parts = clean_line.split()
                        if len(parts) >= 2:
                            authorized_key = f"{parts[0]} {parts[1]}"
                            authorized_keys.append(authorized_key)
                            log.msg(
                                f"[DEBUG][checkers.py][requestAvatarId] Loaded authorized key (without comment): {authorized_key}",
                                system="cowrie"
                            )

                #authorized_keys = [line.strip() for line in f if line.strip()]
                log.msg(f"[DEBUG][checkers.py][requestAvatarId] Loaded {len(authorized_keys)} authorized keys for user: {credentials.username}", system="cowrie")

                if key in authorized_keys:
                    log.msg(f"[DEBUG][checkers.py][requestAvatarId] Key matched for user: {credentials.username}", system="cowrie")
                    log.msg(
                        eventid="cowrie.login.success",
                        format="public key login attempt for [%(username)s] succeeded",
                        username=credentials.username,
                        fingerprint=_pubKey.fingerprint(),
                        key=_pubKey.toString("OPENSSH"),
                        type=_pubKey.sshType(),
                    )
                    return defer.succeed((credentials.username,credentials.ip))
                else:
                    log.msg(f"[DEBUG][checkers.py][requestAvatarId] Key did not match for user: {credentials.username}", system="cowrie")

        except FileNotFoundError:
            log.msg(f"[DEBUG][checkers.py][requestAvatarId] Authorized key file not found: {auth_file}", system="cowrie")

        log.msg(
            eventid="cowrie.login.failed",
            format="public key login attempt for [%(username)s] failed",
            username=credentials.username,
            fingerprint=_pubKey.fingerprint(),
            key=_pubKey.toString("OPENSSH"),
            type=_pubKey.sshType(),
        )
        return failure.Failure(error.ConchError("Incorrect signature"))


# TODO ERROR PRI vracani len credentials.username kedze v avatar ocakavame ip
@implementer(ICredentialsChecker)
class HoneypotNoneChecker:
    """
    Checker that does no authentication check
    """

    credentialInterfaces = (conchcredentials.IUsername,)

    def requestAvatarId(self, credentials):
        log.msg(
            eventid="cowrie.login.success",
            format="login attempt [%(username)s] succeeded",
            username=credentials.username,
        )
        return defer.succeed(credentials.username)


@implementer(ICredentialsChecker)
class HoneypotPasswordChecker:
    """
    Checker that accepts "keyboard-interactive" and "password"
    """

    credentialInterfaces = (
        conchcredentials.IUsernamePasswordIP,
        conchcredentials.IPluggableAuthenticationModulesIP,
    )

    def requestAvatarId(self, credentials):
        if hasattr(credentials, "password"):
            if self.checkUserPass(
                credentials.username, credentials.password, credentials.ip
            ):
                log.msg(f"[DEBUG][ceckers.py]TOUPLE: {(credentials.username, credentials.ip)}", system="cowrie")

                return defer.succeed((credentials.username, credentials.ip))
            return defer.fail(UnauthorizedLogin())
        if hasattr(credentials, "pamConversion"):
            return self.checkPamUser(
                credentials.username, credentials.pamConversion, credentials.ip
            )
        return defer.fail(UnhandledCredentials())

    def checkPamUser(self, username, pamConversion, ip):
        r = pamConversion((("Password:", 1),))
        return r.addCallback(self.cbCheckPamUser, username, ip)

    def cbCheckPamUser(self, responses, username, ip):
        for response, _ in responses:
            if self.checkUserPass(username, response, ip):
                return defer.succeed(username)
        return defer.fail(UnauthorizedLogin())

    def checkUserPass(self, theusername: bytes, thepassword: bytes, ip: str) -> bool:
        # Is the auth_class defined in the config file?
        authclass = CowrieConfig.get("honeypot", "auth_class", fallback="UserDB")
        authmodule = "cowrie.core.auth"

        # Check if authclass exists in this module
        if hasattr(modules[authmodule], authclass):
            authname = getattr(modules[authmodule], authclass)
        else:
            log.msg(f"auth_class: {authclass} not found in {authmodule}")

        theauth = authname()

        if theauth.checklogin(theusername, thepassword, ip):
            log.msg(
                eventid="cowrie.login.success",
                format="login attempt [%(username)s/%(password)s] succeeded",
                username=theusername,
                password=thepassword,
            )
            return True

        log.msg(
            eventid="cowrie.login.failed",
            format="login attempt [%(username)s/%(password)s] failed",
            username=theusername,
            password=thepassword,
        )
        return False
