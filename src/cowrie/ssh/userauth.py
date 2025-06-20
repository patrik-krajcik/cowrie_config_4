# Copyright (c) 2009-2014 Upi Tamminen <desaster@gmail.com>
# See the COPYRIGHT file for more information


from __future__ import annotations

import struct
from typing import Any

from twisted.conch import error
from twisted.conch.interfaces import IConchUser
from twisted.conch.ssh import userauth
from twisted.conch.ssh.common import NS, getNS
from twisted.conch.ssh.transport import DISCONNECT_PROTOCOL_ERROR
from twisted.internet import defer
from twisted.python.failure import Failure
from twisted.python import log
from twisted.conch.ssh import keys
from twisted.conch import  interfaces
from twisted.conch import error, interfaces
from twisted.conch.ssh import keys
from twisted.conch.ssh.common import NS, getNS
from twisted.cred.error import UnauthorizedLogin
from twisted.internet import defer


from cowrie.core import credentials
from cowrie.core.config import CowrieConfig

MSG_USERAUTH_REQUEST = 50

class HoneyPotSSHUserAuthServer(userauth.SSHUserAuthServer):
    """
    This contains modifications to the authentication system to do:
    * Login banners (like /etc/issue.net)
    * Anonymous authentication
    * Keyboard-interactive authentication (PAM)
    * IP based authentication
    """

    bannerSent: bool = False
    user: bytes
    _pamDeferred: defer.Deferred | None

    def serviceStarted(self) -> None:
        log.msg("[DEBUG][userauth.py][HoneyPotSSHUserAuthServer.serviceStarted] Authentication service is starting", system="cowrie")

        self.interfaceToMethod[credentials.IUsername] = b"none"
        self.interfaceToMethod[credentials.IUsernamePasswordIP] = b"password"
        self.interfaceToMethod[credentials.ISSHPrivateKeyIP] = b"publickey"
        keyboard: bool = CowrieConfig.getboolean(
            "ssh", "auth_keyboard_interactive_enabled", fallback=False
        )

        if keyboard is True:
            self.interfaceToMethod[credentials.IPluggableAuthenticationModulesIP] = (
                b"keyboard-interactive"
            )
        self._pamDeferred: defer.Deferred | None = None

        log.msg("[DEBUG][userauth.py][HoneyPotSSHUserAuthServer.serviceStarted] Calling parent serviceStarted()", system="cowrie")
        userauth.SSHUserAuthServer.serviceStarted(self)

    def sendBanner(self):
        """
        This is the pre-login banner. The post-login banner is the MOTD file
        Display contents of <honeyfs>/etc/issue.net
        """
        if self.bannerSent:
            return
        self.bannerSent = True
        try:
            issuefile = CowrieConfig.get("honeypot", "contents_path") + "/etc/issue.net"
            with open(issuefile, "rb") as issue:
                data = issue.read()
        except OSError:
            return
        if not data or not data.strip():
            return

        log.msg("[DEBUG][userauth.py][HoneyPotSSHUserAuthServer.sendBanner] Sending SSH login banner to client", system="cowrie")
        self.transport.sendPacket(userauth.MSG_USERAUTH_BANNER, NS(data) + NS(b"en"))

    def ssh_USERAUTH_REQUEST(self, packet: bytes) -> Any:
        """
        This is overriden to send the login banner.
        """
        log.msg("[DEBUG][userauth.py][HoneyPotSSHUserAuthServer.ssh_USERAUTH_REQUEST] Received user authentication request", system="cowrie")
        self.sendBanner()
        log.msg("[DEBUG][userauth.py][HoneyPotSSHUserAuthServer.ssh_USERAUTH_REQUEST] Passing authentication request to parent", system="cowrie")

        return userauth.SSHUserAuthServer.ssh_USERAUTH_REQUEST(self, packet)

    # def auth_publickey(self, packet):
    #     """
    #     We subclass to intercept non-dsa/rsa keys,
    #     or Conch will crash on ecdsa..
    #     UPDATE: conch no longer crashes. comment this out
    #     """
    #     algName, blob, rest = getNS(packet[1:], 2)
    #     if algName not in (b'ssh-rsa', b'ssh-dsa'):
    #         log.msg("Attempted public key authentication\
    #                           with {} algorithm".format(algName))
    #         return defer.fail(error.ConchError("Incorrect signature"))
    #     return userauth.SSHUserAuthServer.auth_publickey(self, packet)

    def auth_none(self, _packet: bytes) -> Any:
        """
        Allow every login
        """
        c = credentials.Username(self.user)
        srcIp: str = self.transport.transport.getPeer().host  # type: ignore
        return self.portal.login(c, srcIp, IConchUser)
    
    def auth_publickey(self, packet):
        """
        Public key authentication.  Payload::
            byte has signature
            string algorithm name
            string key blob
            [string signature] (if has signature is True)

        Create a SSHPublicKey credential and verify it using our portal.
        """

        log.msg("[DEBUG][userauth.py][HoneyPotSSHUserAuthServer.auth_publickey] Starting public key authentication", system="cowrie")

        hasSig = ord(packet[0:1])
        algName, blob, rest = getNS(packet[1:], 2)

        try:
            keys.Key.fromString(blob)
        except keys.BadKeyError:
            error = "Unsupported key type {} or bad key".format(algName.decode("ascii"))
            self._log.error(error)
            return defer.fail(UnauthorizedLogin(error))

        signature = hasSig and getNS(rest)[0] or None

        srcIp = self.transport.transport.getPeer().host  # type: ignore

        log.msg(f"[DEBUG][userauth.py][HoneyPotSSHUserAuthServer.auth_publickey] Parsed key and source IP:{srcIp} blob={blob}", system="cowrie")

        if hasSig:
            b = (
                NS(self.transport.sessionID)
                + bytes((MSG_USERAUTH_REQUEST,))
                + NS(self.user)
                + NS(self.nextService)
                + NS(b"publickey")
                + bytes((hasSig,))
                + NS(algName)
                + NS(blob)
            )
            c = credentials.SSHPrivateKeyIP(self.user, algName, blob, b, signature, srcIp)

            log.msg("[DEBUG][userauth.py][HoneyPotSSHUserAuthServer.auth_publickey] Calling portal.login() with credentials", system="cowrie")

            return self.portal.login(c, None, interfaces.IConchUser)
        else:
            log.msg("[DEBUG][userauth.py][HoneyPotSSHUserAuthServer.auth_publickey] Calling portal.login() with credentials", system="cowrie")

            c = credentials.SSHPrivateKeyIP(self.user, algName, blob, None, None, srcIp)
            return self.portal.login(c, None, interfaces.IConchUser).addErrback(
                self._ebCheckKey, packet[1:]
            )


    def auth_password(self, packet: bytes) -> Any:
        """
        Overridden to pass src_ip to credentials.UsernamePasswordIP
        """
        log.msg("[DEBUG][userauth.py][HoneyPotSSHUserAuthServer.auth_password] Starting password authentication", system="cowrie")

        password = getNS(packet[1:])[0]
        srcIp = self.transport.transport.getPeer().host  # type: ignore
        log.msg(f"[DEBUG][userauth.py][HoneyPotSSHUserAuthServer.auth_password] Parsed password and source IP: src_ip={srcIp}", system="cowrie")

        c = credentials.UsernamePasswordIP(self.user, password, srcIp)
        log.msg("[DEBUG][userauth.py][HoneyPotSSHUserAuthServer.auth_password] Calling portal.login() with credentials", system="cowrie")
        
        return self.portal.login(c, srcIp, IConchUser).addErrback(self._ebPassword)

    def auth_keyboard_interactive(self, _packet: bytes) -> Any:
        """
        Keyboard interactive authentication.  No payload.  We create a
        PluggableAuthenticationModules credential and authenticate with our
        portal.

        Overridden to pass src_ip to
          credentials.PluggableAuthenticationModulesIP
        """
        if self._pamDeferred is not None:
            self.transport.sendDisconnect(  # type: ignore
                DISCONNECT_PROTOCOL_ERROR,
                "only one keyboard interactive attempt at a time",
            )
            return defer.fail(error.IgnoreAuthentication())
        src_ip = self.transport.transport.getPeer().host  # type: ignore
        c = credentials.PluggableAuthenticationModulesIP(
            self.user, self._pamConv, src_ip
        )
        return self.portal.login(c, src_ip, IConchUser).addErrback(self._ebPassword)

    def _pamConv(self, items: list[tuple[Any, int]]) -> defer.Deferred:
        """
        Convert a list of PAM authentication questions into a
        MSG_USERAUTH_INFO_REQUEST.  Returns a Deferred that will be called
        back when the user has responses to the questions.

        @param items: a list of 2-tuples (message, kind).  We only care about
            kinds 1 (password) and 2 (text).
        @type items: C{list}
        @rtype: L{defer.Deferred}
        """
        resp = []
        for message, kind in items:
            if kind == 1:  # Password
                resp.append((message, 0))
            elif kind == 2:  # Text
                resp.append((message, 1))
            elif kind in (3, 4):
                return defer.fail(error.ConchError("cannot handle PAM 3 or 4 messages"))
            else:
                return defer.fail(error.ConchError(f"bad PAM auth kind {kind}"))
        packet = NS(b"") + NS(b"") + NS(b"")
        packet += struct.pack(">L", len(resp))
        for prompt, echo in resp:
            packet += NS(prompt)
            packet += bytes((echo,))
        self.transport.sendPacket(userauth.MSG_USERAUTH_INFO_REQUEST, packet)  # type: ignore
        self._pamDeferred = defer.Deferred()
        return self._pamDeferred

    def ssh_USERAUTH_INFO_RESPONSE(self, packet: bytes) -> None:
        """
        The user has responded with answers to PAMs authentication questions.
        Parse the packet into a PAM response and callback self._pamDeferred.
        Payload::
            uint32 numer of responses
            string response 1
            ...
            string response n
        """
        assert self._pamDeferred is not None
        d: defer.Deferred = self._pamDeferred
        self._pamDeferred = None
        resp: list

        try:
            resp = []
            numResps = struct.unpack(">L", packet[:4])[0]
            packet = packet[4:]
            while len(resp) < numResps:
                response, packet = getNS(packet)
                resp.append((response, 0))
            if packet:
                log.msg(f"PAM Response: {len(packet):d} extra bytes: {packet!r}")
        except Exception as e:
            d.errback(Failure(e))
        else:
            d.callback(resp)
