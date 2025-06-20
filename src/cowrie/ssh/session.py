# Copyright (c) 2009-2014 Upi Tamminen <desaster@gmail.com>
# See the COPYRIGHT file for more information

"""
This module contains ...
"""

from __future__ import annotations

from typing import Literal

from twisted.conch.ssh import session
from twisted.conch.ssh.common import getNS
from twisted.python import log


class HoneyPotSSHSession(session.SSHSession):
    """
    This is an SSH channel that's used for SSH sessions
    """

    def __init__(self, *args, **kw):
        session.SSHSession.__init__(self, *args, **kw)
        log.msg("[DEBUG][ssh/session.py][__init__] Initialized SSH session channel", system="cowrie")


    def request_env(self, data: bytes) -> Literal[0, 1]:
        name, rest = getNS(data)
        value, rest = getNS(rest)

        if rest:
            log.msg(f"Extra data in request_env: {rest!r}")
            log.msg(f"[WARN][ssh/session.py][request_env] Extra data in ENV request: {rest!r}", system="cowrie")
            return 1

        log.msg(
            eventid="cowrie.client.var",
            format="request_env: %(name)s=%(value)s",
            name=name.decode("utf-8"),
            value=value.decode("utf-8"),
        )
        # FIXME: This only works for shell, not for exec command
        if self.session:
            self.session.environ[name.decode("utf-8")] = value.decode("utf-8")
            log.msg(f"[DEBUG][ssh/session.py][request_env] Environment variable set: {decoded_name}={decoded_value}", system="cowrie")

        return 0

    def request_agent(self, data: bytes) -> int:
        log.msg(f"request_agent: {data!r}")
        log.msg(f"[DEBUG][ssh/session.py][request_agent] SSH agent request received: {data!r}", system="cowrie")
        return 0

    def request_x11_req(self, data: bytes) -> int:
        log.msg(f"request_x11: {data!r}")
        log.msg(f"[DEBUG][ssh/session.py][request_x11_req] X11 request received: {data!r}", system="cowrie")

        return 0

    def closed(self) -> None:
        """
        This is reliably called on session close/disconnect and calls the avatar
        """
        log.msg("[DEBUG][ssh/session.py][closed] SSH session closed", system="cowrie")
        session.SSHSession.closed(self)
        self.client = None

    def eofReceived(self) -> None:
        """
        Redirect EOF to emulated shell. If shell is gone, then disconnect
        """
        log.msg("[DEBUG][ssh/session.py][eofReceived] EOF received from client", system="cowrie")
        if self.session:
            self.session.eofReceived()
        else:
            self.loseConnection()

    def sendEOF(self) -> None:
        """
        Utility function to request to send EOF for this session
        """
        log.msg("[DEBUG][ssh/session.py][sendEOF] Sending EOF to client", system="cowrie")
        self.conn.sendEOF(self)

    def sendClose(self) -> None:
        """
        Utility function to request to send close for this session
        """
        log.msg("[DEBUG][ssh/session.py][sendClose] Sending channel close to client", system="cowrie")
        self.conn.sendClose(self)

    def channelClosed(self) -> None:
        log.msg("[DEBUG][ssh/session.py][channelClosed] SSH session channel has been closed", system="cowrie")
        log.msg("Called channelClosed in SSHSession")
