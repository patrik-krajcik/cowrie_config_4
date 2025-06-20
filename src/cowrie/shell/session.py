# Copyright (c) 2009-2014 Upi Tamminen <desaster@gmail.com>
# See the COPYRIGHT file for more information

from __future__ import annotations

from zope.interface import implementer

from twisted.conch.interfaces import ISession
from twisted.conch.ssh import session
from twisted.python import log

from cowrie.insults import insults
from cowrie.shell import protocol


@implementer(ISession)
class SSHSessionForCowrieUser:
    def __init__(self, avatar, reactor=None):
        """
        Construct an C{SSHSessionForCowrieUser}.

        @param avatar: The L{CowrieUser} for whom this is an SSH session.
        @param reactor: An L{IReactorProcess} used to handle shell and exec
            requests. Uses the default reactor if None.
        """

        #log.msg(f"[DEBUG][shell/session.py][__init__] Initializing shell session for user: {avatar.username}", system="cowrie")

        self.protocol = None
        self.avatar = avatar
        self.server = avatar.server
        self.uid = avatar.uid
        self.gid = avatar.gid
        self.username = avatar.username
        self.transport: Any
        self.environ = {
            "HOME": self.avatar.home,
            "LOGNAME": self.username,
            "SHELL": "/bin/bash",
            "SHLVL": "1",
            "TMOUT": "1800",
            "UID": str(self.uid),
            "USER": self.username,
        }
        if self.uid == 0:
            self.environ["PATH"] = (
                "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
            )
        else:
            self.environ["PATH"] = (
                "/usr/local/bin:/usr/bin:/bin:/usr/local/games:/usr/games"
            )

    def initFS(self, processprotocol, context: str = "unknown") -> None:
        """
        Initialize the attacker's fake file system and log connection info.
        """
        try:
            transport = processprotocol.session.conn.transport
            transportId = transport.transportId
            peer = transport.getPeer()
            peerStr = str(peer)
            ip = peerStr.split("host='")[1].split("'")[0]

            #log.msg(f"[DEBUG][shell/session.py][{context}] Transport ID: {transportId}", system="cowrie")
            #log.msg(f"[DEBUG][shell/session.py][{context}] Peer: {peer}", system="cowrie")
            #log.msg(f"[DEBUG][shell/session.py][{context}] IP: {ip}", system="cowrie")
        except Exception as e:
            log.msg(f"[ERROR][shell/session.py][{context}] Failed to retrieve session info: {e}", system="cowrie")

        #log.msg(f"[DEBUG][shell/session.py][{context}] Initializing fake file system for home: {self.avatar.home}", system="cowrie")
        
        self.server.initFileSystem(self.avatar.home, transportId, ip)

        if self.avatar.first_time  : # TODO add here writing to etc, pasawd, shadow
            #log.msg(f"[DEBUG][shell/session.py][{context}] Creating temporary home directory: {self.avatar.home}", system="cowrie")
            self.server.fs.mkdir(self.avatar.home, self.uid, self.gid, 4096, 16877)
            ssh_dir = self.avatar.home + "/.ssh"
            self.server.fs.mkdir(ssh_dir, self.uid, self.gid, 4096, 16877)
    

    def openShell(self, processprotocol):
        #log.msg(f"[DEBUG][shell/session.py][openShell] Opening interactive shell for user: {self.username}", system="cowrie")
        #log.msg("[DEBUG][shell/session.py][openShell] Creating LoggingServerProtocol with HoneyPotInteractiveProtocol", system="cowrie")

        self.protocol = insults.LoggingServerProtocol(
            protocol.HoneyPotInteractiveProtocol, self
        )

        self.initFS(processprotocol, "openShell")

        self.protocol.fs = self.server.fs

        #log.msg("[DEBUG][shell/session.py][openShell] Making connection from protocol to processprotocol", system="cowrie")
        self.protocol.makeConnection(processprotocol)

        #log.msg("[DEBUG][shell/session.py][openShell] Wrapping protocol and making connection from processprotocol to wrapped protocol", system="cowrie")
        processprotocol.makeConnection(session.wrapProtocol(self.protocol))

        if self.avatar.first_time :
                self.avatar._map_special_files()

    def getPty(self, terminal, windowSize, attrs):
        self.environ["TERM"] = terminal.decode("utf-8")
        log.msg(
            eventid="cowrie.client.size",
            width=windowSize[1],
            height=windowSize[0],
            format="Terminal Size: %(width)s %(height)s",
        )
        #log.msg(f"[DEBUG][shell/session.py][getPty] Terminal type: {terminal}, Size: {windowSize}", system="cowrie")
        self.windowSize = windowSize

    def execCommand(self, processprotocol, cmd):
        #log.msg(f"[DEBUG][shell/session.py][execCommand] Executing remote command: {cmd!r}", system="cowrie")

        self.initFS(processprotocol, "execCommand")

        self.protocol = insults.LoggingServerProtocol(
            protocol.HoneyPotExecProtocol, self, cmd
        )
        
        self.protocol.fs = self.server.fs

        self.protocol.makeConnection(processprotocol)
        processprotocol.makeConnection(session.wrapProtocol(self.protocol))

    def closed(self) -> None:
        """
        this is reliably called on both logout and disconnect
        we notify the protocol here we lost the connection
        """

        #log.msg(f"[DEBUG][shell/session.py][closed] Shell session closed for user: {self.username}", system="cowrie")
        # self.server.fs.save_fs_delta()
        # self.avatar.cleanup()

        if self.protocol:
            self.protocol.connectionLost("disconnected")
            self.protocol = None

    def eofReceived(self) -> None:
        #log.msg(f"[DEBUG][shell/session.py][eofReceived] EOF received", system="cowrie")
        if self.protocol:
            self.protocol.eofReceived()

    def windowChanged(self, windowSize):
        #log.msg(f"[DEBUG][shell/session.py][windowChanged] New terminal size: {windowSize}", system="cowrie")
        self.windowSize = windowSize