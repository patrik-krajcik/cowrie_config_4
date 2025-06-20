# Copyright (c) 2009-2014 Upi Tamminen <desaster@gmail.com>
# See the COPYRIGHT file for more information

from __future__ import annotations

import hashlib
import os
import time
from typing import Any

from twisted.conch.insults import insults
from twisted.internet.protocol import connectionDone
from twisted.python import failure, log

from cowrie.core import ttylog
from cowrie.core.config import CowrieConfig
from cowrie.shell import protocol



class LoggingServerProtocol(insults.ServerProtocol):
    """
    Wrapper for ServerProtocol that implements TTY logging
    """

    ttylogPath: str = CowrieConfig.get("honeypot", "ttylog_path", fallback=".")
    downloadPath: str = CowrieConfig.get("honeypot", "download_path", fallback=".")
    ttylogEnabled: bool = CowrieConfig.getboolean("honeypot", "ttylog", fallback=True)
    bytesReceivedLimit: int = CowrieConfig.getint(
        "honeypot", "download_limit_size", fallback=0
    )

    def __init__(self, protocolFactory=None, *a, **kw):
        log.msg("[DEBUG][insults.py][__init__] Initializing LoggingServerProtocol", system="cowrie")
        self.type: str
        self.ttylogFile: str
        self.ttylogSize: int = 0
        self.bytesSent: int = 0
        self.bytesReceived: int = 0
        self.redirFiles: set[list[str]] = set()
        self.redirlogOpen: bool = False  # it will be set at core/protocol.py
        self.stdinlogOpen: bool = False
        self.ttylogOpen: bool = False
        self.terminalProtocol: Any
        self.transport: Any
        self.startTime: float
        self.stdinlogFile: str
        self.fs: list[Any]

        insults.ServerProtocol.__init__(self, protocolFactory, *a, **kw)

        if protocolFactory is protocol.HoneyPotExecProtocol:
            self.type = "e"  # Execcmd
            log.msg("[DEBUG][insults.py][__init__] Protocol type set to Exec ('e')", system="cowrie")

        else:
            self.type = "i"  # Interactive
            log.msg("[DEBUG][insults.py][__init__] Protocol type set to Interactive ('i')", system="cowrie")


    def getSessionId(self) -> tuple[str, str]:
        transportId = self.transport.session.conn.transport.transportId
        channelId = self.transport.session.id
        self.ip = self.transport.session.conn.transport.transport.getPeer().host
        #log.msg(f"[DEBUG][insults.py][getSessionId] Transport ID: {transportId}, Channel ID: {channelId}, Ip: {self.ip}", system="cowrie")
        return (transportId, channelId)

    def connectionMade(self) -> None:
        #log.msg("[DEBUG][insults.py][connectionMade] Connection established", system="cowrie")
        transportId, channelId = self.getSessionId()
        self.startTime = time.time()

        if self.ttylogEnabled:
            self.ttylogFile = "{}/{}-{}-{}{}.log".format(
                self.ttylogPath,
                time.strftime("%Y%m%d-%H%M%S"),
                transportId,
                channelId,
                self.type,
            )
            ttylog.ttylog_open(self.ttylogFile, self.startTime)
            self.ttylogOpen = True
            self.ttylogSize = 0
            #log.msg(f"[DEBUG][insults.py][connectionMade] TTY log started at {self.ttylogFile}", system="cowrie")


        self.stdinlogFile = "{}/{}-{}-{}-stdin.log".format(
            self.downloadPath,
            time.strftime("%Y%m%d-%H%M%S"),
            transportId,
            channelId,
        )
        #log.msg(f"[DEBUG][insults.py][connectionMade] STDIN log path: {self.stdinlogFile}", system="cowrie")


        if self.type == "e":
            self.stdinlogOpen = True
            # log the command into ttylog
            if self.ttylogEnabled:
                (sess, cmd) = self.protocolArgs
                #log.msg(f"[DEBUG][insults.py][connectionMade] Logging exec command to ttylog: {cmd!r}", system="cowrie")

                ttylog.ttylog_write(
                    self.ttylogFile, len(cmd), ttylog.TYPE_INTERACT, time.time(), cmd
                )
        else:
            self.stdinlogOpen = False

        insults.ServerProtocol.connectionMade(self)

        if self.type == "e":
            self.terminalProtocol.execcmd.encode("utf8")

    def write(self, data: bytes) -> None:
        #log.msg(f"[DEBUG][insults.py][write] Writing {len(data)} bytes to terminal", system="cowrie")
        self.bytesSent += len(data)
        if self.ttylogEnabled and self.ttylogOpen:
            ttylog.ttylog_write(
                self.ttylogFile, len(data), ttylog.TYPE_OUTPUT, time.time(), data
            )
            self.ttylogSize += len(data)
            #log.msg(f"[DEBUG][insults.py][write] Written to ttylog, total size now: {self.ttylogSize}", system="cowrie")


        insults.ServerProtocol.write(self, data)

    def dataReceived(self, data: bytes) -> None:
        """
        Input received from user
        """

        #log.msg(f"[DEBUG][insults.py][dataReceived] Received {len(data)} bytes of input", system="cowrie")

        self.bytesReceived += len(data)
        if self.bytesReceivedLimit and self.bytesReceived > self.bytesReceivedLimit:
            #log.msg("[WARN][insults.py][dataReceived] Data upload limit reached", system="cowrie")

            log.msg(format="Data upload limit reached")
            self.eofReceived()
            return

        if self.stdinlogOpen:
            #log.msg(f"[DEBUG][insults.py][dataReceived] Appending input to stdin log: {self.stdinlogFile}", system="cowrie")
            with open(self.stdinlogFile, "ab") as f:
                f.write(data)
        elif self.ttylogEnabled and self.ttylogOpen:
            #log.msg(f"[DEBUG][insults.py][dataReceived] Writing input to TTY log", system="cowrie")
            ttylog.ttylog_write(
                self.ttylogFile, len(data), ttylog.TYPE_INPUT, time.time(), data
            )

        insults.ServerProtocol.dataReceived(self, data)

    def eofReceived(self) -> None:
        """
        Receive channel close and pass on to terminal
        """

        #log.msg("[DEBUG][insults.py][eofReceived] EOF received from client", system="cowrie")
        if self.terminalProtocol:
            self.terminalProtocol.eofReceived()

    def loseConnection(self) -> None:
        """
        Override super to remove the terminal reset on logout
        """
        #log.msg("[DEBUG][insults.py][loseConnection] Closing connection", system="cowrie")
        self.transport.loseConnection()

    def connectionLost(self, reason: failure.Failure = connectionDone) -> None:
        """
        FIXME: this method is called 4 times on logout....
        it's called once from Avatar.closed() if disconnected
        """
        #log.msg("[DEBUG][insults.py][connectionLost] Connection lost triggered", system="cowrie")

        if self.stdinlogOpen:
            #log.msg("[DEBUG][insults.py][connectionLost] Processing stdin log", system="cowrie")
            try:
                with open(self.stdinlogFile, "rb") as f:
                    shasum = hashlib.sha256(f.read()).hexdigest()
                    shasumfile = os.path.join(self.downloadPath, shasum)
                    if os.path.exists(shasumfile):
                        os.remove(self.stdinlogFile)
                        duplicate = True
                    else:
                        os.rename(self.stdinlogFile, shasumfile)
                        duplicate = False
                

                log.msg(
                    eventid="cowrie.session.file_download",
                    format="Saved stdin contents with SHA-256 %(shasum)s to %(outfile)s",
                    duplicate=duplicate,
                    outfile=shasumfile,
                    shasum=shasum,
                    destfile="",
                )
            except OSError:
                pass
            finally:
                self.stdinlogOpen = False

        if self.redirFiles:
            #log.msg("[DEBUG][insults.py][connectionLost] Processing redirected file outputs", system="cowrie")
            for rp in self.redirFiles:
                rf = rp[0]
                #log.msg(f"[DEBUG][insults.py][connectionLost] rp0 : {rp[0]}", system="cowrie")
                #log.msg(f"[DEBUG][insults.py][connectionLost] rp1 : {rp[1]}", system="cowrie")

                if rp[1]:
                    url = rp[1]
                else:
                    url = rf[rf.find("redir_") + len("redir_") :]

                try:
                    if not os.path.exists(rf):
                        continue

                    if os.path.getsize(rf) == 0:
                        os.remove(rf)
                        continue

                    with open(rf, "rb") as f:
                        shasum = hashlib.sha256(f.read()).hexdigest()
                        shasumfile = os.path.join(self.get_custom_download_path(), shasum)
                        if os.path.exists(shasumfile):
                            os.remove(rf)
                            duplicate = True
                        else:
                            os.rename(rf, shasumfile)
                            duplicate = False

                    #log.msg("[DEBUG][insults.py][connectionLost] Processing redirected file outputs", system="cowrie")

                    #self.fs.update_realfile(self.fs.getfile(rp[1]), shasumfile)
                    
                    A_REALFILE = 9
                    f = self.fs.getfile(rp[1])

                    if f:
                        #log.msg(f"[DEBUG][insults][connectionLost] Linking if f is not None real file '{shasumfile}'", system="cowrie")
                        f[A_REALFILE] = shasumfile

                    log.msg(
                        eventid="cowrie.session.file_download",
                        format="Saved redir contents with SHA-256 %(shasum)s to %(outfile)s",
                        duplicate=duplicate,
                        outfile=shasumfile,
                        shasum=shasum,
                        destfile=url,
                    )
                except OSError:
                    pass
            self.redirFiles.clear()

        if self.ttylogEnabled and self.ttylogOpen:
            #log.msg("[DEBUG][insults.py][connectionLost] Closing TTY log", system="cowrie")
            ttylog.ttylog_close(self.ttylogFile, time.time())
            self.ttylogOpen = False
            shasum = ttylog.ttylog_inputhash(self.ttylogFile)
            shasumfile = os.path.join(self.ttylogPath, shasum)

            if os.path.exists(shasumfile):
                duplicate = True
                os.remove(self.ttylogFile)
            else:
                duplicate = False
                os.rename(self.ttylogFile, shasumfile)
                umask = os.umask(0)
                os.umask(umask)
                os.chmod(shasumfile, 0o666 & ~umask)

            log.msg(
                eventid="cowrie.log.closed",
                format="Closing TTY Log: %(ttylog)s after %(duration)s seconds",
                ttylog=shasumfile,
                size=self.ttylogSize,
                shasum=shasum,
                duplicate=duplicate,
                duration=f"{time.time() - self.startTime:.1f}",
            )

        insults.ServerProtocol.connectionLost(self, reason)

    def get_custom_download_path(self) -> str:
        """
        Determine the correct download path based on persistence mode.
        If persistence is enabled, use a structured directory under state_path.
        """
        # Default download path
        base_path = CowrieConfig.get("honeypot", "download_path", fallback=".")

        persistent_global = CowrieConfig.getboolean("shell", "persistent_global", fallback=False)
        persistent_per_ip = CowrieConfig.getboolean("shell", "persistent_per_ip", fallback=False)

        if not (persistent_global or persistent_per_ip):
            #log.msg(f"[DEBUG][fs.py][get_custom_download_path] Using default download_path: {base_path}", system="cowrie")
            return base_path

        # Use state_path if persistence is active
        state_path = CowrieConfig.get("honeypot", "state_path", fallback=".")
        base_dir = os.path.join(state_path, "filesystems")

        if persistent_global:
            download_dir = os.path.join(base_dir, "global", "downloads")
            #log.msg(f"[DEBUG][fs.py][get_custom_download_path] Global persistence: {download_dir}", system="cowrie")
        elif persistent_per_ip and self.ip:
            cleaned_ip = self.ip.replace(".", "_")
            download_dir = os.path.join(base_dir, cleaned_ip, "downloads")
            #log.msg(f"[DEBUG][fs.py][get_custom_download_path] Per-IP persistence for {self.ip}: {download_dir}", system="cowrie")
        else:
            #log.msg("[DEBUG][fs.py][get_custom_download_path] Persistence enabled but IP not provided. Using default path.", system="cowrie")
            return base_path

        # Ensure the directory exists
        os.makedirs(download_dir, exist_ok=True)
        return download_dir


class LoggingTelnetServerProtocol(LoggingServerProtocol):
    """
    Wrap LoggingServerProtocol with single method to fetch session id for Telnet
    """

    def getSessionId(self) -> tuple[str, str]:
        transportId = self.transport.session.transportId
        sn = self.transport.session.transport.transport.sessionno
        return (transportId, sn)
