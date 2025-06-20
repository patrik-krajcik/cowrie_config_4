# Copyright (c) 2009-2014 Michel Oosterhof <michel@oosterhof.net>
# See the COPYRIGHT file for more information

"""
This module contains code for handling SSH direct-tcpip connection requests
"""

from __future__ import annotations

from twisted.conch.ssh import forwarding
from twisted.python import log

from cowrie.core.config import CowrieConfig


def cowrieOpenConnectForwardingClient(remoteWindow, remoteMaxPacket, data, avatar):
    """
    This function will redirect an SSH forward request to another address
    or will log the request and do nothing
    """
    remoteHP, origHP = forwarding.unpackOpen_direct_tcpip(data)

    log.msg(
        eventid="cowrie.direct-tcpip.request",
        format="direct-tcp connection request to %(dst_ip)s:%(dst_port)s from %(src_ip)s:%(src_port)s",
        dst_ip=remoteHP[0],
        dst_port=remoteHP[1],
        src_ip=origHP[0],
        src_port=origHP[1],
    )

    log.msg(
        f"[DEBUG][forwarding.py] Received direct-tcpip request to {remoteHP[0]}:{remoteHP[1]} from {origHP[0]}:{origHP[1]}",
        system="cowrie"
    )

    # Forward redirect
    redirectEnabled: bool = CowrieConfig.getboolean(
        "ssh", "forward_redirect", fallback=False
    )
    if redirectEnabled:
        log.msg("[DEBUG][forwarding.py] forward_redirect is enabled, checking redirects", system="cowrie")
        redirects = {}
        items = CowrieConfig.items("ssh")
        for i in items:
            if i[0].startswith("forward_redirect_"):
                destPort = i[0].split("_")[-1]
                redirectHP = i[1].split(":")
                redirects[int(destPort)] = (redirectHP[0], int(redirectHP[1]))
        if remoteHP[1] in redirects:
            remoteHPNew = redirects[remoteHP[1]]
            log.msg(
                eventid="cowrie.direct-tcpip.redirect",
                format="redirected direct-tcp connection request from %(src_ip)s:%(src_port)"
                + "d to %(dst_ip)s:%(dst_port)d to %(new_ip)s:%(new_port)d",
                new_ip=remoteHPNew[0],
                new_port=remoteHPNew[1],
                dst_ip=remoteHP[0],
                dst_port=remoteHP[1],
                src_ip=origHP[0],
                src_port=origHP[1],
            )
            log.msg(f"[DEBUG][forwarding.py] Forward redirect: {remoteHP[1]} -> {remoteHPNew[0]}:{remoteHPNew[1]}", system="cowrie")
            return SSHConnectForwardingChannel(
                remoteHPNew, remoteWindow=remoteWindow, remoteMaxPacket=remoteMaxPacket
            )

    # TCP tunnel
    tunnelEnabled: bool = CowrieConfig.getboolean(
        "ssh", "forward_tunnel", fallback=False
    )
    if tunnelEnabled:
        log.msg("[DEBUG][forwarding.py] forward_tunnel is enabled, checking tunnels", system="cowrie")

        tunnels = {}
        items = CowrieConfig.items("ssh")
        for i in items:
            if i[0].startswith("forward_tunnel_"):
                destPort = i[0].split("_")[-1]
                tunnelHP = i[1].split(":")
                tunnels[int(destPort)] = (tunnelHP[0], int(tunnelHP[1]))
        if remoteHP[1] in tunnels:
            remoteHPNew = tunnels[remoteHP[1]]
            log.msg(
                eventid="cowrie.direct-tcpip.tunnel",
                format="tunneled direct-tcp connection request %(src_ip)s:%(src_port)"
                + "d->%(dst_ip)s:%(dst_port)d to %(new_ip)s:%(new_port)d",
                new_ip=remoteHPNew[0],
                new_port=remoteHPNew[1],
                dst_ip=remoteHP[0],
                dst_port=remoteHP[1],
                src_ip=origHP[0],
                src_port=origHP[1],
            )

            log.msg(f"[DEBUG][forwarding.py] Forward tunnel: {remoteHP[1]} -> {remoteHPNew[0]}:{remoteHPNew[1]}", system="cowrie")
            return TCPTunnelForwardingChannel(
                remoteHPNew,
                remoteHP,
                remoteWindow=remoteWindow,
                remoteMaxPacket=remoteMaxPacket,
            )

    log.msg(f"[DEBUG][forwarding.py] No matching redirect/tunnel found, using FakeForwardingChannel", system="cowrie")
    return FakeForwardingChannel(
        remoteHP, remoteWindow=remoteWindow, remoteMaxPacket=remoteMaxPacket
    )


class SSHConnectForwardingChannel(forwarding.SSHConnectForwardingChannel):
    """
    This class modifies the original to close the connection
    """

    name = b"cowrie-forwarded-direct-tcpip"

    def eofReceived(self) -> None:
        log.msg(f"[DEBUG][forwarding.py][SSHConnectForwardingChannel] EOF received, closing forwarded connection", system="cowrie")
        self.loseConnection()


class FakeForwardingChannel(forwarding.SSHConnectForwardingChannel):
    """
    This channel does not forward, but just logs requests.
    """

    name = b"cowrie-discarded-direct-tcpip"

    def channelOpen(self, specificData: bytes) -> None:
        log.msg(f"[DEBUG][forwarding.py][FakeForwardingChannel] Opened discarded channel", system="cowrie")
        

    def dataReceived(self, data: bytes) -> None:
        log.msg(
            eventid="cowrie.direct-tcpip.data",
            format="discarded direct-tcp forward request %(id)s to %(dst_ip)s:%(dst_port)s with data %(data)s",
            dst_ip=self.hostport[0],
            dst_port=self.hostport[1],
            data=repr(data),
            id=self.id,
        )
        log.msg(f"[DEBUG][forwarding.py][FakeForwardingChannel] Closing fake connection with connection refused", system="cowrie")
        self._close("Connection refused")


class TCPTunnelForwardingChannel(forwarding.SSHConnectForwardingChannel):
    """
    This class modifies the original to perform TCP tunneling via the CONNECT method
    """

    name = b"cowrie-tunneled-direct-tcpip"

    def __init__(self, hostport, dstport, *args, **kw):
        """
        Modifies the original to store where the data was originally going to go
        """
        log.msg(f"[DEBUG][forwarding.py][TCPTunnelForwardingChannel] Initializing tunnel to {hostport}, originally requested {dstport}", system="cowrie")
        forwarding.SSHConnectForwardingChannel.__init__(self, hostport, *args, **kw)
        self.dstport = dstport
        self.tunnel_established = False

    def channelOpen(self, specificData: bytes) -> None:
        """
        Modifies the original to send a TCP tunnel request via the CONNECT method
        """
        log.msg(f"[DEBUG][forwarding.py][TCPTunnelForwardingChannel] Opening tunnel channel to {self.dstport}", system="cowrie")
        forwarding.SSHConnectForwardingChannel.channelOpen(self, specificData)
        dst = self.dstport[0] + ":" + str(self.dstport[1])
        connect_hdr = b"CONNECT " + dst.encode("ascii") + b" HTTP/1.1\r\n\r\n"
        log.msg(f"[DEBUG][forwarding.py][TCPTunnelForwardingChannel] Sending CONNECT header: {connect_hdr!r}", system="cowrie")
        forwarding.SSHConnectForwardingChannel.dataReceived(self, connect_hdr)

    def dataReceived(self, data: bytes) -> None:
        log.msg(
            eventid="cowrie.tunnelproxy-tcpip.data",
            format="sending via tunnel proxy %(data)s",
            data=repr(data),
        )
        log.msg(f"[DEBUG][forwarding.py][TCPTunnelForwardingChannel] Tunnel data received: {len(data)} bytes", system="cowrie")
        forwarding.SSHConnectForwardingChannel.dataReceived(self, data)

    def write(self, data: bytes) -> None:
        """
        Modifies the original to strip off the TCP tunnel response
        """
        if not self.tunnel_established and data[:4].lower() == b"http":
            log.msg(f"[DEBUG][forwarding.py][TCPTunnelForwardingChannel] Checking CONNECT response", system="cowrie")

            # Check proxy response code
            try:
                res_code = int(data.split(b" ")[1], 10)
            except ValueError:
                log.err("Failed to parse TCP tunnel response code")
                self._close("Connection refused")
                return
            if res_code != 200:
                log.err(f"Unexpected response code: {res_code}")
                self._close("Connection refused")
            # Strip off rest of packet
            eop = data.find(b"\r\n\r\n")
            if eop > -1:
                data = data[eop + 4 :]
            # This only happens once when the channel is opened
            self.tunnel_established = True
            log.msg(f"[DEBUG][forwarding.py][TCPTunnelForwardingChannel] Tunnel established successfully", system="cowrie")

        forwarding.SSHConnectForwardingChannel.write(self, data)

    def eofReceived(self) -> None:
        log.msg(f"[DEBUG][forwarding.py][TCPTunnelForwardingChannel] EOF received, closing tunnel connection", system="cowrie")
        self.loseConnection()
