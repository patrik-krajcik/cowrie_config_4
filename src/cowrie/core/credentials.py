# Copyright (c) 2015 Michel Oosterhof <michel@oosterhof.net>
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
#
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in the
#    documentation and/or other materials provided with the distribution.
# 3. The names of the author(s) may not be used to endorse or promote
#    products derived from this software without specific prior written
#    permission.
#
# THIS SOFTWARE IS PROVIDED BY THE AUTHORS ``AS IS'' AND ANY EXPRESS OR
# IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
# OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
# IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY DIRECT, INDIRECT,
# INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
# BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
# AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
# OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
# OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
# SUCH DAMAGE.

from __future__ import annotations


from zope.interface import implementer

from twisted.cred.credentials import ICredentials, IUsernamePassword, ISSHPrivateKey
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Callable


class IUsername(ICredentials):
    """
    Encapsulate username only

    @type username: C{bytes}
    @ivar username: The username associated with these credentials.
    """


class IUsernamePasswordIP(IUsernamePassword):
    """
    I encapsulate a username, a plaintext password and a source IP

    @type username: C{bytes}
    @ivar username: The username associated with these credentials.

    @type password: C{bytes}
    @ivar password: The password associated with these credentials.

    @type ip: C{str}
    @ivar ip: The source ip address associated with these credentials.
    """


class IPluggableAuthenticationModulesIP(ICredentials):
    """
    Twisted removed IPAM in 15, adding in Cowrie now
    """

class ISSHPrivateKeyIP(ISSHPrivateKey):
     """
    L{ISSHPrivateKey} credentials encapsulate an SSH public key to be checked
    against a user's private key.

    @ivar username: The username associated with these credentials.
    @type username: L{bytes}

    @ivar algName: The algorithm name for the blob.
    @type algName: L{bytes}

    @ivar blob: The public key blob as sent by the client.
    @type blob: L{bytes}

    @ivar sigData: The data the signature was made from.
    @type sigData: L{bytes}

    @ivar signature: The signed data.  This is checked to verify that the user
        owns the private key.
    @type signature: L{bytes} or L{None}

    @type ip: C{str}
    @ivar ip: The source ip address associated with these credentials.
    """


@implementer(IPluggableAuthenticationModulesIP)
class PluggableAuthenticationModulesIP:
    """
    Twisted removed IPAM in 15, adding in Cowrie now
    """

    def __init__(self, username: bytes, pamConversion: Callable, ip: str) -> None:
        self.username: bytes = username
        self.pamConversion: Callable = pamConversion
        self.ip: str = ip


@implementer(IUsername)
class Username:
    def __init__(self, username: bytes):
        self.username: bytes = username


@implementer(IUsernamePasswordIP)
class UsernamePasswordIP:
    """
    This credential interface also provides an IP address
    """

    def __init__(self, username: bytes, password: bytes, ip: str) -> None:
        f"[DEBUG][credentials.py][UsernamePasswordIP.__init__] Created credentials for user={username.decode(errors='ignore')}, ip={ip}",

        self.username: bytes = username
        self.password: bytes = password
        self.ip: str = ip

    def checkPassword(self, password: bytes) -> bool:
        f"[DEBUG][credentials.py][UsernamePasswordIP.checkPassword] Checking password for user={username.decode(errors='ignore')}, ip={ip}",

        return self.password == password
    

@implementer(ISSHPrivateKeyIP)
class SSHPrivateKeyIP:
    def __init__(self, username, algName, blob, sigData, signature, ip:str):
        self.username = username
        self.algName = algName
        self.blob = blob
        self.sigData = sigData
        self.signature = signature
        self.ip : str = ip

