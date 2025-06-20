# Copyright (c) 2009-2014 Upi Tamminen <desaster@gmail.com>
# See the COPYRIGHT file for more information

"""
This module contains code to run a command
"""

from __future__ import annotations

import os
import re
import shlex
import stat
import time

from twisted.internet import error
from twisted.python import failure, log

from cowrie.core.config import CowrieConfig
from cowrie.shell import fs
from cowrie.core.utils import validate_realfile

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Callable


class HoneyPotCommand:
    """
    This is the super class for all commands in cowrie/commands
    """

    safeoutfile: str = ""

    def __init__(self, protocol, *args, real_paths):
        #log.msg(f"[DEBUG][command.py][__init__] Initializing command with args: {args}", system="cowrie")

        self.real_paths = real_paths 


        self.protocol = protocol
        self.args = list(args)
        self.environ = self.protocol.cmdstack[-1].environ
        self.fs = self.protocol.fs
        self.ip = self.protocol.realClientIP
        self.data: bytes = b""  # output data
        self.input_data: None | (
            bytes
        ) = None  # used to store STDIN data passed via PIPE
        self.writefn: Callable[[bytes], None] = self.protocol.pp.outReceived
        self.errorWritefn: Callable[[bytes], None] = self.protocol.pp.errReceived
        # MS-DOS style redirect handling, inside the command
        # TODO: handle >>, 2>, etc
        if ">" in self.args or ">>" in self.args:
            #log.msg(f"[DEBUG][command.py][__init__] Detected output redirection: {' '.join(self.args)}", system="cowrie")
            if self.args[-1] in [">", ">>"]:
                self.errorWrite("-bash: parse error near '\\n' \n")
                #log.msg(f"[ERROR][command.py][__init__] Redirection operator without filename", system="cowrie")
                return
            self.writtenBytes = 0
            self.writefn = self.write_to_file
            if ">>" in self.args:
                index = self.args.index(">>")
                b_append = True
            else:
                index = self.args.index(">")
                b_append = False

            self.outfile = self.fs.resolve_path(
                str(self.args[(index + 1)]), self.protocol.cwd
            )
            #log.msg(f"[DEBUG][command.py][__init__] Resolved outfile path: {self.outfile}", system="cowrie")

            del self.args[index:]
            p = self.fs.getfile(self.outfile)

            #log.msg(f"[DEBUG][command.py][__init__] p: {p}", system="cowrie")

           # log.msg(f"[DEBUG][command.py] not p = {not p}", system="cowrie")
            #log.msg(f"[DEBUG][command.py] not p[fs.A_REALFILE] = {not p[fs.A_REALFILE] if p else 'N/A'}", system="cowrie")
            #log.msg(f"[DEBUG][command.py] p[fs.A_REALFILE].startswith('honeyfs') = {p[fs.A_REALFILE].startswith('honeyfs') if p and p[fs.A_REALFILE] else 'N/A'}", system="cowrie")
            #log.msg(f"[DEBUG][command.py] not b_append = {not b_append}", system="cowrie")



            validate_realfile(p)
            
            if (
                not p # If file doesnt exist
                or not p[fs.A_REALFILE] # if it doesnt have real life reference
                or p[fs.A_REALFILE].startswith("honeyfs") # If the reference starts with real file inside honeyfs
                or not b_append # if its not to append
            ):
                tmp_fname = "{}-{}-{}-redir_{}".format(
                    time.strftime("%Y%m%d-%H%M%S"),
                    self.protocol.getProtoTransport().transportId,
                    self.protocol.terminal.transport.session.id,
                    re.sub("[^A-Za-z0-9]", "_", self.outfile),
                )

                #log.msg(f"[DEBUG][command.py][__init__] tmp_fname :  {tmp_fname}", system="cowrie")

                self.safeoutfile = os.path.join(
                    self.get_custom_download_path(), tmp_fname
                )

                #log.msg(f"[DEBUG][command.py][__init__] self.safeoutfile: {self.safeoutfile}", system="cowrie")
                #log.msg(f"[DEBUG][command.py][__ini t__] self.safeoutfile: {self.outfile}", system="cowrie")

                perm = stat.S_IRUSR | stat.S_IWUSR | stat.S_IRGRP | stat.S_IROTH
                # Create virtual entry in virtual fs
                try:
                    self.fs.mkfile(
                        self.outfile,
                        self.protocol.user.uid,
                        self.protocol.user.gid,
                        0,
                        stat.S_IFREG | perm,
                    )
                    #log.msg(f"[DEBUG][command.py][__init__] Created redirected file: {self.outfile} -> {self.safeoutfile}", system="cowrie")

                except fs.FileNotFound:
                    # The outfile locates at a non-existing directory.
                    self.errorWrite(
                        f"-bash: {self.outfile}: No such file or directory\n"
                    )
                    #log.msg(f"[ERROR][command.py][__init__] Outfile path not found: {self.outfile}", system="cowrie")
                    self.writefn = self.write_to_failed
                    self.outfile = None
                    self.safeoutfile = ""
                except fs.PermissionDenied:
                    # The outfile locates in a file-system that doesn't allow file creation
                    self.errorWrite(f"-bash: {self.outfile}: Permission denied\n")
                    #log.msg(f"[ERROR][command.py][__init__] Permission denied to write to: {self.outfile}", system="cowrie")
                    self.writefn = self.write_to_failed
                    self.outfile = None
                    self.safeoutfile = ""

                else:
                    with open(self.safeoutfile, "ab"):
                        self.fs.update_realfile(
                            self.fs.getfile(self.outfile), self.safeoutfile
                        )
            else:
                self.safeoutfile = p[fs.A_REALFILE]
                #log.msg(f"[DEBUG][command.py][__init__] Using existing redirected file: {self.safeoutfile}", system="cowrie")


    def write(self, data: str) -> None:
        """
        Write a string to the user on stdout
        """
        #log.msg(f"[DEBUG][command.py][write] Writing to stdout: {data.strip()}", system="cowrie")
        self.writefn(data.encode("utf8"))

    def writeBytes(self, data: bytes) -> None:
        """
        Like write() but input is bytes
        """
        #log.msg(f"[DEBUG][command.py][writeBytes] Writing raw bytes to stdout", system="cowrie")
        self.writefn(data)

    def errorWrite(self, data: str) -> None:
        """
        Write errors to the user on stderr
        """
        #log.msg(f"[DEBUG][command.py][errorWrite] Writing to stderr: {data.strip()}", system="cowrie")
        self.errorWritefn(data.encode("utf8"))

    def check_arguments(self, application, args):
        files = []
        #log.msg(f"[DEBUG][command.py][check_arguments] Checking arguments for {application}: {args}", system="cowrie")

        for arg in args:
            path = self.fs.resolve_path(arg, self.protocol.cwd)
            if self.fs.isdir(path):
                self.errorWrite(
                    f"{application}: error reading `{arg}': Is a directory\n"
                )
                
                #log.msg(f"[WARN][command.py][check_arguments] Skipping directory: {arg}", system="cowrie")
                continue
            files.append(path)
        return files

    def set_input_data(self, data: bytes) -> None:
        #if data is not None :
            #log.msg(f"[DEBUG][command.py][set_input_data] Received STDIN data (length: {len(data)})", system="cowrie")
        #else:
            #log.msg(f"[DEBUG][command.py][set_input_data] Received STDIN data - None", system="cowrie")
        
        self.input_data = data

    def write_to_file(self, data: bytes) -> None:
        #log.msg(f"[DEBUG][command.py][write_to_file] Writing {len(data)} bytes to redirected file: {self.safeoutfile}", system="cowrie")
        with open(self.safeoutfile, "ab") as f:
            f.write(data)
        self.writtenBytes += len(data)
        self.fs.update_size(self.outfile, self.writtenBytes)

    def write_to_failed(self, data: bytes) -> None:
        pass

    def start(self) -> None:
        #log.msg(f"[DEBUG][command.py][start] Starting command execution", system="cowrie")
        if self.writefn != self.write_to_failed:
            self.call()
        self.exit()

    def call(self) -> None:
        #log.msg(f"[DEBUG][command.py][call] Default command call executed. Args: {self.args}", system="cowrie")
        self.write(f"Hello World! [{self.args!r}]\n")

    def exit(self) -> None:
        """
        Sometimes client is disconnected and command exits after. So cmdstack is gone
        """
        #log.msg("[DEBUG][command.py][exit] Exiting command", system="cowrie")
        if (
            self.protocol
            and self.protocol.terminal
            and hasattr(self, "safeoutfile")
            and self.safeoutfile
        ):
            if hasattr(self, "outfile") and self.outfile:
                #log.msg("[DEBUG][command.py][exit] redirFiles redirFiles  redirFiles redirFiles redirFiles redirFiles redirFiles redirFiles redirFiles redirFiles", system="cowrie")
                #log.msg(f"[DEBUG][command.py][exit] safeoutfile = {self.outfile} outfile = {self.outfile} ", system="cowrie")
                self.protocol.terminal.redirFiles.add((self.safeoutfile, self.outfile))
            else:
                #log.msg("[DEBUG][command.py][exit] redirFiles redirFiles  redirFiles redirFiles redirFiles redirFiles redirFiles redirFiles redirFiles redirFiles", system="cowrie")
                self.protocol.terminal.redirFiles.add((self.safeoutfile, ""))

        if len(self.protocol.cmdstack):
            self.protocol.cmdstack.remove(self)

            if len(self.protocol.cmdstack):
                #log.msg("[DEBUG][command.py][exit] Resuming next command in stack", system="cowrie")
                self.protocol.cmdstack[-1].resume()
        else:
            #log.msg("[DEBUG][command.py][exit] No remaining command stack. Ending session.", system="cowrie")
            ret = failure.Failure(error.ProcessDone(status=""))
            # The session could be disconnected already, when his happens .transport is gone
            try:
                self.protocol.terminal.transport.processEnded(ret)
            except AttributeError:
                pass

    def handle_CTRL_C(self) -> None:
        #log.msg("[DEBUG][command.py][handle_CTRL_C] Received CTRL-C signal", system="cowrie")
        log.msg("Received CTRL-C, exiting..")
        self.write("^C\n")
        self.exit()

    def lineReceived(self, line: str) -> None:
        #log.msg(f"[DEBUG][command.py][lineReceived] User input received: {line}", system="cowrie")
        log.msg(f"QUEUED INPUT: {line}")
        # FIXME: naive command parsing, see lineReceived below
        # line = "".join(line)
        self.protocol.cmdstack[0].cmdpending.append(shlex.split(line, posix=True))

    def resume(self) -> None:
        pass

    def handle_TAB(self) -> None:
        pass

    def handle_CTRL_D(self) -> None:
        pass

    def __repr__(self) -> str:
        return str(self.__class__.__name__)
    
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
