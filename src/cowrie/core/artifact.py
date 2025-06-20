# Copyright (c) 2016 Michel Oosterhof <michel@oosterhof.net>

"""
This module contains code to handling saving of honeypot artifacts
These will typically be files uploaded to the honeypot and files
downloaded inside the honeypot, or input being piped in.

Code behaves like a normal Python file handle.

Example:

    with Artifact(name) as f:
        f.write("abc")

or:

    g = Artifact("testme2")
    g.write("def")
    g.close()

"""

from __future__ import annotations

import hashlib
import os
import tempfile
from typing import Any, TYPE_CHECKING

from twisted.python import log

from cowrie.core.config import CowrieConfig

if TYPE_CHECKING:
    from types import TracebackType


class Artifact:

    def __init__(self, label: str, ip:str) -> None:
        self.label: str = label
        self.ip:str = ip
        self.artifactDir: str = self.get_custom_download_path()


        self.fp = tempfile.NamedTemporaryFile(  # pylint: disable=R1732
            dir=self.artifactDir, delete=False
        )
        self.tempFilename = self.fp.name
        self.closed: bool = False

        self.shasum: str = ""
        self.shasumFilename: str = ""

    def __enter__(self) -> Any:
        return self.fp

    def __exit__(
        self,
        etype: type[BaseException] | None,
        einst: BaseException | None,
        etrace: TracebackType | None,
    ) -> bool:
        self.close()
        return True

    def write(self, data: bytes) -> None:
        log.msg( "[ARTIFACT][artifact.py] [DEBUG] Successfully wrote data to artifact:\n",system="cowrie"
        )
        self.fp.write(data)

    def fileno(self) -> Any:
        return self.fp.fileno()

    def close(self, keepEmpty: bool = False) -> tuple[str, str] | None:
        size: int = self.fp.tell()
        if size == 0 and not keepEmpty:
            try:
                os.remove(self.fp.name)
            except FileNotFoundError:
                pass
            return None

        self.fp.seek(0)
        data = self.fp.read()
        self.fp.close()
        self.closed = True

        self.shasum = hashlib.sha256(data).hexdigest()
        self.shasumFilename = os.path.join(self.artifactDir, self.shasum)

        log.msg(
        "[ARTIFACT][artifact.py] [DEBUG] Computed SHA256 and prepared artifact path:\n"
        f"    - SHA256 Sum: {self.shasum}\n"
        f"    - Full Artifact Path: {self.shasumFilename}\n",
        system="cowrie"
        )


        if os.path.exists(self.shasumFilename):
            log.msg("Not storing duplicate content " + self.shasum)
            os.remove(self.fp.name)
        else:
            os.rename(self.fp.name, self.shasumFilename)
            umask = os.umask(0)
            os.umask(umask)
            os.chmod(self.shasumFilename, 0o666 & ~umask)

        return self.shasum, self.shasumFilename
    

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
            log.msg(f"[DEBUG][fs.py][get_custom_download_path] Using default download_path: {base_path}", system="cowrie")
            return base_path

        # Use state_path if persistence is active
        state_path = CowrieConfig.get("honeypot", "state_path", fallback=".")
        base_dir = os.path.join(state_path, "filesystems")

        if persistent_global:
            download_dir = os.path.join(base_dir, "global", "downloads")
            log.msg(f"[DEBUG][fs.py][get_custom_download_path] Global persistence: {download_dir}", system="cowrie")
        elif persistent_per_ip and self.ip:
            cleaned_ip = self.ip.replace(".", "_")
            download_dir = os.path.join(base_dir, cleaned_ip, "downloads")
            log.msg(f"[DEBUG][fs.py][get_custom_download_path] Per-IP persistence for {self.ip}: {download_dir}", system="cowrie")
        else:
            log.msg("[DEBUG][fs.py][get_custom_download_path] Persistence enabled but IP not provided. Using default path.", system="cowrie")
            return base_path

        # Ensure the directory exists
        os.makedirs(download_dir, exist_ok=True)
        return download_dir
