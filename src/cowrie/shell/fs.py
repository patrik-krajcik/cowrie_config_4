# Copyright (c) 2009-2014 Upi Tamminen <desaster@gmail.com>
# See the COPYRIGHT file for more information

# Todo, use os.stat_result, which contains the stat 10-tuple instead of the custom object.

from __future__ import annotations

import errno
import fnmatch
import hashlib
import os
from pathlib import Path
import pickle
import re
import sys
import stat
import time
import tempfile
import shutil
from typing import Any
import copy  # Add at top of file
from cowrie.core.utils import validate_realfile



from twisted.python import log

from cowrie.shell.safewriter import SafeFileWriter

from cowrie.core.config import CowrieConfig

(
    A_NAME,
    A_TYPE,
    A_UID,
    A_GID,
    A_SIZE,
    A_MODE,
    A_CTIME,
    A_CONTENTS,
    A_TARGET,
    A_REALFILE,
) = list(range(0, 10))

T_LINK, T_DIR, T_FILE, T_BLK, T_CHR, T_SOCK, T_FIFO = list(range(0, 7))


SPECIAL_PATHS: list[str] = ["/sys", "/proc", "/dev/pts"]


class _statobj:
    """
    Transform a tuple into a stat object
    """

    def __init__(
        self,
        st_mode: int,
        st_ino: int,
        st_dev: int,
        st_nlink: int,
        st_uid: int,
        st_gid: int,
        st_size: int,
        st_atime: float,
        st_mtime: float,
        st_ctime: float,
    ) -> None:
        self.st_mode: int = st_mode
        self.st_ino: int = st_ino
        self.st_dev: int = st_dev
        self.st_nlink: int = st_nlink
        self.st_uid: int = st_uid
        self.st_gid: int = st_gid
        self.st_size: int = st_size
        self.st_atime: float = st_atime
        self.st_mtime: float = st_mtime
        self.st_ctime: float = st_ctime


class TooManyLevels(Exception):
    """
    62 ELOOP Too many levels of symbolic links.  A path name lookup involved more than 8 symbolic links.
    raise OSError(errno.ELOOP, os.strerror(errno.ENOENT))
    """


class FileNotFound(Exception):
    """
    raise OSError(errno.ENOENT, os.strerror(errno.ENOENT))
    """


class PermissionDenied(Exception):
    """
    Our implementation is rather naive for now

    * TODO: Top-level /proc should return 'no such file' not 'permission
            denied'. However this seems to vary based on kernel version.

    $ sudo touch /sys/.nippon
    touch: cannot touch '/sys/.nippon': Permission denied
    $ sudo touch /proc/test
    touch: cannot touch '/proc/test': No such file or directory
    $ sudo touch /dev/pts/test
    touch: cannot touch '/dev/pts/test': Permission denied
    $ sudo touch /proc/sys/fs/binfmt_misc/.nippon
    touch: cannot touch '/proc/sys/fs/binfmt_misc/.nippon': Permission denied
    $ sudo touch /sys/fs/fuse/connections/.nippon
    touch: cannot touch '/sys/fs/fuse/connections/.nippon': Permission denied
    """


class HoneyPotFilesystem:
    # Modification
    def _get_persistent_fs_path(self) -> str:
        """Determine the path for persistent FS based on mode"""
        base_path = CowrieConfig.get("honeypot", "state_path", fallback="var/lib/cowrie")
        fs_root = os.path.join(base_path, "filesystems")

        if CowrieConfig.getboolean("shell", "persistent_global", fallback=False):
            #log.msg("[DEBUG][fs.py][_get_persistent_fs_path] Using global FS path", system="cowrie")
            return os.path.join(fs_root, "global")

        elif CowrieConfig.getboolean("shell", "persistent_per_ip", fallback=False) and self.ip:
            cleaned_ip = self.ip.replace(".", "_")
            #log.msg(f"[DEBUG][fs.py][_get_persistent_fs_path] Using per-IP FS path for {self.ip}", system="cowrie")
            return os.path.join(fs_root, cleaned_ip)

        return None


    
    def load_base_fs(self) -> list:
        fallback_path = CowrieConfig.get("shell", "filesystem", fallback="src/cowrie/data/fs.pickle")

        try:
            with open(fallback_path, "rb") as f:
                return pickle.load(f)
        except UnicodeDecodeError:
            with open(fallback_path, "rb") as f:
                return pickle.load(f, encoding="utf8")
        except Exception as e:
            #log.err(f"[DEBUG][fs.py] Failed to load base FS: {str(e)}")
            sys.exit(1)
    

    def save_fs_delta(self):
        #log.msg(f"[DEBUG][fs.py][save_fs_delta] Is not ? {self.persist_dir}", system="cowrie")
        if not self.persist_dir:
            return

        try:
            os.makedirs(self.persist_dir, exist_ok=True)
            delta = self.generate_diffs(self.base_fs, self.fs)
            
            delta_path = os.path.join(self.persist_dir, "delta.pickle")

            with SafeFileWriter(delta_path, mode='wb') as f:
                pickle.dump(delta, f)


            #log.msg(f"[DEBUG][fs.py][save_fs_delta] Saved delta to {self.persist_dir}/delta.pickle", system="cowrie")
        except Exception as e:
            log.err(f"[ERROR][fs.py]Error saving delta: {str(e)}")



    def __init__(self, arch: str, home: str, transportId: str, ip: str) -> None:
        #log.msg(f"[DEBUG][fs.py][HoneyPotFilesystem.__init__] Initializing filesystem with arch={arch}, home={home}", system="cowrie")

        """
        Create a new fake filesystem for a session.
        Stores architecture, home path, transport ID, and attacker IP.
        """
        self.arch = arch
        self.home = home
        self.transportId = transportId
        self.ip = ip
        self.fs: list[Any]
        
        # Modification

        self.fs = self.load_base_fs()

        # self.fs[A_TARGET] = None
        
        # self.fs.append(None) 
        

        # delta_path = os.path.join("src/cowrie/data", "fs.pickle")
        # with open(delta_path, "wb") as f:
        #     pickle.dump(self.fs, f)

        self.persist_dir = self._get_persistent_fs_path()

        #log.msg(f"[DEBUG][fs.py][HoneyPotFilesystem.__init__] File system state initialized", system="cowrie")
        self.init_honeyfs(CowrieConfig.get("honeypot", "contents_path"))

        self.base_fs = copy.deepcopy(self.fs)
        self.first_time = True

        if self.persist_dir:
            os.makedirs(self.persist_dir, exist_ok=True)
            delta_file = os.path.join(self.persist_dir, "delta.pickle")

            if os.path.exists(delta_file):
                try:
                    with open(delta_file, "rb") as f:
                        delta = pickle.load(f)
                    self.fs = self.apply_diffs(self.fs,delta)
                    self.first_time = False
                    #log.msg(f"[DEBUG][fs.py][__init__] Applied delta from {delta_file}", system="cowrie")
                except Exception as e:
                    log.err(f"[ERROR][fs.py] Error loading delta: {str(e)}")

       
        self.arch: str = arch
        self.home: str = home

        self.tempfiles: dict[int, str] = {}
        self.filenames: dict[int, str] = {}
       
        self.newcount: int = 0


        

    def init_honeyfs(self, honeyfs_path: str) -> None:
        """
        Explore the honeyfs at 'honeyfs_path' and set all A_REALFILE attributes on
        the virtual filesystem.
        """
        #log.msg(f"[DEBUG][fs.py][init_honeyfs] Scanning honeyfs from {honeyfs_path}", system="cowrie")



        for path, _directories, filenames in os.walk(honeyfs_path):
            for filename in filenames:
                realfile_path: str = os.path.join(path, filename)

                virtual_path: str = "/" + os.path.relpath(realfile_path, honeyfs_path)
                # if virtual_path in {'/etc/passwd', '/etc/group', '/etc/shadow'}:
                #     log.msg(
                #         f"[FS] Skipping auth file: {virtual_path}",
                #         system="cowrie"
                #     )
                #     continue

                f: list[Any] | None = self.getfile(virtual_path, follow_symlinks=False)
                if f and f[A_TYPE] == T_FILE:
                    self.update_realfile(f, realfile_path)
                    #log.msg(f"[DEBUG][fs.py][init_honeyfs] Linked real file {realfile_path} -> virtual {virtual_path}", system="cowrie")

        
        
    def resolve_path(self, pathspec: str, cwd: str) -> str:
        """
        This function does not need to be in this class, it has no dependencies
        """
        cwdpieces: list[str] = []

        # If a path within home directory is specified, convert it to an absolute path
        if pathspec.startswith("~/"):
            path = self.home + pathspec[1:]
        else:
            path = pathspec

        pieces = path.rstrip("/").split("/")

        if path[0] == "/":
            cwdpieces = []
        else:
            cwdpieces = [x for x in cwd.split("/") if len(x) and x is not None]

        while 1:
            if not pieces:
                break
            piece = pieces.pop(0)
            if piece == "..":
                if cwdpieces:
                    cwdpieces.pop()
                continue
            if piece in (".", ""):
                continue
            cwdpieces.append(piece)

        return "/{}".format("/".join(cwdpieces))

    def resolve_path_wc(self, path: str, cwd: str) -> list[str]:
        """
        Resolve_path with wildcard support (globbing)
        """
        pieces: list[str] = path.rstrip("/").split("/")
        cwdpieces: list[str]
        if len(pieces[0]):
            cwdpieces = [x for x in cwd.split("/") if len(x) and x is not None]
            path = path[1:]
        else:
            cwdpieces, pieces = [], pieces[1:]
        found: list[str] = []

        def foo(p, cwd):
            if not p:
                found.append("/{}".format("/".join(cwd)))
            elif p[0] == ".":
                foo(p[1:], cwd)
            elif p[0] == "..":
                foo(p[1:], cwd[:-1])
            else:
                names = [x[A_NAME] for x in self.get_path("/".join(cwd))]
                matches = [x for x in names if fnmatch.fnmatchcase(x, p[0])]
                for match in matches:
                    foo(p[1:], [*cwd, match])

        foo(pieces, cwdpieces)
        return found

    def get_path(self, path: str, follow_symlinks: bool = True) -> Any:
        """
        This returns the Cowrie file system objects for a directory
        """
        #log.msg(f"[DEBUG][fs.py][get_path] Resolving directory: {path}", system="cowrie")

        cwd: list[Any] = self.fs
        for part in path.split("/"):
            if not part:
                continue
            ok = False
            for c in cwd[A_CONTENTS]:
                if c[A_NAME] == part:
                    if c[A_TYPE] == T_LINK:
                        f = self.getfile(c[A_TARGET], follow_symlinks=follow_symlinks)
                        if f is None:
                            ok = False
                            break
                        else:
                            cwd = f
                    else:
                        cwd = c
                    ok = True
                    break
            if not ok:
                log.msg(f"[WARN][fs.py][get_path] Failed to resolve: {path}, part: {part}", system="cowrie")
                raise FileNotFound
        
        #log.msg(f"[DEBUG][fs.py][get_path] Successfully resolved path: {path}", system="cowrie")
        return cwd[A_CONTENTS]

    def exists(self, path: str) -> bool:
        """
        Return True if path refers to an existing path.
        Returns False for broken symbolic links.
        """
        f: list[Any] | None = self.getfile(path, follow_symlinks=True)
        exists = f is not None
        #log.msg(f"[DEBUG][fs.py][exists] Path '{path}' exists={exists}", system="cowrie")
        return exists

    def lexists(self, path: str) -> bool:
        """
        Return True if path refers to an existing path.
        Returns True for broken symbolic links.
        """
        f: list[Any] | None = self.getfile(path, follow_symlinks=False)
        exists = f is not None
        #log.msg(f"[DEBUG][fs.py][lexists] Path '{path}' lexists={exists}", system="cowrie")
        return exists

    def update_realfile(self, f: Any, realfile: str) -> None:
        validate_realfile(f)
        if (
            not f[A_REALFILE]
            and os.path.exists(realfile)
            and not os.path.islink(realfile)
            and os.path.isfile(realfile)
            and f[A_SIZE] < 25000000
        ):
            #log.msg(f"[DEBUG][fs.py][update_realfile] Linking real file '{realfile}'", system="cowrie")
            f[A_REALFILE] = realfile


    def getfile(self, path: str, follow_symlinks: bool = True) -> list[Any] | None:
        """
        This returns the Cowrie file system object for a path
        """
        if path == "/":
            return self.fs
        pieces: list[str] = path.strip("/").split("/")
        cwd: str = ""
        p: list[Any] | None = self.fs
        for piece in pieces:
            if not isinstance(p, list):
                #log.msg(f"[WARN][fs.py][getfile] Unexpected type at '{cwd}', expected list", system="cowrie")
                return None

            if piece not in [x[A_NAME] for x in p[A_CONTENTS]]:
                #log.msg(f"[DEBUG][fs.py][getfile] Path segment '{piece}' not found in '{cwd}'", system="cowrie")
                return None

            for x in p[A_CONTENTS]:
                if x[A_NAME] == piece:
                    if piece == pieces[-1] and not follow_symlinks:
                        p = x
                    elif x[A_TYPE] == T_LINK:
                        if x[A_TARGET][0] == "/":
                            target_path = x[A_TARGET]
                        else:
                            target_path = "/".join((cwd, x[A_TARGET]))

                        fileobj = self.getfile(target_path, follow_symlinks=follow_symlinks)
                        if not fileobj:
                            #log.msg(f"[WARN][fs.py][getfile] Broken symlink '{piece}' -> '{target_path}'", system="cowrie")
                            return None
                        p = fileobj
                    else:
                        p = x
            # cwd = '/'.join((cwd, piece))
        return p

    def file_contents(self, target: str) -> bytes:
        """
        Retrieve the content of a file in the honeyfs
        It follows links.
        It tries A_REALFILE first and then tries honeyfs directory
        Then return the executable header for executables
        """
        path: str = self.resolve_path(target, os.path.dirname(target))
        if not path or not self.exists(path):
            #log.msg(f"[WARN][fs.py][file_contents] File not found: {target}", system="cowrie")
            raise FileNotFound
        f: Any = self.getfile(path)

        if f[A_TYPE] == T_DIR:
            #log.msg(f"[WARN][fs.py][file_contents] Tried to read directory: {path}", system="cowrie")
            raise IsADirectoryError

        validate_realfile(f)
        
        if f[A_TYPE] == T_FILE and f[A_REALFILE]:
            #log.msg(f"[DEBUG][fs.py][file_contents] Reading real file from: {f[A_REALFILE]}", system="cowrie")
            return Path(f[A_REALFILE]).read_bytes()

        if f[A_TYPE] == T_FILE and f[A_SIZE] == 0:
            #log.msg(f"[DEBUG][fs.py][file_contents] Zero-size virtual file: {path}", system="cowrie")
            # Zero-byte file lacking A_REALFILE backing: probably empty.
            # (The exceptions to this are some system files in /proc and /sys,
            # but it's likely better to return nothing than suspiciously fail.)
            return b""

        if f[A_TYPE] == T_FILE and f[A_MODE] & stat.S_IXUSR:
            arch_path = os.path.join(
                CowrieConfig.get("honeypot", "data_path"),
                "arch",
                self.arch
            )

            #log.msg(f"[DEBUG][fs.py][file_contents] Returning executable binary from: {arch_path}", system="cowrie")
            return open(arch_path, "rb").read()
    
        #log.msg(f"[DEBUG][fs.py][file_contents] Returning empty contents for {path}", system="cowrie")
        return b""

    def mkfile(
        self,
        path: str,
        uid: int,
        gid: int,
        size: int,
        mode: int,
        ctime: float | None = None,
    ) -> bool:
        if self.newcount > 10000:
            #log.msg(f"[WARN][fs.py][mkfile] Quota exceeded, cannot create: {path}", system="cowrie")
            return False

        if ctime is None:
            ctime = time.time()
        _path: str = os.path.dirname(path)

        if any([_path.startswith(_p) for _p in SPECIAL_PATHS]):
            #log.msg(f"[WARN][fs.py][mkfile] Attempt to write to restricted path: {_path}", system="cowrie")
            raise PermissionDenied

        _dir = self.get_path(_path)
        outfile: str = os.path.basename(path)

        if outfile in [x[A_NAME] for x in _dir]:
            #log.msg(f"[DEBUG][fs.py][mkfile] Overwriting existing file: {path}", system="cowrie")
            _dir.remove(next(x for x in _dir if x[A_NAME] == outfile))

        _dir.append([outfile, T_FILE, uid, gid, size, mode, ctime, [], None, None])
        self.newcount += 1
        
        #log.msg(f"[DEBUG][fs.py][mkfile] File created: {path}, uid={uid}, gid={gid}, mode={oct(mode)}, size={size}", system="cowrie")

        return True

    def mkdir(
        self,
        path: str,
        uid: int,
        gid: int,
        size: int,
        mode: int,
        ctime: float | None = None,
    ) -> None:
        if self.newcount > 10000:
            #log.msg(f"[WARN][fs.py][mkdir] Quota exceeded, cannot create: {path}", system="cowrie")
            raise OSError(errno.EDQUOT, os.strerror(errno.EDQUOT), path)

        if ctime is None:
            ctime = time.time()

        if not path.strip("/"):
            #log.msg(f"[ERROR][fs.py][mkdir] Empty or invalid path: '{path}'", system="cowrie")
            raise OSError(errno.ENOENT, os.strerror(errno.ENOENT), path)

        try:
            directory = self.get_path(os.path.dirname(path.strip("/")))
        except (IndexError, FileNotFound):
            #log.msg(f"[ERROR][fs.py][mkdir] Parent directory not found for: {path}", system="cowrie")
            raise OSError(errno.ENOENT, os.strerror(errno.ENOENT), path) from None

        directory.append(
            [os.path.basename(path), T_DIR, uid, gid, size, mode, ctime, [], None, None]
        )
        self.newcount += 1
        #log.msg(f"[DEBUG][fs.py][mkdir] Directory created: {path}, uid={uid}, gid={gid}, mode={oct(mode)}", system="cowrie")


    def isfile(self, path: str) -> bool:
        """
        Return True if path is an existing regular file. This follows symbolic
        links, so both islink() and isfile() can be true for the same path.
        """
        try:
            f: list[Any] | None = self.getfile(path)
        except Exception:
            #log.msg(f"[DEBUG][fs.py][isfile] Exception while checking: {path}", system="cowrie")
            return False

        is_file = f is not None and f[A_TYPE] == T_FILE
        #log.msg(f"[DEBUG][fs.py][isfile] Path '{path}' isfile={is_file}", system="cowrie")
        return is_file

    def islink(self, path: str) -> bool:
        """
        Return True if path refers to a directory entry that is a symbolic
        link. Always False if symbolic links are not supported by the python
        runtime.
        """
        try:
            f: list[Any] | None = self.getfile(path)
        except Exception:
            #log.msg(f"[DEBUG][fs.py][islink] Exception while checking: {path}", system="cowrie")
            return False

        is_link = f is not None and f[A_TYPE] == T_LINK
        #log.msg(f"[DEBUG][fs.py][islink] Path '{path}' islink={is_link}", system="cowrie")
        return is_link

    def isdir(self, path: str) -> bool:
        """
        Return True if path is an existing directory.
        This follows symbolic links, so both islink() and isdir() can be true for the same path.
        """
        if path == "/":
            return True
        try:
            directory = self.getfile(path)
        except Exception:
            #log.msg(f"[DEBUG][fs.py][isdir] Exception while checking: {path}", system="cowrie")
            return False
        
        is_dir = directory is not None and directory[A_TYPE] == T_DIR
        #log.msg(f"[DEBUG][fs.py][isdir] Path '{path}' isdir={is_dir}", system="cowrie")
        return is_dir

    # Below additions for SFTP support, try to keep functions here similar to os.*

    def open(self, filename: str, openFlags: int, mode: int) -> int | None:
        """
        #log.msg("fs.open %s" % filename)

        #if (openFlags & os.O_APPEND == os.O_APPEND):
        #    log.msg("fs.open append")

        #if (openFlags & os.O_CREAT == os.O_CREAT):
        #    log.msg("fs.open creat")

        #if (openFlags & os.O_TRUNC == os.O_TRUNC):
        #    log.msg("fs.open trunc")

        #if (openFlags & os.O_EXCL == os.O_EXCL):
        #    log.msg("fs.open excl")

        # treat O_RDWR same as O_WRONLY
        """

        #log.msg(f"[DEBUG][fs.py][open] Opening file: {filename} with flags={openFlags}, mode={oct(mode)}", system="cowrie")

        if openFlags & os.O_WRONLY == os.O_WRONLY or openFlags & os.O_RDWR == os.O_RDWR:
            # strip executable bit
            hostmode: int = mode & ~(111)
            hostfile: str = "{}/{}_sftp_{}".format(
                self.get_custom_download_path(),
                time.strftime("%Y%m%d-%H%M%S"),
                re.sub("[^A-Za-z0-9]", "_", filename),
            )
            self.mkfile(filename, 0, 0, 0, stat.S_IFREG | mode)
            fd = os.open(hostfile, openFlags, hostmode)
            self.update_realfile(self.getfile(filename), hostfile)
            self.tempfiles[fd] = hostfile
            self.filenames[fd] = filename
    
            #log.msg(f"[DEBUG][fs.py][open] File descriptor {fd} created and writing to host file: {hostfile}", system="cowrie")
            return fd

        # TODO: throw exception
        if openFlags & os.O_RDONLY == os.O_RDONLY:
            #log.msg(f"[DEBUG][fs.py][open] Read-only access not supported for: {filename}", system="cowrie")
            return None

        # TODO: throw exception
        #log.msg(f"[WARN][fs.py][open] Unsupported open flags for: {filename}", system="cowrie")
        return None

    def read(self, fd: int, n: int) -> bytes:
        # this should not be called, we intercept at readChunk
        raise NotImplementedError

    def write(self, fd: int, string: bytes) -> int:
        #log.msg(f"[DEBUG][fs.py][write] Writing {len(string)} bytes to fd: {fd}", system="cowrie")
        return os.write(fd, string)

    def close(self, fd: int) -> None:
        if not fd:
            return
        if self.tempfiles[fd] is not None:
            with open(self.tempfiles[fd], "rb") as f:
                shasum: str = hashlib.sha256(f.read()).hexdigest()
            shasumfile: str = (
                self.get_custom_download_path() + "/" + shasum
            )
            if os.path.exists(shasumfile):
                os.remove(self.tempfiles[fd])
                #log.msg(f"[DEBUG][fs.py][close] Duplicate upload. Deleted temp: {self.tempfiles[fd]}", system="cowrie")
                duplicate = True

            else:
                os.rename(self.tempfiles[fd], shasumfile)
                #log.msg(f"[DEBUG][fs.py][close] Renamed temp to: {shasumfile}", system="cowrie")
                duplicate = False

            f = self.getfile(self.filenames[fd])

            if f:
                f[A_REALFILE] = shasumfile

            
            log.msg(
                format='SFTP Uploaded file "%(filename)s" to %(outfile)s',
                eventid="cowrie.session.file_upload",
                duplicate=duplicate,
                filename=os.path.basename(self.filenames[fd]),
                outfile=shasumfile,
                shasum=shasum,
            )
            del self.tempfiles[fd]
            del self.filenames[fd]
        os.close(fd)
        #log.msg(f"[DEBUG][fs.py][close] Closed file descriptor: {fd}", system="cowrie")

    def lseek(self, fd: int, offset: int, whence: int) -> int:
        if not fd:
            return True

        result = os.lseek(fd, offset, whence)
        #log.msg(f"[DEBUG][fs.py][lseek] Seeked fd: {fd} to offset: {offset} (whence={whence})", system="cowrie")
        return result

    def mkdir2(self, path: str) -> None:
        """
        FIXME mkdir() name conflicts with existing mkdir
        """
        #log.msg(f"[DEBUG][fs.py][mkdir2] Creating directory: {path}", system="cowrie")

        directory: list[Any] | None = self.getfile(path)
        if directory:
            #log.msg(f"[WARN][fs.py][mkdir2] Directory already exists: {path}", system="cowrie")
            raise OSError(errno.EEXIST, os.strerror(errno.EEXIST), path)

        self.mkdir(path, 0, 0, 4096, 16877)
        #log.msg(f"[DEBUG][fs.py][mkdir2] Directory created: {path}", system="cowrie")


    def rmdir(self, path: str) -> bool:
        p: str = path.rstrip("/")
        name: str = os.path.basename(p)
        parent: str = os.path.dirname(p)

        #log.msg(f"[DEBUG][fs.py][rmdir] Removing directory: {path}", system="cowrie")

        directory: Any = self.getfile(p, follow_symlinks=False)

        if not directory:
            #log.msg(f"[WARN][fs.py][rmdir] Directory does not exist: {path}", system="cowrie")
            raise OSError(errno.EEXIST, os.strerror(errno.EEXIST), p)

        if directory[A_TYPE] != T_DIR:
            #log.msg(f"[WARN][fs.py][rmdir] Not a directory: {path}", system="cowrie")
            raise OSError(errno.ENOTDIR, os.strerror(errno.ENOTDIR), p)

        if len(self.get_path(p)) > 0:
            #log.msg(f"[WARN][fs.py][rmdir] Directory not empty: {path}", system="cowrie")
            raise OSError(errno.ENOTEMPTY, os.strerror(errno.ENOTEMPTY), p)

        pdir = self.get_path(parent, follow_symlinks=True)

        for i in pdir[:]:
            if i[A_NAME] == name:
                pdir.remove(i)
                #log.msg(f"[DEBUG][fs.py][rmdir] Successfully removed directory: {path}", system="cowrie")
                return True

        return False

    def utime(self, path: str, _atime: float, mtime: float) -> None:
        p: list[Any] | None = self.getfile(path)
        if not p:
            #log.msg(f"[WARN][fs.py][utime] Cannot set time, path not found: {path}", system="cowrie")
            raise OSError(errno.ENOENT, os.strerror(errno.ENOENT))

        p[A_CTIME] = mtime
        #log.msg(f"[DEBUG][fs.py][utime] Set ctime of {path} to {mtime}", system="cowrie")


    def chmod(self, path: str, perm: int) -> None:
        p: list[Any] | None = self.getfile(path)
        if not p:
            #log.msg(f"[WARN][fs.py][chmod] Path not found: {path}", system="cowrie")
            raise OSError(errno.ENOENT, os.strerror(errno.ENOENT))

        p[A_MODE] = stat.S_IFMT(p[A_MODE]) | perm
        #log.msg(f"[DEBUG][fs.py][chmod] Changed mode of {path} to {oct(perm)}", system="cowrie")


    def chown(self, path: str, uid: int, gid: int) -> None:
        p: list[Any] | None = self.getfile(path)
        if not p:
            #log.msg(f"[WARN][fs.py][chown] Path not found: {path}", system="cowrie")
            raise OSError(errno.ENOENT, os.strerror(errno.ENOENT))

        if uid != -1:
            p[A_UID] = uid
        if gid != -1:
            p[A_GID] = gid
        #log.msg(f"[DEBUG][fs.py][chown] Changed ownership of {path} to uid={uid}, gid={gid}", system="cowrie")


    def remove(self, path: str) -> None:
        p: list[Any] | None = self.getfile(path, follow_symlinks=False)
        if not p:
            #log.msg(f"[WARN][fs.py][remove] File not found: {path}", system="cowrie")
            raise OSError(errno.ENOENT, os.strerror(errno.ENOENT))

        self.get_path(os.path.dirname(path)).remove(p)
        #log.msg(f"[DEBUG][fs.py][remove] Removed file: {path}", system="cowrie")


    def readlink(self, path: str) -> str:
        p: list[Any] | None = self.getfile(path, follow_symlinks=False)
        if not p:
            #log.msg(f"[WARN][fs.py][readlink] Path not found: {path}", system="cowrie")
            raise OSError(errno.ENOENT, os.strerror(errno.ENOENT))
        if not p[A_MODE] & stat.S_IFLNK:
            raise OSError

        #log.msg(f"[DEBUG][fs.py][readlink] {path} points to {p[A_TARGET]}", system="cowrie")
        return p[A_TARGET]  # type: ignore

    def symlink(self, targetPath: str, linkPath: str) -> None:
        raise NotImplementedError

    def rename(self, oldpath: str, newpath: str) -> None:
        old: list[Any] | None = self.getfile(oldpath)
        if not old:
            #log.msg(f"[WARN][fs.py][rename] Old path not found: {oldpath}", system="cowrie")
            raise OSError(errno.ENOENT, os.strerror(errno.ENOENT))

        new = self.getfile(newpath)

        if new:
            #log.msg(f"[WARN][fs.py][rename] Target already exists: {newpath}", system="cowrie")
            raise OSError(errno.EEXIST, os.strerror(errno.EEXIST))

        self.get_path(os.path.dirname(oldpath)).remove(old)
        old[A_NAME] = os.path.basename(newpath)
        self.get_path(os.path.dirname(newpath)).append(old)
        #log.msg(f"[DEBUG][fs.py][rename] Renamed {oldpath} -> {newpath}", system="cowrie")


    def listdir(self, path: str) -> list[str]:
        names: list[str] = [x[A_NAME] for x in self.get_path(path)]
        #log.msg(f"[DEBUG][fs.py][listdir] Listing directory: {path} with {len(names)} entries", system="cowrie")
        return names

    def lstat(self, path: str) -> _statobj:
        #log.msg(f"[DEBUG][fs.py][lstat] lstat called on: {path}", system="cowrie")
        return self.stat(path, follow_symlinks=False)

    def stat(self, path: str, follow_symlinks: bool = True) -> _statobj:
        p: list[Any] | None
        if path == "/":
            p = ["/", T_DIR, 0, 0, 4096, 16877, time.time(), [], None, None]
        else:
            p = self.getfile(path, follow_symlinks=follow_symlinks)

        if not p:
            #log.msg(f"[WARN][fs.py][stat] stat failed: {path}", system="cowrie")
            raise OSError(errno.ENOENT, os.strerror(errno.ENOENT))

        #log.msg(f"[DEBUG][fs.py][stat] stat on {path} - mode: {oct(p[A_MODE])}, size: {p[A_SIZE]}", system="cowrie")
        return _statobj(
            p[A_MODE],
            0,
            0,
            1,
            p[A_UID],
            p[A_GID],
            p[A_SIZE],
            p[A_CTIME],
            p[A_CTIME],
            p[A_CTIME],
        )

    def realpath(self, path: str) -> str:
        return path

    def update_size(self, filename: str, size: int, remove: bool = False) -> None:
        f: list[Any] | None = self.getfile(filename)
        if not f:
            return
        if f[A_TYPE] != T_FILE:
            return

        f[A_SIZE] = size
        #log.msg(f"[DEBUG][fs.py][update_size] Updated size of {filename} to {size} bytes", system="cowrie")

        persistent_global = CowrieConfig.getboolean("shell", "persistent_global", fallback=False)
        persistent_per_ip = CowrieConfig.getboolean("shell", "persistent_per_ip", fallback=False)

        if not (persistent_global or persistent_per_ip):
            #log.msg(f"[DEBUG][fs.py][update_size] Persistence not enabled, skipping authorized_keys handling", system="cowrie")
            return

        # === Additional logic for authorized_keys tracking ===
        user = self.extract_username_from_authorized_keys(filename)

        if user:
            #log.msg(f"[DEBUG][fs.py][update_size] Detected authorized_keys modification for {filename}", system="cowrie")

            state_path = CowrieConfig.get("honeypot", "state_path", fallback=".")
            filesystems_dir = os.path.join(state_path, "filesystems")

            if persistent_global:
                dest_dir = os.path.join(filesystems_dir, "global")
            else:
                if hasattr(self, "ip") and self.ip:
                    cleaned_ip = self.ip.replace(".", "_")
                    dest_dir = os.path.join(filesystems_dir, cleaned_ip)
                else:
                    #log.msg(f"[DEBUG][fs.py][update_size] No IP available for per-IP persistence, skipping", system="cowrie")
                    return

            os.makedirs(dest_dir, exist_ok=True)

            dest_file = os.path.join(dest_dir, f"{user}_authorized_keys")
            realfile = f[A_REALFILE]

            if remove : 
                try:
                    with open(dest_file, "w") as f:
                        pass  # Properly create an empty file
                    #log.msg(f"[DEBUG][fs.py][update_size] Created empty authorized_keys at {dest_file} (no realfile linked)", system="cowrie")
                    return
                except Exception as e:
                    log.err(f"[ERROR][fs.py][update_size] Error handling authorized_keys persistence: {e}", system="cowrie")

            try:
                if realfile and os.path.exists(realfile):
                    shutil.copyfile(realfile, dest_file)
                    #log.msg(f"[DEBUG][fs.py][update_size] Saved authorized_keys from real file {realfile} to {dest_file}", system="cowrie")
                else:
                    # open(dest_file, "a").close()
                    # log.msg(f"[DEBUG][fs.py][update_size] Created empty authorized_keys at {dest_file} (no realfile linked)", system="cowrie")
                    with open(dest_file, "w") as f:
                        pass  # Properly create an empty file
                    #log.msg(f"[DEBUG][fs.py][update_size] Created empty authorized_keys at {dest_file} (no realfile linked)", system="cowrie")

            except Exception as e:
                log.err(f"[ERROR][fs.py][update_size] Error handling authorized_keys persistence: {e}", system="cowrie")





    def find_node(fs, path_components):
        """
        Find node given path components (e.g. ['bin', 'bash'])
        Returns node or None if not found
        """
        try:
            current = fs
            for name in path_components:
                if len(current) < 8 or not isinstance(current[7], list):
                    #log.msg(f"[DELTA] Path component '{name}' not found (not a directory)", system="cowrie")
                    return None
                    
                found = None
                for child in current[7]:
                    if child[0] == name:
                        found = child
                        break
                        
                if not found:
                    #log.msg(f"[DELTA] Path component '{name}' not found in directory", system="cowrie")
                    return None
                current = found
            
            return current
        except Exception as e:
            path = '/'.join(path_components)
            #log.msg(f"[DELTA] Error finding {path}: {str(e)}", system="cowrie")
            return None

    def generate_diffs(self,original, modified, current_path=None):
        """
        Generate differences between two filesystems with Cowrie logging
        Returns list of (action, path_parts, data)
        """
        try:
            if current_path is None:
                current_path = []
            
            diffs = []
            path_str = '/' + '/'.join(current_path)
            
            # Handle case where one exists and other doesn't
            if bool(original) != bool(modified):
                action = 'create' if modified else 'delete'
                #log.msg(f"[DELTA] Found {action} at {path_str}", system="cowrie")
                diffs.append((action, current_path.copy(), modified))
                return diffs
            
            # Compare metadata (indices 1-6)
            #for i in range(1, min(len(original), len(modified), 7)):
            for i in list(range(1, 7)) + [8, 9]:
                if original[i] != modified[i]:
                    #log.msg(f"[DELTA] Metadata changed at {path_str}: index {i} {original[i]}->{modified[i]}", system="cowrie")
                    diffs.append(('modify', current_path.copy(), {
                        'index': i,
                        'old': original[i],
                        'new': modified[i]
                    }))
            
            # Compare children if both are directories
            orig_children = original[7] if len(original) > 7 and isinstance(original[7], list) else []
            mod_children = modified[7] if len(modified) > 7 and isinstance(modified[7], list) else []
            
            orig_map = {child[0]: child for child in orig_children}
            mod_map = {child[0]: child for child in mod_children}
            
            # Check deleted
            for name in set(orig_map) - set(mod_map):
                full_path = path_str + '/' + name if path_str != '/' else path_str + name
                #log.msg(f"[DELTA] Found deletion at {full_path}", system="cowrie")
                diffs.append(('delete', current_path + [name], None))
            
            # Check created
            for name in set(mod_map) - set(orig_map):
                full_path = path_str + '/' + name if path_str != '/' else path_str + name
                #log.msg(f"[DELTA] Found creation at {full_path}", system="cowrie")
                diffs.append(('create', current_path + [name], mod_map[name]))
            
            # Check modified
            for name in set(orig_map) & set(mod_map):
                diffs.extend(self.generate_diffs(
                    orig_map[name], 
                    mod_map[name],
                    current_path + [name]
                ))
            
            return diffs
        except Exception as e:
            path = '/' + '/'.join(current_path) if current_path else '/'
            #log.msg(f"[DELTA] Error comparing {path}: {str(e)}", system="cowrie")
            return []

    def apply_diffs(self,base_fs, diffs):
        """
        Apply differences to base filesystem with Cowrie logging
        Returns new filesystem (doesn't modify original)
        """
        try:
            start_time = time.monotonic()
            fs = copy.deepcopy(base_fs)
            
            for action, path_parts, data in diffs:


                if time.monotonic() - start_time > 10:
                    #log.msg(f"[WARN] Applying diffs took too long (> 10 seconds), returning base filesystem", system="cowrie")
                    return copy.deepcopy(base_fs)
            

                path_str = '/' + '/'.join(path_parts) if path_parts else '/'
                
                # Navigate to parent
                parent = fs
                for part in path_parts[:-1]:
                    if len(parent) < 8:
                        #log.msg(f"[DELTA] Cannot navigate to {path_str} - parent not a directory", system="cowrie")
                        break
                    found = None
                    for child in parent[7]:
                        if child[0] == part:
                            found = child
                            break
                    if not found:
                        #log.msg(f"[DELTA] Parent path not found for {path_str}", system="cowrie")
                        break
                    parent = found
                else:
                    # Found parent, handle action
                    target_name = path_parts[-1] if path_parts else ''
                    
                    if action == 'create':
                        if len(parent) < 8:
                            parent.append([])  # Add children list
                        #log.msg(f"[DELTA] Applying creation at {path_str}", system="cowrie")
                        parent[7].append(data)
                        
                    elif action == 'delete':
                        if len(parent) >= 8:
                            #log.msg(f"[DELTA] Applying deletion at {path_str}", system="cowrie")
                            parent[7] = [c for c in parent[7] if c[0] != target_name]
                            
                    elif action == 'modify':
                        for child in parent[7]:
                            if child[0] == target_name:
                                idx = data['index']
                                if idx < len(child):
                                    #log.msg(f"[DELTA] Applying modification at {path_str} index {idx}", system="cowrie")
                                    child[idx] = data['new']
                                break
            
            return fs
        except Exception as e:
            #log.msg(f"[DELTA] Error applying differences: {str(e)}", system="cowrie")
            return copy.deepcopy(base_fs)  # Return unchanged copy on error


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
            log.msg(f"[DEBUG][fs.py][get_custom_download_path] Global persistence: {download_dir}", system="cowrie")
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
    

    def extract_username_from_authorized_keys(self, filename: str) -> str:
        """
        Extract username if the filename matches an authorized_keys path.
        Return the username or empty string if not found.
        """

        if filename.endswith("/.ssh/authorized_keys"):
            parts = [p for p in filename.split("/") if p]  # Split and ignore empty strings

            if len(parts) >= 3 and parts[0] == "home":
                return parts[1]  # /home/<user>/... ? return user
            elif len(parts) >= 2 and parts[0] == "root":
                return "root"
            else:
                #log.msg(f"[DEBUG][fs.py][extract_username_from_authorized_keys] Cannot determine username from path: {filename}", system="cowrie")
                return ""
        
        return ""
