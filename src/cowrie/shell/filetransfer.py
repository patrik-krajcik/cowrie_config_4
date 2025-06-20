# Copyright (c) 2009-2014 Upi Tamminen <desaster@gmail.com>
# See the COPYRIGHT file for more information

"""
This module contains ...
"""

from __future__ import annotations

import os

from zope.interface import implementer

import twisted
import twisted.conch.ls
from twisted.conch.interfaces import ISFTPFile, ISFTPServer
from twisted.conch.ssh import filetransfer
from twisted.conch.ssh.filetransfer import (
    FXF_APPEND,
    FXF_CREAT,
    FXF_EXCL,
    FXF_READ,
    FXF_TRUNC,
    FXF_WRITE,
)
from twisted.python import log
from twisted.python.compat import nativeString

from cowrie.shell import pwd
from cowrie.core.config import CowrieConfig
from cowrie.core.utils import validate_realfile


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

@implementer(ISFTPFile)
class CowrieSFTPFile:
    """
    SFTPTFile
    """ 

    contents: bytes
    bytesReceivedLimit: int = CowrieConfig.getint(
        "honeypot", "download_limit_size", fallback=0
    )

    def __init__(self, sftpserver, filename, flags, attrs):
        log.msg(f"[DEBUG][filetransfer.py][CowrieSFTPFile.__init__] Initializing SFTP file for: {filename} with flags={flags}", system="cowrie")

        self.sftpserver = sftpserver
        self.filename = filename
        self.bytesReceived: int = 0

        openFlags = 0
        if flags & FXF_READ == FXF_READ and flags & FXF_WRITE == 0:
            openFlags = os.O_RDONLY
        if flags & FXF_WRITE == FXF_WRITE and flags & FXF_READ == 0:
            openFlags = os.O_WRONLY
        if flags & FXF_WRITE == FXF_WRITE and flags & FXF_READ == FXF_READ:
            openFlags = os.O_RDWR
        if flags & FXF_APPEND == FXF_APPEND:
            openFlags |= os.O_APPEND
        if flags & FXF_CREAT == FXF_CREAT:
            openFlags |= os.O_CREAT
        if flags & FXF_TRUNC == FXF_TRUNC:
            openFlags |= os.O_TRUNC
        if flags & FXF_EXCL == FXF_EXCL:
            openFlags |= os.O_EXCL

        log.msg(f"[DEBUG][filetransfer.py][CowrieSFTPFile.__init__] Calculated openFlags: {openFlags}", system="cowrie")

        if "permissions" in attrs:
            filemode = attrs["permissions"]
            del attrs["permissions"]
        else:
            filemode = 0o777

        log.msg(f"[DEBUG][filetransfer.py][CowrieSFTPFile.__init__] Opening file with mode: {oct(filemode)}", system="cowrie")

        fd = sftpserver.fs.open(filename, openFlags, filemode)
        if attrs:
            log.msg(f"[DEBUG][filetransfer.py][CowrieSFTPFile.__init__] Setting additional file attributes: {attrs}", system="cowrie")
            self.sftpserver.setAttrs(filename, attrs)
        self.fd = fd

        # Cache a copy of file in memory to read from in readChunk
        if flags & FXF_READ == FXF_READ:
            self.contents = self.sftpserver.fs.file_contents(self.filename)
            log.msg(f"[DEBUG][filetransfer.py][CowrieSFTPFile.__init__] Loaded file contents for reading ({len(self.contents)} bytes)", system="cowrie")


    def close(self):
        if self.bytesReceived > 0:
            log.msg(f"[DEBUG][filetransfer.py][CowrieSFTPFile.close] Updating file size for {self.filename}: +{self.bytesReceived} bytes", system="cowrie")
            self.sftpserver.fs.update_size(self.filename, self.bytesReceived)
        log.msg(f"[DEBUG][filetransfer.py][CowrieSFTPFile.close] Closing file {self.filename}", system="cowrie")
        return self.sftpserver.fs.close(self.fd)

    def readChunk(self, offset: int, length: int) -> bytes:
        log.msg(f"[DEBUG][filetransfer.py][CowrieSFTPFile.readChunk] Reading {length} bytes at offset {offset} from {self.filename}", system="cowrie")
        return self.contents[offset : offset + length]

    def writeChunk(self, offset: int, data: bytes) -> None:
        log.msg(f"[DEBUG][filetransfer.py][CowrieSFTPFile.writeChunk] Writing {len(data)} bytes at offset {offset} to {self.filename}", system="cowrie")
        self.bytesReceived += len(data)
        if self.bytesReceivedLimit and self.bytesReceived > self.bytesReceivedLimit:
            log.msg("[WARN][filetransfer.py][CowrieSFTPFile.writeChunk] Download quota exceeded, raising error", system="cowrie")
            raise filetransfer.SFTPError(filetransfer.FX_FAILURE, "Quota exceeded")
        self.sftpserver.fs.lseek(self.fd, offset, os.SEEK_SET)
        self.sftpserver.fs.write(self.fd, data)

    def getAttrs(self):
        log.msg(f"[DEBUG][filetransfer.py][CowrieSFTPFile.getAttrs] Getting file attributes for {self.filename}", system="cowrie")
        s = self.sftpserver.fs.stat(self.filename)
        return self.sftpserver.getAttrs(s)

    def setAttrs(self, attrs):
        log.msg(f"[DEBUG][filetransfer.py][CowrieSFTPFile.setAttrs] setAttrs() not implemented - attempted with attrs: {attrs}", system="cowrie")
        raise NotImplementedError


class CowrieSFTPDirectory:
    def __init__(self, server, directory):
        log.msg(f"[DEBUG][filetransfer.py][CowrieSFTPDirectory.__init__] Opening SFTP directory: {directory}", system="cowrie")
        self.server = server
        self.files = server.fs.listdir(directory)
        self.files = [".", "..", *self.files]
        self.fileiter = iter(self.files)  # <-- ADD THIS LINE!
        self.dir = directory
        log.msg(f"[DEBUG][filetransfer.py][CowrieSFTPDirectory.__init__] Directory contents: {self.files}", system="cowrie")


    def __iter__(self):
        return self

    def __next__(self):
        try:
            f = next(self.fileiter)
            
            # Handle virtual files mapping
            files_to_check = [
                ("/etc/passwd", 0),
                ("/etc/group", 1)
            ]
            
            real_paths = [None, None]
            for virtual_path, index in files_to_check:
                file_obj = self.server.fs.getfile(virtual_path, follow_symlinks=False)
                if file_obj is not None and file_obj[A_TYPE] == T_FILE:
                    validate_realfile(file_obj)
                    real_paths[index] = file_obj[A_REALFILE]
                    log.msg(f"[FS] Mapped {virtual_path} to {real_paths[index]}", system="cowrie")

            # Handle special directory entries
            if f == "..":
                dir_components = [x for x in self.dir.strip().split("/") if x]
                pdir = "/" + "/".join(dir_components[:-1]) if len(dir_components) > 1 else "/"
                
                try:
                    s = self.server.fs.lstat(pdir)
                    s1 = self.server.fs.lstat(pdir)
                    
                    # Get owner/group names from mapped files
                    owner_name = "root"
                    group_name = "root"
                    if real_paths[0]:
                        with open(real_paths[0]) as passwd:
                            for line in passwd:
                                if f"::{s.st_uid}:" in line:
                                    owner_name = line.split(":")[0]
                                    break
                    if real_paths[1]:
                        with open(real_paths[1]) as group:
                            for line in group:
                                if f":{s.st_gid}:" in line:
                                    group_name = line.split(":")[0]
                                    break
                    
                    s1.st_uid = owner_name
                    s1.st_gid = group_name
                    longname = twisted.conch.ls.lsLine(f, s1)
                    attrs = self.server._getAttrs(s)
                    
                    log.msg(f"[SFTP] '..' entry for {pdir}, owner={owner_name}, group={group_name}", system="cowrie")
                    return (f, longname, attrs)
                    
                except Exception as e:
                    log.msg(f"[SFTP] Error processing '..': {str(e)}", system="cowrie")
                    raise StopIteration

            elif f == ".":
                try:
                    s = self.server.fs.lstat(self.dir)
                    s1 = self.server.fs.lstat(self.dir)
                    
                    # Get owner/group names
                    owner_name = "root"
                    group_name = "root"
                    if real_paths[0]:
                        with open(real_paths[0]) as passwd:
                            for line in passwd:
                                if f"::{s.st_uid}:" in line:
                                    owner_name = line.split(":")[0]
                                    break
                    if real_paths[1]:
                        with open(real_paths[1]) as group:
                            for line in group:
                                if f":{s.st_gid}:" in line:
                                    group_name = line.split(":")[0]
                                    break
                    
                    s1.st_uid = owner_name
                    s1.st_gid = group_name
                    longname = twisted.conch.ls.lsLine(f, s1)
                    attrs = self.server._getAttrs(s)
                    
                    log.msg(f"[SFTP] '.' entry for {self.dir}, owner={owner_name}, group={group_name}", system="cowrie")
                    return (f, longname, attrs)
                    
                except Exception as e:
                    log.msg(f"[SFTP] Error processing '.': {str(e)}", system="cowrie")
                    raise StopIteration

            else:
                # Regular file entry
                try:
                    fullpath = os.path.join(self.dir, str(f))  # Ensure f is string
                    s = self.server.fs.lstat(fullpath)
                    s2 = self.server.fs.lstat(fullpath)
                    
                    # Get owner/group names
                    owner_name = "root"
                    group_name = "root"
                    if real_paths[0]:
                        with open(real_paths[0]) as passwd:
                            for line in passwd:
                                if f"::{s.st_uid}:" in line:
                                    owner_name = line.split(":")[0]
                                    break
                    if real_paths[1]:
                        with open(real_paths[1]) as group:
                            for line in group:
                                if f":{s.st_gid}:" in line:
                                    group_name = line.split(":")[0]
                                    break
                    
                    s2.st_uid = owner_name
                    s2.st_gid = group_name
                    longname = twisted.conch.ls.lsLine(f, s2)
                    attrs = self.server._getAttrs(s)
                    
                    log.msg(f"[SFTP] Entry '{f}' at {fullpath}, owner={owner_name}, group={group_name}", system="cowrie")
                    return (f, longname, attrs)
                    
                except Exception as e:
                    log.msg(f"[SFTP] Error processing '{f}': {str(e)}", system="cowrie")
                    raise StopIteration

        except StopIteration:
            raise
        except Exception as e:
            log.msg(f"[SFTP] Error in directory iteration: {str(e)}", system="cowrie")
            raise StopIteration

    def close(self):
        log.msg(f"[DEBUG][filetransfer.py][CowrieSFTPDirectory.close] Closing directory: {self.dir}", system="cowrie")
        self.files = []


    # Check if file exists in virtual FS and get its real path
    def get_virtual_file_path(self, virtual_path):
        """Returns real path if file exists in virtual FS, None otherwise"""
        f = self.server.fs.getfile(virtual_path, follow_symlinks=False)
        if f is not None and f[A_TYPE] == T_FILE:  # Explicit None check
            return f[A_REALPATH]  # Assuming this is where real path is stored
        return None


@implementer(ISFTPServer)
class SFTPServerForCowrieUser:
    def __init__(self, avatar):
        log.msg(f"[DEBUG][filetransfer.py][SFTPServerForCowrieUser.__init__] Initializing SFTP server for user: {avatar.username}", system="cowrie")
        self.avatar = avatar
        self.avatar.server.initFileSystem(self.avatar.home,"",self.avatar.real_ip)

        if self.avatar.first_time  : 
            log.msg(f"[DEBUG][filetransfer.py][__init__] Creating temporary home directory: {self.avatar.home}", system="cowrie")
            self.avatar.server.fs.mkdir(self.avatar.home, self.avatar.uid, self.avatar.gid, 4096, 16877)
            ssh_dir = self.avatar.home + "/.ssh"
            self.server.fs.mkdir(ssh_dir, self.uid, self.gid, 4096, 16832)
            
        self.fs = self.avatar.server.fs

        if self.avatar.first_time :
                self.avatar._map_special_files()

    def _absPath(self, path):
        home = self.avatar.home
        abspath = os.path.abspath(os.path.join(nativeString(home), nativeString(path)))
        log.msg(f"[DEBUG][filetransfer.py][SFTPServerForCowrieUser._absPath] Resolved absolute path: {path} -> {abspath}", system="cowrie")
        return abspath

    def _setAttrs(self, path, attrs):
        log.msg(f"[DEBUG][filetransfer.py][SFTPServerForCowrieUser._setAttrs] Setting attrs on {path}: {attrs}", system="cowrie")
        if "uid" in attrs and "gid" in attrs:
            self.fs.chown(path, attrs["uid"], attrs["gid"])
        if "permissions" in attrs:
            self.fs.chmod(path, attrs["permissions"])
        if "atime" in attrs and "mtime" in attrs:
            self.fs.utime(path, attrs["atime"], attrs["mtime"])

    def _getAttrs(self, s):
        attrs = {
            "size": s.st_size,
            "uid": s.st_uid,
            "gid": s.st_gid,
            "permissions": s.st_mode,
            "atime": int(s.st_atime),
            "mtime": int(s.st_mtime),
        }
        log.msg(f"[DEBUG][filetransfer.py][SFTPServerForCowrieUser._getAttrs] Fetched attrs: {attrs}", system="cowrie")
        return attrs

    def gotVersion(self, otherVersion, extData):
        return {}

    def openFile(self, filename, flags, attrs):
        log.msg(f"SFTP openFile: {filename}")        
        log.msg(f"[DEBUG][filetransfer.py][SFTPServerForCowrieUser.openFile] Opening file: {filename} with flags={flags} and attrs={attrs}", system="cowrie")
        return CowrieSFTPFile(self, self._absPath(filename), flags, attrs)

    def removeFile(self, filename):
        log.msg(f"SFTP removeFile: {filename}")        
        log.msg(f"[DEBUG][filetransfer.py][SFTPServerForCowrieUser.removeFile] Removing file: {filename}", system="cowrie")
        return self.fs.remove(self._absPath(filename))

    def renameFile(self, oldpath, newpath):
        log.msg(f"SFTP renameFile: {oldpath} {newpath}")        
        log.msg(f"[DEBUG][filetransfer.py][SFTPServerForCowrieUser.renameFile] Renaming file: {oldpath} -> {newpath}", system="cowrie")
        return self.fs.rename(self._absPath(oldpath), self._absPath(newpath))

    def makeDirectory(self, path, attrs):
        log.msg(f"SFTP makeDirectory: {path}")
        log.msg(f"[DEBUG][filetransfer.py][SFTPServerForCowrieUser.makeDirectory] Creating directory: {path}", system="cowrie")
        path = self._absPath(path)
        self.fs.mkdir2(path)
        self._setAttrs(path, attrs)

    def removeDirectory(self, path):
        log.msg(f"SFTP removeDirectory: {path}")
        log.msg(f"[DEBUG][filetransfer.py][SFTPServerForCowrieUser.removeDirectory] Removing directory: {path}", system="cowrie")
        return self.fs.rmdir(self._absPath(path))

    def openDirectory(self, path):
        log.msg(f"SFTP OpenDirectory: {path}")
        log.msg(f"[DEBUG][filetransfer.py][SFTPServerForCowrieUser.openDirectory] Opening directory: {path}", system="cowrie")
        return CowrieSFTPDirectory(self, self._absPath(path))

    def getAttrs(self, path, followLinks):
        log.msg(f"SFTP getAttrs: {path}")
        log.msg(f"[DEBUG][filetransfer.py][SFTPServerForCowrieUser.getAttrs] Getting attributes for: {path} (followLinks={followLinks})", system="cowrie")
        path = self._absPath(path)
        if followLinks:
            s = self.fs.stat(path)
        else:
            s = self.fs.lstat(path)
        return self._getAttrs(s)

    def setAttrs(self, path, attrs):
        log.msg(f"SFTP setAttrs: {path}")
        log.msg(f"[DEBUG][filetransfer.py][SFTPServerForCowrieUser.setAttrs] Setting attributes for: {path} -> {attrs}", system="cowrie")
        path = self._absPath(path)
        return self._setAttrs(path, attrs)

    def readLink(self, path):
        log.msg(f"SFTP readLink: {path}")
        log.msg(f"[DEBUG][filetransfer.py][SFTPServerForCowrieUser.readLink] Reading symlink: {path}", system="cowrie")
        path = self._absPath(path)
        return self.fs.readlink(path)

    def makeLink(self, linkPath, targetPath):
        log.msg(f"SFTP makeLink: {linkPath} {targetPath}")
        log.msg(f"[DEBUG][filetransfer.py][SFTPServerForCowrieUser.makeLink] Creating symlink: {linkPath} -> {targetPath}", system="cowrie")
        linkPath = self._absPath(linkPath)
        targetPath = self._absPath(targetPath)
        return self.fs.symlink(targetPath, linkPath)

    def realPath(self, path):
        log.msg(f"[DEBUG][filetransfer.py][SFTPServerForCowrieUser.realPath] Resolving real path for: {path}", system="cowrie")
        return self.fs.realpath(self._absPath(path))

    def extendedRequest(self, extName, extData):
        log.msg(f"[DEBUG][filetransfer.py][SFTPServerForCowrieUser.extendedRequest] Unsupported extended request: {extName}", system="cowrie")
        raise NotImplementedError
