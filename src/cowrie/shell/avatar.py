# Copyright (c) 2009-2014 Upi Tamminen <desaster@gmail.com>
# See the COPYRIGHT file for more information


from __future__ import annotations

from zope.interface import implementer

from twisted.conch import avatar
from twisted.conch.error import ConchError
from twisted.conch.interfaces import IConchUser, ISession, ISFTPServer
from twisted.conch.ssh import filetransfer as conchfiletransfer
from twisted.conch.ssh.connection import OPEN_UNKNOWN_CHANNEL_TYPE
from twisted.python import components, log

from cowrie.core.config import CowrieConfig
from cowrie.shell import filetransfer, pwd
from cowrie.shell import session as shellsession
from cowrie.shell import server
from cowrie.ssh import forwarding
from cowrie.ssh import session as sshsession

import os
import shutil
import random
from hashlib import md5
from pathlib import Path

import string
import crypt
from datetime import datetime


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


@implementer(IConchUser)
class CowrieUser(avatar.ConchUser):
    def __init__(self, username: bytes, server: server.CowrieServer, ip) -> None:
        #log.msg(f"[DEBUG][avatar.py][CowrieUser.__init__] Initializing CowrieUser for username: {username}", system="cowrie")
        #log.msg(f"[DEBUG][avatar.py][CowrieUser.__init__] Initializing CowrieUser for ip: {ip}", system="cowrie")


        avatar.ConchUser.__init__(self)
        self.username: str = username.decode("utf-8")
        self.server = server
        


        #log.msg("[DEBUG][avatar.py][CowrieUser.__init__] Setting default channelLookup to HoneyPotSSHSession", system="cowrie")
        self.channelLookup[b"session"] = sshsession.HoneyPotSSHSession
        
        self.temp_files = []
        self.real_ip = ip
        self.ip = ip.replace('.', '_')

        #this is how we get the modes
        #CowrieConfig.getboolean("shell", "persistent_global", fallback=False) 
        #CowrieConfig.getboolean("shell", "persistent_per_ip", fallback=False)
        # This is how we check the mode if both of them are false then its working normally, if one of them is true then we use that mode respectively. Their directories are here var/lib/cowrie/filesystems/ and here there is one directory for global and one for each ip but like this 10_180_15_10 without.
        # The modes means this global - saves file state for everyone - they share one; per ip - only attackers from same ip share directory
        # And i want the flow to work like this and use these names of variables self.server.fs.first_time - we will check if they are connecting for the first_time. for default mode its always first since it resets after each connection
        # If first_time is true and if both modes are false : we will make temporary files for group passwd shadow in var/lib/cowrie/temp_user_files in this format ip=10_11_12_13 ip_passwd ip_group ip_shadow ip2_passwd....; these files will be removed after the session ends. we will copy files from 
        # honeyfs/etc/passwd... they will serve as template and we will just add one record for current user in all these files shadow: david:$6$VGmCSy9Y$QnryWI8rx5bz0JleV1gtfP8JCUmeMcD2Oa7AylzCHP97lZfgL9SPaOq8UMHQzTbXGvQ2vPrr7Gz5qO9EZbRMG.:15800:0:99999:7:::
        # passwd : phil:x:1000:1000:Phil California,,,:/home/phil:/bin/bash; there is no need for name or something random can be doesnt matter
        # group : david:x:1002: here is important that the same user has same id in passwd and group
        # if first_time is true but one of the modes is True we will create these files in var/lib/cowrie/filesystems/global or ip respectively. they can be named normally passwd, group, shadow since they are all in own directories not like for default mode. and we will also add record for current user
        # if not first time - it automatically means that we have mode per ip or global; we will try to load files if they exist; if not we will create them normally as before with added record but they should exist beforehand. we will try to find the user there. if user is not there we will add him there
        # just in case somebody from same ip connected via different user 
        # its important that IDs not repeat in one file of passwd


        self.persistent_global = CowrieConfig.getboolean("shell", "persistent_global", fallback=False)
        self.persistent_per_ip = CowrieConfig.getboolean("shell", "persistent_per_ip", fallback=False)
        #log.msg(f"[DEBUG][avatar.py] persistent_global: {self.persistent_global}", system="cowrie")
        #log.msg(f"[DEBUG][avatar.py] persistent_per_ip: {self.persistent_per_ip}", system="cowrie") 
        
        if not (self.persistent_global or self.persistent_per_ip):
            self.mode = 'default'
        elif self.persistent_global:
            self.mode = 'global'
        else:
            self.mode = 'perip'

        #log.msg(f"[DEBUG][avatar.py] Filesystem mode selected: {self.mode}", system="cowrie")

        # TODO PRILEZITOS PRE SQL
        self.first_time = True

        #elf._check_first_time()
        #log.msg(f"[DEBUG][avatar.py] Assuming first time: {self.first_time}", system="cowrie")

        try:
            
            if self.first_time:
                #log.msg("[DEBUG][avatar.py] First time detected - initializing filesystem", system="cowrie")
                self._initialize_filesystem()


            pwentry = self._get_or_create_user()

            #log.msg(f"[DEBUG][avatar.py] User entry loaded or created: {pwentry}", system="cowrie")

            self.uid = pwentry["pw_uid"]
            self.gid = pwentry["pw_gid"]
            self.home = pwentry["pw_dir"]
            
            #log.msg(f"[DEBUG][avatar.py] UID set to: {self.uid}", system="cowrie")

            #log.msg(f"[DEBUG][avatar.py] GID set to: {self.gid}", system="cowrie")
            #log.msg(f"[DEBUG][avatar.py] Home directory set to: {self.home}", system="cowrie")

        
        except Exception as e:
            log.msg(f"[ERROR][avatar.py] New filesystem failed: {str(e)} - falling back to legacy", system="cowrie")
            # Fallback to original implementation

            self.first_time = False

            try:
                log.msg("[DEBUG][avatar.py][CowrieUser.__init__] Attempting to get existing user from passwd", system="cowrie")
                pwentry = pwd.Passwd().getpwnam(self.username)
                self.first_time = False
                log.msg("[DEBUG][avatar.py][CowrieUser.__init__] Found existing user entry", system="cowrie")
            except KeyError:
                log.msg("[DEBUG][avatar.py][CowrieUser.__init__] User not found, creating new temporary passwd entry", system="cowrie")
                pwentry = pwd.Passwd().setpwentry(self.username)
                self.first_time = True

            self.uid = pwentry["pw_uid"]
            self.gid = pwentry["pw_gid"]
            self.home = pwentry["pw_dir"]

            log.msg(f"[DEBUG][avatar.py][CowrieUser.__init__] User context: uid={self.uid}, gid={self.gid}, home={self.home}, temporary={self.first_time}", system="cowrie")


        # SFTP support enabled only when option is explicitly set
        if CowrieConfig.getboolean("ssh", "sftp_enabled", fallback=False):
            self.subsystemLookup[b"sftp"] = conchfiletransfer.FileTransferServer
            #log.msg("[DEBUG][avatar.py][CowrieUser.__init__] SFTP support enabled and registered", system="cowrie")


        # SSH forwarding disabled only when option is explicitly set
        if CowrieConfig.getboolean("ssh", "forwarding", fallback=True):
            self.channelLookup[b"direct-tcpip"] = (
                forwarding.cowrieOpenConnectForwardingClient
            )
            #log.msg("[DEBUG][avatar.py][CowrieUser.__init__] SSH forwarding enabled and registered", system="cowrie")


    def logout(self) -> None:
        #log.msg(f"[DEBUG][avatar.py][CowrieUser.logout] User '{self.username}' is logging out", system="cowrie")
        self.server.fs.save_fs_delta()
        self.cleanup()

        log.msg(f"avatar {self.username} logging out")

    def lookupChannel(self, channelType, windowSize, maxPacket, data):
        """
        Override this to get more info on the unknown channel
        """
        #log.msg(f"[DEBUG][avatar.py][CowrieUser.lookupChannel] Received request to open channel: {channelType}", system="cowrie")

        klass = self.channelLookup.get(channelType, None)
        if not klass:
            #log.msg(f"[DEBUG][avatar.py][CowrieUser.lookupChannel] Unknown channel type requested: {channelType}", system="cowrie")

            raise ConchError(
                OPEN_UNKNOWN_CHANNEL_TYPE, f"unknown channel: {channelType}"
            )
        else:
            #log.msg(f"[DEBUG][avatar.py][CowrieUser.lookupChannel] Resolved channel class: {klass.__name__}", system="cowrie")
            return klass(
                remoteWindow=windowSize,
                remoteMaxPacket=maxPacket,
                data=data,
                avatar=self,
            )


    def _initialize_filesystem(self):
            """Create necessary files based on mode"""
            #log.msg(f"[DEBUG][avatar.py][_initialize_filesystem] Initializing filesystem for mode: {self.mode}", system="cowrie")
            base_files = ['passwd', 'group', 'shadow']
            
            if self.mode == 'default':
                target_dir = 'var/lib/cowrie/temp_user_files'
                os.makedirs(target_dir, exist_ok=True)
                #log.msg(f"[DEBUG][avatar.py][_initialize_filesystem] Created directory: {target_dir}", system="cowrie")
                
                for fname in base_files:
                    src = f'honeyfs/etc/{fname}'
                    dst = f'{target_dir}/{self.ip}_{fname}'
                    shutil.copy(src, dst)
                    self.temp_files.append(dst)
                    #log.msg(f"[DEBUG][avatar.py][_initialize_filesystem] Copied {src} to {dst}", system="cowrie")
                    
            else:  # global or perip mode
                if self.mode == 'global':
                    target_dir = 'var/lib/cowrie/filesystems/global'
                    file_prefix = ''
                else:
                    target_dir = f'var/lib/cowrie/filesystems/{self.ip}'
                    file_prefix = ''
                
                os.makedirs(target_dir, exist_ok=True)
                #log.msg(f"[DEBUG][avatar.py][_initialize_filesystem] Created directory: {target_dir}", system="cowrie")
                
                for fname in base_files:
                    src = f'honeyfs/etc/{fname}'
                    dst = f'{target_dir}/{file_prefix}{fname}'
                    if not os.path.exists(dst):
                        shutil.copy(src, dst)
                        #log.msg(f"[DEBUG][avatar.py][_initialize_filesystem] Copied {src} to {dst}", system="cowrie")
                    self.temp_files.append(dst)

    def _get_or_create_user(self): # TODO AK NEEXISTUJE
        """Get existing user or create new entry with unique IDs"""
        #log.msg(f"[DEBUG][avatar.py][_get_or_create_user] Checking if user exists or needs creation", system="cowrie")

        # Determine which files to use
        if self.mode == 'default':
            file_prefix = f'var/lib/cowrie/temp_user_files/{self.ip}_'
        elif self.mode == 'global':
            file_prefix = 'var/lib/cowrie/filesystems/global/'
        else:  # perip
            file_prefix = f'var/lib/cowrie/filesystems/{self.ip}/'
        
        files = {
            'passwd': f'{file_prefix}passwd',
            'group': f'{file_prefix}group',
            'shadow': f'{file_prefix}shadow'
        }
        
        # Check if user exists
        user_entry = self._find_user_in_passwd(files['passwd'])
        if user_entry:
            #log.msg(f"[DEBUG][avatar.py][_get_or_create_user] Found existing user: {user_entry['pw_name']}", system="cowrie")
            self.first_time = False
            return user_entry
            
        # Create new user with unique IDs
        #log.msg(f"[DEBUG][avatar.py][_get_or_create_user] No existing user found, creating new one", system="cowrie")
        return self._add_user_to_files(files)

    def _find_user_in_passwd(self, passwd_file):
        #log.msg(f"[DEBUG][avatar.py][_find_user_in_passwd] Looking for user in {passwd_file}", system="cowrie")
        """Check if user exists in passwd file"""
        try:
            with open(passwd_file) as f:
                for line in f:
                    if line.startswith(f'{self.username}:'):
                        parts = line.strip().split(':')
                        #log.msg(f"[DEBUG][avatar.py][_find_user_in_passwd] User found: {parts[0]}", system="cowrie")

                        return {
                            'pw_name': parts[0],
                            'pw_uid': int(parts[2]),
                            'pw_gid': int(parts[3]),
                            'pw_dir': parts[5]
                        }
        except FileNotFoundError:
            log.msg(f"[DEBUG][avatar.py][_find_user_in_passwd] File not found: {passwd_file}", system="cowrie")
        return None

    def _add_user_to_files(self, files):
        """Add new user to all files with perfect newline handling"""
        #log.msg(f"[DEBUG] Adding new user to files", system="cowrie")
        
        # Generate unique IDs (existing code)
        base_id = int(md5(self.username.encode()).hexdigest()[:8], 16) % 50000
        uid = gid = base_id + 1500
        while (self._id_exists_in_file(uid, files['passwd']) or 
            self._id_exists_in_file(gid, files['group'])):
            uid = gid = random.randint(1500, 10000)

        # Prepare entries
        entries = {
            'passwd': f"{self.username}:x:{uid}:{gid}::/home/{self.username}:/bin/bash",
            'group': f"{self.username}:x:{gid}:{self.username}",
            'shadow': self._generate_shadow_entry(self.username)  # Use random generator
        }

        for file_type, entry in entries.items():
            file_path = files[file_type]
            
            # Read existing content and clean empty lines
            try:
                with open(file_path, 'r') as f:
                    lines = [line.strip() for line in f.readlines() if line.strip()]
            except FileNotFoundError:
                lines = []
            
            # Add new entry
            lines.append(entry)
            
            # Write back with perfect formatting
            with open(file_path, 'w') as f:
                f.write('\n'.join(lines) + '\n')  # Exactly one newline between records
        
        #log.msg(f"[USER] Created user {self.username} (UID:{uid})", system="cowrie")
        return {
            'pw_name': self.username,
            'pw_uid': uid,
            'pw_gid': gid,
            'pw_dir': f"/home/{self.username}"
        }

    def _id_exists_in_file(self, id, filename):
        """Check if ID exists in given file"""
        try:
            with open(filename) as f:
                for line in f:
                    parts = line.strip().split(':')
                    if len(parts) > 2 and int(parts[2]) == id:
                        return True
        except FileNotFoundError:
            pass
        return False
    

    def _map_special_files(self):
        #log.msg(f"[DEBUG][avatar.py][_map_special_files] Mapping virtual files to real paths", system="cowrie")
        """Map virtual paths to real paths for special files with fallback to honeyfs"""
        special_files = {
            '/etc/passwd': None,
            '/etc/group': None,
            '/etc/shadow': None
        }

        # Determine the real paths based on mode
        if self.mode == 'default':
            base_dir = 'var/lib/cowrie/temp_user_files'
            for virtual_path in special_files:
                filename = virtual_path.split('/')[-1]  # passwd, group, shadow
                special_files[virtual_path] = f"{base_dir}/{self.ip}_{filename}"
        elif self.mode == 'global':
            base_dir = 'var/lib/cowrie/filesystems/global'
            for virtual_path in special_files:
                filename = virtual_path.split('/')[-1]
                special_files[virtual_path] = f"{base_dir}/{filename}"
        else:  # perip
            base_dir = f'var/lib/cowrie/filesystems/{self.ip}'
            for virtual_path in special_files:
                filename = virtual_path.split('/')[-1]
                special_files[virtual_path] = f"{base_dir}/{filename}"

        # Update the filesystem mappings
        for virtual_path in special_files:
            # First try the custom path
            real_path = special_files[virtual_path]
            if not os.path.exists(real_path) or os.path.islink(real_path) or not os.path.isfile(real_path):
                # Fall back to honeyfs
                real_path = f"honeyfs{virtual_path}"
                log.msg(
                    f"[FS] Using honeyfs fallback for {virtual_path}",
                    system="cowrie"
                )

            f = self.server.fs.getfile(virtual_path, follow_symlinks=False)

            if f and f[A_TYPE] == T_FILE:
                #log.msg(f"[DEBUG][avatar.py][mapping_realfile] Linking real file '{real_path}'", system="cowrie")
                f[A_REALFILE] = real_path

    def cleanup(self):
        """Remove temporary files (default mode only)"""
        if self.mode == 'default':
            for f in self.temp_files:
                try:
                    os.unlink(f)
                except OSError:
                    log.msg(f"[CLEANUP] Failed to remove {f}", system="cowrie")


    def _check_first_time(self):
        """Determine if this is the first time based on mode and delta.pickle existence"""
        if self.mode == 'default':
            # Always first_time in default mode (resets each session)
            self.first_time = True
        else:
            # For global/perip modes, check delta.pickle existence
            if self.mode == 'global':
                delta_path = Path('var/lib/cowrie/filesystems/global/delta.pickle')
            else:  # perip mode
                delta_path = Path(f'var/lib/cowrie/filesystems/{self.ip}/delta.pickle')
            
            # first_time is True if delta.pickle doesn't exist
            self.first_time = not delta_path.exists()
        
        log.msg(
            f"[FS] Mode: {self.mode}, first_time: {self.first_time}",
            system="cowrie"
        )

    def _generate_shadow_entry(self, username):
        """Generate random shadow entry with proper salted SHA-512 hash"""
        # Generate random 16-character salt
        salt_chars = string.ascii_letters + string.digits + './'
        salt = '$6$' + ''.join(random.choice(salt_chars) for _ in range(16))
        
        # Generate random password hash (doesn't need to match actual password)
        password_hash = crypt.crypt(str(random.randint(0, 1000000)), salt)
        
        # Generate random but realistic dates
        last_change = (datetime.now() - datetime(1970,1,1)).days - random.randint(0, 90)
        min_days = 0
        max_days = 99999
        warn_days = random.randint(7, 14)
        inactive_days = random.randint(0, 30)
        expire_date = ''
    
        return f"{username}:{password_hash}:{last_change}:{min_days}:{max_days}:{warn_days}:{inactive_days}:{expire_date}"

log.msg("[DEBUG][avatar.py] Registering ISFTPServer adapter for CowrieUser", system="cowrie")
components.registerAdapter(filetransfer.SFTPServerForCowrieUser, CowrieUser, ISFTPServer)

log.msg("[DEBUG][avatar.py] Registering ISession adapter for CowrieUser", system="cowrie")
components.registerAdapter(shellsession.SSHSessionForCowrieUser, CowrieUser, ISession)
