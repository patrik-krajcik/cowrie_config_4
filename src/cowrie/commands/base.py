# Copyright (c) 2009 Upi Tamminen <desaster@gmail.com>
# See the COPYRIGHT file for more information

# coding=utf-8

from __future__ import annotations

import codecs
import datetime
import getopt
import random
import re
import time

from twisted.internet import error, reactor
from twisted.python import failure, log
from datetime import datetime, timedelta

from cowrie.core import utils
from cowrie.shell.command import HoneyPotCommand
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Callable

commands: dict[str, Callable] = {}


class Command_whoami(HoneyPotCommand):
    def call(self) -> None:
        self.write(f"{self.protocol.user.username}\n")


commands["/usr/bin/whoami"] = Command_whoami
commands["whoami"] = Command_whoami
commands["/usr/bin/users"] = Command_whoami
commands["users"] = Command_whoami


class Command_help(HoneyPotCommand):
    def call(self) -> None:
        self.write(
            """GNU bash, version 4.2.37(1)-release (x86_64-pc-linux-gnu)
These shell commands are defined internally.  Type `help' to see this list.
Type `help name' to find out more about the function `name'.
Use `info bash' to find out more about the shell in general.
Use `man -k' or `info' to find out more about commands not in this list.

A star (*) next to a name means that the command is disabled.

 job_spec [&]                                                                                   history [-c] [-d offset] [n] or history -anrw [filename] or history -ps arg [arg...]
 (( expression ))                                                                               if COMMANDS; then COMMANDS; [ elif COMMANDS; then COMMANDS; ]... [ else COMMANDS; ] fi
 . filename [arguments]                                                                         jobs [-lnprs] [jobspec ...] or jobs -x command [args]
 :                                                                                              kill [-s sigspec | -n signum | -sigspec] pid | jobspec ... or kill -l [sigspec]
 [ arg... ]                                                                                     let arg [arg ...]
 [[ expression ]]                                                                               local [option] name[=value] ...
 alias [-p] [name[=value] ... ]                                                                 logout [n]
 bg [job_spec ...]                                                                              mapfile [-n count] [-O origin] [-s count] [-t] [-u fd] [-C callback] [-c quantum] [array]
 bind [-lpvsPVS] [-m keymap] [-f filename] [-q name] [-u name] [-r keyseq] [-x keyseq:shell-c>  popd [-n] [+N | -N]
 break [n]                                                                                      printf [-v var] format [arguments]
 builtin [shell-builtin [arg ...]]                                                              pushd [-n] [+N | -N | dir]
 caller [expr]                                                                                  pwd [-LP]
 case WORD in [PATTERN [| PATTERN]...) COMMANDS ;;]... esac                                     read [-ers] [-a array] [-d delim] [-i text] [-n nchars] [-N nchars] [-p prompt] [-t timeout>
 cd [-L|[-P [-e]]] [dir]                                                                        readarray [-n count] [-O origin] [-s count] [-t] [-u fd] [-C callback] [-c quantum] [array]>
 command [-pVv] command [arg ...]                                                               readonly [-aAf] [name[=value] ...] or readonly -p
 compgen [-abcdefgjksuv] [-o option]  [-A action] [-G globpat] [-W wordlist]  [-F function] [>  return [n]
 complete [-abcdefgjksuv] [-pr] [-DE] [-o option] [-A action] [-G globpat] [-W wordlist]  [-F>  select NAME [in WORDS ... ;] do COMMANDS; done
 compopt [-o|+o option] [-DE] [name ...]                                                        set [-abefhkmnptuvxBCHP] [-o option-name] [--] [arg ...]
 continue [n]                                                                                   shift [n]
 coproc [NAME] command [redirections]                                                           shopt [-pqsu] [-o] [optname ...]
 declare [-aAfFgilrtux] [-p] [name[=value] ...]                                                 source filename [arguments]
 dirs [-clpv] [+N] [-N]                                                                         suspend [-f]
 disown [-h] [-ar] [jobspec ...]                                                                test [expr]
 echo [-neE] [arg ...]                                                                          time [-p] pipeline
 enable [-a] [-dnps] [-f filename] [name ...]                                                   times
 eval [arg ...]                                                                                 trap [-lp] [[arg] signal_spec ...]
 exec [-cl] [-a name] [command [arguments ...]] [redirection ...]                               true
 exit [n]                                                                                       type [-afptP] name [name ...]
 export [-fn] [name[=value] ...] or export -p                                                   typeset [-aAfFgilrtux] [-p] name[=value] ...
 false                                                                                          ulimit [-SHacdefilmnpqrstuvx] [limit]
 fc [-e ename] [-lnr] [first] [last] or fc -s [pat=rep] [command]                               umask [-p] [-S] [mode]
 fg [job_spec]                                                                                  unalias [-a] name [name ...]
 for NAME [in WORDS ... ] ; do COMMANDS; done                                                   unset [-f] [-v] [name ...]
 for (( exp1; exp2; exp3 )); do COMMANDS; done                                                  until COMMANDS; do COMMANDS; done
 function name { COMMANDS ; } or name () { COMMANDS ; }                                         variables - Names and meanings of some shell variables
 getopts optstring name [arg]                                                                   wait [id]
 hash [-lr] [-p pathname] [-dt] [name ...]                                                      while COMMANDS; do COMMANDS; done
 help [-dms] [pattern ...]                                                                      { COMMANDS ; }\n"""
        )


commands["help"] = Command_help


class Command_w(HoneyPotCommand):
    def call(self) -> None:
        self.write(
            " {} up {},  1 user,  load average: 0.00, 0.00, 0.00\n".format(
                time.strftime("%H:%M:%S"), utils.uptime(self.protocol.uptime())
            )
        )
        self.write(
            "USER     TTY      FROM              LOGIN@   IDLE   JCPU   PCPU WHAT\n"
        )
        self.write(
            "{:8s} pts/0    {} {}    0.00s  0.00s  0.00s w\n".format(
                self.protocol.user.username,
                self.protocol.clientIP[:17].ljust(17),
                time.strftime("%H:%M", time.localtime(self.protocol.logintime)),
            )
        )


commands["/usr/bin/w"] = Command_w
commands["w"] = Command_w


class Command_who(HoneyPotCommand):
    def call(self) -> None:
        self.write(
            "{:8s} pts/0        {} {} ({})\n".format(
                self.protocol.user.username,
                time.strftime("%Y-%m-%d", time.localtime(self.protocol.logintime)),
                time.strftime("%H:%M", time.localtime(self.protocol.logintime)),
                self.protocol.clientIP,
            )
        )


commands["/usr/bin/who"] = Command_who
commands["who"] = Command_who


class Command_echo(HoneyPotCommand):
    def call(self) -> None:
        newline = True
        escape_decode = False

        try:
            optlist, args = getopt.getopt(self.args, "eEn")
            for opt in optlist:
                if opt[0] == "-e":
                    escape_decode = True
                elif opt[0] == "-E":
                    escape_decode = False
                elif opt[0] == "-n":
                    newline = False
        except Exception:
            args = self.args

        try:
            # replace r'\\x' with r'\x'
            string = " ".join(args).replace(r"\\x", r"\x")

            # replace single character escape \x0 with \x00
            string = re.sub(
                r"(?<=\\)x([0-9a-fA-F])(?=\\|\"|\'|\s|$)", r"x0\g<1>", string
            )

            # if the string ends with \c escape, strip it and set newline flag to False
            if string.endswith("\\c"):
                string = string[:-2]
                newline = False

            if newline is True:
                string += "\n"

            if escape_decode:
                data: bytes = codecs.escape_decode(string)[0]  # type: ignore
                self.writeBytes(data)
            else:
                self.write(string)

        except ValueError:
            log.msg("echo command received Python incorrect hex escape")


commands["/bin/echo"] = Command_echo
commands["echo"] = Command_echo


class Command_printf(HoneyPotCommand):
    def call(self) -> None:
        if not self.args:
            self.write("printf: usage: printf [-v var] format [arguments]\n")
        else:
            if "-v" not in self.args and len(self.args) < 2:
                # replace r'\\x' with r'\x'
                s = "".join(self.args[0]).replace("\\\\x", "\\x")

                # replace single character escape \x0 with \x00
                s = re.sub(r"(?<=\\)x([0-9a-fA-F])(?=\\|\"|\'|\s|$)", r"x0\g<1>", s)

                # strip single and double quotes
                s = s.strip("\"'")

                # if the string ends with \c escape, strip it
                if s.endswith("\\c"):
                    s = s[:-2]

                data: bytes = codecs.escape_decode(s)[0]  # type: ignore
                self.writeBytes(data)


commands["/usr/bin/printf"] = Command_printf
commands["printf"] = Command_printf


class Command_clear(HoneyPotCommand):
    def call(self) -> None:
        self.protocol.terminal.reset()


commands["/usr/bin/clear"] = Command_clear
commands["clear"] = Command_clear
commands["/usr/bin/reset"] = Command_clear
commands["reset"] = Command_clear


class Command_hostname(HoneyPotCommand):
    def call(self) -> None:
        if self.args:
            if self.protocol.user.username == "root":
                self.protocol.hostname = self.args[0]
            else:
                self.write("hostname: you must be root to change the host name\n")
        else:
            self.write(f"{self.protocol.hostname}\n")


commands["/bin/hostname"] = Command_hostname
commands["hostname"] = Command_hostname


import random
from datetime import datetime, timedelta

class Command_ps(HoneyPotCommand):
    # Class-level cache for consistent process listing during session
    _process_cache = {}
    
    # Predefined process templates
    SYSTEM_PROCESSES = [
        # Kernel processes (always shown with PID < 100)
        {"USER": "root", "PID": 1, "COMMAND": "/sbin/init", "STAT": "Ss", "TTY": "?"},
        {"USER": "root", "PID": 2, "COMMAND": "[kthreadd]", "STAT": "S", "TTY": "?"},
        {"USER": "root", "PID": 3, "COMMAND": "[rcu_gp]", "STAT": "I<", "TTY": "?"},
        
        # System services (PID 100-500)
        {"USER": "root", "PID": 101, "COMMAND": "/lib/systemd/systemd-journald", "STAT": "Ss", "TTY": "?"},
        {"USER": "root", "PID": 102, "COMMAND": "/lib/systemd/systemd-udevd", "STAT": "Ss", "TTY": "?"},
        {"USER": "systemd+", "PID": 103, "COMMAND": "/lib/systemd/systemd-timesyncd", "STAT": "Ssl", "TTY": "?"},
        {"USER": "root", "PID": 104, "COMMAND": "/usr/sbin/cron -f", "STAT": "Ss", "TTY": "?"},
        {"USER": "root", "PID": 105, "COMMAND": "/usr/sbin/sshd -D", "STAT": "Ss", "TTY": "?"},
    ]
    
    TERMINAL_PROCESSES = [
        {"USER": "root", "COMMAND": "/bin/login -p --", "STAT": "Ss", "TTY": "tty1"},
        {"USER": "user", "COMMAND": "-bash", "STAT": "S+", "TTY": "tty1"},
        {"USER": "user", "COMMAND": "sudo su - user", "STAT": "S", "TTY": "pts/0"},
    ]
    
    USER_PROCESSES = [
        {"COMMAND": "vim file.txt", "STAT": "S", "TTY": "pts/0"},
        {"COMMAND": "top", "STAT": "S", "TTY": "pts/0"},
        {"COMMAND": "htop", "STAT": "S", "TTY": "pts/0"},
        {"COMMAND": "tail -f log.txt", "STAT": "S", "TTY": "pts/0"},
    ]
    
    def call(self) -> None:
        user = self.protocol.user.username
        args = self.args[0] if self.args else ""
        
        # Initialize cache for this session if not exists
        if not self._process_cache.get(self.protocol.sessionno):

            self._init_process_cache(user)
        
        # Get cached processes for this session
        processes = self._process_cache[self.protocol.sessionno]
        
        # Determine output format
        if "aux" in " ".join(self.args):
            self._show_processes(processes['aux'], user, "aux")
        elif "u" in args:
            self._show_processes(processes['u'], user, "u")
        #elif "f" in args:
            #self._show_processes(processes['f'], user, "f")
        elif "a" in args:
            self._show_processes(processes['a'], user, "a")
        elif "x" in args:
            self._show_processes(processes['x'], user, "x")
        elif "w" in args:
            self._show_processes(processes['w'], user, "w")
        else:
            self._show_processes(processes['minimal'], user, "minimal")

    def _init_process_cache(self, user):
        """Initialize process cache for this session with consistent but dynamic processes"""
        session_id = self.protocol.sessionno

        now = datetime.now()
        hour_min = now.strftime("%H:%M")
        random_days_ago = (now - timedelta(days=random.randint(0, 30))).strftime("%b%d")
        
        # Generate base PIDs for this session
        base_pid = random.randint(320, 350)
        user_pid = base_pid + 1
        ps_pid = base_pid + 2
        
        # Common process attributes
        common_attrs = {
            "START": hour_min,
            "%CPU": round(random.uniform(0.0, 0.2), 1),
            "%MEM": round(random.uniform(0.1, 0.3), 1),
            "VSZ": random.randint(8000, 9000),
            "RSS": random.randint(4000, 6000),
        }
        # Create SSH parent process

        sshd_process = {
            "USER": "root",
            "PID": base_pid,
            "COMMAND": f"/usr/sbin/sshd: {user}@pts/0",
            "STAT": "Ss",
            "TTY": "?",
            "TIME": "0:00",
            **common_attrs,
            "VSZ": random.randint(17000, 18000),
            "RSS": random.randint(6000, 7000),
        }
        
        # Create system processes with some randomness
        system_processes = self._generate_system_processes(random_days_ago)
        
        # Create terminal processes with some randomness
        terminal_processes = self._generate_terminal_processes(user, hour_min)
        
        # Create user processes with some randomness
        user_processes = self._generate_user_processes(user, hour_min)
        
        # Create minimal processes (always shown)
        
        minimal_processes = [
            {
                "USER": user,
                "PID": user_pid,
                "COMMAND": "-bash",
                "STAT": "Ss",
                "TTY": "pts/0",
                "TIME": "0:00",
                **common_attrs
            },
            {
                "USER": user,
                "PID": ps_pid,
                "COMMAND": "ps" + (" " + " ".join(self.args) if self.args else ""),
                "STAT": "R+",
                "TTY": "pts/0",
                "TIME": "0:00",
                **common_attrs
            }
        ]

        minimal_processes_long = [
            {
                "USER": user,
                "PID": user_pid,
                "COMMAND": "-bash",
                "STAT": "Ss",
                "TTY": "pts/0",
                "TIME": "00:00:00",
                **common_attrs
            },
            {
                "USER": user,
                "PID": ps_pid,
                "COMMAND": "ps" + (" " + " ".join(self.args) if self.args else ""),
                "STAT": "R+",
                "TTY": "pts/0",
                "TIME": "00:00:00",
                **common_attrs
            }
        ]

        
        
        # Build different views
        self._process_cache[session_id] = {
            # Minimal - just current shell and ps
            'minimal': minimal_processes_long,
            
            # ps a - processes with terminals
            'a': [sshd_process] + terminal_processes + minimal_processes,
            
            # ps x - processes without controlling terminal + current
            'x': system_processes + minimal_processes,

            'w': [p for p in (system_processes + minimal_processes) if p["TTY"] != "?"],
            
            # ps u - user-oriented format
            'u': [sshd_process] + user_processes + minimal_processes,
            
            # ps aux - everything
            'aux': system_processes + terminal_processes + [sshd_process] + user_processes + minimal_processes,
            
            # ps f - forest format
           # 'f': self._build_process_tree(user, base_pid, hour_min)
        }

    def _generate_system_processes(self, start_time):
        """Generate system processes with some randomness"""
        processes = []
        
        # Always include core system processes
        for proc in self.SYSTEM_PROCESSES:
            processes.append({
                **proc,
                "%CPU": round(random.uniform(0.0, 0.1), 1),
                "%MEM": round(random.uniform(0.1, 0.5), 1),
                "VSZ": random.randint(10000, 200000),
                "RSS": random.randint(1000, 15000),
                "TIME": "0:00",
                "START": start_time
            })
        
        # Add some random kernel processes
        kernel_procs = [
            "[kworker/0:0]", "[kworker/1:0]", "[kworker/2:0]", "[kworker/3:0]",
            "[ksoftirqd/0]", "[ksoftirqd/1]", "[ksoftirqd/2]", "[ksoftirqd/3]",
            "[migration/0]", "[migration/1]", "[migration/2]", "[migration/3]",
            "[rcu_sched]", "[rcu_bh]", "[watchdog/0]", "[watchdog/1]"
        ]
        
        for i in range(random.randint(5, 10)):
            pid = random.randint(10, 99)
            processes.append({
                "USER": "root",
                "PID": pid,
                "COMMAND": random.choice(kernel_procs),
                "STAT": random.choice(["S", "I<", "D<", "I"]),
                "TTY": "?",
                "%CPU": 0.0,
                "%MEM": 0.0,
                "VSZ": 0,
                "RSS": 0,
                "TIME": "0:00",
                "START": start_time
            })
        
        return processes

    def _generate_terminal_processes(self, user, start_time):
        """Generate terminal-related processes with some randomness"""
        processes = []
        
        # Always include some terminal processes
        for proc in self.TERMINAL_PROCESSES:
            processes.append({
                **proc,
                "USER": proc["USER"].replace("user", user),
                "PID": random.randint(200, 250),
                "%CPU": round(random.uniform(0.0, 0.2), 1),
                "%MEM": round(random.uniform(0.1, 0.3), 1),
                "VSZ": random.randint(5000, 10000),
                "RSS": random.randint(2000, 5000),
                "TIME": "0:00",
                "START": start_time
            })
        
        # Add some random terminal processes
        if random.random() > 0.5:
            processes.append({
                "USER": user,
                "PID": random.randint(251, 300),
                "COMMAND": random.choice(["sudo", "su", "screen", "tmux"]),
                "STAT": random.choice(["S", "S+", "Sl"]),
                "TTY": random.choice(["pts/1", "pts/2"]),
                "%CPU": round(random.uniform(0.0, 0.1), 1),
                "%MEM": round(random.uniform(0.1, 0.2), 1),
                "VSZ": random.randint(5000, 8000),
                "RSS": random.randint(2000, 4000),
                "TIME": "0:00",
                "START": start_time
            })
        
        return processes

    def _generate_user_processes(self, user, start_time):
        """Generate user processes with some randomness"""
        processes = []
        
        # Add some random user processes
        for proc in random.sample(self.USER_PROCESSES, random.randint(1, 3)):
            processes.append({
                **proc,
                "USER": user,
                "PID": random.randint(300, 350),
                "%CPU": round(random.uniform(0.0, 0.5), 1),
                "%MEM": round(random.uniform(0.1, 0.5), 1),
                "VSZ": random.randint(5000, 15000),
                "RSS": random.randint(2000, 6000),
                "TIME": f"0:{random.randint(0, 59):02d}",
                "START": start_time
            })
        
        return processes

    def _build_process_tree(self, user, base_pid, start_time):
        """Build process tree for forest format"""
        return [
            {
                "USER": "root",
                "PID": base_pid,
                "PPID": random.randint(500, 600),
                "C": 0,
                "STIME": start_time,
                "TTY": "?",
                "TIME": "00:00:00",
                "CMD": f"/usr/sbin/sshd: {user}@pts/0"
            },
            {
                "USER": user,
                "PID": base_pid + 1,
                "PPID": base_pid,
                "C": 0,
                "STIME": start_time,
                "TTY": "pts/0",
                "TIME": "00:00:00",
                "CMD": "-bash"
            },
            {
                "USER": user,
                "PID": base_pid + 2,
                "PPID": base_pid + 1,
                "C": 0,
                "STIME": start_time,
                "TTY": "pts/0",
                "TIME": "00:00:00",
                "CMD": "ps" + (" " + " ".join(self.args) if self.args else "")
            }
        ]

    def _show_processes(self, processes, user, format_type):
        """Display processes in the appropriate format"""
        processes = sorted(processes, key=lambda x: x["PID"])
                    
        
        if processes:
            processes[-1]["COMMAND"] = "ps" + (" " + " ".join(self.args) if self.args else "")

        if format_type in ['aux', 'u']:
            self._show_user_format(processes)
        #elif format_type == 'f':
            #self._show_forest_format(processes)
        elif format_type in ['a', 'x','w']:
            self._show_system_format(processes)
        else:  # minimal or w
            self._show_minimal_format(processes, wide=False)

    def _show_user_format(self, processes):
        """Show in USER format (for ps u and ps aux)"""
        self.write("USER         PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND\n")
        for p in processes:
            self.write("{user:<10} {pid:>5} {cpu:>4} {mem:>4} {vsz:>6} {rss:>5} {tty:<8} {stat:<4} {start:<5} {time:>6} {cmd}\n".format(
                user=p["USER"],
                pid=p["PID"],
                cpu=p.get("%CPU", 0.0),
                mem=p.get("%MEM", 0.0),
                vsz=p.get("VSZ", 0),
                rss=p.get("RSS", 0),
                tty=p["TTY"],
                stat=p["STAT"],
                start=p["START"],
                time=p["TIME"],
                cmd=p["COMMAND"]
            ))

    def _show_forest_format(self, processes):
        """Show in forest format (ps f)"""
        self.write("UID        PID  PPID  C STIME TTY          TIME CMD\n")
        for p in processes:
            self.write("{user:<6} {pid:>6} {ppid:>5} {c:>2} {stime:<5} {tty:<12} {time:>7} {cmd}\n".format(
                user=p["USER"],
                pid=p["PID"],
                ppid=p["PPID"],
                c=p["C"],
                stime=p["STIME"],
                tty=p["TTY"],
                time=p["TIME"],
                cmd=p["CMD"]
            ))

    def _show_system_format(self, processes):
        """Show in system format (ps a and ps x)"""
        self.write("    PID TTY      STAT   TIME COMMAND\n")
        for p in processes:
            self.write("{pid:>7} {tty:<6} {stat:>6} {time:>6} {cmd}\n".format(
                pid=p["PID"],
                tty=p["TTY"],
                stat=p["STAT"],
                time=p["TIME"],
                cmd=p["COMMAND"]
            ))

    def _show_minimal_format(self, processes, wide=False):
        """Show minimal format (default ps and ps w)"""
        self.write("    PID TTY          TIME CMD\n")
        for p in processes:
            line = "{pid:>7} {tty:<8} {time} {cmd}".format(
                pid=p["PID"],
                tty=p["TTY"],
                time=p["TIME"],
                cmd=p["COMMAND"]
            )
                    
            # Handle width
            term_width = int(self.environ.get("COLUMNS", 132 if wide else 80))
            if len(line) > term_width:
                line = line[:term_width]
            
            self.write(line + "\n")

commands["/bin/ps"] = Command_ps
commands["ps"] = Command_ps


class Command_id(HoneyPotCommand):
    def call(self) -> None:
        u = self.protocol.user
        self.write(
            f"uid={u.uid}({u.username}) gid={u.gid}({u.username}) groups={u.gid}({u.username})\n"
        )


commands["/usr/bin/id"] = Command_id
commands["id"] = Command_id


class Command_passwd(HoneyPotCommand):
    def start(self) -> None:
        self.write(f"Changing password for {self.protocol.user.username}.\n")
        self.write("Current password: ")
        self.protocol.password_input = True
        self.state = 'current'
        self.attempts = 0
        self.max_attempts = 3
        self.callbacks = [
            self.check_current_password,
            self.get_new_password,
            self.verify_new_password
        ]

    def check_current_password(self, line: str) -> None:
        # Always accept current password in honeypot
        self.write("New password: ")
        self.state = 'new'

    def get_new_password(self, line: str) -> None:
        if not line.strip():
            self.write("Bad: new password cannot be empty\n")
            self.write("New password: ")
            return
            
        self.new_password = line.strip()
        self.write("Retype new password: ")
        self.state = 'verify'

    def verify_new_password(self, line: str) -> None:
        if line.strip() != self.new_password:
            self.attempts += 1
            if self.attempts >= self.max_attempts:
                self.write("Sorry, passwords do not match\n")
                self.write("passwd: Authentication token manipulation error\n")
                self.write("passwd: password unchanged\n")
                self.protocol.password_input = False
                self.exit()
                return
            
            self.write("Sorry, passwords do not match\n")
            self.write("New password: ")
            self.state = 'new'
            # Reset the callback chain
            self.callbacks = [
                self.get_new_password,
                self.verify_new_password
            ]
        else:
            # Successful password change
            if random.random() < 0.3:  # 30% chance of fake failure
                self.write("The password has not been changed.\n")
                self.write("New password: ")
                self.state = 'new'
                self.callbacks = [
                    self.get_new_password,
                    self.verify_new_password
                ]
            else:
                self.write("passwd: password updated successfully\n")
                self.protocol.password_input = False
                self.exit()

    def handle_CTRL_C(self) -> None:
        self.write("^C")
        self.protocol.password_input = False
        self.write("passwd: Authentication token manipulation error\n")
        self.write("passwd: password unchanged\n")
        self.exit()

    def lineReceived(self, line: str) -> None:
        log.msg(
            eventid="cowrie.command.success",
            realm="passwd",
            input=line,
            format="INPUT (%(realm)s): %(input)s",
        )
        
        if not self.callbacks:
            return
            
        callback = self.callbacks[0]
        callback(line.strip())
        
        # Only pop if we're moving to next state
        if (self.state == 'current' and line.strip()) or \
           (self.state == 'new' and line.strip()) or \
           (self.state == 'verify' and line.strip() == getattr(self, 'new_password', None)):
            self.callbacks.pop(0)

commands["/usr/bin/passwd"] = Command_passwd
commands["passwd"] = Command_passwd


class Command_shutdown(HoneyPotCommand):
    def start(self) -> None:
        if self.args and self.args[0].strip().count("--help"):
            output = [
                "Usage:     shutdown [-akrhHPfnc] [-t secs] time [warning message]",
                "-a:      use /etc/shutdown.allow ",
                "-k:      don't really shutdown, only warn. ",
                "-r:      reboot after shutdown. ",
                "-h:      halt after shutdown. ",
                "-P:      halt action is to turn off power. ",
                "-H:      halt action is to just halt. ",
                "-f:      do a 'fast' reboot (skip fsck). ",
                "-F:      Force fsck on reboot. ",
                '-n:      do not go through "init" but go down real fast. ',
                "-c:      cancel a running shutdown. ",
                "-t secs: delay between warning and kill signal. ",
                '** the "time" argument is mandatory! (try "now") **',
            ]
            for line in output:
                self.write(f"{line}\n")
            self.exit()
        elif (
            len(self.args) > 1
            and self.args[0].strip().count("-h")
            and self.args[1].strip().count("now")
        ):
            self.write("\n")
            self.write(
                f"Broadcast message from root@{self.protocol.hostname} (pts/0) ({time.ctime()}):\n"
            )
            self.write("\n")
            self.write("The system is going down for maintenance NOW!\n")
            reactor.callLater(3, self.finish)  # type: ignore[attr-defined]
        elif (
            len(self.args) > 1
            and self.args[0].strip().count("-r")
            and self.args[1].strip().count("now")
        ):
            self.write("\n")
            self.write(
                f"Broadcast message from root@{self.protocol.hostname} (pts/0) ({time.ctime()}):\n"
            )
            self.write("\n")
            self.write("The system is going down for reboot NOW!\n")
            reactor.callLater(3, self.finish)  # type: ignore[attr-defined]
        else:
            self.write("Try `shutdown --help' for more information.\n")
            self.exit()

    def finish(self) -> None:
        stat = failure.Failure(error.ProcessDone(status=""))
        self.protocol.terminal.transport.processEnded(stat)


commands["/sbin/shutdown"] = Command_shutdown
commands["shutdown"] = Command_shutdown
commands["/sbin/poweroff"] = Command_shutdown
commands["poweroff"] = Command_shutdown
commands["/sbin/halt"] = Command_shutdown
commands["halt"] = Command_shutdown


class Command_reboot(HoneyPotCommand):
    def start(self) -> None:
        self.write("\n")
        self.write(
            f"Broadcast message from root@{self.protocol.hostname} (pts/0) ({time.ctime()}):\n\n"
        )
        self.write("The system is going down for reboot NOW!\n")
        reactor.callLater(3, self.finish)  # type: ignore[attr-defined]

    def finish(self) -> None:
        stat = failure.Failure(error.ProcessDone(status=""))
        self.protocol.terminal.transport.processEnded(stat)


commands["/sbin/reboot"] = Command_reboot
commands["reboot"] = Command_reboot


class Command_history(HoneyPotCommand):
    def call(self) -> None:
        try:
            if self.args and self.args[0] == "-c":
                self.protocol.historyLines = []
                self.protocol.historyPosition = 0
                return
            count = 1
            for line in self.protocol.historyLines:
                self.write(f" {str(count).rjust(4)}  {line}\n")
                count += 1
        except Exception:
            # Non-interactive shell, do nothing
            pass


commands["history"] = Command_history


class Command_date(HoneyPotCommand):
    def call(self) -> None:
        time = datetime.datetime.utcnow()
        self.write("{}\n".format(time.strftime("%a %b %d %H:%M:%S UTC %Y")))


commands["/bin/date"] = Command_date
commands["date"] = Command_date


class Command_yes(HoneyPotCommand):
    def start(self) -> None:
        self.y()

    def y(self) -> None:
        if self.args:
            self.write("{}\n".format(" ".join(self.args)))
        else:
            self.write("y\n")
        self.scheduled = reactor.callLater(0.01, self.y)  # type: ignore[attr-defined]

    def handle_CTRL_C(self) -> None:
        self.scheduled.cancel()
        self.exit()


commands["/usr/bin/yes"] = Command_yes
commands["yes"] = Command_yes


class Command_php(HoneyPotCommand):
    HELP = (
        "Usage: php [options] [-f] <file> [--] [args...]\n"
        "       php [options] -r <code> [--] [args...]\n"
        "       php [options] [-B <begin_code>] -R <code> [-E <end_code>] [--] [args...]\n"
        "       php [options] [-B <begin_code>] -F <file> [-E <end_code>] [--] [args...]\n"
        "       php [options] -- [args...]\n"
        "       php [options] -a\n"
        "\n"
        "  -a               Run interactively\n"
        "  -c <path>|<file> Look for php.ini file in this directory\n"
        "  -n               No php.ini file will be used\n"
        "  -d foo[=bar]     Define INI entry foo with value 'bar'\n"
        "  -e               Generate extended information for debugger/profiler\n"
        "  -f <file>        Parse and execute <file>.\n"
        "  -h               This help\n"
        "  -i               PHP information\n"
        "  -l               Syntax check only (lint)\n"
        "  -m               Show compiled in modules\n"
        "  -r <code>        Run PHP <code> without using script tags <?..?>\n"
        "  -B <begin_code>  Run PHP <begin_code> before processing input lines\n"
        "  -R <code>        Run PHP <code> for every input line\n"
        "  -F <file>        Parse and execute <file> for every input line\n"
        "  -E <end_code>    Run PHP <end_code> after processing all input lines\n"
        "  -H               Hide any passed arguments from external tools.\n"
        "  -s               Output HTML syntax highlighted source.\n"
        "  -v               Version number\n"
        "  -w               Output source with stripped comments and whitespace.\n"
        "  -z <file>        Load Zend extension <file>.\n"
        "\n"
        "  args...          Arguments passed to script. Use -- args when first argument\n"
        "                   starts with - or script is read from stdin\n"
        "\n"
        "  --ini            Show configuration file names\n"
        "\n"
        "  --rf <name>      Show information about function <name>.\n"
        "  --rc <name>      Show information about class <name>.\n"
        "  --re <name>      Show information about extension <name>.\n"
        "  --ri <name>      Show configuration for extension <name>.\n"
        "\n"
    )

    VERSION = "PHP 5.3.5 (cli)\n" "Copyright (c) 1997-2010 The PHP Group\n"

    def start(self) -> None:
        if self.args:
            if self.args[0] == "-v":
                self.write(Command_php.VERSION)
            elif self.args[0] == "-h":
                self.write(Command_php.HELP)
            self.exit()

    def lineReceived(self, line: str) -> None:
        log.msg(
            eventid="cowrie.command.success",
            realm="php",
            input=line,
            format="INPUT (%(realm)s): %(input)s",
        )

    def handle_CTRL_D(self) -> None:
        self.exit()


commands["/usr/bin/php"] = Command_php
commands["php"] = Command_php


class Command_chattr(HoneyPotCommand):
    def call(self) -> None:
        if len(self.args) < 1:
            self.write("Usage: chattr [-RVf] [-+=AacDdeijsSu] [-v version] files...\n")
            return
        elif len(self.args) < 2:
            self.write("Must use '-v', =, - or +'\n")
            return
        if not self.fs.exists(self.args[1]):
            self.write(
                "chattr: No such file or directory while trying to stat "
                + self.args[1]
                + "\n"
            )


commands["/usr/bin/chattr"] = Command_chattr
commands["chattr"] = Command_chattr


class Command_set(HoneyPotCommand):
    # Basic functionaltly (show only), need enhancements
    # This will show ALL environ vars, not only the global ones
    # With enhancements it should work like env when -o posix is used
    def call(self) -> None:
        for i in sorted(list(self.environ.keys())):
            self.write(f"{i}={self.environ[i]}\n")


commands["set"] = Command_set


class Command_nop(HoneyPotCommand):
    def call(self) -> None:
        pass


commands["umask"] = Command_nop
commands["unset"] = Command_nop
commands["export"] = Command_nop
commands["alias"] = Command_nop
commands["jobs"] = Command_nop
commands["kill"] = Command_nop
commands["/bin/kill"] = Command_nop
commands["/bin/pkill"] = Command_nop
commands["/bin/killall"] = Command_nop
commands["/bin/killall5"] = Command_nop
commands["/bin/su"] = Command_nop
commands["su"] = Command_nop
commands["/bin/chown"] = Command_nop
commands["chown"] = Command_nop
commands["/bin/chgrp"] = Command_nop
commands["chgrp"] = Command_nop
commands["/usr/bin/chattr"] = Command_nop
commands["chattr"] = Command_nop
commands[":"] = Command_nop
commands["do"] = Command_nop
commands["done"] = Command_nop
