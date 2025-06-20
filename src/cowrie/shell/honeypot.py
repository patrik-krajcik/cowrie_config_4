# Copyright (c) 2009-2014 Upi Tamminen <desaster@gmail.com>
# See the COPYRIGHT file for more information


from __future__ import annotations

import copy
import os
import re
import shlex
from typing import Any

from twisted.internet import error
from twisted.python import failure, log
from twisted.python.compat import iterbytes

from cowrie.core.config import CowrieConfig
from cowrie.shell import fs
from cowrie.shell import protocol


class HoneyPotShell:
    def __init__(
        self, protocol: Any, interactive: bool = True, redirect: bool = False
    ) -> None:

        #log.msg("[DEBUG][honeypot.py][__init__] Initializing HoneyPotShell", system="cowrie")
        self.protocol = protocol
        self.interactive: bool = interactive
        self.redirect: bool = redirect  # to support output redirection
        self.cmdpending: list[list[str]] = []
        self.environ: dict[str, str] = copy.copy(protocol.environ)
        if hasattr(protocol.user, "windowSize"):
            self.environ["COLUMNS"] = str(protocol.user.windowSize[1])
            self.environ["LINES"] = str(protocol.user.windowSize[0])
        self.lexer: shlex.shlex | None = None

        # this is the first prompt after starting
        self.showPrompt()

    def lineReceived(self, line: str) -> None:
        #log.msg(f"[DEBUG][honeypot.py][lineReceived] Line received: {line}", system="cowrie")
        log.msg(eventid="cowrie.command.input", input=line, format="CMD: %(input)s")
        self.lexer = shlex.shlex(instream=line, punctuation_chars=True, posix=True)
        # Add these special characters that are not in the default lexer
        self.lexer.wordchars += "@%{}=$:+^,()`"

        tokens: list[str] = []

        while True:
            try:
                tokkie: str | None = self.lexer.get_token()
                # log.msg("tok: %s" % (repr(tok)))
                #log.msg(f"[DEBUG][honeypot.py][lineReceived] Token parsed: {tokkie}", system="cowrie")

                if tokkie is None:  # self.lexer.eof put None for mypy
                    if tokens:
                        #log.msg(f"[DEBUG][honeypot.py][lineReceived] Appending final token list: {tokens}", system="cowrie")
                        self.cmdpending.append(tokens)
                    break
                else:
                    tok: str = tokkie

                # For now, treat && and || same as ;, just execute without checking return code
                if tok == "&&" or tok == "||":
                    if tokens:
                        #log.msg(f"[DEBUG][honeypot.py][lineReceived] Encountered {tok}, running pending tokens: {tokens}", system="cowrie")
                        self.cmdpending.append(tokens)
                        tokens = []
                        continue
                    else:
                        self.protocol.terminal.write(
                            f"-bash: syntax error near unexpected token `{tok}'\n".encode()
                        )
                        #log.msg(f"[ERROR][honeypot.py][lineReceived] Syntax error on unexpected token: {tok}", system="cowrie")
                        break
                elif tok == ";":
                    if tokens:
                        #log.msg(f"[DEBUG][honeypot.py][lineReceived] Semicolon encountered, appending: {tokens}", system="cowrie")
                        self.cmdpending.append(tokens)
                        tokens = []
                    continue
                elif tok == "$?":
                    tok = "0"
                elif tok[0] == "(":
                    #log.msg(f"[DEBUG][honeypot.py][lineReceived] Command substitution triggered on: {tok}", system="cowrie")
                    cmd = self.do_command_substitution(tok)
                    tokens = cmd.split()
                    continue
                elif "$(" in tok or "`" in tok:
                    #log.msg(f"[DEBUG][honeypot.py][lineReceived] Inline command substitution in token: {tok}", system="cowrie")
                    tok = self.do_command_substitution(tok)
                elif tok.startswith("${"):
                    #log.msg(f"[DEBUG][honeypot.py][lineReceived] Environment var substitution (curly braces): {tok}", system="cowrie")
                    envRex = re.compile(r"^\${([_a-zA-Z0-9]+)}$")
                    envSearch = envRex.search(tok)
                    if envSearch is not None:
                        envMatch = envSearch.group(1)
                        if envMatch in list(self.environ.keys()):
                            tok = self.environ[envMatch]
                        else:
                            #log.msg(f"[DEBUG][honeypot.py][lineReceived] Unknown env var: {envMatch}, skipping token", system="cowrie")
                            continue
                elif tok.startswith("$"):
                    #log.msg(f"[DEBUG][honeypot.py][lineReceived] Environment var substitution (dollar): {tok}", system="cowrie")
                    envRex = re.compile(r"^\$([_a-zA-Z0-9]+)$")
                    envSearch = envRex.search(tok)
                    if envSearch is not None:
                        envMatch = envSearch.group(1)
                        if envMatch in list(self.environ.keys()):
                            tok = self.environ[envMatch]
                        else:
                            #log.msg(f"[DEBUG][honeypot.py][lineReceived] Unknown env var: {envMatch}, skipping token", system="cowrie")
                            continue

                tokens.append(tok)
            except Exception as e:
                #log.msg(f"[ERROR][honeypot.py][lineReceived] Exception while parsing line: {e}", system="cowrie")
                self.protocol.terminal.write(
                    b"-bash: syntax error: unexpected end of file\n"
                )
                # Could run runCommand here, but i'll just clear the list instead
                log.msg(f"exception: {e}")
                self.cmdpending = []
                self.showPrompt()
                return

        if self.cmdpending:
            #log.msg(f"[DEBUG][honeypot.py][lineReceived] Running parsed command(s): {self.cmdpending}", system="cowrie")
            # if we have a complete command, go and run it
            self.runCommand()
        else:
            #log.msg(f"[DEBUG][honeypot.py][lineReceived] No command to run, showing prompt again", system="cowrie")
            # if there's no command, display a prompt again
            self.showPrompt()

    def do_command_substitution(self, start_tok: str) -> str:
        """
        this performs command substitution, like replace $(ls) `ls`
        """
        #log.msg(f"[DEBUG][honeypot.py][do_command_substitution] Starting command substitution for: {start_tok}", system="cowrie")

        result = ""
        if start_tok[0] == "(":
            # start parsing the (...) expression
            cmd_expr = start_tok
            pos = 1
            log.msg("[DEBUG][honeypot.py][do_command_substitution] Detected bare () command substitution", system="cowrie")

        elif "$(" in start_tok:
            # split the first token to prefix and $(... part
            dollar_pos = start_tok.index("$(")
            result = start_tok[:dollar_pos]
            cmd_expr = start_tok[dollar_pos:]
            pos = 2
            #log.msg(f"[DEBUG][honeypot.py][do_command_substitution] Detected $(...) command substitution, prefix: {result}", system="cowrie")

        elif "`" in start_tok:
            # split the first token to prefix and `... part
            backtick_pos = start_tok.index("`")
            result = start_tok[:backtick_pos]
            cmd_expr = start_tok[backtick_pos:]
            pos = 1
            #log.msg(f"[DEBUG][honeypot.py][do_command_substitution] Detected backtick command substitution, prefix: {result}", system="cowrie")

        else:
            #log.msg(f"[WARN][honeypot.py][do_command_substitution] Unrecognized substitution: {start_tok}", system="cowrie")
            log.msg(f"failed command substitution: {start_tok}")
            return start_tok

        opening_count = 1
        closing_count = 0

        # parse the remaining tokens and execute subshells
        while opening_count > closing_count:
            if cmd_expr[pos] in (")", "`"):
                # found an end of $(...) or `...`
                closing_count += 1
                if opening_count == closing_count:
                    #log.msg(f"[DEBUG][honeypot.py][do_command_substitution] Substitution bounds found: {cmd_expr[:pos+1]}", system="cowrie")
                    if cmd_expr[0] == "(":
                        # execute the command in () and print to user
                        self.protocol.terminal.write(
                            self.run_subshell_command(cmd_expr[: pos + 1]).encode()
                        )
                    else:
                        # execute the command in $() or `` and return the output
                        result += self.run_subshell_command(cmd_expr[: pos + 1])

                    # check whether there are more command substitutions remaining
                    if pos < len(cmd_expr) - 1:
                        remainder = cmd_expr[pos + 1 :]
                        #log.msg(f"[DEBUG][honeypot.py][do_command_substitution] Handling command remainder: {remainder}", system="cowrie")

                        if "$(" in remainder or "`" in remainder:
                            result = self.do_command_substitution(result + remainder)
                        else:
                            result += remainder
                else:
                    pos += 1
            elif cmd_expr[pos : pos + 2] == "$(":
                # found a new $(...) expression
                opening_count += 1
                pos += 2
                #log.msg("[DEBUG][honeypot.py][do_command_substitution] Nested $(...) detected", system="cowrie")

            else:
                if opening_count > closing_count and pos == len(cmd_expr) - 1:
                    if self.lexer:
                        tokkie = self.lexer.get_token()
                        if tokkie is None:  # self.lexer.eof put None for mypy
                            break
                        else:
                            cmd_expr = cmd_expr + " " + tokkie
                            #log.msg(f"[DEBUG][honeypot.py][do_command_substitution] Extended cmd_expr: {cmd_expr}", system="cowrie")

                elif opening_count == closing_count:
                    result += cmd_expr[pos]
                pos += 1

        #log.msg(f"[DEBUG][honeypot.py][do_command_substitution] Final substitution result: {result}", system="cowrie")
        return result

    def run_subshell_command(self, cmd_expr: str) -> str:
        # extract the command from $(...) or `...` or (...) expression
        if cmd_expr.startswith("$("):
            cmd = cmd_expr[2:-1]
        else:
            cmd = cmd_expr[1:-1]

        #log.msg(f"[DEBUG][honeypot.py][run_subshell_command] Running subshell command: {cmd}", system="cowrie")


        # instantiate new shell with redirect output
        self.protocol.cmdstack.append(
            HoneyPotShell(self.protocol, interactive=False, redirect=True)
        )
        # call lineReceived method that indicates that we have some commands to parse
        self.protocol.cmdstack[-1].lineReceived(cmd)
        # and remove the shell
        res = self.protocol.cmdstack.pop()

        try:
            output: str
            if cmd_expr.startswith("("):
                output = res.protocol.pp.redirected_data.decode()
            else:
                # trailing newlines are stripped for command substitution
                output = res.protocol.pp.redirected_data.decode().rstrip("\n")

            #log.msg(f"[DEBUG][honeypot.py][run_subshell_command] Subshell output: {output}", system="cowrie")

        except AttributeError:
            log.msg("[ERROR][honeypot.py][run_subshell_command] Subshell output missing", system="cowrie")
            return ""

        else:
            return output

    def runCommand(self):
        pp = None

        def runOrPrompt() -> None:
            if self.cmdpending:
                #log.msg("[DEBUG][honeypot.py][runCommand] Pending command found, running next.", system="cowrie")
                self.runCommand()
            else:
                #log.msg("[DEBUG][honeypot.py][runCommand] No pending command, showing prompt.", system="cowrie")
                self.showPrompt()

        def parse_arguments(arguments: list[str]) -> list[str]:
            #log.msg(f"[DEBUG][honeypot.py][runCommand][parse_arguments] Raw arguments: {arguments}", system="cowrie")
            parsed_arguments = []
            for arg in arguments:
                parsed_arguments.append(arg)

            return parsed_arguments

        def parse_file_arguments(arguments: str) -> list[str]:
            #log.msg(f"[DEBUG][honeypot.py][runCommand][parse_file_arguments] Argument: {arguments}", system="cowrie")

            """
            Look up arguments in the file system
            """
            parsed_arguments = []
            for arg in arguments:
                matches = self.protocol.fs.resolve_path_wc(arg, self.protocol.cwd)
                if matches:
                    #log.msg(f"[DEBUG][honeypot.py][runCommand][parse_file_arguments] Resolved {arg} to {matches}", system="cowrie")
                    parsed_arguments.extend(matches)
                else:
                    #log.msg(f"[DEBUG][honeypot.py][runCommand][parse_file_arguments] No match for {arg}, keeping original", system="cowrie")
                    parsed_arguments.append(arg)

            return parsed_arguments

        if not self.cmdpending:
            if self.protocol.pp.next_command is None:  # command dont have pipe(s)
                #log.msg("[DEBUG][honeypot.py][runCommand] No command pending and not part of pipe, checking interactive mode.", system="cowrie")
                if self.interactive:
                    #log.msg("[DEBUG][honeypot.py][runCommand] Interactive shell, showing prompt.", system="cowrie")
                    self.showPrompt()
                else:
                    # when commands passed to a shell via PIPE, we spawn a HoneyPotShell in none interactive mode
                    # if there are another shells on stack (cmdstack), let's just exit our new shell
                    # else close connection
                    if len(self.protocol.cmdstack) == 1:
                        #log.msg("[DEBUG][honeypot.py][runCommand] Non-interactive shell, last shell on stack — closing session.", system="cowrie")
                        ret = failure.Failure(error.ProcessDone(status=""))
                        self.protocol.terminal.transport.processEnded(ret)
                    else:
                        #log.msg("[DEBUG][honeypot.py][runCommand] Non-interactive shell, popping shell off stack.", system="cowrie")
                        return
            else:
                log.msg("[DEBUG][honeypot.py][runCommand] No command pending, but part of pipe.", system="cowrie")
            return

        cmdAndArgs = self.cmdpending.pop(0)
        cmd2 = copy.copy(cmdAndArgs)
        #log.msg(f"[DEBUG][honeypot.py][runCommand] Parsed command line: {cmd2}", system="cowrie")


        # Probably no reason to be this comprehensive for just PATH...
        environ = copy.copy(self.environ)
        cmd_array = []
        cmd: dict[str, Any] = {}
        while cmdAndArgs:
            piece = cmdAndArgs.pop(0)
            if piece.count("="):
                key, val = piece.split("=", 1)
                environ[key] = val
                #log.msg(f"[DEBUG][honeypot.py][runCommand] Set environment variable: {key}={val}", system="cowrie")
                continue
            cmd["command"] = piece
            cmd["rargs"] = []
            #log.msg(f"[DEBUG][honeypot.py][runCommand] Command detected: {piece}", system="cowrie")
            break

        if "command" not in cmd or not cmd["command"]:
            #log.msg("[DEBUG][honeypot.py][runCommand] No valid command found, skipping to prompt.", system="cowrie")
            runOrPrompt()
            return

        pipe_indices = [i for i, x in enumerate(cmdAndArgs) if x == "|"]
        #log.msg(f"[DEBUG][honeypot.py][runCommand] Pipe indices: {pipe_indices}", system="cowrie")

        multipleCmdArgs: list[list[str]] = []
        pipe_indices.append(len(cmdAndArgs))
        start = 0

        # Gather all arguments with pipes

        for _index, pipe_indice in enumerate(pipe_indices):
            cmd_segment = cmdAndArgs[start:pipe_indice]
            #log.msg(f"[DEBUG][honeypot.py][runCommand] Parsed command segment: {cmd_segment}", system="cowrie")
            multipleCmdArgs.append(cmd_segment)
            start = pipe_indice + 1

        cmd["rargs"] = parse_arguments(multipleCmdArgs.pop(0))
        # parse_file_arguments parses too much. should not parse every argument
        # cmd['rargs'] = parse_file_arguments(multipleCmdArgs.pop(0))
        #log.msg(f"[DEBUG][honeypot.py][runCommand] First command: {cmd['command'] if 'command' in cmd else '[UNKNOWN]'}, Args: {cmd['rargs']}", system="cowrie")
        cmd_array.append(cmd)
        cmd = {}

        for value in multipleCmdArgs:
            cmd["command"] = value.pop(0)
            cmd["rargs"] = parse_arguments(value)
            #log.msg(f"[DEBUG][honeypot.py][runCommand] Piped command: {cmd['command']}, Args: {cmd['rargs']}", system="cowrie")
            cmd_array.append(cmd)
            cmd = {}

        lastpp = None
        for index, cmd in reversed(list(enumerate(cmd_array))):
            #log.msg(f"[DEBUG][honeypot.py][runCommand] Resolving command '{cmd['command']}' at pipeline index {index}", system="cowrie")

            cmdclass = self.protocol.getCommand(
                cmd["command"], environ["PATH"].split(":")
            )
            if cmdclass:

                full_input = cmd["command"] + " " + " ".join(cmd["rargs"])
                #log.msg(f"[DEBUG][honeypot.py][runCommand] Command found: {full_input}", system="cowrie")

                log.msg(
                    input=cmd["command"] + " " + " ".join(cmd["rargs"]),
                    format="Command found: %(input)s",
                )

                if index == len(cmd_array) - 1:
                    #log.msg(f"[DEBUG][honeypot.py][runCommand] Creating StdOutStdErrEmulationProtocol for last command '{cmd['command']}'", system="cowrie")
                    lastpp = StdOutStdErrEmulationProtocol(
                        self.protocol, cmdclass, cmd["rargs"], None, None, self.redirect
                    )
                    pp = lastpp
                else:
                    #log.msg(f"[DEBUG][honeypot.py][runCommand] Creating piped StdOutStdErrEmulationProtocol for '{cmd['command']}'", system="cowrie")
                    pp = StdOutStdErrEmulationProtocol(
                        self.protocol,
                        cmdclass,
                        cmd["rargs"],
                        None,
                        lastpp,
                        self.redirect,
                    )
                    lastpp = pp
            else:
                log.msg(
                    eventid="cowrie.command.failed",
                    input=" ".join(cmd2),
                    format="Command not found: %(input)s",
                )

                #log.msg(f"[ERROR][honeypot.py][runCommand] Command not found: {cmd['command']}, aborting pipeline", system="cowrie")

                self.protocol.terminal.write(
                    "-bash: {}: command not found\n".format(cmd["command"]).encode(
                        "utf8"
                    )
                )

                if (
                    isinstance(self.protocol, protocol.HoneyPotExecProtocol)
                    and not self.cmdpending
                ):
                    stat = failure.Failure(error.ProcessDone(status=""))
                    self.protocol.terminal.transport.processEnded(stat)

                runOrPrompt()
                pp = None  # Got a error. Don't run any piped commands
                break
        if pp:
            #log.msg("[DEBUG][honeypot.py][runCommand] All commands parsed successfully. Executing first command.", system="cowrie")
            self.protocol.call_command(pp, cmdclass, *cmd_array[0]["rargs"])

    def resume(self) -> None:
        #log.msg("[DEBUG][honeypot.py][resume] Resuming shell", system="cowrie")

        if self.interactive:
            self.protocol.setInsertMode()
        self.runCommand()

    def showPrompt(self) -> None:
        if not self.interactive:
            log.msg("[DEBUG][honeypot.py][showPrompt] Not interactive, skipping prompt", system="cowrie")
            return

        prompt = ""
        if CowrieConfig.has_option("honeypot", "prompt"):
            prompt = CowrieConfig.get("honeypot", "prompt")
            prompt += " "
        else:
            cwd = self.protocol.cwd
            homelen = len(self.protocol.user.avatar.home)
            if cwd == self.protocol.user.avatar.home:
                cwd = "~"
            elif (
                len(cwd) > (homelen + 1)
                and cwd[: (homelen + 1)] == self.protocol.user.avatar.home + "/"
            ):
                cwd = "~" + cwd[homelen:]

            # Example: [root@svr03 ~]#   (More of a "CentOS" feel)
            # Example: root@svr03:~#     (More of a "Debian" feel)
            prompt = f"{self.protocol.user.username}@{self.protocol.hostname}:{cwd}"
            if not self.protocol.user.uid:
                prompt += "# "  # "Root" user
            else:
                prompt += "$ "  # "Non-Root" user

        #log.msg(f"[DEBUG][honeypot.py][showPrompt] Showing prompt: {prompt}", system="cowrie")
        self.protocol.terminal.write(prompt.encode("ascii"))
        self.protocol.ps = (prompt.encode("ascii"), b"> ")

    def eofReceived(self) -> None:
        """
        this should probably not go through ctrl-d, but use processprotocol to close stdin
        """
        #log.msg("[DEBUG][honeypot.py][eofReceived] EOF received, passing CTRL-D", system="cowrie")
        log.msg("received eof, sending ctrl-d to command")
        if self.protocol.cmdstack:
            self.protocol.cmdstack[-1].handle_CTRL_D()

    def handle_CTRL_C(self) -> None:
        #log.msg("[DEBUG][honeypot.py][handle_CTRL_C] Received CTRL-C", system="cowrie")
        self.protocol.lineBuffer = []
        self.protocol.lineBufferIndex = 0
        self.protocol.terminal.write(b"\n")
        self.showPrompt()

    def handle_CTRL_D(self) -> None:
        log.msg("Received CTRL-D, exiting..")
        #log.msg("[DEBUG][honeypot.py][handle_CTRL_D] Received CTRL-D, ending process", system="cowrie")
        stat = failure.Failure(error.ProcessDone(status=""))
        self.protocol.terminal.transport.processEnded(stat)

    def handle_TAB(self) -> None:
        """
        lineBuffer is an array of bytes
        """
        if not self.protocol.lineBuffer:
            log.msg("[DEBUG][honeypot.py][handle_TAB] Line buffer empty, skipping", system="cowrie")
            return

        line: bytes = b"".join(self.protocol.lineBuffer)
        if line[-1:] == b" ":
            clue = ""
        else:
            clue = line.split()[-1].decode("utf8")

        # clue now contains the string to complete or is empty.
        # line contains the buffer as bytes
        basedir = os.path.dirname(clue)
        if basedir and basedir[-1] != "/":
            basedir += "/"

        if not basedir:
            tmppath = self.protocol.cwd
        else:
            tmppath = basedir

        try:
            r = self.protocol.fs.resolve_path(tmppath, self.protocol.cwd)
        except Exception:
            log.msg(f"[DEBUG][honeypot.py][handle_TAB] Path resolution failed: {e}", system="cowrie")
            return

        files = []
        for x in self.protocol.fs.get_path(r):
            if clue == "":
                files.append(x)
                continue
            if not x[fs.A_NAME].startswith(os.path.basename(clue)):
                continue
            files.append(x)

        if not files:
            log.msg("[DEBUG][honeypot.py][handle_TAB] No matching completions found", system="cowrie")
            return

        #log.msg(f"[DEBUG][honeypot.py][handle_TAB] Found {len(files)} completions for clue '{clue}'", system="cowrie")

        # Clear early so we can call showPrompt if needed
        for _i in range(self.protocol.lineBufferIndex):
            self.protocol.terminal.cursorBackward()
            self.protocol.terminal.deleteCharacter()

        newbuf = ""
        if len(files) == 1:
            #log.msg(f"[DEBUG][honeypot.py][handle_TAB] Single match found: {files[0][fs.A_NAME]}", system="cowrie")
            newbuf = " ".join(
                line.decode("utf8").split()[:-1] + [f"{basedir}{files[0][fs.A_NAME]}"]
            )
            if files[0][fs.A_TYPE] == fs.T_DIR:
                newbuf += "/"
            else:
                newbuf += " "
            newbyt = newbuf.encode("utf8")
        else:
            if os.path.basename(clue):
                prefix = os.path.commonprefix([x[fs.A_NAME] for x in files])
            else:
                prefix = ""

            #log.msg(f"[DEBUG][honeypot.py][handle_TAB] Multiple matches, common prefix: '{prefix}'", system="cowrie")

            first = line.decode("utf8").split(" ")[:-1]
            newbuf = " ".join([*first, f"{basedir}{prefix}"])
            newbyt = newbuf.encode("utf8")

            if newbyt == b"".join(self.protocol.lineBuffer):
                #log.msg(f"[DEBUG][honeypot.py][handle_TAB] Listing all {len(files)} matching files", system="cowrie")
                self.protocol.terminal.write(b"\n")
                maxlen = max(len(x[fs.A_NAME]) for x in files) + 1
                perline = int(self.protocol.user.windowSize[1] / (maxlen + 1))
                count = 0
                for file in files:
                    if count == perline:
                        count = 0
                        self.protocol.terminal.write(b"\n")
                    self.protocol.terminal.write(
                        file[fs.A_NAME].ljust(maxlen).encode("utf8")
                    )
                    count += 1
                self.protocol.terminal.write(b"\n")
                self.showPrompt()

        #log.msg(f"[DEBUG][honeypot.py][handle_TAB] Autocompleted line: '{newbuf}'", system="cowrie")
        self.protocol.lineBuffer = [y for x, y in enumerate(iterbytes(newbyt))]
        self.protocol.lineBufferIndex = len(self.protocol.lineBuffer)
        self.protocol.terminal.write(newbyt)


class StdOutStdErrEmulationProtocol:
    """
    Pipe support written by Dave Germiquet
    Support for commands chaining added by Ivan Korolev (@fe7ch)
    """

    __author__ = "davegermiquet"

    def __init__(
        self, protocol, cmd, cmdargs, input_data, next_command, redirect=False
    ):
        self.cmd = cmd
        self.cmdargs = cmdargs
        self.input_data: bytes = input_data
        self.next_command = next_command
        self.data: bytes = b""
        self.redirected_data: bytes = b""
        self.err_data: bytes = b""
        self.protocol = protocol
        self.redirect = redirect  # dont send to terminal if enabled
        #log.msg(
        #    f"[DEBUG][StdOutStdErrEmulationProtocol][__init__] Initialized with command '{cmd.__name__}' and args: {cmdargs}, redirect: {redirect}",
        #    system="cowrie"
        #)

    def connectionMade(self) -> None:
        #log.msg(f"[DEBUG][StdOutStdErrEmulationProtocol][connectionMade] Connection established for command '{self.cmd.__name__}'", system="cowrie")
        self.input_data = b""

    def outReceived(self, data: bytes) -> None:
        """
        Invoked when a command in the chain called 'write' method
        If we have a next command, pass the data via input_data field
        Else print data to the terminal
        """
        self.data = data
        #log.msg(f"[DEBUG][StdOutStdErrEmulationProtocol][outReceived] Output received ({len(data)} bytes)", system="cowrie")

        if not self.next_command:
            if not self.redirect:
                if self.protocol is not None and self.protocol.terminal is not None:
                    self.protocol.terminal.write(data)
                    #log.msg(f"[DEBUG][StdOutStdErrEmulationProtocol][outReceived] Output sent to terminal", system="cowrie")
                else:
                    log.msg("Connection was probably lost. Could not write to terminal")
            else:
                self.redirected_data += self.data
                #log.msg(f"[DEBUG][StdOutStdErrEmulationProtocol][outReceived] Output redirected ({len(self.redirected_data)} total bytes)", system="cowrie")

        else:
            if self.next_command.input_data is None:
                self.next_command.input_data = self.data
            else:
                self.next_command.input_data += self.data

            #log.msg("[DEBUG][StdOutStdErrEmulationProtocol][outReceived] Output passed to next command in pipe", system="cowrie")


    def insert_command(self, command):
        """
        Insert the next command into the list.
        """
        command.next_command = self.next_command
        self.next_command = command
        #log.msg(f"[DEBUG][StdOutStdErrEmulationProtocol][insert_command] Command inserted into pipe chain: {command.cmd.__name__}", system="cowrie")


    def errReceived(self, data: bytes) -> None:
        #log.msg(f"[DEBUG][StdOutStdErrEmulationProtocol][errReceived] Received stderr data ({len(data)} bytes)", system="cowrie")
        if self.protocol and self.protocol.terminal:
            self.protocol.terminal.write(data)
        self.err_data = self.err_data + data

    def inConnectionLost(self) -> None:
        log.msg("[DEBUG][StdOutStdErrEmulationProtocol][inConnectionLost] Input connection lost", system="cowrie")


    def outConnectionLost(self) -> None:
        """
        Called from HoneyPotBaseProtocol.call_command() to run a next command in the chain
        """
        #log.msg("[DEBUG][StdOutStdErrEmulationProtocol][outConnectionLost] Output connection lost", system="cowrie")

        if self.next_command:
            # self.next_command.input_data = self.data
            #log.msg("[DEBUG][StdOutStdErrEmulationProtocol][outConnectionLost] Executing next command in pipe chain", system="cowrie")
            npcmd = self.next_command.cmd
            npcmdargs = self.next_command.cmdargs
            self.protocol.call_command(self.next_command, npcmd, *npcmdargs)

    def errConnectionLost(self) -> None:
        log.msg("[DEBUG][StdOutStdErrEmulationProtocol][errConnectionLost] Error output connection lost", system="cowrie")

    def processExited(self, reason: failure.Failure) -> None:
        #log.msg(f"[DEBUG][StdOutStdErrEmulationProtocol][processExited] Command '{self.cmd.__name__}' exited with code {reason.value.exitCode}", system="cowrie")
        log.msg(f"processExited for {self.cmd}, status {reason.value.exitCode}")

    def processEnded(self, reason: failure.Failure) -> None:
        #log.msg(f"[DEBUG][StdOutStdErrEmulationProtocol][processEnded] Command '{self.cmd.__name__}' fully ended with code {reason.value.exitCode}", system="cowrie")
        log.msg(f"processEnded for {self.cmd}, status {reason.value.exitCode}")
