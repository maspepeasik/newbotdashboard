"""
PentestBot v2 — Command Runner
Async wrapper around external CLI tools.
Handles timeouts, streaming, error capture, and binary detection.
"""

import asyncio
import os
import shutil
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from utils.logger import get_logger

logger = get_logger("utils.cmd")


@dataclass
class CommandResult:
    """Output of a single external command execution."""
    command: list[str]
    returncode: int
    stdout: str
    stderr: str
    duration: float
    timed_out: bool = False

    @property
    def success(self) -> bool:
        return self.returncode == 0 and not self.timed_out

    @property
    def cmd_str(self) -> str:
        return " ".join(self.command)

    def __repr__(self) -> str:
        return (
            f"CommandResult(cmd={self.cmd_str!r}, "
            f"rc={self.returncode}, "
            f"duration={self.duration:.1f}s, "
            f"stdout_len={len(self.stdout)}, "
            f"timed_out={self.timed_out})"
        )


class CommandRunner:
    """
    Async executor for external security tools.
    Provides timeout handling, stderr capture, and structured results.
    """

    def __init__(self, default_timeout: int = 300, work_dir: Optional[Path] = None):
        self.default_timeout = default_timeout
        self.work_dir = work_dir

    def resolve_binary(self, binary: str) -> Optional[str]:
        """Resolve a binary from PATH or common install directories."""
        if not binary:
            return None

        if os.path.isabs(binary) or any(sep in binary for sep in (os.sep, "/")):
            return binary if Path(binary).exists() else None

        resolved = shutil.which(binary)
        if resolved:
            return resolved

        candidates = [
            Path.home() / "go" / "bin" / binary,
            Path("/home/ubuntu/go/bin") / binary,
            Path("/usr/local/bin") / binary,
            Path("/usr/bin") / binary,
            Path("/opt/testssl.sh") / binary,
        ]
        for candidate in candidates:
            if candidate.exists():
                return str(candidate)
        return None

    def which(self, binary: str) -> bool:
        """Return True if `binary` can be resolved for execution."""
        return self.resolve_binary(binary) is not None

    async def run(
        self,
        cmd: list[str],
        timeout: Optional[int] = None,
        cwd: Optional[Path] = None,
        stdin_data: Optional[str] = None,
    ) -> CommandResult:
        """
        Execute `cmd` asynchronously.
        Returns CommandResult regardless of success/failure.
        """
        effective_timeout = timeout if timeout is not None else self.default_timeout
        effective_cwd = str(cwd or self.work_dir or Path.cwd())
        effective_cmd = list(cmd)

        resolved_binary = self.resolve_binary(effective_cmd[0])
        if resolved_binary:
            effective_cmd[0] = resolved_binary

        logger.debug(f"RUN [{effective_timeout}s]: {' '.join(effective_cmd)}")
        start = time.monotonic()

        proc: Optional[asyncio.subprocess.Process] = None
        timed_out = False

        try:
            proc = await asyncio.create_subprocess_exec(
                *effective_cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                stdin=asyncio.subprocess.PIPE if stdin_data else None,
                cwd=effective_cwd,
            )

            stdout_bytes = bytearray()
            stderr_bytes = bytearray()
            
            async def read_stream(stream, is_stderr):
                try:
                    while True:
                        data = await stream.read(8192)
                        if not data:
                            break
                        if is_stderr:
                            stderr_bytes.extend(data)
                        else:
                            stdout_bytes.extend(data)
                except asyncio.CancelledError:
                    pass
                except Exception:
                    pass

            if stdin_data:
                try:
                    proc.stdin.write(stdin_data.encode())
                    proc.stdin.write_eof()
                    await proc.stdin.wait_closed()
                except Exception:
                    pass

            tasks = [
                asyncio.create_task(read_stream(proc.stdout, False)),
                asyncio.create_task(read_stream(proc.stderr, True)),
                asyncio.create_task(proc.wait())
            ]

            await asyncio.wait_for(asyncio.gather(*tasks), timeout=effective_timeout)

            returncode = proc.returncode or 0
            stdout = stdout_bytes.decode("utf-8", errors="replace")
            stderr = stderr_bytes.decode("utf-8", errors="replace")

        except asyncio.TimeoutError:
            timed_out = True
            if proc:
                try:
                    proc.kill()
                except Exception:
                    pass
            for t in tasks:
                t.cancel()
            returncode = -1
            stdout = stdout_bytes.decode("utf-8", errors="replace")
            stderr = stderr_bytes.decode("utf-8", errors="replace")
            stderr += f"\n[TIMEOUT] Command exceeded {effective_timeout}s limit."
            logger.warning(f"TIMEOUT [{effective_timeout}s]: {' '.join(effective_cmd[:3])}")

        except FileNotFoundError:
            returncode = -1
            stdout = ""
            stderr = f"[NOT FOUND] Binary not found: {effective_cmd[0]}"
            logger.error(f"NOT FOUND: {effective_cmd[0]}")

        except Exception as e:
            returncode = -1
            stdout = ""
            stderr = f"[ERROR] Unexpected error: {e}"
            logger.exception(f"Unexpected error running {effective_cmd[0]}: {e}")

        finally:
            duration = time.monotonic() - start

        result = CommandResult(
            command=effective_cmd,
            returncode=returncode,
            stdout=stdout,
            stderr=stderr,
            duration=duration,
            timed_out=timed_out,
        )

        if result.success:
            logger.debug(
                f"OK [{duration:.1f}s]: {cmd[0]} "
                f"(stdout={len(stdout)} bytes)"
            )
        else:
            logger.debug(
                f"FAIL [{duration:.1f}s]: {cmd[0]} "
                f"rc={returncode} stderr={stderr[:200]!r}"
            )

        return result

    async def run_with_file_input(
        self,
        cmd: list[str],
        input_file: Path,
        timeout: Optional[int] = None,
        cwd: Optional[Path] = None,
        input_flag: str = "-l",
    ) -> CommandResult:
        """
        Run a command that takes a file as input via a flag (e.g. -l, --list).
        Appends `input_flag input_file` to the command.
        """
        full_cmd = cmd + [input_flag, str(input_file)]
        return await self.run(full_cmd, timeout=timeout, cwd=cwd)

    async def run_piped(
        self,
        cmds: list[list[str]],
        timeout: Optional[int] = None,
        cwd: Optional[Path] = None,
    ) -> CommandResult:
        """
        Run a shell pipeline: cmd1 | cmd2 | ... | cmdN
        Each command's stdout is piped to the next's stdin.
        """
        effective_timeout = timeout if timeout is not None else self.default_timeout
        effective_cwd = str(cwd or self.work_dir or Path.cwd())

        shell_cmd = " | ".join(" ".join(c) for c in cmds)
        logger.debug(f"PIPE [{effective_timeout}s]: {shell_cmd}")
        start = time.monotonic()
        timed_out = False

        try:
            proc = await asyncio.create_subprocess_shell(
                shell_cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=effective_cwd,
            )
            stdout_bytes, stderr_bytes = await asyncio.wait_for(
                proc.communicate(),
                timeout=effective_timeout,
            )
            returncode = proc.returncode or 0
            stdout = stdout_bytes.decode("utf-8", errors="replace")
            stderr = stderr_bytes.decode("utf-8", errors="replace")

        except asyncio.TimeoutError:
            timed_out = True
            returncode = -1
            stdout = ""
            stderr = f"[TIMEOUT] Pipeline exceeded {effective_timeout}s."

        except Exception as e:
            returncode = -1
            stdout = ""
            stderr = f"[ERROR] {e}"

        duration = time.monotonic() - start
        return CommandResult(
            command=["shell_pipe"],
            returncode=returncode,
            stdout=stdout,
            stderr=stderr,
            duration=duration,
            timed_out=timed_out,
        )
