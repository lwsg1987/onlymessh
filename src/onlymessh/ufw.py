"""Thin wrapper around the ``ufw`` command line."""

from __future__ import annotations

import shutil
import subprocess

from .rules import ParseError, Rule, parse_status


class UfwError(RuntimeError):
    pass


class Ufw:
    def __init__(self, cmd: str = "ufw", runner=None, timeout: float = 60.0) -> None:
        if "/" not in cmd:
            resolved = shutil.which(cmd)
            if resolved is None:
                raise UfwError(f"`{cmd}` not found on PATH")
            cmd = resolved
        self.cmd = cmd
        self._runner = runner or subprocess.run
        self.timeout = timeout

    def _run(self, *args: str) -> str:
        # ufw calls iptables, which can block for a long time when the
        # netfilter lock is held.  Without a timeout a single stuck call
        # freezes the sync loop forever.
        try:
            proc = self._runner(
                [self.cmd, *args],
                capture_output=True, text=True, timeout=self.timeout,
            )
        except subprocess.TimeoutExpired as exc:
            raise UfwError(f"ufw {' '.join(args)} timed out after {self.timeout}s") from exc
        if proc.returncode != 0:
            msg = (proc.stderr or proc.stdout or "").strip()
            raise UfwError(f"ufw {' '.join(args)} failed: {msg}")
        return proc.stdout

    def status(self) -> tuple[bool, list[Rule]]:
        try:
            return parse_status(self._run("status"))
        except ParseError as exc:
            raise UfwError(str(exc)) from exc

    def is_active(self) -> bool:
        active, _ = self.status()
        return active

    def allow_from(self, source: str) -> None:
        self._run("allow", "from", source)

    def delete_allow_from(self, source: str) -> None:
        self._run("delete", "allow", "from", source)

    def version(self) -> str:
        return self._run("version").splitlines()[0].strip()
