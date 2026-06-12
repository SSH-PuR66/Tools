from __future__ import annotations

import os
import shlex
import socket
import stat
import subprocess
from pathlib import Path

from controltrace.models import Evidence


class LinuxCollector:
    platform = "linux"

    def hostname(self) -> str:
        return socket.gethostname()

    def read_file_setting(self, path: str, key: str) -> Evidence:
        file_path = Path(path)

        if not file_path.exists():
            return Evidence(
                source=path,
                collected=False,
                value="",
                error="File does not exist",
            )

        try:
            lines = file_path.read_text(encoding="utf-8", errors="replace").splitlines()
            observed_values: list[str] = []

            for line in lines:
                stripped = line.strip()

                if not stripped or stripped.startswith("#"):
                    continue

                parts = stripped.split()

                if len(parts) >= 2 and parts[0].lower() == key.lower():
                    observed_values.append(" ".join(parts[1:]))

            if not observed_values:
                return Evidence(
                    source=path,
                    collected=True,
                    value=f"{key}=<not set>",
                )

            return Evidence(
                source=path,
                collected=True,
                value=f"{key}={observed_values[-1]}",
            )

        except OSError as exc:
            return Evidence(
                source=path,
                collected=False,
                value="",
                error=str(exc),
            )

    def read_file_contains(self, path: str, expected_substrings: list[str]) -> Evidence:
        file_path = Path(path)

        if not file_path.exists():
            return Evidence(
                source=path,
                collected=False,
                value="",
                error="File does not exist",
            )

        try:
            content = file_path.read_text(encoding="utf-8", errors="replace")
            missing = [text for text in expected_substrings if text not in content]

            if missing:
                value = f"missing={missing}"
            else:
                value = "all expected substrings present"

            return Evidence(
                source=path,
                collected=True,
                value=value,
            )

        except OSError as exc:
            return Evidence(
                source=path,
                collected=False,
                value="",
                error=str(exc),
            )

    def run_command(self, command: str, timeout: float = 5.0) -> Evidence:
        try:
            args = shlex.split(command)

            result = subprocess.run(
                args,
                capture_output=True,
                text=True,
                timeout=timeout,
                check=False,
            )

            output = (result.stdout + "\n" + result.stderr).strip()

            return Evidence(
                source=command,
                collected=True,
                value=output,
                error=None if result.returncode == 0 else f"Return code {result.returncode}",
            )

        except (OSError, subprocess.TimeoutExpired) as exc:
            return Evidence(
                source=command,
                collected=False,
                value="",
                error=str(exc),
            )

    def path_permission(self, path: str) -> Evidence:
        file_path = Path(path)

        if not file_path.exists():
            return Evidence(
                source=path,
                collected=False,
                value="",
                error="Path does not exist",
            )

        try:
            mode = file_path.stat().st_mode
            permissions = stat.filemode(mode)
            world_writable = bool(mode & stat.S_IWOTH)

            return Evidence(
                source=path,
                collected=True,
                value=f"permissions={permissions}; world_writable={world_writable}",
            )

        except OSError as exc:
            return Evidence(
                source=path,
                collected=False,
                value="",
                error=str(exc),
            )

    def user_shells(self) -> Evidence:
        passwd = Path("/etc/passwd")

        if not passwd.exists():
            return Evidence(
                source="/etc/passwd",
                collected=False,
                value="",
                error="File does not exist",
            )

        try:
            risky_shells = []

            for line in passwd.read_text(encoding="utf-8", errors="replace").splitlines():
                if not line or line.startswith("#"):
                    continue

                parts = line.split(":")
                if len(parts) < 7:
                    continue

                username = parts[0]
                uid = parts[2]
                shell = parts[6]

                if shell not in ["/usr/sbin/nologin", "/sbin/nologin", "/bin/false"]:
                    risky_shells.append(f"{username}:{uid}:{shell}")

            return Evidence(
                source="/etc/passwd",
                collected=True,
                value="; ".join(risky_shells) if risky_shells else "no interactive shells observed",
            )

        except OSError as exc:
            return Evidence(
                source="/etc/passwd",
                collected=False,
                value="",
                error=str(exc),
            )

    def current_user_is_root(self) -> bool:
        return hasattr(os, "geteuid") and os.geteuid() == 0
