from __future__ import annotations

import os
import platform
import shutil
from pathlib import Path

from bomradar.models import ProviderError
from bomradar.utils.subprocess_runner import Runner, run_command

VULNX_GO_PACKAGE = "github.com/projectdiscovery/vulnx/v2/cmd/vulnx@latest"


def install_vulnx(runner: Runner = run_command) -> Path:
    if shutil.which("go") is None:
        raise ProviderError(
            "Cannot install vulnx because Go is not installed or is not on PATH. "
            "Install Go, restart your shell, then run bomradar again."
        )

    result = runner(["go", "install", VULNX_GO_PACKAGE], 300)
    if result.returncode != 0:
        raise ProviderError(f"vulnx installation failed: {result.stderr.strip() or result.stdout.strip()}")

    install_dir = _go_bin_dir(runner)
    executable = install_dir / _vulnx_executable_name()
    if not executable.exists():
        raise ProviderError(
            f"vulnx installation completed, but {executable} was not found. "
            f"Make sure {install_dir} is on PATH."
        )

    add_directory_to_path(install_dir, runner)
    return executable


def add_directory_to_path(directory: Path, runner: Runner = run_command) -> None:
    path_entries = os.environ.get("PATH", "").split(os.pathsep)
    directory_text = str(directory)
    if directory_text not in path_entries:
        os.environ["PATH"] = os.pathsep.join([os.environ.get("PATH", ""), directory_text])

    if platform.system().lower() == "windows":
        _add_user_path_windows(directory, runner)
    else:
        _add_user_path_shell_profile(directory)


def _go_bin_dir(runner: Runner) -> Path:
    gopath = runner(["go", "env", "GOBIN"], 30)
    if gopath.returncode == 0 and gopath.stdout.strip():
        return Path(gopath.stdout.strip()).expanduser()

    gopath = runner(["go", "env", "GOPATH"], 30)
    if gopath.returncode == 0 and gopath.stdout.strip():
        return Path(gopath.stdout.strip()).expanduser() / "bin"

    return Path.home() / "go" / "bin"


def _add_user_path_windows(directory: Path, runner: Runner) -> None:
    current = os.environ.get("PATH", "")
    user_path_result = runner(
        [
            "powershell",
            "-NoProfile",
            "-Command",
            "[Environment]::GetEnvironmentVariable('Path', 'User')",
        ],
        30,
    )
    user_path = user_path_result.stdout.strip() if user_path_result.returncode == 0 else ""
    entries = [entry for entry in user_path.split(";") if entry]
    directory_text = str(directory)
    if any(entry.lower() == directory_text.lower() for entry in entries):
        return
    new_user_path = ";".join([*entries, directory_text]) if entries else directory_text
    result = runner(
        [
            "powershell",
            "-NoProfile",
            "-Command",
            f"[Environment]::SetEnvironmentVariable('Path', '{_escape_powershell(new_user_path)}', 'User')",
        ],
        30,
    )
    if result.returncode != 0:
        os.environ["PATH"] = current
        raise ProviderError(
            "vulnx was installed, but SBOMradar could not persist the Go bin directory to "
            f"your user PATH. Add this directory manually: {directory}"
        )


def _escape_powershell(value: str) -> str:
    return value.replace("'", "''")


def _add_user_path_shell_profile(directory: Path) -> None:
    profile = Path.home() / ".profile"
    line = f'\nexport PATH="$PATH:{directory}"\n'
    try:
        existing = profile.read_text(encoding="utf-8") if profile.exists() else ""
        if str(directory) not in existing:
            profile.write_text(existing + line, encoding="utf-8")
    except OSError as exc:
        raise ProviderError(
            "vulnx was installed, but SBOMradar could not persist the Go bin directory "
            f"to your shell profile. Add this directory manually: {directory}"
        ) from exc


def _vulnx_executable_name() -> str:
    return "vulnx.exe" if platform.system().lower() == "windows" else "vulnx"
