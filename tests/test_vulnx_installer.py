import os
from pathlib import Path

import pytest

from bomradar.models import ProviderError
from bomradar.utils import vulnx_installer
from bomradar.utils.subprocess_runner import CommandResult


def test_windows_path_persistence_adds_go_bin(monkeypatch) -> None:
    calls: list[list[str]] = []

    def runner(command: list[str], timeout: int) -> CommandResult:
        calls.append(command)
        if "GetEnvironmentVariable" in command[-1]:
            return CommandResult(0, r"C:\Windows\System32", "")
        if "SetEnvironmentVariable" in command[-1]:
            return CommandResult(0, "", "")
        raise AssertionError(f"Unexpected command: {command}")

    monkeypatch.setattr(vulnx_installer.platform, "system", lambda: "Windows")
    monkeypatch.setenv("PATH", r"C:\Windows\System32")

    vulnx_installer.add_directory_to_path(Path(r"C:\Users\example\go\bin"), runner)

    assert r"C:\Users\example\go\bin" in os.environ["PATH"]
    assert any("SetEnvironmentVariable" in command[-1] for command in calls)
    set_command = next(command[-1] for command in calls if "SetEnvironmentVariable" in command[-1])
    assert r"C:\Windows\System32;C:\Users\example\go\bin" in set_command


def test_windows_path_persistence_skips_existing_user_path(monkeypatch) -> None:
    calls: list[list[str]] = []

    def runner(command: list[str], timeout: int) -> CommandResult:
        calls.append(command)
        return CommandResult(0, r"C:\Windows\System32;C:\Users\example\go\bin", "")

    monkeypatch.setattr(vulnx_installer.platform, "system", lambda: "Windows")
    monkeypatch.setenv("PATH", r"C:\Windows\System32")

    vulnx_installer.add_directory_to_path(Path(r"C:\Users\example\go\bin"), runner)

    assert not any("SetEnvironmentVariable" in command[-1] for command in calls)


def test_windows_path_persistence_escapes_single_quotes(monkeypatch) -> None:
    commands: list[str] = []

    def runner(command: list[str], timeout: int) -> CommandResult:
        commands.append(command[-1])
        if "GetEnvironmentVariable" in command[-1]:
            return CommandResult(0, r"C:\Existing", "")
        return CommandResult(0, "", "")

    monkeypatch.setattr(vulnx_installer.platform, "system", lambda: "Windows")
    monkeypatch.setenv("PATH", r"C:\Existing")

    vulnx_installer.add_directory_to_path(Path(r"C:\Users\O'Brien\go\bin"), runner)

    set_command = next(command for command in commands if "SetEnvironmentVariable" in command)
    assert r"O''Brien" in set_command


def test_install_vulnx_requires_go(monkeypatch) -> None:
    monkeypatch.setattr(vulnx_installer.shutil, "which", lambda name: None)

    with pytest.raises(ProviderError, match="Go is not installed"):
        vulnx_installer.install_vulnx()


def test_install_vulnx_success_on_windows(monkeypatch) -> None:
    install_dir = Path("test-output/go/bin")
    install_dir.mkdir(parents=True, exist_ok=True)
    executable = install_dir / "vulnx.exe"
    executable.write_text("", encoding="utf-8")
    commands: list[list[str]] = []

    def runner(command: list[str], timeout: int) -> CommandResult:
        commands.append(command)
        if command[:2] == ["go", "install"]:
            return CommandResult(0, "", "")
        if command == ["go", "env", "GOBIN"]:
            return CommandResult(0, str(install_dir), "")
        if "GetEnvironmentVariable" in command[-1]:
            return CommandResult(0, "", "")
        if "SetEnvironmentVariable" in command[-1]:
            return CommandResult(0, "", "")
        return CommandResult(0, "", "")

    monkeypatch.setattr(vulnx_installer.shutil, "which", lambda name: r"C:\Program Files\Go\bin\go.exe")
    monkeypatch.setattr(vulnx_installer.platform, "system", lambda: "Windows")

    assert vulnx_installer.install_vulnx(runner) == executable
    assert ["go", "install", vulnx_installer.VULNX_GO_PACKAGE] in commands
