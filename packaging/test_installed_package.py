#!/usr/bin/env python3
"""Build mojo-tls and test it in an isolated package environment."""

import os
import platform
import shutil
import subprocess
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
MOJO_NET = ROOT / ".deps" / "mojo-net"
CHANNELS = ["https://conda.modular.com/max", "conda-forge"]
RATTLER_BUILD = "rattler-build>=0.30,<0.31"
RATTLER_INDEX = "rattler-index>=0.30,<0.31"
PACKAGE_BUILD_TIMEOUT_SECONDS = 20 * 60
PACKAGE_TEST_TIMEOUT_SECONDS = 5 * 60


def run(
    command: list[str],
    cwd: Path = ROOT,
    timeout_seconds: int = PACKAGE_BUILD_TIMEOUT_SECONDS,
) -> None:
    environment = os.environ.copy()
    environment.pop("PIXI_PROJECT_MANIFEST", None)
    subprocess.run(
        command,
        cwd=cwd,
        env=environment,
        check=True,
        timeout=timeout_seconds,
    )


def platform_subdir() -> str:
    machine = platform.machine().lower()
    if platform.system() == "Darwin" and machine == "arm64":
        return "osx-arm64"
    if platform.system() == "Linux" and machine in {"x86_64", "amd64"}:
        return "linux-64"
    if platform.system() == "Linux" and machine in {"aarch64", "arm64"}:
        return "linux-aarch64"
    raise RuntimeError(f"unsupported package platform: {platform.system()} {machine}")


def add_channels(command: list[str], local_channel: Path) -> None:
    command.extend(["--channel", local_channel.as_uri()])
    for channel in CHANNELS:
        command.extend(["--channel", channel])


def main() -> None:
    if not (MOJO_NET / "pixi.toml").is_file():
        raise RuntimeError("run python3 tools/fetch_deps.py before package-test")

    with tempfile.TemporaryDirectory(prefix="mojo-tls-package-") as temp:
        work = Path(temp)
        net_output = work / "mojo-net"
        channel = work / "channel"
        channel_subdir = channel / platform_subdir()
        channel_subdir.mkdir(parents=True)
        (channel / "noarch").mkdir()

        run(
            [
                "pixi",
                "publish",
                "--clean",
                "--path",
                str(MOJO_NET),
                "--target-dir",
                str(net_output),
            ]
        )
        net_packages = sorted(net_output.glob("mojo-net-*.conda"))
        if len(net_packages) != 1:
            raise RuntimeError(
                f"expected one mojo-net package, found {len(net_packages)}"
            )
        shutil.copy2(net_packages[0], channel_subdir / net_packages[0].name)
        run(
            [
                "pixi",
                "exec",
                "--spec",
                RATTLER_INDEX,
                "rattler-index",
                "fs",
                str(channel),
            ]
        )

        output = work / "mojo-tls"
        build_command = [
            "pixi",
            "exec",
            "--spec",
            RATTLER_BUILD,
            "rattler-build",
            "build",
            "--recipe",
            str(ROOT / "recipe" / "recipe.yaml"),
            "--output-dir",
            str(output),
            "--no-test",
        ]
        add_channels(build_command, channel)
        run(build_command)

        packages = sorted(output.rglob("mojo-tls-*.conda"))
        if len(packages) != 1:
            raise RuntimeError(
                f"expected one mojo-tls package, found {len(packages)}"
            )

        test_command = [
            "pixi",
            "exec",
            "--spec",
            RATTLER_BUILD,
            "rattler-build",
            "test",
            "--package-file",
            str(packages[0]),
        ]
        add_channels(test_command, channel)
        run(test_command, timeout_seconds=PACKAGE_TEST_TIMEOUT_SECONDS)


if __name__ == "__main__":
    main()
