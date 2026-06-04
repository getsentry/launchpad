import os
import shutil
import subprocess

from devenv import constants
from devenv.lib import brew, fs, proc  # type: ignore

ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

def main(context: dict[str, str]) -> int:
    reporoot = context["reporoot"]

    if constants.DARWIN:
        brew.install()

        proc.run(
            (f"{constants.homebrew_bin}/brew", "bundle"),
            cwd=reporoot,
        )

    if os.path.exists(f"{reporoot}/.devenv/bin/uv"):
        os.remove(f"{reporoot}/.devenv/bin/uv")

    if os.path.exists(f"{reporoot}/.devenv/bin/uvx"):
        os.remove(f"{reporoot}/.devenv/bin/uvx")

    if not shutil.which("uv"):
        print("\n\n\ndevenv is no longer managing uv; please run `brew install uv`.\n\n\n")
        return 1

    print("syncing .venv ...")
    proc.run(
        ("uv", "sync", "--frozen", "--quiet", "--active"),
    )

    fs.ensure_symlink("../../config/hooks/post-merge", f"{reporoot}/.git/hooks/post-merge")  # type: ignore

    deps_path = os.path.join(ROOT_DIR, "scripts", "deps")
    subprocess.check_output([deps_path])

    return 0
