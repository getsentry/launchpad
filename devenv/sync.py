import os
import subprocess
import sys

from devenv import constants
from devenv.lib import proc, config, venv, fs, uv # type: ignore

ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEPS_PATH = os.path.join(ROOT_DIR, "scripts", "deps")

def main(context: dict[str, str]) -> int:
    reporoot = context["reporoot"]
    cfg = config.get_repo(reporoot)

    uv.install(
        cfg["uv"]["version"],
        cfg["uv"][constants.SYSTEM_MACHINE],
        cfg["uv"][f"{constants.SYSTEM_MACHINE}_sha256"],
        reporoot,
    )

    proc.run(("uv", "sync", "--frozen", "--quiet"))

    fs.ensure_symlink("../../config/hooks/post-merge", f"{reporoot}/.git/hooks/post-merge")  # type: ignore

    proc.run((DEPS_PATH,))

    return 0
