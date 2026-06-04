import os
import shutil
import subprocess

from devenv.lib import proc, config, venv, fs # type: ignore

ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

def main(context: dict[str, str]) -> int:
    reporoot = context["reporoot"]

    if os.path.exists(f"{reporoot}/.devenv/bin/uv"):
        os.remove(f"{reporoot}/.devenv/bin/uv")

    if os.path.exists(f"{reporoot}/.devenv/bin/uvx"):
        os.remove(f"{reporoot}/.devenv/bin/uvx")

    if not shutil.which("uv"):
        print("\n\n\ndevenv is no longer managing uv; please run `brew install uv`.\n\n\n")
        return 1

    venv_dir, python_version, requirements, editable_paths, bins = venv.get(reporoot, "launchpad")  # type: ignore
    url, sha256 = config.get_python(reporoot, python_version)  # type: ignore
    print(f"ensuring venv at {venv_dir}...")
    venv.ensure(venv_dir, python_version, url, sha256)  # type: ignore

    print(f"syncing venv with {requirements} using uv...")

    # Install requirements using uv, the `devenv.sync` method hardcodes pip
    proc.run(("uv", "pip", "install", "-r", requirements))

    # Install editable packages if specified (uv handles this via pip backend)
    if editable_paths is not None:
        for path in editable_paths:
            proc.run(("uv", "pip", "install", "-e", path))

    # Create symlinks for binaries if specified
    if bins is not None:
        binroot = fs.ensure_binroot(reporoot)  # type: ignore
        for name in bins:
            fs.ensure_symlink(  # type: ignore
                expected_src=f"{venv_dir}/bin/{name}", dest=f"{binroot}/{name}"
            )

    fs.ensure_symlink("../../config/hooks/post-merge", f"{reporoot}/.git/hooks/post-merge")  # type: ignore


    deps_path = os.path.join(ROOT_DIR, "scripts", "deps")
    subprocess.check_output([deps_path])

    return 0
