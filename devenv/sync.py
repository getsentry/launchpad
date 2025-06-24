from devenv.lib import config, venv, fs  # type: ignore
import subprocess
import sys

def run_uv_command(cmd: list[str], cwd: str) -> None:
    """Run a uv command and handle errors."""
    print(f"Running: uv {' '.join(cmd)}")
    result = subprocess.run(["uv"] + cmd, cwd=cwd, capture_output=True, text=True)
    if result.stdout:
        print(result.stdout)
    if result.stderr:
        print(result.stderr, file=sys.stderr)
    if result.returncode != 0:
        raise subprocess.CalledProcessError(result.returncode, ["uv"] + cmd)

def main(context: dict[str, str]) -> int:
    reporoot = context["reporoot"]

    venv_dir, python_version, requirements, editable_paths, bins = venv.get(reporoot, "launchpad")  # type: ignore
    url, sha256 = config.get_python(reporoot, python_version)  # type: ignore
    print(f"ensuring venv at {venv_dir}...")
    venv.ensure(venv_dir, python_version, url, sha256)  # type: ignore

    print(f"syncing venv with {requirements} using uv...")

    # Install requirements using uv, the `devenv.sync` method hardcodes pip
    run_uv_command(["pip", "install", "-r", requirements], reporoot)

    # Install editable packages if specified (uv handles this via pip backend)
    if editable_paths is not None:
        for path in editable_paths:
            run_uv_command(["pip", "install", "-e", path], reporoot)

    # Create symlinks for binaries if specified
    if bins is not None:
        binroot = fs.ensure_binroot(reporoot)  # type: ignore
        for name in bins:
            fs.ensure_symlink(  # type: ignore
                expected_src=f"{venv_dir}/bin/{name}", dest=f"{binroot}/{name}"
            )

    fs.ensure_symlink("../../config/hooks/post-merge", f"{reporoot}/.git/hooks/post-merge")  # type: ignore

    return 0
