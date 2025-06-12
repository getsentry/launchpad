from devenv.lib import config, venv, fs

def main(context: dict[str, str]) -> int:
    reporoot = context["reporoot"]

    venv_dir, python_version, requirements, editable_paths, bins = venv.get(reporoot, "venv")
    url, sha256 = config.get_python(reporoot, python_version)
    print(f"ensuring venv at {venv_dir}...")
    venv.ensure(venv_dir, python_version, url, sha256)

    print(f"syncing venv with {requirements}...")
    venv.sync(reporoot, venv_dir, requirements, editable_paths, bins)

    fs.ensure_symlink("../../config/hooks/post-merge", f"{reporoot}/.git/hooks/post-merge")

    return 0
