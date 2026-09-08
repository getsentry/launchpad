from pathlib import Path

import pytest

from launchpad.utils.android.bundletool import Bundletool, DeviceSpec


@pytest.fixture
def bundletool(mocker) -> Bundletool:
    mocker.patch("launchpad.utils.android.bundletool.shutil.which", return_value="/usr/local/bin/bundletool")
    tool = Bundletool()
    mocker.patch.object(tool, "_generate_keystore", return_value=("password", "alias"))
    mocker.patch.object(tool, "_run_command")
    return tool


def test_build_apks_targets_device_during_build(bundletool: Bundletool, tmp_path: Path) -> None:
    bundletool.build_apks(
        bundle_path=tmp_path / "app.aab",
        output_dir=tmp_path / "output",
        device_spec=DeviceSpec(),
    )

    build_command = bundletool._run_command.call_args_list[0].args[0]
    extract_command = bundletool._run_command.call_args_list[1].args[0]

    assert "--mode=universal" not in build_command
    device_spec_arg = next(argument for argument in build_command if argument.startswith("--device-spec="))
    assert device_spec_arg in extract_command


def test_build_universal_apk_does_not_target_device_during_build(bundletool: Bundletool, tmp_path: Path) -> None:
    bundletool.build_apks(
        bundle_path=tmp_path / "app.aab",
        output_dir=tmp_path / "output",
        device_spec=DeviceSpec(),
        universal_apk=True,
    )

    build_command = bundletool._run_command.call_args_list[0].args[0]
    extract_command = bundletool._run_command.call_args_list[1].args[0]

    assert "--mode=universal" in build_command
    assert not any(argument.startswith("--device-spec=") for argument in build_command)
    assert any(argument.startswith("--device-spec=") for argument in extract_command)
