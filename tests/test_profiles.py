"""Unified profile system tests: built-ins, validation, custom profiles."""

import json

import pytest

from boardaudit.profiles import (
    BUILTIN_PROFILES,
    ProfileError,
    add_profile_file,
    get_profile,
    list_profiles,
    load_profile_file,
    profile_template,
    resolve_profile_arg,
    validate_profile_data,
    write_profile_template,
)


def test_builtin_catalog_covers_three_kinds():
    kinds = {p.kind for p in BUILTIN_PROFILES.values()}
    assert kinds == {"board", "router", "disk"}
    assert len(list_profiles(kind="board")) == 15
    assert len(list_profiles(kind="router")) == 13
    assert len(list_profiles(kind="disk")) == 7
    assert len(BUILTIN_PROFILES) == 35


def test_builtin_ids_are_unique_and_valid():
    for profile_id, profile in BUILTIN_PROFILES.items():
        assert profile.profile_id == profile_id
        assert profile.name


def test_get_profile_and_unknown():
    profile = get_profile("nvme-ssd")
    assert profile.kind == "disk"
    assert profile.interface == "NVMe"
    with pytest.raises(ProfileError):
        get_profile("not-a-profile")


def test_resolve_profile_arg_by_id_and_file(tmp_path):
    assert resolve_profile_arg("esp32").profile_id == "esp32"
    assert resolve_profile_arg(None) is None
    path = tmp_path / "custom.json"
    path.write_text(json.dumps({
        "id": "my-board", "kind": "board", "name": "My Board",
        "family": "ESP32", "flash_size": 4194304, "app_offset": 65536,
        "default_baud": 115200, "acquisition_tool": "esptool",
    }))
    assert resolve_profile_arg(str(path)).profile_id == "my-board"
    with pytest.raises(ProfileError):
        resolve_profile_arg("no-such-profile")


def test_validate_profile_rejects_bad_id_kind_and_fields():
    _, errors = validate_profile_data({"id": "bad id!", "kind": "board", "name": "X"})
    assert errors
    _, errors = validate_profile_data({"id": "ok", "kind": "phone", "name": "X"})
    assert errors
    _, errors = validate_profile_data(
        {"id": "ok", "kind": "board", "name": "X", "surprise": 1}
    )
    assert any("unknown profile field" in e for e in errors)
    _, errors = validate_profile_data({"id": "ok", "kind": "board"})
    assert errors  # missing name


def test_validate_profile_rejects_shell_and_secrets():
    _, errors = validate_profile_data({
        "id": "evil", "kind": "board", "name": "Evil",
        "acquisition_tool": "esptool; rm -rf /",
    })
    assert errors
    _, errors = validate_profile_data({
        "id": "evil2", "kind": "board", "name": "Evil",
        "notes": "download from https://user:pass@example.com/x",
    })
    assert errors
    _, errors = validate_profile_data({
        "id": "evil3", "kind": "board", "name": "Evil",
        "notes": "key AKIAIOSFODNN7EXAMPLE here",
    })
    assert errors


def test_profile_template_and_validate_roundtrip(tmp_path):
    for kind in ("board", "router", "disk"):
        path = tmp_path / f"new-{kind}.json"
        written = write_profile_template(kind, f"new-{kind}", path)
        profile = load_profile_file(written)
        assert profile.kind == kind
        assert profile.profile_id == f"new-{kind}"
    with pytest.raises(ProfileError):
        write_profile_template("phone", "x", tmp_path / "x.json")


def test_add_profile_file_roundtrip(tmp_path, monkeypatch):
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    src = tmp_path / "custom.json"
    src.write_text(json.dumps({
        "id": "my-router", "kind": "router", "name": "My Router",
        "soc": "Custom SoC", "vendor_family": "Custom",
        "flash_size": 16777216, "filesystem": "SquashFS",
    }))
    target = add_profile_file(src)
    assert target.name == "my-router.json"
    assert target.is_file()
    # Loading it back through the merged catalog works.
    assert get_profile("my-router").soc == "Custom SoC"
    # A second add without --force is refused.
    with pytest.raises(ProfileError):
        add_profile_file(src)
    # With --force it overwrites.
    assert add_profile_file(src, force=True) == target


def test_load_profile_file_bad_type(tmp_path):
    path = tmp_path / "bad.txt"
    path.write_text("not a profile")
    with pytest.raises(ProfileError):
        load_profile_file(path)
    missing = tmp_path / "missing.json"
    with pytest.raises(ProfileError):
        load_profile_file(missing)


def test_template_for_each_kind_is_valid():
    for kind in ("board", "router", "disk"):
        data = profile_template(kind, f"tpl-{kind}")
        profile, errors = validate_profile_data(data)
        assert errors == []
        assert profile is not None and profile.kind == kind
