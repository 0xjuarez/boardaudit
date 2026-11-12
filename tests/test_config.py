"""Config file tests: defaults, redaction cannot be disabled, thresholds."""

from boardaudit.config import find_config_file, load_config


def test_load_config_defaults(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    config, warnings = load_config()
    assert config["output_dir"] == "boardaudit-out"
    assert config["redaction"] is True
    assert config["risk_thresholds"] == {"medium": 25, "high": 50, "critical": 80}
    assert warnings == []
    assert find_config_file(tmp_path) is None


def test_load_config_from_file(tmp_path):
    path = tmp_path / "boardaudit.toml"
    path.write_text(
        '[boardaudit]\noutput_dir = "my-scans"\nredaction = true\n'
        "[boardaudit.risk_thresholds]\nmedium = 20\nhigh = 40\ncritical = 70\n"
    )
    config, warnings = load_config(path)
    assert config["output_dir"] == "my-scans"
    assert config["risk_thresholds"] == {"medium": 20, "high": 40, "critical": 70}
    assert warnings == []


def test_config_cannot_disable_redaction(tmp_path):
    path = tmp_path / "boardaudit.toml"
    path.write_text('[boardaudit]\nredaction = false\n')
    config, warnings = load_config(path)
    assert config["redaction"] is True
    assert any("redaction" in warning for warning in warnings)


def test_config_invalid_toml_falls_back(tmp_path):
    path = tmp_path / "boardaudit.toml"
    path.write_text("[boardaudit\nnot valid toml")
    config, warnings = load_config(path)
    assert config["output_dir"] == "boardaudit-out"
    assert config["redaction"] is True
    assert warnings


def test_config_bad_thresholds_fall_back(tmp_path):
    path = tmp_path / "boardaudit.toml"
    path.write_text(
        "[boardaudit.risk_thresholds]\nmedium = 90\nhigh = 50\ncritical = 10\n"
    )
    config, warnings = load_config(path)
    assert config["risk_thresholds"] == {"medium": 25, "high": 50, "critical": 80}
    assert warnings


def test_load_config_missing_path(tmp_path):
    config, warnings = load_config(tmp_path / "nope.toml")
    assert config["redaction"] is True
    assert warnings
