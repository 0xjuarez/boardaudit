"""Path traversal and scan-id validation tests."""

import pytest

from boardaudit.report import scan_dir, validate_scan_id


def test_valid_scan_id():
    assert validate_scan_id("20261107-120000") == "20261107-120000"
    assert validate_scan_id("scan_1-a") == "scan_1-a"


def test_invalid_scan_ids():
    for bad in ["../etc", "..", "a/b", "a b", "a;b", "", "a\\b", "a/b/c"]:
        with pytest.raises(ValueError):
            validate_scan_id(bad)


def test_scan_dir_stays_inside_base(tmp_path):
    directory = scan_dir(tmp_path, "20261107-120000")
    assert directory == (tmp_path / "20261107-120000").resolve()


def test_scan_dir_rejects_traversal(tmp_path):
    with pytest.raises(ValueError):
        scan_dir(tmp_path, "../escape")
