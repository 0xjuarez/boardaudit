"""Batch analysis, diff, and collect_files tests."""

import pytest

from boardaudit.batch import batch_analyze, collect_files, diff_files

EXAMPLE_KEY = b"AKIA" + b"IOSFODNN7EXAMPLE"


def _write(tmp_path, name, payload=b""):
    path = tmp_path / name
    path.write_bytes(b"\x00" * 1024 + payload)
    return path


def test_collect_files_include_exclude(tmp_path):
    _write(tmp_path, "a.bin")
    _write(tmp_path, "b.bin")
    _write(tmp_path, "c.txt")
    sub = tmp_path / "sub"
    sub.mkdir()
    _write(sub, "d.bin")
    files, skipped = collect_files(tmp_path, include=["*.bin"], exclude=["b.bin"])
    assert {p.name for p in files} == {"a.bin", "d.bin"}
    assert skipped  # b.bin excluded
    files2, _ = collect_files(tmp_path, max_files=1)
    assert len(files2) == 1


def test_collect_files_missing_dir():
    with pytest.raises(ValueError):
        collect_files("/nonexistent-dir-xyz")


def test_batch_analyze(tmp_path):
    _write(tmp_path, "a.bin", EXAMPLE_KEY)
    _write(tmp_path, "b.bin", b"plain firmware")
    report = batch_analyze([tmp_path / "a.bin", tmp_path / "b.bin"])
    assert report["kind"] == "batch"
    assert report["total_files"] == 2
    assert report["analyzed_files"] == 2
    assert report["total_findings"] >= 1
    assert report["max_score"] >= 40
    assert EXAMPLE_KEY.decode() not in str(report)


def test_batch_analyze_with_missing_file(tmp_path):
    _write(tmp_path, "a.bin")
    report = batch_analyze([tmp_path / "a.bin", tmp_path / "missing.bin"])
    assert report["analyzed_files"] == 1
    assert len(report["failed_files"]) == 1


def test_batch_analyze_workers(tmp_path):
    _write(tmp_path, "a.bin", EXAMPLE_KEY)
    _write(tmp_path, "b.bin")
    report = batch_analyze(
        [tmp_path / "a.bin", tmp_path / "b.bin"], workers=2
    )
    assert report["analyzed_files"] == 2
    assert report["total_findings"] >= 1


def test_diff_files_identical_and_changed(tmp_path):
    a = _write(tmp_path, "a.bin", b"version one")
    b = _write(tmp_path, "b.bin", b"version one")
    diff = diff_files(a, b)
    assert diff["identical"] is True
    assert diff["findings_added"] == []
    assert diff["findings_removed"] == []

    c = _write(tmp_path, "c.bin", EXAMPLE_KEY)
    diff2 = diff_files(a, c)
    assert diff2["identical"] is False
    assert diff2["score_b"] > diff2["score_a"]
    added_rules = {f["rule"] for f in diff2["findings_added"]}
    assert "aws_access_key" in added_rules
    assert EXAMPLE_KEY.decode() not in str(diff2)
