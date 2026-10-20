"""Substantive boundary tests for the standalone offline release verifier."""
import importlib.util
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("release_verify", ROOT / "scripts" / "release_verify.py")
release_verify = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(release_verify)


def copy_samples(destination: Path) -> None:
    samples = destination / "samples"
    samples.mkdir()
    for name in release_verify.SAMPLES:
        source = ROOT / "samples" / f"{name}.jsonl"
        (samples / source.name).write_bytes(source.read_bytes())


def test_passes_all_samples_and_is_machine_readable():
    result = release_verify.verify_all(ROOT)
    assert result["status"] == "passed"
    assert result["summary"] == {"fixtures_total": 3, "fixtures_passed": 3, "fixtures_failed": 0}
    assert set(result["fixtures"]) == set(release_verify.SAMPLES)
    assert json.loads(json.dumps(result, sort_keys=True, separators=(",", ":"))) == result
    assert "AGENTTRACE_SYNTHETIC_SECRET_001" not in json.dumps(result)


def test_is_offline_and_writes_no_output(tmp_path):
    assert release_verify.verify_all(ROOT)["status"] == "passed"
    assert list(tmp_path.iterdir()) == []


def test_missing_fixture_is_a_bounded_machine_failure(tmp_path):
    samples = tmp_path / "samples"
    samples.mkdir()
    for name in ("benign", "risky"):
        source = ROOT / "samples" / f"{name}.jsonl"
        (samples / source.name).write_bytes(source.read_bytes())
    result = release_verify.verify_all(tmp_path)
    assert result["status"] == "failed"
    assert result["fixtures"]["forensic"] == {"status": "failed", "error": "FileNotFoundError"}
    assert "synthetic-forensic" not in json.dumps(result)


def test_malformed_fixture_fails_without_executing_content(tmp_path):
    copy_samples(tmp_path)
    (tmp_path / "samples" / "risky.jsonl").write_text('not-json\n', encoding="utf-8")
    result = release_verify.verify_all(tmp_path)
    assert result["status"] == "failed"
    assert result["fixtures"]["risky"] == {"status": "failed", "error": "ImportFailure"}


def test_valid_boundary_change_remains_deterministic(tmp_path):
    copy_samples(tmp_path)
    forensic = tmp_path / "samples" / "forensic.jsonl"
    forensic.write_bytes(forensic.read_bytes() + b"\n")
    result = release_verify.verify_all(tmp_path)
    assert result["status"] == "passed"
    assert result["fixtures"]["forensic"]["status"] == "passed"


def test_cli_returns_json_and_nonzero_for_bad_root(tmp_path, capsys):
    assert release_verify.main(["--root", str(tmp_path)]) == 1
    result = json.loads(capsys.readouterr().out)
    assert result["status"] == "failed"
    assert result["summary"]["fixtures_failed"] == 3
