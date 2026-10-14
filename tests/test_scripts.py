import math
import runpy
import sys
from pathlib import Path

import pytest

import halstead

ROOT = Path(__file__).resolve().parent.parent


def test_halstead_counts_simple_assignment(tmp_path, capsys):
    source = tmp_path / "tiny.py"
    source.write_text("x = 1\n")
    halstead.halstead(str(source))
    out = capsys.readouterr().out
    # operator: "="   operands: x, 1
    assert "n1=1 n2=2 N1=1 N2=2" in out
    assert "vocabulary=3 length=3" in out
    assert f"volume={3 * math.log2(3):.2f}" in out


def test_halstead_counts_keywords_and_brackets_once(tmp_path, capsys):
    source = tmp_path / "tiny.py"
    source.write_text("def f(a):\n    return [a, None]\n")
    halstead.halstead(str(source))
    # operators: def ( : return [ ,    operands: f a a None
    assert "n1=6 n2=3 N1=6 N2=4" in capsys.readouterr().out


def test_halstead_script_runs_on_each_argument(tmp_path, monkeypatch, capsys):
    first, second = tmp_path / "a.py", tmp_path / "b.py"
    first.write_text("x = 1\n")
    second.write_text("y = 2\n")
    monkeypatch.setattr(sys, "argv", ["halstead.py", str(first), str(second)])
    runpy.run_path(str(ROOT / "halstead.py"), run_name="__main__")
    out = capsys.readouterr().out
    assert f"== {first} ==" in out
    assert f"== {second} ==" in out


def test_create_artifact_writes_netid(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(sys, "argv", ["create_artifact.py", "ab1234"])
    runpy.run_path(str(ROOT / "scripts" / "create_artifact.py"), run_name="__main__")
    assert (tmp_path / "artifact.md").read_text() == "ab1234\n"
    assert "created artifact.md" in capsys.readouterr().out


def test_create_artifact_requires_netid(monkeypatch):
    monkeypatch.setattr(sys, "argv", ["create_artifact.py"])
    with pytest.raises(SystemExit, match="Usage"):
        runpy.run_path(
            str(ROOT / "scripts" / "create_artifact.py"), run_name="__main__"
        )
