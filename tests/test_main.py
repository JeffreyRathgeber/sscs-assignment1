import json
import sys

import merkle_ref as ref
import pytest
import requests
from conftest import FakeResponse
from jsonschema import validate

import main

CHECKPOINT_SCHEMA = {
    "type": "object",
    "properties": {
        "inactiveShards": {"type": "array"},
        "rootHash": {"type": "string"},
        "signedTreeHead": {"type": "string"},
        "treeID": {"type": "string"},
        "treeSize": {"type": "integer"},
    },
    "required": ["inactiveShards", "rootHash", "signedTreeHead", "treeID", "treeSize"],
}


@pytest.fixture
def route(monkeypatch):
    """Replace requests.get with a fake that answers by URL suffix."""

    def install(routes):
        calls = []

        def fake_get(url, params=None, timeout=None):
            calls.append((url, params))
            for suffix, result in routes.items():
                if url.endswith(suffix):
                    if isinstance(result, Exception):
                        raise result
                    return FakeResponse(result)
            raise AssertionError(f"unexpected request: {url}")

        monkeypatch.setattr(main.requests, "get", fake_get)
        return calls

    return install


def run_main(monkeypatch, *args):
    monkeypatch.setattr(sys, "argv", ["main.py", *args])
    main.main()


def checkpoint(tree_size=8, tree_id="1234", root="aa" * 32):
    return {
        "inactiveShards": [],
        "rootHash": root,
        "signedTreeHead": "rekor.sigstore.dev - 1234\n8\nabc=\n",
        "treeID": tree_id,
        "treeSize": tree_size,
    }


# --- get_log_entry / get_verification_proof / get_latest_checkpoint ---


@pytest.mark.parametrize("bad_index", [-1, "5", None, 1.5])
def test_get_log_entry_rejects_invalid_index_without_request(route, bad_index):
    calls = route({})
    with pytest.raises(ValueError, match="invalid log index"):
        main.get_log_entry(bad_index)
    assert calls == []


def test_get_log_entry_returns_entry_and_prints_uuid_in_debug(route, capsys):
    calls = route({"/log/entries": {"uuid-1": {"body": "x"}}})
    assert main.get_log_entry(7, debug=True) == {"body": "x"}
    assert "entry uuid: uuid-1" in capsys.readouterr().out
    assert calls[0][1] == {"logIndex": 7}


def test_get_log_entry_raises_when_no_entry(route):
    route({"/log/entries": {}})
    with pytest.raises(LookupError, match="no entry found"):
        main.get_log_entry(7)


def test_get_log_entry_raises_on_http_error(monkeypatch):
    monkeypatch.setattr(
        main.requests, "get", lambda *a, **k: FakeResponse({}, status=500)
    )
    with pytest.raises(requests.HTTPError):
        main.get_log_entry(7)


def test_get_verification_proof_returns_proof_and_prints_in_debug(signed_entry, capsys):
    proof = main.get_verification_proof(signed_entry.entry, debug=True)
    assert proof["logIndex"] == signed_entry.log_index
    out = capsys.readouterr().out
    assert "tree size: 5" in out
    assert "number of proof hashes:" in out


def test_get_latest_checkpoint_returns_json_and_prints_in_debug(route, capsys):
    route({"/log": checkpoint()})
    assert main.get_latest_checkpoint(debug=True) == checkpoint()
    assert "tree id: 1234" in capsys.readouterr().out


# --- inclusion ---


def test_inclusion_accepts_valid_entry(route, signed_entry, capsys):
    route({"/log/entries": {"uuid": signed_entry.entry}})
    main.inclusion(signed_entry.log_index, str(signed_entry.artifact), debug=True)
    out = capsys.readouterr().out
    assert "Offline verification successful" in out
    assert "leaf hash:" in out


@pytest.mark.parametrize("path", [None, "", "no/such/file"])
def test_inclusion_rejects_bad_artifact_path(route, capsys, path):
    calls = route({})
    main.inclusion(1, path)
    assert "invalid --artifact file path" in capsys.readouterr().out
    assert calls == []


def test_inclusion_rejects_negative_index(route, signed_entry, capsys):
    route({})
    main.inclusion(-1, str(signed_entry.artifact))
    out = capsys.readouterr().out
    assert "Offline verification failed: invalid log index: -1" in out


def test_inclusion_rejects_modified_artifact(route, signed_entry, capsys):
    route({"/log/entries": {"uuid": signed_entry.entry}})
    signed_entry.artifact.write_bytes(b"modified")
    main.inclusion(signed_entry.log_index, str(signed_entry.artifact))
    out = capsys.readouterr().out
    assert "Offline verification failed: signature is invalid" in out
    assert "successful" not in out


def test_inclusion_reports_merkle_root_mismatch(route, signed_entry, capsys):
    signed_entry.entry["verification"]["inclusionProof"]["rootHash"] = "00" * 32
    route({"/log/entries": {"uuid": signed_entry.entry}})
    main.inclusion(signed_entry.log_index, str(signed_entry.artifact))
    out = capsys.readouterr().out
    assert "Merkle root mismatch" in out
    assert "calculated root" in out


def test_inclusion_reports_missing_entry(route, signed_entry, capsys):
    route({"/log/entries": {}})
    main.inclusion(99, str(signed_entry.artifact))
    assert "no entry found at log index 99" in capsys.readouterr().out


def test_inclusion_reports_network_failure(route, signed_entry, capsys):
    route({"/log/entries": requests.ConnectionError("network down")})
    main.inclusion(1, str(signed_entry.artifact))
    assert "Offline verification failed: network down" in capsys.readouterr().out


# --- consistency ---


@pytest.fixture
def log_8():
    leaves = ref.make_leaves(8)
    latest = checkpoint(tree_size=8, root=ref.root(leaves).hex())
    prev = {"treeID": "1234", "treeSize": 3, "rootHash": ref.root(leaves[:3]).hex()}
    proof = {"hashes": [h.hex() for h in ref.consistency_proof(3, leaves)]}
    return prev, latest, proof


@pytest.mark.parametrize("prev", [{}, None, {"treeID": "1", "treeSize": 2}])
def test_consistency_rejects_incomplete_checkpoint(route, capsys, prev):
    calls = route({})
    main.consistency(prev)
    assert "empty or incomplete" in capsys.readouterr().out
    assert calls == []


def test_consistency_accepts_valid_proof(route, log_8, capsys):
    prev, latest, proof = log_8
    calls = route({"/log": latest, "/log/proof": proof})
    main.consistency(prev, debug=True)
    out = capsys.readouterr().out
    assert "Consistency verification successful" in out
    assert "number of proof hashes:" in out
    assert calls[-1][1] == {"firstSize": 3, "lastSize": 8, "treeID": "1234"}


def test_consistency_rejects_different_tree_id(route, log_8, capsys):
    prev, latest, proof = log_8
    prev["treeID"] = "9999"
    route({"/log": latest, "/log/proof": proof})
    main.consistency(prev)
    assert "tree ID does not match" in capsys.readouterr().out


def test_consistency_requires_smaller_previous_checkpoint(route, log_8, capsys):
    prev, latest, proof = log_8
    prev["treeSize"] = 8
    route({"/log": latest, "/log/proof": proof})
    main.consistency(prev)
    assert "must be smaller" in capsys.readouterr().out


def test_consistency_reports_root_mismatch(route, log_8, capsys):
    prev, latest, proof = log_8
    prev["rootHash"] = "00" * 32
    route({"/log": latest, "/log/proof": proof})
    main.consistency(prev)
    assert "root hash mismatch" in capsys.readouterr().out


def test_consistency_reports_network_failure(route, log_8, capsys):
    prev, _, _ = log_8
    route({"/log": requests.ConnectionError("network down")})
    main.consistency(prev)
    assert "Consistency verification failed: network down" in capsys.readouterr().out


# --- command line ---


def test_checkpoint_option_prints_valid_checkpoint_json(route, monkeypatch, capsys):
    route({"/log": checkpoint()})
    run_main(monkeypatch, "-c")
    validate(instance=json.loads(capsys.readouterr().out), schema=CHECKPOINT_SCHEMA)


def test_checkpoint_with_debug_saves_checkpoint_file(
    route, monkeypatch, tmp_path, capsys
):
    route({"/log": checkpoint()})
    monkeypatch.chdir(tmp_path)
    run_main(monkeypatch, "-c", "-d")
    assert "enabled debug mode" in capsys.readouterr().out
    saved = json.loads((tmp_path / "checkpoint.json").read_text())
    validate(instance=saved, schema=CHECKPOINT_SCHEMA)


def test_checkpoint_option_reports_fetch_failure(route, monkeypatch, capsys):
    route({"/log": requests.ConnectionError("network down")})
    run_main(monkeypatch, "-c")
    assert "failed to fetch checkpoint: network down" in capsys.readouterr().out


def test_inclusion_option_calls_inclusion(monkeypatch):
    seen = []
    monkeypatch.setattr(main, "inclusion", lambda *args: seen.append(args))
    run_main(monkeypatch, "--inclusion", "42", "--artifact", "a.md", "-d")
    assert seen == [(42, "a.md", True)]


@pytest.mark.parametrize(
    ("args", "message"),
    [
        ([], "tree id"),
        (["--tree-id", "1"], "tree size"),
        (["--tree-id", "1", "--tree-size", "5"], "root hash"),
    ],
)
def test_consistency_option_requires_all_arguments(monkeypatch, capsys, args, message):
    monkeypatch.setattr(main, "consistency", lambda *a: pytest.fail("called"))
    run_main(monkeypatch, "--consistency", *args)
    assert message in capsys.readouterr().out


def test_consistency_option_calls_consistency(monkeypatch):
    seen = []
    monkeypatch.setattr(main, "consistency", lambda *args: seen.append(args))
    run_main(
        monkeypatch,
        "--consistency",
        "--tree-id",
        "1",
        "--tree-size",
        "5",
        "--root-hash",
        "ab",
    )
    assert seen == [({"treeID": "1", "treeSize": 5, "rootHash": "ab"}, False)]


def test_no_options_does_nothing(monkeypatch, capsys):
    run_main(monkeypatch)
    assert capsys.readouterr().out == ""
