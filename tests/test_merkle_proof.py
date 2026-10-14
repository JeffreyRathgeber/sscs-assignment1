import base64
import hashlib

import merkle_ref as ref
import pytest

from merkle_proof import (
    DefaultHasher,
    Hasher,
    RootMismatchError,
    compute_leaf_hash,
    verify_consistency,
    verify_inclusion,
)

SIZES = range(1, 10)


def hexes(hashes: list[bytes]) -> list[str]:
    return [h.hex() for h in hashes]


def test_hasher_matches_rfc6962_definitions():
    assert DefaultHasher.empty_root() == hashlib.sha256(b"").digest()
    assert DefaultHasher.hash_leaf(b"abc") == ref.leaf_hash(b"abc")
    assert DefaultHasher.hash_children(b"l" * 32, b"r" * 32) == ref.node_hash(
        b"l" * 32, b"r" * 32
    )
    assert DefaultHasher.size() == 32


def test_hasher_accepts_other_hash_function():
    assert Hasher(hashlib.sha512).size() == 64


@pytest.mark.parametrize("size", SIZES)
def test_verify_inclusion_accepts_valid_proofs(size):
    leaves = ref.make_leaves(size)
    tree_root = ref.root(leaves).hex()
    for index in range(size):
        verify_inclusion(
            DefaultHasher,
            index,
            size,
            ref.leaf_hash(leaves[index]).hex(),
            hexes(ref.inclusion_proof(index, leaves)),
            tree_root,
        )


def test_verify_inclusion_debug_prints_hashes(capsys):
    leaves = ref.make_leaves(4)
    verify_inclusion(
        DefaultHasher,
        1,
        4,
        ref.leaf_hash(leaves[1]).hex(),
        hexes(ref.inclusion_proof(1, leaves)),
        ref.root(leaves).hex(),
        debug=True,
    )
    out = capsys.readouterr().out
    assert "Calculated root hash" in out
    assert "Given root hash" in out


def test_verify_inclusion_rejects_wrong_root():
    leaves = ref.make_leaves(5)
    with pytest.raises(RootMismatchError):
        verify_inclusion(
            DefaultHasher,
            2,
            5,
            ref.leaf_hash(leaves[2]).hex(),
            hexes(ref.inclusion_proof(2, leaves)),
            ref.root(ref.make_leaves(6)).hex(),
        )


def test_verify_inclusion_rejects_wrong_leaf():
    leaves = ref.make_leaves(5)
    with pytest.raises(RootMismatchError):
        verify_inclusion(
            DefaultHasher,
            2,
            5,
            ref.leaf_hash(b"not in the tree").hex(),
            hexes(ref.inclusion_proof(2, leaves)),
            ref.root(leaves).hex(),
        )


def test_verify_inclusion_rejects_index_beyond_size():
    leaves = ref.make_leaves(4)
    with pytest.raises(ValueError, match="beyond size"):
        verify_inclusion(
            DefaultHasher,
            4,
            4,
            ref.leaf_hash(leaves[0]).hex(),
            [],
            ref.root(leaves).hex(),
        )


def test_verify_inclusion_rejects_wrong_leaf_hash_length():
    with pytest.raises(ValueError, match="unexpected size"):
        verify_inclusion(DefaultHasher, 0, 1, "abcd", [], "00" * 32)


def test_verify_inclusion_rejects_wrong_proof_length():
    leaves = ref.make_leaves(4)
    proof = hexes(ref.inclusion_proof(1, leaves))[:-1]
    with pytest.raises(ValueError, match="wrong proof size"):
        verify_inclusion(
            DefaultHasher,
            1,
            4,
            ref.leaf_hash(leaves[1]).hex(),
            proof,
            ref.root(leaves).hex(),
        )


def test_root_mismatch_message_is_plain_hex():
    message = str(RootMismatchError(bytes.fromhex("ab" * 32), bytes.fromhex("cd" * 32)))
    assert "cd" * 32 in message
    assert "ab" * 32 in message
    assert "b'" not in message


@pytest.mark.parametrize("new_size", SIZES)
def test_verify_consistency_accepts_valid_proofs(new_size):
    leaves = ref.make_leaves(new_size)
    new_root = ref.root(leaves).hex()
    for old_size in range(1, new_size + 1):
        verify_consistency(
            DefaultHasher,
            old_size,
            new_size,
            hexes(ref.consistency_proof(old_size, leaves)),
            ref.root(leaves[:old_size]).hex(),
            new_root,
        )


def test_verify_consistency_rejects_tampered_new_root():
    leaves = ref.make_leaves(7)
    with pytest.raises(RootMismatchError):
        verify_consistency(
            DefaultHasher,
            3,
            7,
            hexes(ref.consistency_proof(3, leaves)),
            ref.root(leaves[:3]).hex(),
            ref.root(ref.make_leaves(8)).hex(),
        )


def test_verify_consistency_rejects_tampered_old_root():
    leaves = ref.make_leaves(7)
    with pytest.raises(RootMismatchError):
        verify_consistency(
            DefaultHasher,
            3,
            7,
            hexes(ref.consistency_proof(3, leaves)),
            ref.root(ref.make_leaves(3)[::-1]).hex(),
            ref.root(leaves).hex(),
        )


def test_verify_consistency_same_size_needs_matching_roots():
    root_hex = ref.root(ref.make_leaves(4)).hex()
    verify_consistency(DefaultHasher, 4, 4, [], root_hex, root_hex)
    with pytest.raises(RootMismatchError):
        verify_consistency(
            DefaultHasher, 4, 4, [], root_hex, ref.root(ref.make_leaves(5)).hex()
        )


def test_verify_consistency_empty_old_tree_needs_empty_proof():
    root_hex = ref.root(ref.make_leaves(4)).hex()
    verify_consistency(DefaultHasher, 0, 4, [], "", root_hex)
    with pytest.raises(ValueError, match="expected empty"):
        verify_consistency(DefaultHasher, 0, 4, ["00" * 32], "", root_hex)


@pytest.mark.parametrize(
    ("old_size", "new_size", "proof", "message"),
    [
        (5, 3, [], "size2"),
        (4, 4, ["00" * 32], "not empty"),
        (2, 5, [], "empty bytearray_proof"),
        (2, 5, ["00" * 32] * 9, "wrong bytearray_proof size"),
    ],
)
def test_verify_consistency_rejects_malformed_input(old_size, new_size, proof, message):
    with pytest.raises(ValueError, match=message):
        verify_consistency(
            DefaultHasher, old_size, new_size, proof, "00" * 32, "11" * 32
        )


def test_compute_leaf_hash_matches_rfc6962():
    body = b'{"kind": "hashedrekord"}'
    expected = ref.leaf_hash(body).hex()
    assert compute_leaf_hash(base64.b64encode(body).decode()) == expected
