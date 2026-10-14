"""Independent RFC 6962 reference implementation used to build test proofs."""

import hashlib


def leaf_hash(data: bytes) -> bytes:
    return hashlib.sha256(b"\x00" + data).digest()


def node_hash(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(b"\x01" + left + right).digest()


def split(n: int) -> int:
    """Largest power of two strictly less than n."""
    k = 1
    while k * 2 < n:
        k *= 2
    return k


def root(leaves: list[bytes]) -> bytes:
    if not leaves:
        return hashlib.sha256(b"").digest()
    if len(leaves) == 1:
        return leaf_hash(leaves[0])
    k = split(len(leaves))
    return node_hash(root(leaves[:k]), root(leaves[k:]))


def inclusion_proof(index: int, leaves: list[bytes]) -> list[bytes]:
    if len(leaves) == 1:
        return []
    k = split(len(leaves))
    if index < k:
        return inclusion_proof(index, leaves[:k]) + [root(leaves[k:])]
    return inclusion_proof(index - k, leaves[k:]) + [root(leaves[:k])]


def _subproof(m: int, leaves: list[bytes], complete: bool) -> list[bytes]:
    if m == len(leaves):
        return [] if complete else [root(leaves)]
    k = split(len(leaves))
    if m <= k:
        return _subproof(m, leaves[:k], complete) + [root(leaves[k:])]
    return _subproof(m - k, leaves[k:], False) + [root(leaves[:k])]


def consistency_proof(old_size: int, leaves: list[bytes]) -> list[bytes]:
    return _subproof(old_size, leaves, True)


def make_leaves(n: int) -> list[bytes]:
    return [f"leaf-{i}".encode() for i in range(n)]
