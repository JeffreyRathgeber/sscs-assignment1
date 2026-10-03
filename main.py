import argparse
from util import extract_public_key, verify_artifact_signature
from merkle_proof import (DefaultHasher, RootMismatchError, verify_consistency,
                          verify_inclusion, compute_leaf_hash)


import base64
import io
import json
import os
from contextlib import redirect_stdout
import requests

REKOR_URL = "https://rekor.sigstore.dev/api/v1"

def get_log_entry(log_index, debug=False):
    # verify that log index value is sane
    if not isinstance(log_index, int) or log_index < 0:
        raise ValueError(f"invalid log index: {log_index}")
    resp = requests.get(f"{REKOR_URL}/log/entries",
                        params={"logIndex": log_index}, timeout=30)
    resp.raise_for_status()
    data = resp.json()
    if not data:
        raise LookupError(f"no entry found at log index {log_index}")
    uuid, entry = next(iter(data.items()))
    if debug:
        print("entry uuid:", uuid)
    return entry

def get_verification_proof(entry, debug=False):
    # verify that log index value is sane
    proof = entry["verification"]["inclusionProof"]
    if debug:
        print("proof logIndex:", proof["logIndex"])
        print("tree size:", proof["treeSize"])
        print("root hash:", proof["rootHash"])
        print("number of proof hashes:", len(proof["hashes"]))
    return proof

def inclusion(log_index, artifact_filepath, debug=False):
    # verify that log index and artifact filepath values are sane
    if log_index is None or log_index < 0:
        print("log index must be a non-negative integer")
        return
    if not artifact_filepath or not os.path.isfile(artifact_filepath):
        print("please give a valid --artifact file path")
        return
    try:
        entry = get_log_entry(log_index, debug)

        # extract_public_key(certificate)
        body = json.loads(base64.b64decode(entry["body"]))
        sig = base64.b64decode(body["spec"]["signature"]["content"])
        cert_pem = base64.b64decode(body["spec"]["signature"]["publicKey"]["content"])
        public_key = extract_public_key(cert_pem)

        # verify_artifact_signature(signature, public_key, artifact_filepath)
        out = io.StringIO()
        with redirect_stdout(out):
            verify_artifact_signature(sig, public_key, artifact_filepath)
        if out.getvalue():
            print(out.getvalue().strip())
            print("Offline verification failed: signature check failed")
            return

        # get_verification_proof(log_index)
        # verify_inclusion(DefaultHasher, index, tree_size, leaf_hash, hashes, root_hash)
        proof = get_verification_proof(entry, debug)
        leaf_hash = compute_leaf_hash(entry["body"])
        if debug:
            print("leaf hash:", leaf_hash)
        verify_inclusion(DefaultHasher, proof["logIndex"], proof["treeSize"],
                         leaf_hash, proof["hashes"], proof["rootHash"], debug)
        print("Offline verification successful")
    except RootMismatchError as e:
        print("Offline verification failed: Merkle root mismatch")
        print(e)
    except Exception as e:
        print(f"Offline verification failed: {e}")

def get_latest_checkpoint(debug=False):
    # Fetch the latest checkpoint from rekor
    resp = requests.get(f"{REKOR_URL}/log", timeout=30)
    resp.raise_for_status()
    checkpoint = resp.json()
    if debug:
        print("tree id:", checkpoint["treeID"])
        print("tree size:", checkpoint["treeSize"])
        print("root hash:", checkpoint["rootHash"])
    return checkpoint

def consistency(prev_checkpoint, debug=False):
    # verify that prev checkpoint is not empty
    if not prev_checkpoint or not all(
            k in prev_checkpoint for k in ("treeID", "treeSize", "rootHash")):
        print("previous checkpoint is empty or incomplete")
        return
    # get_latest_checkpoint()
    try:
        latest = get_latest_checkpoint(debug)

        old_size = prev_checkpoint["treeSize"]
        new_size = latest["treeSize"]
        if str(prev_checkpoint["treeID"]) != str(latest["treeID"]):
            print("Consistency verification failed: tree ID does not match "
                  "the current log tree")
            return
        if old_size >= new_size:
            print("Consistency verification failed: the previous checkpoint "
                  "must be smaller than the latest one")
            return

        resp = requests.get(f"{REKOR_URL}/log/proof",
                            params={"firstSize": old_size,
                                    "lastSize": new_size,
                                    "treeID": latest["treeID"]},
                            timeout=30)
        resp.raise_for_status()
        proof = resp.json()["hashes"]
        if debug:
            print("old size:", old_size, "old root:", prev_checkpoint["rootHash"])
            print("new size:", new_size, "new root:", latest["rootHash"])
            print("number of proof hashes:", len(proof))

        verify_consistency(DefaultHasher, old_size, new_size, proof,
                           prev_checkpoint["rootHash"], latest["rootHash"])
        print("Consistency verification successful")
    except RootMismatchError as e:
        print("Consistency verification failed: root hash mismatch")
        print(e)
    except Exception as e:
        print(f"Consistency verification failed: {e}")

def main():
    debug = False
    parser = argparse.ArgumentParser(description="Rekor Verifier")
    parser.add_argument('-d', '--debug', help='Debug mode',
                        required=False, action='store_true') # Default false
    parser.add_argument('-c', '--checkpoint', help='Obtain latest checkpoint\
                        from Rekor Server public instance',
                        required=False, action='store_true')
    parser.add_argument('--inclusion', help='Verify inclusion of an\
                        entry in the Rekor Transparency Log using log index\
                        and artifact filename.\
                        Usage: --inclusion 126574567',
                        required=False, type=int)
    parser.add_argument('--artifact', help='Artifact filepath for verifying\
                        signature',
                        required=False)
    parser.add_argument('--consistency', help='Verify consistency of a given\
                        checkpoint with the latest checkpoint.',
                        action='store_true')
    parser.add_argument('--tree-id', help='Tree ID for consistency proof',
                        required=False)
    parser.add_argument('--tree-size', help='Tree size for consistency proof',
                        required=False, type=int)
    parser.add_argument('--root-hash', help='Root hash for consistency proof',
                        required=False)
    args = parser.parse_args()
    if args.debug:
        debug = True
        print("enabled debug mode")
    if args.checkpoint:
        # get and print latest checkpoint from server
        # if debug is enabled, store it in a file checkpoint.json
        try:
            checkpoint = get_latest_checkpoint(debug)
        except requests.RequestException as e:
            print(f"failed to fetch checkpoint: {e}")
            return
        print(json.dumps(checkpoint, indent=4))
        if debug:
            with open("checkpoint.json", "w") as f:
                json.dump(checkpoint, f, indent=4)
    if args.inclusion is not None:
        inclusion(args.inclusion, args.artifact, debug)
    if args.consistency:
        if not args.tree_id:
            print("please specify tree id for prev checkpoint")
            return
        if not args.tree_size:
            print("please specify tree size for prev checkpoint")
            return
        if not args.root_hash:
            print("please specify root hash for prev checkpoint")
            return

        prev_checkpoint = {}
        prev_checkpoint["treeID"] = args.tree_id
        prev_checkpoint["treeSize"] = args.tree_size
        prev_checkpoint["rootHash"] = args.root_hash

        consistency(prev_checkpoint, debug)

if __name__ == "__main__":
    main()
