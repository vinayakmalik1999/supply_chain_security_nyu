"""
Rekor Verifier Utility

This module provides functions to interact with the Sigstore Rekor transparency log
for verifying artifact inclusion, consistency, and signatures using cryptographic proofs.

It supports:
- Extracting log indices from Rekor bundles.
- Fetching Rekor log entries and checkpoints.
- Verifying inclusion proofs and consistency proofs.
- Validating artifact signatures against embedded certificates.

Command-line usage is supported for debugging, inclusion checks, and consistency checks.
"""

import argparse
import base64
import json
import logging as log

import requests
from .util import extract_public_key, verify_artifact_signature

from .merkle_proof import (
    DefaultHasher,
    verify_consistency,
    verify_inclusion,
    compute_leaf_hash,
)


BUNDLE_FILE_PATH = "artifact.bundle"
CHECKPOINT_FILE_PATH = "checkpoint.json"


def get_log_index_from_bundle():
    """
    Extract the Rekor log index from the artifact.bundle file.

    Returns:
        int | None: The log index if found, otherwise None.

    Raises:
        KeyError: If 'rekorBundle' or 'Payload' keys are missing in the bundle.
    """
    with open(BUNDLE_FILE_PATH, "r", encoding="utf-8") as file:
        dump = json.load(file)
        try:
            return dump["rekorBundle"]["Payload"]["logIndex"]
        except KeyError as e:
            log.error("%s", e)
            return None


def get_log_entry(log_index):
    """
    Retrieve a Rekor log entry by its log index.

    Args:
        log_index (int): The log index of the entry.

    Returns:
        dict | None: The log entry JSON object if found, otherwise None.

    Logs:
        Error if the Rekor API call fails or log_index is invalid.
    """
    if log_index is None:
        log.info("log_index cannot be empty")
        return None
    try:
        return requests.get(
            f"https://rekor.sigstore.dev/api/v1/log/entries?logIndex={log_index}",
            timeout=10,
        ).json()
    except requests.exceptions.RequestException as ex:
        log.error("upstream response error from sigstore: %s", ex)
        return None


def inclusion(log_index, artifact_filepath, debug=False):
    """
    Verify artifact inclusion in the Rekor transparency log.

    This function validates both the artifact signature and the inclusion proof.

    Args:
        log_index (int): The Rekor log index to verify.
        artifact_filepath (str): Path to the artifact to verify.
        debug (bool): Enables debug output if True.

    Raises:
        Exception: If the signature or inclusion proof verification fails.
    """

    log_entry = get_log_entry(log_index)
    raw_obj = next(iter(log_entry.values()))
    body_encoded = raw_obj.get("body")

    body = json.loads(base64.b64decode(body_encoded))
    sig_spec = body["spec"]["signature"]
    signature = base64.b64decode(sig_spec["content"])
    cert_data = base64.b64decode(sig_spec["publicKey"]["content"])
    public_key = extract_public_key(cert_data)

    try:
        verify_artifact_signature(signature, public_key, artifact_filepath)
        print("Signature is valid.")
    except ValueError as err:
        print("Signature is not valid:", err)

    proof_data = raw_obj["verification"]["inclusionProof"]
    leaf_hash_hex = compute_leaf_hash(body_encoded)

    leaf_info = {
        "index": proof_data.get("logIndex"),
        "size": proof_data.get("treeSize"),
        "hash": leaf_hash_hex,
    }

    try:
        verify_inclusion(
            DefaultHasher,
            leaf_info,
            proof_data.get("hashes", []),
            proof_data.get("rootHash"),
            debug,
        )
        print("Offline root hash calculation for inclusion verified.")
    except ValueError as err:
        print("Offline root hash calculation for inclusion failed:", err)


def get_latest_checkpoint(debug=False):
    """
    Fetch the latest Rekor checkpoint from the public instance.

    Args:
        debug (bool): If True, saves the checkpoint to a local file.

    Returns:
        dict | None: Latest checkpoint JSON data if successful, otherwise None.

    Logs:
        Error if the Rekor API call fails.
    """

    try:
        checkpoint = requests.get(
            "https://rekor.sigstore.dev/api/v1/log", timeout=10
        ).json()
        # store output in checkpoint.json if debug is on
        if debug:
            with open(CHECKPOINT_FILE_PATH, "w", encoding="utf-8") as file:
                json.dump(checkpoint, file)

        return checkpoint

    except requests.exceptions.RequestException as ex:
        log.error("Upstream response error from sigstore: %s", ex)
        return None


def consistency(prev_checkpoint, debug=False):
    """
    Verify the consistency between a previous checkpoint and the latest one.

    Args:
        prev_checkpoint (dict): Dictionary containing previous checkpoint details
            with keys 'treeID', 'treeSize', and 'rootHash'.

    Raises:
        Exception: If consistency verification fails.
    """
    latest_checkpoint = get_latest_checkpoint()

    old_tree_size = prev_checkpoint["treeSize"]
    old_root = prev_checkpoint["rootHash"]
    old_tree_id = prev_checkpoint["treeID"]
    new_tree_size = latest_checkpoint["treeSize"]
    new_root = latest_checkpoint["rootHash"]

    try:
        proof = requests.get(
            f"https://rekor.sigstore.dev/api/v1/log/proof?firstSize={old_tree_size}"
            f"&lastSize={new_tree_size}&treeID={old_tree_id}",
            timeout=10,
        ).json()
        proof_hashes = list(proof.get("hashes", []))
        if debug:
            print(f"Fetched {len(proof_hashes)} proof hashes for consistency check.")
    except requests.exceptions.RequestException as ex:
        log.error("Error retrieving proof: %s", ex)
        return

    try:
        # Updated call to match the new signature
        verify_consistency(
            DefaultHasher,
            sizes=(old_tree_size, new_tree_size),
            proof=proof_hashes,
            roots=(old_root, new_root),
        )
        print("Consistency verification successful.")
    except ValueError as e:
        print("Consistency verification failed:", str(e))
        if debug:
            print(f"Old root: {old_root}\nNew root: {new_root}")


def main():
    """
    Command-line interface entry point for the program.

    Supports inclusion proof checks, consistency verification,
    and checkpoint retrieval.
    """
    debug = False
    parser = argparse.ArgumentParser(description="Rekor Verifier")
    parser.add_argument(
        "-d", "--debug", help="Debug mode", required=False, action="store_true"
    )  # Default false
    parser.add_argument(
        "-c",
        "--checkpoint",
        help="Obtain latest checkpoint\
                        from Rekor Server public instance",
        required=False,
        action="store_true",
    )
    parser.add_argument(
        "--inclusion",
        help="Verify inclusion of an\
                        entry in the Rekor Transparency Log using log index\
                        and artifact filename.\
                        Usage: --inclusion 126574567",
        required=False,
        type=int,
    )
    parser.add_argument(
        "--artifact",
        help="Artifact filepath for verifying\
                        signature",
        required=False,
    )
    parser.add_argument(
        "--consistency",
        help="Verify consistency of a given\
                        checkpoint with the latest checkpoint.",
        action="store_true",
    )
    parser.add_argument(
        "--tree-id", help="Tree ID for consistency proof", required=False
    )
    parser.add_argument(
        "--tree-size", help="Tree size for consistency proof", required=False, type=int
    )
    parser.add_argument(
        "--root-hash", help="Root hash for consistency proof", required=False
    )
    args = parser.parse_args()
    if args.debug:
        debug = True
        print("enabled debug mode")
    if args.checkpoint:
        # get and print latest checkpoint from server
        # if debug is enabled, store it in a file checkpoint.json
        checkpoint = get_latest_checkpoint(debug)
        print(json.dumps(checkpoint, indent=4))
    if args.inclusion:
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
