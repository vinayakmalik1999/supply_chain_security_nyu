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
from util import extract_public_key, verify_artifact_signature
from merkle_proof import (
    DefaultHasher,
    verify_consistency,
    verify_inclusion,
    compute_leaf_hash,
)

# //------ NOTE: I have used Pycharm's autocomplete code function
# in a lot of places as well as stackoverflow in the code however the logic is all mine -----//

bundle_file_path = "artifact.bundle"
checkpoint_file_path = "checkpoint.json"


def get_log_index_from_bundle():
    """
    Extract the Rekor log index from the artifact.bundle file.

    Returns:
        int | None: The log index if found, otherwise None.

    Raises:
        KeyError: If 'rekorBundle' or 'Payload' keys are missing in the bundle.
    """
    with open(bundle_file_path, "r") as file:
        dump = json.load(file)
        try:
            log_index = dump["rekorBundle"]["Payload"]["logIndex"]
            return log_index
        except KeyError as e:
            log.error(e)
            return None


def get_log_entry(log_index, debug=False):
    """
    Retrieve a Rekor log entry by its log index.

    Args:
        log_index (int): The log index of the entry.
        debug (bool): If True, enables debug logging.

    Returns:
        dict | None: The log entry JSON object if found, otherwise None.

    Logs:
        Error if the Rekor API call fails or log_index is invalid.
    """
    if log_index is None:
        log.info("log_index cannot be empty")
        return
    log_entry = {}
    try:
        log_entry = requests.get(
            f"https://rekor.sigstore.dev/api/v1/log/entries?logIndex={log_index}"
        ).json()
        return log_entry

    except requests.exceptions.RequestException as ex:
        log.error("upstream response error from sigstore:", ex)
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

    # verify that log index and artifact filepath values are sane
    log_entry = get_log_entry(log_index, debug)
    raw_obj = log_entry[list(log_entry.keys())[0]]
    body_encoded = raw_obj.get("body")
    body = json.loads(base64.b64decode(body_encoded))
    signature = base64.b64decode(body["spec"]["signature"]["content"])
    cert = base64.b64decode(body["spec"]["signature"]["publicKey"]["content"])
    public_key = extract_public_key(cert)
    try:
        verify_artifact_signature(signature, public_key, artifact_filepath)
        print("Signature is valid.")
    except Exception as e:
        print("Signature is not valid", str(e))

    inclusion_proof = raw_obj["verification"]["inclusionProof"]

    index = inclusion_proof.get("logIndex")
    root_hash = inclusion_proof.get("rootHash")
    tree_size = inclusion_proof.get("treeSize")
    hashes = inclusion_proof.get("hashes")
    leaf_hash = compute_leaf_hash(body_encoded)

    try:
        verify_inclusion(
            DefaultHasher, index, tree_size, leaf_hash, hashes, root_hash, debug
        )
        print("Offline root hash calculation for inclusion verified.")
    except Exception as e:
        print("Offline root hash calculation for inclusion failed.", str(e))


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
        checkpoint = requests.get("https://rekor.sigstore.dev/api/v1/log").json()
        # store output in checkpoint.json if debug is on
        if debug:
            with open(checkpoint_file_path, "w") as file:
                json.dump(checkpoint, file)

        return checkpoint

    except requests.exceptions.RequestException as ex:
        log.error("upstream response error from sigstore:", ex)
        return None


def consistency(prev_checkpoint, debug=False):
    """
    Verify the consistency between a previous checkpoint and the latest one.

    Args:
        prev_checkpoint (dict): A dictionary containing the previous checkpoint details
            with keys 'treeID', 'treeSize', and 'rootHash'.
        debug (bool): Enables debug output if True.

    Raises:
        Exception: If consistency verification fails.
    """
    # verify that prev checkpoint is not empty
    latest_checkpoint = get_latest_checkpoint()

    old_tree_size = prev_checkpoint["treeSize"]
    old_root = prev_checkpoint["rootHash"]
    old_tree_id = prev_checkpoint["treeID"]
    new_tree_size = latest_checkpoint["treeSize"]
    new_root = latest_checkpoint["rootHash"]

    try:
        proof = requests.get(
            f"https://rekor.sigstore.dev/api/v1/log/proof?firstSize={old_tree_size}&lastSize={new_tree_size}&treeID={old_tree_id}"
        ).json()
        proof_hashes = [h for h in proof.get("hashes", [])]
    except requests.exceptions.RequestException as ex:
        log.error("error:", ex)
        return
    try:
        verify_consistency(
            DefaultHasher,
            old_tree_size,
            new_tree_size,
            proof_hashes,
            old_root,
            new_root,
        )
        print("Consistency verification successful.")
    except Exception as e:
        print("Consistency verification failed:", str(e))


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
