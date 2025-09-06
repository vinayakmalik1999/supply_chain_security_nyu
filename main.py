import argparse
import base64
import json
import logging as log
import hashlib

import requests
from util import extract_public_key, verify_artifact_signature
from merkle_proof import DefaultHasher, verify_consistency, verify_inclusion, compute_leaf_hash

# //------ NOTE: I have used Pycharm's autocomplete code function
# in a lot of places as well as stackoverflow in the code however the logic is all mine -----//

bundle_file_path='artifact.bundle'
checkpoint_file_path='checkpoint.json'
# NOTE: verify this to make sure, but extracting log index first from the artifact.bundle
def get_log_index_from_bundle():
    # Assuming file path remains the same
    with open(bundle_file_path, 'r') as file:
        dump = json.load(file)
        try:
            log_index = dump.get('rekorBundle').get('Payload').get('logIndex')
            return log_index
        except KeyError as e:
            log.error(e)
            return None

def get_log_entry(log_index, debug=False):
    # verify that log index value is sane
    if log_index is None:
        log.info("log_index cannot be empty")
        return
    log_entry = {}
    try:
        log_entry = requests.get(f'https://rekor.sigstore.dev/api/v1/log/entries?logIndex={log_index}').json()
        return log_entry

    except requests.exceptions.RequestException as ex:
        log.error('upstream response error from sigstore:',ex)
        return None

def get_verification_proof(log_index, debug=False):
    # verify that log index value is sane
    pass

def inclusion(log_index, artifact_filepath, debug=False):
    # verify that log index and artifact filepath values are sane
    log_entry = get_log_entry(log_index,debug)
    raw_obj = log_entry[list(log_entry.keys())[0]]
    body_encoded = raw_obj.get('body')
    body = json.loads(base64.b64decode(body_encoded))
    signature = base64.b64decode(body["spec"]["signature"]["content"])
    cert = base64.b64decode(body["spec"]["signature"]["publicKey"]["content"])
    public_key = extract_public_key(cert)
    print(raw_obj)

    x = verify_artifact_signature(signature, public_key, artifact_filepath)
    print(x)
    inclusion_proof = raw_obj.get("verification").get("inclusionProof")

    index = inclusion_proof.get("logIndex")
    root_hash = inclusion_proof.get("rootHash")
    tree_size = inclusion_proof.get("treeSize")
    hashes = inclusion_proof.get("hashes")
    leaf_hash = compute_leaf_hash(body_encoded)
    # NOTE: what is this for???
    # get_verification_proof(log_index)
    verify_inclusion(DefaultHasher, index, tree_size, leaf_hash, hashes, root_hash, True)

def get_latest_checkpoint(debug=False):
    # again check this but retreiving log_index first from file
    log_index = get_log_index_from_bundle()
    if log_index is None:
        log.info("log_index cannot be empty")
        return
    try:
        checkpoint = requests.get(f'https://rekor.sigstore.dev/api/v1/log?logIndex={log_index}').json()
        # store output in checkpoint.json
        with open(checkpoint_file_path, 'w') as file:
            # NOTE: maybe no need to json convert look later
            json.dump(checkpoint,file)

        return checkpoint

    except requests.exceptions.RequestException as ex:
        log.error('upstream response error from sigstore:',ex)
        return None

def consistency(prev_checkpoint, debug=False):
    # verify that prev checkpoint is not empty
    # get_latest_checkpoint()
    pass

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
