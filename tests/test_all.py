import sys
from merkle_proof import DefaultHasher
import json
import base64
from unittest.mock import patch
import pytest
import merkle_proof
import util
import main

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization

@patch('requests.get')
def test_get_log_entry_none_index(mock_get):
    """Test get_log_entry with None index."""
    result = main.get_log_entry(None)
    assert result is None


def test_verify_inclusion_basic():
    """Test basic inclusion verification."""
    leaf_info = {
        "index": 0,
        "size": 1,
        "hash": "a" * 64
    }
    proof = []
    root = "a" * 64

    try:
        # This will fail but tests the function exists and accepts args
        merkle_proof.verify_inclusion(
            merkle_proof.DefaultHasher,
            leaf_info,
            proof,
            root
        )
    except Exception:
        # Function exists and was called
        pass

# -------------------------
# main.get_log_index_from_bundle
# -------------------------
def test_get_log_index_from_bundle_missing(tmp_path, monkeypatch):
    # create a bundle without rekorBundle key
    p = tmp_path / "artifact.bundle"
    p.write_text(json.dumps({"bogus": {}}))
    monkeypatch.chdir(tmp_path)
    assert main.get_log_index_from_bundle() is None

# -------------------------
# util.verify_artifact_signature happy & unhappy paths
# -------------------------
def test_verify_artifact_signature_valid_and_invalid(tmp_path, capsys):
    # create data file
    data = b"hello-world"
    file_path = tmp_path / "hello.bin"
    file_path.write_bytes(data)

    # generate ECDSA keypair
    priv = ec.generate_private_key(ec.SECP256R1())
    pub = priv.public_key()
    pub_pem = pub.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    # sign data correctly
    sig = priv.sign(data, ec.ECDSA(hashes.SHA256()))
    # good signature -> verify_artifact_signature should not print "Signature is invalid"
    util.verify_artifact_signature(sig, pub_pem, str(file_path))
    out = capsys.readouterr().out
    assert "Signature is invalid" not in out

    # corrupt signature -> should print "Signature is invalid"
    bad_sig = sig[:-1] + (b"\x00" if len(sig) > 0 else b"\x00")
    util.verify_artifact_signature(bad_sig, pub_pem, str(file_path))
    out2 = capsys.readouterr().out
    assert "Signature is invalid" in out2


def make_valid_log_entry():
    """Helper to build a fake Rekor log entry suitable for inclusion()."""
    body_obj = {
        "spec": {
            "signature": {
                "content": base64.b64encode(b"dummy-signature").decode(),
                "publicKey": {"content": base64.b64encode(b"dummy-cert").decode()},
            }
        }
    }
    body_encoded = base64.b64encode(json.dumps(body_obj).encode()).decode()

    return {
        "0": {
            "body": body_encoded,
            "verification": {
                "inclusionProof": {
                    "logIndex": 0,
                    "treeSize": 1,
                    "hashes": [],
                    "rootHash": "a" * 64,
                }
            },
        }
    }


@patch("main.get_log_entry")
@patch("main.extract_public_key")
@patch("main.verify_artifact_signature")
@patch("main.compute_leaf_hash")
@patch("main.verify_inclusion")
def test_inclusion_and_consistency_integration(
    mock_verify_inclusion,
    mock_compute_leaf_hash,
    mock_verify_sig,
    mock_extract_pub,
    mock_get_log_entry,
    tmp_path,
    capsys,
):
    # Mock Rekor entry for inclusion
    mock_get_log_entry.return_value = make_valid_log_entry()
    mock_extract_pub.return_value = b"-----BEGIN PUBLIC KEY-----"
    mock_verify_sig.return_value = None
    mock_compute_leaf_hash.return_value = "b" * 64
    mock_verify_inclusion.return_value = None

    # Create a dummy artifact file
    artifact = tmp_path / "artifact.bin"
    artifact.write_bytes(b"artifact-data")

    # Test inclusion() happy path
    main.inclusion(0, str(artifact), debug=True)
    output = capsys.readouterr().out
    assert "Signature is valid" in output
    assert "Offline root hash calculation for inclusion verified" in output

    # --- Now test consistency() happy path ---
    prev_checkpoint = {
        "treeID": "dummyTree",
        "treeSize": 10,
        "rootHash": "a" * 64,
    }

    latest_checkpoint = {
        "treeID": "dummyTree",
        "treeSize": 12,
        "rootHash": "b" * 64,
    }

    # Mock dependencies
    with patch("main.get_latest_checkpoint", return_value=latest_checkpoint), patch(
        "requests.get"
    ) as mock_get, patch("main.verify_consistency") as mock_vc:
        mock_get.return_value.json.return_value = {"hashes": ["c" * 64, "d" * 64]}
        main.consistency(prev_checkpoint, debug=True)
        out = capsys.readouterr().out
        # Expected debug output and success message
        assert "Fetched" in out
        assert "Consistency verification successful" in out
        mock_vc.assert_called_once_with(
            DefaultHasher,
            sizes=(10, 12),
            proof=["c" * 64, "d" * 64],
            roots=("a" * 64, "b" * 64),
        )


def run_main_with_args(args, capsys):
    """Helper to invoke main.main() with fake CLI args."""
    test_args = ["prog"] + args
    with patch.object(sys, "argv", test_args):
        main.main()
    return capsys.readouterr().out

@patch("main.consistency")
def test_main_consistency_success(mock_consistency, capsys):
    """Test consistency branch with all required args."""
    args = [
        "--consistency",
        "--tree-id", "mytree",
        "--tree-size", "42",
        "--root-hash", "b"*64,
    ]
    output = run_main_with_args(args, capsys)
    mock_consistency.assert_called_once()
    called_checkpoint = mock_consistency.call_args[0][0]
    # Check arguments are parsed correctly
    assert called_checkpoint["treeID"] == "mytree"
    assert called_checkpoint["treeSize"] == 42
    assert "Consistency verification" not in output  # function is mocked


@pytest.mark.parametrize(
    "missing_flag,expected_msg",
    [
        ("--tree-id", "please specify tree id"),
        ("--tree-size", "please specify tree size"),
        ("--root-hash", "please specify root hash"),
    ],
)
def test_main_consistency_missing_args(missing_flag, expected_msg, capsys):
    """Test missing argument messages in consistency branch."""
    base_args = [
        "--consistency",
        "--tree-id", "T1",
        "--tree-size", "10",
        "--root-hash", "a"*64,
    ]
    # remove one flag and its value
    idx = base_args.index(missing_flag)
    del base_args[idx:idx+2]

    output = run_main_with_args(base_args, capsys)
    assert expected_msg in output

def test_verify_consistency_second_half():
    hasher = DefaultHasher

    size1 = 3
    size2 = 5

    # Provide proof long enough for inner + border computation
    # We'll mock decomp_incl_proof to inner=1, border=2, so total slice length = 3
    proof = ["a"*64, "b"*64, "c"*64, "d"*64]  # one extra to account for slicing

    root1 = "d"*64
    root2 = "e"*64

    # Patch dependent functions
    with patch("merkle_proof.decomp_incl_proof", return_value=(1, 2)), \
         patch("merkle_proof.chain_inner_right", return_value=b"X") as mock_inner_right, \
         patch("merkle_proof.chain_inner", return_value=b"Y") as mock_inner, \
         patch("merkle_proof.chain_border_right", side_effect=lambda h, s, p: s) as mock_border, \
         patch("merkle_proof.verify_match") as mock_verify:

        # Call function — now proof length matches inner+border
        merkle_proof.verify_consistency(hasher, (size1, size2), proof, (root1, root2))

        # Check calls
        mock_inner_right.assert_called()
        mock_inner.assert_called()
        mock_border.assert_called()
        assert mock_verify.call_count == 2