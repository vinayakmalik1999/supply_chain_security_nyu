"""
Merkle Tree Proof Verification Utilities

This module implements cryptographic hash functions and proof verification logic
for verifying inclusion and consistency proofs in transparency logs.
"""

import hashlib
import binascii
import base64

# domain separation prefixes according to the RFC
RFC6962_LEAF_HASH_PREFIX = 0
RFC6962_NODE_HASH_PREFIX = 1


class Hasher:
    """
    Provides RFC 6962-compatible hashing operations using a specified hash function.

    Attributes:
        hash_func (Callable): Hash function to use (e.g., hashlib.sha256).
    """

    def __init__(self, hash_func=hashlib.sha256):
        self.hash_func = hash_func

    def new(self):
        """
        Create a new hash object using the configured hash function.

        Returns:
            hashlib._Hash: A new hash object instance.
        """
        return self.hash_func()

    def empty_root(self):
        """
        Compute the digest of an empty tree.

        Returns:
            bytes: The digest representing an empty Merkle tree root.
        """
        return self.new().digest()

    def hash_leaf(self, leaf):
        """
        Compute the hash of a leaf node.

        Args:
            leaf (bytes): The raw leaf data.

        Returns:
            bytes: The leaf hash.
        """
        h = self.new()
        h.update(bytes([RFC6962_LEAF_HASH_PREFIX]))
        h.update(leaf)
        return h.digest()

    def hash_children(self, left, right):
        """
        Compute the hash of two child nodes with the node hash prefix.

        Args:
            left (bytes): Left child hash.
            right (bytes): Right child hash.

        Returns:
            bytes: Parent hash.
        """
        h = self.new()
        b = bytes([RFC6962_NODE_HASH_PREFIX]) + left + right
        h.update(b)
        return h.digest()

    def size(self):
        """
        Get the digest size (in bytes) of the configured hash function.

        Returns:
            int: The digest size.
        """
        return self.new().digest_size


# DefaultHasher is a SHA256 based LogHasher
DefaultHasher = Hasher(hashlib.sha256)


def verify_consistency(hasher, sizes, proof, roots):
    """
    Verify the consistency proof between two tree sizes in a Merkle tree.

    Args:
        hasher (Hasher): The hash function wrapper to use.
        sizes (tuple[int, int]): (size1, size2) of old and new trees.
        proof (list[str]): List of proof hashes in hexadecimal form.
        roots (tuple[str, str]): Hex-encoded roots of the smaller and larger trees.

    Raises:
        ValueError: If proof is invalid or inputs are inconsistent.
        RootMismatchError: If calculated roots don't match the expected roots.
    """
    size1, size2 = sizes
    root1, root2 = bytes.fromhex(roots[0]), bytes.fromhex(roots[1])
    bytearray_proof = [bytes.fromhex(h) for h in proof]

    if size2 < size1:
        raise ValueError(f"size2 ({size2}) < size1 ({size1})")
    if size1 == size2:
        if bytearray_proof:
            raise ValueError("size1=size2, but proof is not empty")
        verify_match(root1, root2)
        return
    if size1 == 0:
        if bytearray_proof:
            raise ValueError(
                f"expected empty proof, but got {len(bytearray_proof)} components"
            )
        return
    if not bytearray_proof:
        raise ValueError("empty proof")

    inner, border = decomp_incl_proof(size1 - 1, size2)
    shift = (size1 & -size1).bit_length() - 1
    inner -= shift

    seed = root1 if size1 == 1 << shift else bytearray_proof[0]
    proof_slice = bytearray_proof[1:] if size1 != 1 << shift else bytearray_proof

    if len(proof_slice) != inner + border:
        raise ValueError(f"wrong proof size {len(proof_slice)}, want {inner + border}")

    # compute masks
    mask = (size1 - 1) >> shift

    # compute and verify roots
    verify_match(
        chain_border_right(
            hasher,
            chain_inner_right(hasher, seed, proof_slice[:inner], mask),
            proof_slice[inner:],
        ),
        root1,
    )

    verify_match(
        chain_border_right(
            hasher,
            chain_inner(hasher, seed, proof_slice[:inner], mask),
            proof_slice[inner:],
        ),
        root2,
    )


def verify_match(calculated, expected):
    """
    Verify that two root hashes match.

    Args:
        calculated (bytes): Calculated hash.
        expected (bytes): Expected hash.

    Raises:
        RootMismatchError: If the roots differ.
    """
    if calculated != expected:
        raise RootMismatchError(expected, calculated)


def decomp_incl_proof(index, size):
    """
    Decompose an inclusion proof into inner and border proof sizes.

    Args:
        index (int): Leaf index.
        size (int): Tree size.

    Returns:
        tuple[int, int]: (inner_proof_size, border_proof_size)
    """
    inner = inner_proof_size(index, size)
    border = bin(index >> inner).count("1")
    return inner, border


def inner_proof_size(index, size):
    """
    Calculate the number of inner proof elements for a given leaf index and tree size.

    Args:
        index (int): Leaf index.
        size (int): Tree size.

    Returns:
        int: Inner proof size.
    """
    return (index ^ (size - 1)).bit_length()


def chain_inner(hasher, seed, proof, index):
    """
    Compute the inner chain of hashes for an inclusion proof.

    Args:
        hasher (Hasher): Hash function wrapper.
        seed (bytes): Initial seed hash.
        proof (list[bytes]): List of sibling node hashes.
        index (int): Leaf index.

    Returns:
        bytes: Resulting hash.
    """
    for i, h in enumerate(proof):
        if (index >> i) & 1 == 0:
            seed = hasher.hash_children(seed, h)
        else:
            seed = hasher.hash_children(h, seed)
    return seed


def chain_inner_right(hasher, seed, proof, index):
    """
    Compute the right-side inner chain for consistency proof verification.

    Args:
        hasher (Hasher): Hash function wrapper.
        seed (bytes): Initial hash seed.
        proof (list[bytes]): Proof hashes.
        index (int): Leaf index.

    Returns:
        bytes: Final computed hash.
    """
    for i, h in enumerate(proof):
        if (index >> i) & 1 == 1:
            seed = hasher.hash_children(h, seed)
    return seed


def chain_border_right(hasher, seed, proof):
    """
    Compute the border (outer) hash chain for proof verification.

    Args:
        hasher (Hasher): Hash function wrapper.
        seed (bytes): Initial hash seed.
        proof (list[bytes]): Proof hashes.

    Returns:
        bytes: Final computed hash.
    """
    for h in proof:
        seed = hasher.hash_children(h, seed)
    return seed


class RootMismatchError(Exception):
    """
    Raised when a calculated Merkle root does not match the expected root.
    """

    def __init__(self, expected_root, calculated_root):
        """
        Initialize the error with expected and calculated roots.

        Args:
            expected_root (bytes): The expected root hash.
            calculated_root (bytes): The computed root hash.
        """
        self.expected_root = binascii.hexlify(bytearray(expected_root))
        self.calculated_root = binascii.hexlify(bytearray(calculated_root))

    def __str__(self):
        """
        Return a readable error message with both root values.

        Returns:
            str: Formatted error message.
        """
        return (
            f"calculated root:\n{self.calculated_root}\n"
            f" does not match expected root:\n{self.expected_root}"
        )


def root_from_inclusion_proof(hasher, index, size, leaf_hash, proof):
    """
    Compute the Merkle root from an inclusion proof.

    Args:
        hasher (Hasher): Hash function wrapper.
        index (int): Leaf index in the tree.
        size (int): Total number of leaves in the tree.
        leaf_hash (bytes): Hash of the leaf node.
        proof (list[bytes]): Proof hashes in byte format.

    Returns:
        bytes: Computed Merkle root.

    Raises:
        ValueError: If index or proof size are invalid.
    """
    if index >= size:
        raise ValueError(f"index is beyond size: {index} >= {size}")

    if len(leaf_hash) != hasher.size():
        raise ValueError(
            f"leaf_hash has unexpected size {len(leaf_hash)}, want {hasher.size()}"
        )

    inner, border = decomp_incl_proof(index, size)
    if len(proof) != inner + border:
        raise ValueError(f"wrong proof size {len(proof)}, want {inner + border}")

    res = chain_inner(hasher, leaf_hash, proof[:inner], index)
    res = chain_border_right(hasher, res, proof[inner:])
    return res


def verify_inclusion(hasher, leaf_info, proof, root, debug=False):
    """
    Verify the inclusion of a leaf in a Merkle tree.

    Args:
        hasher (Hasher): Hash function wrapper.
        leaf_info (dict): Dictionary containing 'index' (int), 'size' (int),
         and 'hash' (str, hex-encoded leaf).
        proof (list[str]): List of proof hashes (hex-encoded).
        root (str): Hex-encoded Merkle root.
        debug (bool): If True, prints calculated vs. expected root.

    Raises:
        RootMismatchError: If calculated root does not match provided root.
    """
    index = leaf_info["index"]
    size = leaf_info["size"]
    leaf_hash = bytes.fromhex(leaf_info["hash"])
    bytearray_proof = [bytes.fromhex(h) for h in proof]
    bytearray_root = bytes.fromhex(root)

    calc_root = root_from_inclusion_proof(
        hasher, index, size, leaf_hash, bytearray_proof
    )
    verify_match(calc_root, bytearray_root)

    if debug:
        print("Calculated root hash", calc_root.hex())
        print("Given root hash", bytearray_root.hex())


def compute_leaf_hash(body):
    """
    Compute the Merkle leaf hash from an entry body, as per RFC 6962.

    Args:
        body (str): Base64-encoded entry body.

    Returns:
        str: Hex-encoded SHA-256 leaf hash.
    """
    entry_bytes = base64.b64decode(body)

    # create a new sha256 hash object
    h = hashlib.sha256()
    # write the leaf hash prefix
    h.update(bytes([RFC6962_LEAF_HASH_PREFIX]))

    # write the actual leaf data
    h.update(entry_bytes)

    # return the computed hash
    return h.hexdigest()
