# Rekor Verifier Utility

[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Sigstore](https://img.shields.io/badge/Sigstore-Rekor-purple.svg)](https://sigstore.dev)

A Python tool for verifying artifacts and ensuring integrity using [Sigstore's Rekor](https://docs.sigstore.dev/rekor/overview/) transparency log. Built for the NYU Software Supply Chain Security class, this tool demonstrates how transparency logs work and how to cryptographically verify software artifacts.

> **Note:** This tool works with artifacts that have already been signed using Sigstore Cosign. It focuses on verification rather than signing.

## 🎯 What It Does

This tool helps you work with the Rekor transparency log to:

- **📋 Fetch Checkpoints** - Retrieve the latest state of the Rekor transparency log
- **✅ Verify Inclusion** - Confirm that a signed artifact's log entry exists in the transparency log
- **🔒 Verify Consistency** - Ensure the log hasn't been tampered with between checkpoints
- **🔐 Validate Signatures** - Cryptographically verify artifact signatures using certificates from log entries

**In simple terms:** It helps you confirm that your artifact was properly logged in Rekor and that the transparency log itself is trustworthy and hasn't been modified.

## 📋 Prerequisites

Before you begin, ensure you have:

- **Python 3.9 or higher** - Check with `python --version` or `python3 --version`
- **pip** - Python package installer (usually comes with Python)
- **git** - For cloning the repository

## 🚀 Installation

### 1. Clone the Repository

```bash
git clone https://github.com/vinayakmalik1999/supply_chain_security_nyu.git
cd supply_chain_security_nyu
```

### 2. Set Up Virtual Environment (Recommended)

```bash
# On macOS/Linux
python3.9 -m venv .venv
source .venv/bin/activate
```

### 3. Install Dependencies

```bash
pip install -r requirements.txt
```

This will install:
- `cryptography` - For signature verification and certificate handling
- `requests` - For HTTP communication with the Rekor API

### 4. Install Static Analysis tools**
```bash
pip install -r tools.txt
```

### 5. Verify Installation

```bash
python3 main.py --checkpoint
```

You should see the latest checkpoint information from Rekor!

## 📖 Usage

### Fetch Latest Checkpoint

Retrieve the current state of the Rekor transparency log:

```bash
python3 main.py --checkpoint
```

**With debug mode:**
```bash
python3 main.py --checkpoint --debug
```
Debug mode saves the checkpoint to `checkpoint_latest.json` for later verification.

---

### Verify Artifact Inclusion

Confirm that a specific log entry (for a signed artifact) exists in the transparency log:

```bash
python3 main.py --inclusion <log-index> --artifact <artifact>
```

**Prerequisites:**
- Your artifact must have been previously signed with Cosign
- You need the log index from when it was signed

**Example workflow:**

```bash
# Step 1: Sign your artifact with Cosign (if not already signed)
# This uploads the signature to Rekor and returns a log index
cosign sign-blob --bundle=artifact.bundle artifact.txt
# Output includes: "tlog entry created with index: 125847350"

# Step 2: Verify the artifact exists in Rekor
python main.py --inclusion 125847350 --artifact artifact.txt
```

**Debug mode:**
```bash
python main.py --inclusion 125847350 --artifact artifact.txt --debug
```
This saves `log_entry_125847350.json` with detailed verification data.

---

### Verify Log Consistency

Ensure the transparency log is append-only and hasn't been tampered with between two checkpoints:

```bash
python main.py --consistency --tree-id <tree-id> --tree-size <tree-size> --root-hash <root-hash>
```

**Example workflow:**

```bash
# Step 1: Fetch and save an older checkpoint
python main.py --checkpoint --debug
# This saves checkpoint_latest.json with:
# - tree-id: 1234567890
# - tree-size: 125847000
# - root-hash: c8f9a5b2e3d4a1f7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1

# Step 2: Wait some time (hours/days) or perform operations that add to the log

# Step 3: Verify consistency between the old checkpoint and current log state
python main.py --consistency \
  --tree-id 1234567890 \
  --tree-size 125847000 \
  --root-hash c8f9a5b2e3d4a1f7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1
```
---

### Debug Mode

Add `--debug` to any command to save intermediate data locally and see detailed output:

```bash
python main.py --checkpoint --debug
python main.py --inclusion 12345 --artifact file.txt --debug
python main.py --consistency --tree-id <id> --tree-size <size> --root-hash <hash> --debug
```

**Debug mode creates:**
- `checkpoint_latest.json` - Latest checkpoint data
- `log_entry_<index>.json` - Detailed log entry information
- Additional verification data and intermediate results

## 📦 Dependencies

This project requires two Python packages to run, specified in `requirements.txt`:

### Core Dependencies

- **`cryptography`** - Provides cryptographic primitives
  - ECDSA signature verification
  - X.509 certificate parsing and handling

- **`requests`** - HTTP client library
- - **`pre-commit`** - Precommit hooks framework

NOTE: while there are other dependencies they are not required to run the utility

### Installing Dependencies

```bash
# Install from requirements.txt
pip install -r requirements.txt
```

### Verifying Dependencies

```bash
# Check installed versions
pip list | grep -E "cryptography|requests"
```

## 📚 Documentation

- **[SECURITY.md](SECURITY.md)** - Security policy, threat model, and vulnerability reporting
- **[CONTRIBUTING.md](CONTRIBUTING.md)** - Guidelines for contributing to the project

---

*This is an educational project demonstrating transparency log verification. For production use, please use official Sigstore tools.*