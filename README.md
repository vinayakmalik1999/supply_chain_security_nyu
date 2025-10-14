Rekor Verifier Utility

Python tool for Sigstore’s Rekor transparency log. Built for NYU Software Supply Chain Security class.

**What it does:**

* Sign an artifact and upload its signature to Rekor (via Sigstore Cosign).
* Verify inclusion of a log entry and its signature using the transparency log.
* Verify log consistency between an older checkpoint and the latest checkpoint.

Basically, it helps you confirm that your artifact was properly logged and that the log itself hasn’t been tampered with.
Python: 3.9

**Install**:
* git clone repo
* cd repo

Will need to install required packages with pip

**Usage**

Fetch latest checkpoint:

`python main.py --checkpoint
`

Verify artifact inclusion:

`python main.py --inclusion <log-index> --artifact <your-artifact>
`

Verify checkpoint consistency:

`python main.py --consistency --tree-id <tree-id> --tree-size <tree-size> --root-hash <root-hash>
`

Use --debug to save checkpoints locally and see extra info.

**How it works**

* Fetches entries/checkpoints from Rekor's public API.
* Extracts signatures and certificates from the log entry.
* Verifies signatures using the provided utility functions.

* Verifies inclusion and consistency proofs using Merkle trees.

Based on the following Template Repo: https://github.com/mayank-ramnani/python-rekor-monitor-template.git