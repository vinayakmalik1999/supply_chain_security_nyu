# Security Policy

This document outlines the security policy for the Rekor Verifier Utility, including supported versions, vulnerability reporting procedures, and security update practices.

## Project Overview

The Rekor Verifier Utility is an educational project developed for the NYU Software Supply Chain Security class. It provides cryptographic verification of artifacts using Sigstore's Rekor transparency log, implementing critical security features including signature verification, Merkle tree proofs, and log consistency checks.

## Supported Versions

As an educational project, we maintain the following support policy:

| Version | Supported          | Notes |
| ------- | ------------------ | ----- |
| Latest (main branch) | :white_check_mark: | Active development |
| Previous releases | :x: | No backports |

**Note:** This is an educational project. For production use, please consider using official Sigstore tools like [cosign](https://github.com/sigstore/cosign) or [sigstore-python](https://github.com/sigstore/sigstore-python).

## Reporting a Vulnerability

We take security vulnerabilities seriously. If you discover a security issue in this project, please follow responsible disclosure practices.

### How to Report

**For security vulnerabilities, please DO NOT open a public GitHub issue.**

Instead, please report security issues through one of the following channels:

1. **Preferred Method**: Use GitHub's [Private Vulnerability Reporting](https://github.com/vinayakmalik1999/supply_chain_security_nyu/security/advisories/new) feature
   - Navigate to the Security tab
   - Click "Report a vulnerability"
   - Fill out the advisory form with details

2. **Alternative**: Email the repository maintainer directly
   - Contact: vinayakmalik1999@gmail.com
   - Subject line: `[SECURITY] Rekor Verifier Vulnerability Report`

### What to Include

Please provide the following information in your report:

- **Description**: Clear description of the vulnerability
- **Reproduction Steps**: Detailed steps to reproduce the issue
- **Environment**: Python version, OS, and dependency versions used

### Example Report Template

```
**Vulnerability Type**: [e.g., Cryptographic weakness, Input validation, API misuse]

**Affected Component**: [e.g., merkle_proof.py, signature verification]

**Description**:
[Detailed description of the vulnerability]

**Steps to Reproduce**:
1. [Step 1]
2. [Step 2]
3. [Expected vs Actual behavior]

**Environment**:
- Python version: 3.9.x
- OS: Ubuntu 22.04
- Dependencies: [versions]
```

### What to Expect

- **Acknowledgment**: We will acknowledge receipt of your report within **48 hours**
- **Resolution Timeline**: We aim to address vulnerabilities within **30 days**

### Disclosure Policy

- **Private Discussion**: We will work with you privately to understand and fix the issue
- **Credit**: With your permission, we will credit you in the security advisory and release notes

## Security Update Process

### How Updates Are Handled

1. **Vulnerability Assessment**: Security issues are triaged based on severity and impact
2. **Fix Development**: Patches are developed and tested in a private branch
3. **Security Advisory**: A GitHub Security Advisory is created (when appropriate)
4. **Release**: Fixes are released with detailed changelogs
5. **Notification**: Security fixes are announced via commit messages

### Security Release Format

Security releases will be tagged with clear version numbers and include:

- **Security Advisory**: Detailed description of the vulnerability 
- **Affected Versions**: Versions impacted by the vulnerability
- **Fixed Version**: Version containing the fix
- **Workarounds**: Temporary mitigations (if available)
- **Credits**: Recognition of security researchers who reported the issue

## Educational Context

**Important**: This is an educational project for learning supply chain security concepts. It demonstrates:

- How transparency logs work
- Cryptographic verification techniques
- Sigstore ecosystem integration

## Security Hall of Fame

We recognize and thank security researchers who responsibly disclose vulnerabilities:

*No vulnerabilities reported yet.*

---

**Last Updated**: November 2025  
**Project Status**: Educational / Active Development  
**Maintainer**: vinayakmalik1999

For questions about this security policy, please open a public issue (for non-security topics) or contact the maintainer directly (for security concerns).