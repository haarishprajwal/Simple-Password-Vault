# Security Policy

## Overview
This document describes the security practices, design decisions, and known limitations of the **Simple Password Vault (CLI)** project.  
The goal of this project is to demonstrate secure password storage concepts using Java and modern cryptography in an academic or learning context.

---

## Supported Versions
This project does not maintain multiple released versions.

| Version | Supported |
|--------|-----------|
| Current | Yes |

---

## Security Design

### Encryption
- Symmetric encryption using **AES-256**
- Encryption mode: **AES-GCM**
- Provides confidentiality, integrity, and authentication
- Detects any tampering with encrypted data

### Key Management
- Encryption keys are **never stored**
- Keys are derived at runtime from the master password
- Key derivation uses **PBKDF2 with HmacSHA256**
- 100,000 iterations used to slow down brute-force attacks

### Randomness
- `SecureRandom` is used for:
  - Salt generation
  - Initialization Vector (IV)
  - Password generation
- Ensures cryptographic-grade randomness

### Authentication
- AES-GCM authentication tag is verified during decryption
- Incorrect master password or modified vault file causes decryption failure
- Custom authentication exception is thrown on failure

---

## Data Storage

### Encrypted Data
- All vault data is stored in an encrypted binary file: out/vault.dat
- Data is serialized, encrypted, and written atomically

### Plaintext Data
- CSV export (`out/export.csv`) is **plaintext by design**
- Audit log (`out/audit_log.txt`) is plaintext and contains no secrets
- Application log (`out/app.log`) contains operational logs only

---

## Audit Logging
The following actions are logged with timestamps:
- Add entry
- Get entry
- Delete entry
- Export vault
- Exit application

Logs are stored in:
```
out/audit_log.txt
out/app.log
```

---

## Memory Safety
- Passwords and keys are wiped from memory after use
- Character arrays are used instead of immutable strings for sensitive input
- Derived keys are cleared once the vault is locked or application exits

---

## Input Validation
- Empty or invalid site keys are rejected
- Missing master password is not allowed
- Errors provide clear and user-friendly messages

---

## Known Limitations
- Single-user vault
- No role-based access control
- No automatic vault locking after inactivity
- CSV export is not encrypted
- CLI-only interface (no GUI)

---

## Threat Model (Out of Scope)
The following threats are not addressed by this project:
- Compromised operating system
- Malware or keyloggers
- Memory dumping attacks
- Physical access to a running machine

---

## Responsible Use
This project is intended for:
- Academic submissions
- Learning cryptography and secure storage concepts
- Demonstrating secure coding practices

It is **not intended for production use**.

---

## Reporting Security Issues
If you discover a security issue:
1. Do not disclose it publicly
2. Document the issue clearly
3. Report it to the project maintainers or instructors

---

## Disclaimer
This software is provided for educational purposes only.  
The authors are not responsible for misuse or data loss.
