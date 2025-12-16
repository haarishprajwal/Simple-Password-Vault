<p align="center">
  <img src="./assets/Screenshot 2025-12-16 143808.png" width="780">
</p>


# Simple Password Vault (CLI)

## Overview
Simple Password Vault is a command-line based Java application that securely stores, retrieves, and manages passwords.  
All sensitive data is encrypted on disk using modern cryptographic standards and can only be accessed using a master password.

The application is intentionally built as a CLI tool (no web or GUI) to demonstrate core Java, security, and software engineering concepts.

---

## Features
- Command-line menu driven interface
- Secure password storage using AES-256 encryption
- Master password based vault unlocking
- Add, retrieve, delete, and list password entries
- Export vault data to CSV (plaintext, with warning)
- Audit logging of all critical actions
- Encrypted vault persisted to disk
- Secure password generation
- Input validation and error handling

---

## Encryption & Security
- AES-256 symmetric encryption
- AES-GCM mode for confidentiality and integrity
- PBKDF2 with HmacSHA256 for key derivation
- Random salt and initialization vector
- SecureRandom for cryptographic randomness
- Authentication tag verification to detect tampering
- Sensitive data wiped from memory after use

---

## Architecture & Design
- Object-Oriented Programming principles
- Strategy Pattern used for encryption (CipherStrategy)
- Separation of concerns between CLI, encryption, and storage
- Custom exception for authentication failure
- Java Collections used for in-memory storage
- Java Streams used for sorted listing
- File-based persistence

---

## How It Works
1. User starts the application
2. Master password is requested
3. If vault exists, it is decrypted and loaded
4. If vault does not exist, a new encrypted vault is created
5. User interacts with the CLI menu
6. All changes are encrypted and saved automatically

---

## CLI Menu Options
```
1. Add Entry  
2. Get Entry  
3. Delete Entry  
4. List Entries  
5. Export Vault (CSV)  
6. Help  
7. Quit
```

---

## Export Warning
Exported CSV files are stored in plaintext format.  
This feature is intended for backup or migration purposes only.  
Users should store exported files securely and delete them after use.

---

## Input & Output
- Input: Standard input (keyboard)
- Output:
- Console output
- Encrypted vault file (`vault.dat`)
- Audit log (`audit_log.txt`)
- CSV export (`export.csv`)
- Application log (`app.log`)

All output files are generated inside the `out/` directory.

---

## Sample Usage
- Start the application
- Enter master password
- Choose menu options to manage passwords
- Export vault if needed
- Quit to safely save and exit

---

## Performance Considerations
- HashMap provides constant-time lookups
- AES-GCM provides fast encryption
- Suitable for small to medium vault sizes

---

## Limitations
- CLI only, no GUI
- Single-user vault
- CSV export is not encrypted

---

## License
This project is for academic and educational purposes.
