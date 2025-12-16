# Problem Statement

## Title
Secure Local Password Vault Using Java (CLI-Based)

---

## Background
With the increasing number of online services, users are required to manage multiple usernames and passwords.  
Storing passwords in plaintext files, browsers, or unsecured applications exposes users to risks such as data theft, unauthorized access, and credential leakage.

There is a need for a **secure, lightweight, and offline password storage solution** that demonstrates strong security principles while remaining simple to use and easy to evaluate in an academic environment.

---

## Problem Definition
Design and implement a **command-line based password vault** that securely stores user credentials on a local system.  
The system must ensure that stored data remains confidential, tamper-proof, and accessible only to authorized users through a master password.

The application should operate entirely through a CLI interface without using any web or GUI components.

---

## Objectives
- To securely store and retrieve passwords using strong encryption
- To protect stored data from unauthorized access or modification
- To demonstrate practical use of cryptography in software development
- To apply object-oriented programming and design patterns in Java
- To build a menu-driven CLI application using standard input and output

---

## Scope
The system shall:
- Allow users to add, retrieve, delete, and list password entries
- Encrypt all stored data before writing to disk
- Use a master password for authentication
- Support exporting stored data to a CSV file
- Maintain audit logs for important actions

The system shall not:
- Provide a graphical user interface
- Support multiple users or remote access
- Automatically sync or back up data online

---

## Constraints
- The application must be implemented in Java
- Only local file storage is permitted
- All interaction must occur via the command line
- No third-party encryption libraries are allowed beyond Java standard libraries
- Performance must be acceptable for small to medium data sizes

---

## Security Requirements
- Use industry-standard encryption algorithms
- Ensure encryption keys are never stored on disk
- Detect tampering or incorrect authentication attempts
- Use secure random number generation for cryptographic values
- Prevent exposure of sensitive data in memory where possible

---

## Expected Outcome
The final system should:
- Provide a functional and user-friendly CLI password vault
- Store credentials securely in encrypted form
- Prevent unauthorized access without the correct master password
- Demonstrate clean code structure and secure coding practices
- Meet academic evaluation and assessment requirements

---

## Intended Audience
- Students learning Java and cybersecurity concepts
- Faculty evaluating secure application design
- Reviewers assessing software engineering practices

---

## Conclusion
This project aims to bridge the gap between theoretical cryptography concepts and real-world application by implementing a secure password vault using Java.  
It emphasizes security, correctness, and maintainability while remaining simple enough for academic evaluation.
