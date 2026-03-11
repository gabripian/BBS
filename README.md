# BBS – Cryptographically Secure Bulletin Board System

**Group project** – C++ client-server application for Linux implementing a secure **Bulletin Board System (BBS)** where users can read and post messages identified by nickname and password.

## Overview

**BBS Server** (multithreaded) stores user data and messages.  
**Clients** connect via TCP to perform 5 operations:
- Register/Login with cryptographic authentication  
- Read last *n* messages  
- Download specific message  
- Add new message  
- Logout  

**Security priority**: Uses **OpenSSL** for AES-256, RSA-Ephemeral key exchange, HMAC-SHA256, ensuring confidentiality, integrity, replay protection, non-malleability, and perfect forward secrecy.

## Protocol Summary

1. **Key Exchange (RSAE)**: Client-server negotiate session key using ephemeral RSA keys.  
2. **Registration/Login**: Includes challenge-response via email, encrypted with session key.  
3. **Session**: Encrypted commands (List/Get/Add/Logout) with counter for replay protection.  

All session messages follow **Encrypt-then-MAC** paradigm with fresh IVs.


## Build & Run

```bash
# Compile server and client
make

# Run server (multithreaded)
./server

# Connect with client
./client <server_ip> <port>

```

**Note:** Server keys must be generated and placed in the respective directories before first run.
