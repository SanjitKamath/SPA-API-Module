# Hybrid File Encryption System

A modern hybrid encryption system for secure file transfer using client-side AES-256-GCM and RSA-OAEP key exchange between a **React** frontend and **FastAPI** backend.

This project demonstrates end-to-end encryption and integrity assurance for file transmission across untrusted networks while leveraging standards-compliant cryptographic primitives.

---

## Features

- **AES-256-GCM** encryption of file contents (symmetric encryption)
- **RSA-OAEP** key exchange using 2048-bit public keys
- **Authenticated encryption** with integrity check via SHA-256
- **Replay attack prevention** using timestamps and random nonces
- **Cross-platform support** via Web Crypto API and Python cryptography
- Handles both **encrypted and plain uploads** (for testing)

---

## Project Structure

```
├── SPA/
│   └── spa.jsx              # Main React file encryption client
├── API/
│   ├── main.py              # FastAPI app setup and routes
│   ├── encryption_middleware.py  # Middleware for decrypting/verifying data
│   └── RSA_Key_Gen.py       # Utility (assumed) for RSA key generation
├── received_files/          # Where decrypted files are stored
├── README.md
```

---

## Quick Start

### Backend (FastAPI)

```
# Install dependencies
pip install requirements.txt

# Run the server
python main.py
```

By default, FastAPI runs on [`http://localhost:8000`](http://localhost:8000)

### Frontend (React + Web Crypto API)

```
cd frontend
npm install
npm run dev 
```

Access the app at [`https://localhost:5173`](https://localhost:5173)

---

## API Endpoints

| Method | Endpoint               | Description                        |
|--------|------------------------|------------------------------------|
| GET    | `/get-public-key/`     | Returns PEM-formatted RSA public key |
| POST   | `/upload-encrypted`    | Uploads encrypted payload (JSON)   |
| GET    | `/health`              | Server health check                |

---

## Cryptographic Flow

1. Browser generates an **AES-256-GCM** key.
2. Encrypts file content with random 12-byte IV (nonce).
3. Hashes plaintext + timestamp + nonce using **SHA-256**.
4. Encrypts AES key using server's **RSA-OAEP** (SHA-256).
5. Sends base64-encoded encrypted data, wrapped key, and hash.
6. Middleware on the server:
   - Validates timestamp (+/- 5 min)
   - Checks **nonce reuse** ➜ replay protection
   - Decrypts RSA key ➜ decrypts AES payload
   - Verifies hash and saves file
7. Responds with encrypted message using same AES session key.

---

## Configuration Options

| Name                   | File                     | Description                      |
|------------------------|--------------------------|----------------------------------|
| `MAX_FILE_SIZE_MB`     | `spa.jsx`                | Max upload size (frontend demo)  |
| `UPLOAD_DIR`           | `main.py`                | Folder for decrypted file output |
| `NONCE_EXPIRY_SECONDS` | `encryption_middleware.py` | Allowed timestamp window (5 min) |

---

## Security Measures

### Implemented

- AES-GCM mode with 128-bit tags
- RSA-OAEP padding with SHA-256 for secure AES key wrapping
- Replay attack protection via timestamp + nonce store
- Hash-based integrity verification (CryptoJS/SHA-256)
- Custom header check: `"X-Encrypted-Request": "true"` to compare time with and without encryption


## Troubleshooting

| Problem                         | Solution                                 |
|----------------------------------|------------------------------------------|
| `File too large`                | Increase `MAX_FILE_SIZE_MB` in `spa.jsx` |
| `Timestamp out of range`        | Sync local system clock with server      |
| `Replay detected`               | Ensure nonce/memo is regenerated for each upload |
| `RSA decrypt failed`            | Check if correct public/private keys used |
| `Crypto not supported`          | Use modern HTTPS browsers (Chrome, Firefox) |

---

