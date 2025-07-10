# === Import Statements ===

from fastapi import FastAPI, Form, Request, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, PlainTextResponse
from pydantic import BaseModel
from typing import List, Deque
from collections import deque
import base64
import time
import os

# Cryptography-related imports
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding, serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding

from RSA_Key_Gen import generate_rsa_keys  # RSA key generator

# === FastAPI App Setup ===

app = FastAPI()

# Allow cross-origin requests from any domain (for dev/testing)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# === Global Variables ===

# RSA public and private keys
pr, pu = generate_rsa_keys()

# Stores latest admin message (from frontend)
latest_admin_message = "No admin message yet."

# Stores latest decrypted message from client
latest_decrypted_frontend_message = "No client message yet."

# In-memory session AES key shared with the client
client_aes_key: bytes = b""

# Nonce tracking to prevent replay attacks
RECENT_NONCES: Deque = deque(maxlen=1000)
NONCE_EXPIRY_SECONDS = 5 * 60  # 5 minutes validity for a nonce

# === Utility Functions ===

def purge_expired_nonces():
    """Removes expired nonces from memory."""
    now = time.time()
    while RECENT_NONCES and RECENT_NONCES[0][1] < now - NONCE_EXPIRY_SECONDS:
        RECENT_NONCES.popleft()

# === WebSocket Connection Manager ===

class ConnectionManager:
    def __init__(self):
        self.active_connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)

    async def broadcast(self, message: str):
        """Send message to all connected WebSocket clients."""
        for connection in self.active_connections:
            try:
                await connection.send_text(message)
            except:
                pass  # Ignore send failures

manager = ConnectionManager()

# === Routes ===

@app.get("/get-public-key/")
async def get_public_key():
    """Returns server's RSA public key to client."""
    return JSONResponse(content={"public_key": pu.decode("utf-8")})

@app.post("/encrypt-message")
async def encrypt_for_client(server_message: str = Form(...)):
    """
    Encrypts admin message using AES-GCM and sends to WebSocket clients.
    Also computes and broadcasts the SHA-256 hash of the message.
    """
    global latest_admin_message, client_aes_key
    latest_admin_message = server_message

    if not client_aes_key:
        return JSONResponse({"error": "Client AES key not available yet."}, status_code=400)

    # Generate 12-byte nonce for AES-GCM
    nonce = os.urandom(12)

    # Perform AES-GCM encryption
    cipher = Cipher(algorithms.AES(client_aes_key), modes.GCM(nonce), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted_msg = encryptor.update(server_message.encode()) + encryptor.finalize()
    tag = encryptor.tag

    # Combine nonce + ciphertext + tag
    encrypted_payload = nonce + encrypted_msg + tag
    encrypted_msg_b64 = base64.b64encode(encrypted_payload).decode("utf-8")

    # Compute hash of plaintext for integrity verification
    digest = hashes.Hash(hashes.SHA256())
    digest.update(server_message.encode())
    server_msg_hash = digest.finalize().hex()

    # Broadcast encrypted message and hash
    await manager.broadcast(f"new-message:{encrypted_msg_b64}")
    await manager.broadcast(f"admin-hash:{server_msg_hash}")

    return JSONResponse({
        "status": "OK",
        "encrypted_response": encrypted_msg_b64,
        "hash": server_msg_hash
    })

@app.post("/decrypt")
async def hybrid_decrypt(request: Request):
    """
    Handles hybrid decryption from client:
    - Decrypts RSA-encrypted AES key
    - Uses AES key to decrypt message
    - Verifies hash and nonce
    - Returns encrypted admin message
    """
    global latest_admin_message, latest_decrypted_frontend_message, client_aes_key
    try:
        # Parse JSON body
        data = await request.json()
        encrypted_key_b64 = data.get("encrypted_key")
        encrypted_data_b64 = data.get("encrypted_data")
        timestamp = data.get("timestamp")
        nonce = data.get("nonce")
        received_hash = data.get("hash")

        # Validate timestamp format
        try:
            msg_time = float(timestamp) / 1000.0
        except (ValueError, TypeError):
            return JSONResponse({"error": "Invalid timestamp"}, status_code=400)

        now = time.time()
        if abs(now - msg_time) > NONCE_EXPIRY_SECONDS:
            return JSONResponse({"error": "Timestamp out of range"}, status_code=400)

        # Replay attack protection
        purge_expired_nonces()
        for n, t in RECENT_NONCES:
            if n == nonce:
                return JSONResponse({"error": "Replay detected: nonce already used"}, status_code=400)
        RECENT_NONCES.append((nonce, msg_time))

        # Check for required fields
        if not all([encrypted_key_b64, encrypted_data_b64, timestamp, nonce, received_hash]):
            return JSONResponse({"error": "Missing required fields"}, status_code=400)

        # Decode base64 values
        encrypted_key = base64.b64decode(encrypted_key_b64)
        encrypted_data = base64.b64decode(encrypted_data_b64)

        if len(encrypted_data) < 28:  # IV + tag
            return JSONResponse({"error": "Invalid encrypted data length"}, status_code=400)

        # Load server's RSA private key
        private_key = serialization.load_pem_private_key(pr, password=None, backend=default_backend())

        # Decrypt AES key
        aes_key = private_key.decrypt(
            encrypted_key,
            asym_padding.OAEP(
                mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        client_aes_key = aes_key  # Store for future use

        # Split payload into nonce, ciphertext, tag
        nonce_gcm = encrypted_data[:12]
        ciphertext = encrypted_data[12:-16]
        tag = encrypted_data[-16:]

        # Decrypt message using AES-GCM
        cipher = Cipher(algorithms.AES(aes_key), modes.GCM(nonce_gcm, tag), backend=default_backend())
        decryptor = cipher.decryptor()
        decrypted = decryptor.update(ciphertext) + decryptor.finalize()
        result = decrypted.decode("utf-8")

        # Hash check: ensure integrity
        reconstructed_payload = (result + timestamp + nonce).encode()
        digest = hashes.Hash(hashes.SHA256())
        digest.update(reconstructed_payload)
        computed_hash = digest.finalize().hex()

        if computed_hash != received_hash:
            return JSONResponse({"error": "Hash mismatch. Message may have been tampered with."}, status_code=400)

        # Store and broadcast client message
        latest_decrypted_frontend_message = result
        await manager.broadcast(f"new-client-message:{result}")

        # Encrypt admin message and respond
        resp_nonce = os.urandom(12)
        cipher_resp = Cipher(algorithms.AES(aes_key), modes.GCM(resp_nonce), backend=default_backend())
        encryptor_resp = cipher_resp.encryptor()
        encrypted_resp = encryptor_resp.update(latest_admin_message.encode()) + encryptor_resp.finalize()
        tag_resp = encryptor_resp.tag
        encrypted_payload_resp = resp_nonce + encrypted_resp + tag_resp
        encrypted_resp_b64 = base64.b64encode(encrypted_payload_resp).decode("utf-8")

        return JSONResponse({"status": "OK", "encrypted_response": encrypted_resp_b64})

    except Exception as e:
        return JSONResponse(content={"error": str(e)}, status_code=400)

@app.get("/latest-client-message")
async def get_latest_client_message():
    """Returns the most recently decrypted client message."""
    return JSONResponse(content={"message": latest_decrypted_frontend_message})

@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    """
    WebSocket endpoint for real-time communication.
    Keeps connection alive and allows broadcasting.
    """
    await manager.connect(websocket)
    try:
        while True:
            await websocket.receive_text()  # Keeps connection open
    except WebSocketDisconnect:
        manager.disconnect(websocket)

@app.get("/health")
async def health_check():
    """Health check endpoint."""
    return PlainTextResponse(content="Server is up", status_code=200)

# Entry point if run directly
if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000)
