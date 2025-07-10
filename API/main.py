from fastapi import FastAPI, Form, Request, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, PlainTextResponse
from pydantic import BaseModel
from typing import List, Deque
from collections import deque
import base64
import time
import os

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding, serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding

from RSA_Key_Gen import generate_rsa_keys

app = FastAPI()
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

pr, pu = generate_rsa_keys()

latest_admin_message = "No admin message yet."
latest_decrypted_frontend_message = "No client message yet."
client_aes_key: bytes = b""
RECENT_NONCES: Deque = deque(maxlen=1000)
NONCE_EXPIRY_SECONDS = 5 * 60  # 5 minutes

def purge_expired_nonces():
    now = time.time()
    while RECENT_NONCES and RECENT_NONCES[0][1] < now - NONCE_EXPIRY_SECONDS:
        RECENT_NONCES.popleft()

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
        for connection in self.active_connections:
            try:
                await connection.send_text(message)
            except:
                pass

manager = ConnectionManager()

@app.get("/get-public-key/")
async def get_public_key():
    return JSONResponse(content={"public_key": pu.decode("utf-8")})

@app.post("/encrypt-message")
async def encrypt_for_client(server_message: str = Form(...)):
    global latest_admin_message, client_aes_key
    latest_admin_message = server_message
    if not client_aes_key:
        return JSONResponse({"error": "Client AES key not available yet."}, status_code=400)

    # Generate new nonce for each encryption
    nonce = os.urandom(12)
    
    # AES-GCM encryption
    cipher = Cipher(
        algorithms.AES(client_aes_key),
        modes.GCM(nonce),
        backend=default_backend()
    )
    encryptor = cipher.encryptor()
    encrypted_msg = encryptor.update(server_message.encode()) + encryptor.finalize()
    tag = encryptor.tag
    
    # Payload structure: nonce + ciphertext + tag
    encrypted_payload = nonce + encrypted_msg + tag
    encrypted_msg_b64 = base64.b64encode(encrypted_payload).decode("utf-8")

    # Compute hash for integrity check
    digest = hashes.Hash(hashes.SHA256())
    digest.update(server_message.encode())
    server_msg_hash = digest.finalize().hex()

    await manager.broadcast(f"new-message:{encrypted_msg_b64}")
    await manager.broadcast(f"admin-hash:{server_msg_hash}")

    return JSONResponse({
        "status": "OK",
        "encrypted_response": encrypted_msg_b64,
        "hash": server_msg_hash
    })

@app.post("/decrypt")
async def hybrid_decrypt(request: Request):
    global latest_admin_message, latest_decrypted_frontend_message, client_aes_key
    try:
        data = await request.json()
        encrypted_key_b64 = data.get("encrypted_key")
        encrypted_data_b64 = data.get("encrypted_data")
        timestamp = data.get("timestamp")
        nonce = data.get("nonce")
        received_hash = data.get("hash")

        try:
            msg_time = float(timestamp) / 1000.0
        except (ValueError, TypeError):
            return JSONResponse({"error": "Invalid timestamp"}, status_code=400)

        now = time.time()
        if abs(now - msg_time) > NONCE_EXPIRY_SECONDS:
            return JSONResponse({"error": "Timestamp out of range"}, status_code=400)

        purge_expired_nonces()
        for n, t in RECENT_NONCES:
            if n == nonce:
                return JSONResponse({"error": "Replay detected: nonce already used"}, status_code=400)
        RECENT_NONCES.append((nonce, msg_time))

        if not all([encrypted_key_b64, encrypted_data_b64, timestamp, nonce, received_hash]):
            return JSONResponse({"error": "Missing required fields"}, status_code=400)

        encrypted_key = base64.b64decode(encrypted_key_b64)
        encrypted_data = base64.b64decode(encrypted_data_b64)

        # Verify payload has minimum length (nonce + tag)
        if len(encrypted_data) < 28:
            return JSONResponse({"error": "Invalid encrypted data length"}, status_code=400)

        private_key = serialization.load_pem_private_key(pr, password=None, backend=default_backend())
        aes_key = private_key.decrypt(
            encrypted_key,
            asym_padding.OAEP(
                mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        client_aes_key = aes_key

        # Split GCM payload: nonce (12B) + ciphertext + tag (16B)
        nonce_gcm = encrypted_data[:12]
        ciphertext = encrypted_data[12:-16]
        tag = encrypted_data[-16:]

        cipher = Cipher(
            algorithms.AES(aes_key),
            modes.GCM(nonce_gcm, tag),
            backend=default_backend()
        )
        decryptor = cipher.decryptor()
        decrypted = decryptor.update(ciphertext) + decryptor.finalize()
        result = decrypted.decode("utf-8")

        # Verify message integrity
        reconstructed_payload = (result + timestamp + nonce).encode()
        digest = hashes.Hash(hashes.SHA256())
        digest.update(reconstructed_payload)
        computed_hash = digest.finalize().hex()

        if computed_hash != received_hash:
            return JSONResponse({"error": "Hash mismatch. Message may have been tampered with."}, status_code=400)

        latest_decrypted_frontend_message = result
        await manager.broadcast(f"new-client-message:{result}")

        # Prepare encrypted admin response using new nonce
        resp_nonce = os.urandom(12)
        cipher_resp = Cipher(
            algorithms.AES(aes_key),
            modes.GCM(resp_nonce),
            backend=default_backend()
        )
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
    return JSONResponse(content={"message": latest_decrypted_frontend_message})

@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        while True:
            # Keep connection alive by listening for messages
            await websocket.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(websocket)

@app.get("/health")
async def health_check():
    return PlainTextResponse(content="Server is up", status_code=200)

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000)