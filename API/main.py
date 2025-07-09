# main.py

# Standard library
import base64

# FastAPI imports
from fastapi import FastAPI, Form, Request, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, PlainTextResponse

# Pydantic and typing for data models and type hints
from pydantic import BaseModel
from typing import List

# Cryptography libraries for AES/RSA encryption, decryption, and padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding, serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding

# Custom RSA key generation function
from RSA_Key_Gen import generate_rsa_keys  # Should return (private_key_bytes, public_key_bytes)

# Initialize FastAPI application
app = FastAPI()

# Enable CORS for all origins and methods (useful for local frontend testing)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Generate RSA key pair at server startup
pr, pu = generate_rsa_keys()

# Global state variables
latest_admin_message = "No admin message yet."                    # Most recent message sent by the admin
latest_decrypted_frontend_message = "No client message yet."     # Most recent message received and decrypted from the client
client_aes_key: bytes = b""                                       # AES key shared by the client (sent encrypted with RSA)

# WebSocket connection manager class to track all active connections and broadcast messages
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
                pass  # Silently ignore any broadcast failures (client may have disconnected)

# Instantiate the WebSocket manager
manager = ConnectionManager()

# Endpoint to provide RSA public key to frontend
@app.get("/get-public-key/")
async def get_public_key():
    return JSONResponse(content={"public_key": pu.decode("utf-8")})

# Admin sends a message to be encrypted and broadcast to all WebSocket clients
@app.post("/encrypt-message")
async def encrypt_for_client(server_message: str = Form(...)):
    global latest_admin_message, client_aes_key

    latest_admin_message = server_message

    # AES key must already be set from the client
    if not client_aes_key:
        return JSONResponse({"error": "Client AES key not available yet."}, status_code=400)

    #Hash the server message to ensure integrity
    digest = hashes.Hash(hashes.SHA256())
    digest.update(server_message.encode())
    server_msg_hash = digest.finalize().hex()

    # Pad the admin message using PKCS7
    padder = padding.PKCS7(128).padder()
    padded_msg = padder.update(server_message.encode()) + padder.finalize()

    # Encrypt the message with AES ECB mode (note: not secure for real-world usage)
    cipher = Cipher(algorithms.AES(client_aes_key), modes.ECB(), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted_msg = encryptor.update(padded_msg) + encryptor.finalize()

    # Encode encrypted message in base64 for transmission
    encrypted_msg_b64 = base64.b64encode(encrypted_msg).decode("utf-8")

    # Broadcast both the encrypted message and hash to all connected WebSocket clients
    await manager.broadcast(f"new-message:{encrypted_msg_b64}")
    await manager.broadcast(f"admin-hash:{server_msg_hash}")

    return JSONResponse({"status": "Message stored and broadcasted."})

# Endpoint to handle hybrid decryption of client messages (AES key encrypted with RSA)
@app.post("/decrypt")
async def hybrid_decrypt(request: Request):
    global latest_admin_message, latest_decrypted_frontend_message, client_aes_key

    try:
        data = await request.json()

        # Extract required fields from JSON payload
        encrypted_key_b64 = data.get("encrypted_key")
        encrypted_data_b64 = data.get("encrypted_data")
        timestamp = data.get("timestamp")
        nonce = data.get("nonce")
        received_hash = data.get("hash")

        # Ensure all required fields are present
        if not all([encrypted_key_b64, encrypted_data_b64, timestamp, nonce, received_hash]):
            return JSONResponse({"error": "Missing required fields"}, status_code=400)

        # Decode base64 values to raw bytes
        encrypted_key = base64.b64decode(encrypted_key_b64)
        encrypted_data = base64.b64decode(encrypted_data_b64)

        # Load the private RSA key from PEM bytes
        private_key = serialization.load_pem_private_key(pr, password=None, backend=default_backend())

        # Decrypt AES key using RSA private key (OAEP padding)
        aes_key = private_key.decrypt(
            encrypted_key,
            asym_padding.OAEP(
                mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        client_aes_key = aes_key  # Store the decrypted AES key for future use

        # Decrypt the message with AES
        cipher = Cipher(algorithms.AES(aes_key), modes.ECB(), backend=default_backend())
        decryptor = cipher.decryptor()
        padded_data = decryptor.update(encrypted_data) + decryptor.finalize()

        # Remove PKCS7 padding
        unpadder = padding.PKCS7(128).unpadder()
        decrypted = unpadder.update(padded_data) + unpadder.finalize()
        result = decrypted.decode("utf-8")

        # Reconstruct payload and validate hash to ensure message integrity
        reconstructed_payload = (result + timestamp + nonce).encode()
        digest = hashes.Hash(hashes.SHA256())
        digest.update(reconstructed_payload)
        computed_hash = digest.finalize().hex()

        if computed_hash != received_hash:
            return JSONResponse({"error": "Hash mismatch. Message may have been tampered with."}, status_code=400)

        # Store and broadcast the verified, decrypted client message
        latest_decrypted_frontend_message = result
        await manager.broadcast(f"new-client-message:{result}")

        # Prepare and return encrypted admin response using same AES key
        padder = padding.PKCS7(128).padder()
        padded_response = padder.update(latest_admin_message.encode()) + padder.finalize()
        response_cipher = Cipher(algorithms.AES(aes_key), modes.ECB(), backend=default_backend())
        response_encryptor = response_cipher.encryptor()
        encrypted_response = response_encryptor.update(padded_response) + response_encryptor.finalize()
        encrypted_response_b64 = base64.b64encode(encrypted_response).decode("utf-8")

        return JSONResponse({"status": "OK", "encrypted_response": encrypted_response_b64})

    except Exception as e:
        # Catch and return any runtime error that occurs during the decryption process
        return JSONResponse(content={"error": str(e)}, status_code=400)

# Returns the last decrypted message received from client
@app.get("/latest-client-message")
async def get_latest_client_message():
    return JSONResponse(content={"message": latest_decrypted_frontend_message})

# WebSocket handler to maintain persistent connection with clients
@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        while True:
            await websocket.receive_text()  # Keep the connection open
    except WebSocketDisconnect:
        manager.disconnect(websocket)

# Simple endpoint to check if server is running
@app.get("/health")
async def health_check():
    return PlainTextResponse(content="Server is up", status_code=200)

# Run the FastAPI app using Uvicorn
if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000)