import base64
from fastapi import FastAPI, Form, Request, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, PlainTextResponse
from pydantic import BaseModel
from typing import List

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding, serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding

from RSA_Key_Gen import generate_rsa_keys  # Ensure this module returns (private_bytes, public_bytes)

app = FastAPI()

# CORS Setup
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Adjust as needed for production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# RSA Key Pair Generation
pr, pu = generate_rsa_keys()  # pr and pu are PEM-formatted bytes

# Global In-Memory State
latest_admin_message = "No admin message yet."
latest_decrypted_frontend_message = "No client message yet."
client_aes_key: bytes = b""  # This will hold the AES key from the frontend

# WebSocket Manager
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
                pass  # Ignore broken connections

manager = ConnectionManager()

# -------- ROUTES --------

@app.get("/get-public-key/")
async def get_public_key():
    return JSONResponse(content={"public_key": pu.decode("utf-8")})

@app.post("/encrypt-message")
async def encrypt_for_client(server_message: str = Form(...)):
    global latest_admin_message, client_aes_key, latest_decrypted_frontend_message

    latest_admin_message = server_message

    if not client_aes_key:
        return JSONResponse({"error": "Client AES key not available yet."}, status_code=400)

    # Pad and encrypt admin message using AES key
    padder = padding.PKCS7(128).padder()
    padded_msg = padder.update(server_message.encode()) + padder.finalize()

    cipher = Cipher(algorithms.AES(client_aes_key), modes.ECB(), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted_msg = encryptor.update(padded_msg) + encryptor.finalize()

    encrypted_msg_b64 = base64.b64encode(encrypted_msg).decode("utf-8")

    # Broadcast encrypted message and plaintext (optional)
    await manager.broadcast(f"new-message:{encrypted_msg_b64}")
    await manager.broadcast(f"new-admin-plaintext:{server_message}")

    return JSONResponse({"status": "Message stored and broadcasted."})

@app.post("/decrypt")
async def hybrid_decrypt(request: Request):
    global latest_admin_message, latest_decrypted_frontend_message, client_aes_key

    try:
        data = await request.json()
        encrypted_key_b64 = data.get("encrypted_key")
        encrypted_data_b64 = data.get("encrypted_data")

        if not encrypted_key_b64 or not encrypted_data_b64:
            return JSONResponse({"error": "Missing encrypted_key or encrypted_data"}, status_code=400)

        encrypted_key = base64.b64decode(encrypted_key_b64)
        encrypted_data = base64.b64decode(encrypted_data_b64)

        # Decrypt AES key using RSA private key
        private_key = serialization.load_pem_private_key(pr, password=None, backend=default_backend())
        aes_key = private_key.decrypt(
            encrypted_key,
            asym_padding.OAEP(
                mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        client_aes_key = aes_key  # Save AES key

        # Decrypt frontend message using AES
        cipher = Cipher(algorithms.AES(aes_key), modes.ECB(), backend=default_backend())
        decryptor = cipher.decryptor()
        padded_data = decryptor.update(encrypted_data) + decryptor.finalize()

        unpadder = padding.PKCS7(128).unpadder()
        decrypted = unpadder.update(padded_data) + unpadder.finalize()
        result = decrypted.decode("utf-8")

        latest_decrypted_frontend_message = result

        # Broadcast decrypted client message
        await manager.broadcast(f"new-client-message:{result}")

        # Encrypt admin message as response using AES
        padder = padding.PKCS7(128).padder()
        padded_response = padder.update(latest_admin_message.encode()) + padder.finalize()

        response_cipher = Cipher(algorithms.AES(aes_key), modes.ECB(), backend=default_backend())
        response_encryptor = response_cipher.encryptor()
        encrypted_response = response_encryptor.update(padded_response) + response_encryptor.finalize()
        encrypted_response_b64 = base64.b64encode(encrypted_response).decode("utf-8")

        return JSONResponse({
            "status": "OK",
            "encrypted_response": encrypted_response_b64
            
        })

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
            await websocket.receive_text()  # Keep connection open
    except WebSocketDisconnect:
        manager.disconnect(websocket)

@app.get("/health")
async def health_check():
    return PlainTextResponse(content="Server is up", status_code=200)

# Optional: for local debugging
if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
