# main.py (FastAPI with embedded backend.py logic for dummy response handling)

from fastapi import FastAPI, Form, Request, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, PlainTextResponse
import base64, os, time, binascii, json
from collections import deque
from typing import Optional
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
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

RECENT_NONCES = deque(maxlen=1000)
NONCE_EXPIRY_SECONDS = 300
UPLOAD_DIR = "./received_files"
os.makedirs(UPLOAD_DIR, exist_ok=True)

def purge_expired_nonces():
    now = time.time()
    while RECENT_NONCES and RECENT_NONCES[0][1] < now - NONCE_EXPIRY_SECONDS:
        RECENT_NONCES.popleft()

def handle_dummy_file_logic(file_name: str, file_type: str, decrypted_bytes: bytes) -> dict:
    file_path = os.path.join(UPLOAD_DIR, os.path.basename(file_name))
    with open(file_path, "wb") as f:
        f.write(decrypted_bytes)

    print(f"✅ File saved: {file_name} ({file_type})")
    dummy_message = {"message": "You have sent an encrypted file!"}
    print(f"📝 Dummy message generated: {dummy_message}")

    return {
        "status": "✅ File received and processed",
        "file_name": file_name,
        "file_type": file_type,
        "file_size": os.path.getsize(file_path),
        "dummy_message": dummy_message
    }

def handle_dummy_file_logic_u(file_name: str, file_type: str, decrypted_bytes: bytes) -> dict:
    file_path = os.path.join(UPLOAD_DIR, os.path.basename(file_name))
    with open(file_path, "wb") as f:
        f.write(decrypted_bytes)

    print(f"✅ File saved: {file_name} ({file_type})")
    dummy_message = {"message": "You have sent an unencrypted file!"}
    print(f"📝 Dummy message generated: {dummy_message}")

    return {
        "status": "✅ File received and processed",
        "file_name": file_name,
        "file_type": file_type,
        "file_size": os.path.getsize(file_path),
        "dummy_message": dummy_message
    }

@app.post("/upload-unencrypted")
async def upload_unencrypted(file: UploadFile = File(...)):
    try:
        contents = await file.read()
        file_name = file.filename
        file_type = file.content_type

        response = handle_dummy_file_logic_u(file_name, file_type, contents)
        return JSONResponse(content={
            "status": response["status"],
            "file_name": response["file_name"],
            "file_type": response["file_type"],
            "file_size": response["file_size"],
            "dummy_message": response["dummy_message"]
        })
    except Exception as e:
        return JSONResponse(content={"error": str(e)}, status_code=500)

@app.get("/")
async def index():
    return PlainTextResponse("Welcome to the Unified API Server")

@app.get("/get-public-key/")
async def get_public_key():
    return JSONResponse(content={"public_key": pu.decode("utf-8")})

@app.post("/encrypt-message")
async def encrypt_for_client(server_message: str = Form(...)):
    global latest_admin_message, client_aes_key
    latest_admin_message = server_message

    if not client_aes_key:
        return JSONResponse({"error": "Client AES key not available yet."}, status_code=400)

    nonce = os.urandom(12)
    encryptor = Cipher(
        algorithms.AES(client_aes_key), modes.GCM(nonce), backend=default_backend()
    ).encryptor()
    ciphertext = encryptor.update(server_message.encode()) + encryptor.finalize()
    tag = encryptor.tag

    encrypted_payload = nonce + ciphertext + tag
    encrypted_msg_b64 = base64.b64encode(encrypted_payload).decode("utf-8")

    digest = hashes.Hash(hashes.SHA256())
    digest.update(server_message.encode())
    server_msg_hash = digest.finalize().hex()

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
        file_name = data.get("file_name", "unknown.bin")
        file_type = data.get("file_type", "application/octet-stream")

        if not all([encrypted_key_b64, encrypted_data_b64, timestamp, nonce, received_hash]):
            return JSONResponse({"error": "Missing required fields"}, status_code=400)

        msg_time = float(timestamp) / 1000.0
        now = time.time()
        if abs(now - msg_time) > NONCE_EXPIRY_SECONDS:
            return JSONResponse({"error": "Timestamp out of range"}, status_code=400)

        purge_expired_nonces()
        for n, t in RECENT_NONCES:
            if n == nonce:
                return JSONResponse({"error": "Replay detected"}, status_code=400)
        RECENT_NONCES.append((nonce, msg_time))

        encrypted_key = base64.b64decode(encrypted_key_b64)
        encrypted_data = base64.b64decode(encrypted_data_b64)
        if len(encrypted_data) < 28:
            return JSONResponse({"error": "Encrypted data too short"}, status_code=400)

        aes_key = serialization.load_pem_private_key(pr, password=None, backend=default_backend()).decrypt(
            encrypted_key,
            asym_padding.OAEP(
                mgf=asym_padding.MGF1(hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        client_aes_key = aes_key

        nonce_gcm, ciphertext, tag = encrypted_data[:12], encrypted_data[12:-16], encrypted_data[-16:]
        decryptor = Cipher(
            algorithms.AES(aes_key), modes.GCM(nonce_gcm, tag), backend=default_backend()
        ).decryptor()
        decrypted_bytes = decryptor.update(ciphertext) + decryptor.finalize()

        digest = hashes.Hash(hashes.SHA256())
        digest.update(binascii.hexlify(decrypted_bytes) + timestamp.encode() + nonce.encode())
        computed_hash = digest.finalize().hex()

        if computed_hash != received_hash:
            return JSONResponse({"error": "Hash mismatch"}, status_code=400)

        latest_decrypted_frontend_message = f"Received binary file: {file_name} ({file_type})"

        # Call embedded backend logic instead of Flask
        backend_response = handle_dummy_file_logic(file_name, file_type, decrypted_bytes)
        dummy = backend_response.get("dummy_message")
        if isinstance(dummy, dict):
            latest_admin_message = dummy.get("message", latest_admin_message)

        resp_nonce = os.urandom(12)
        encryptor = Cipher(
            algorithms.AES(aes_key), modes.GCM(resp_nonce), backend=default_backend()
        ).encryptor()
        ciphertext = encryptor.update(latest_admin_message.encode()) + encryptor.finalize()
        tag = encryptor.tag

        encrypted_payload = resp_nonce + ciphertext + tag
        encrypted_resp_b64 = base64.b64encode(encrypted_payload).decode("utf-8")

        return JSONResponse({
            "status": "OK",
            "encrypted_response": encrypted_resp_b64,
            "decrypted_file_info": {
                "name": file_name,
                "type": file_type,
                "size": len(decrypted_bytes),
                "json_preview": None
            }
        })

    except Exception as e:
        return JSONResponse(content={"error": str(e)}, status_code=400)

@app.get("/latest-client-message")
async def get_latest_client_message():
    return JSONResponse(content={"message": latest_decrypted_frontend_message})

@app.get("/health")
async def health_check():
    return PlainTextResponse(content="Server is up", status_code=200)

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, http="h11")
