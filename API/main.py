from fastapi import FastAPI, Form, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, PlainTextResponse
import base64, os, time, binascii, requests
from collections import deque
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
from RSA_Key_Gen import generate_rsa_keys  # RSA keypair generation utility

# Initialize FastAPI app
app = FastAPI()

# Enable CORS for all origins and headers (for frontend compatibility)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Generate and hold server-side RSA keys
pr, pu = generate_rsa_keys()  # pr = private key, pu = public key (PEM bytes)

# In-memory state holders
latest_admin_message = "No admin message yet."
latest_decrypted_frontend_message = "No client message yet."
client_aes_key: bytes = b""  # Will be populated during hybrid decryption

# Replay protection settings
RECENT_NONCES = deque(maxlen=1000)  # FIFO queue to track recent nonces
NONCE_EXPIRY_SECONDS = 300          # Valid time window for nonce reuse prevention (5 minutes)

# Utility to remove old nonces from memory
def purge_expired_nonces():
    now = time.time()
    while RECENT_NONCES and RECENT_NONCES[0][1] < now - NONCE_EXPIRY_SECONDS:
        RECENT_NONCES.popleft()

#####################################################################################################################
#####################################################################################################################

@app.get("/get-public-key/")
async def get_public_key():
    """
    Returns server's RSA public key to the client (frontend).
    """
    return JSONResponse(content={"public_key": pu.decode("utf-8")})

#####################################################################################################################
#####################################################################################################################

@app.post("/encrypt-message")
async def encrypt_for_client(server_message: str = Form(...)):
    """
    Accepts admin input from a dashboard/UI and returns AES-GCM encrypted version for the client.
    """
    global latest_admin_message, client_aes_key
    latest_admin_message = server_message

    # Ensure AES key is available (from prior /decrypt call)
    if not client_aes_key:
        return JSONResponse({"error": "Client AES key not available yet."}, status_code=400)

    # Encrypt admin message using AES-GCM
    nonce = os.urandom(12)
    cipher = Cipher(algorithms.AES(client_aes_key), modes.GCM(nonce), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted_msg = encryptor.update(server_message.encode()) + encryptor.finalize()
    tag = encryptor.tag

    encrypted_payload = nonce + encrypted_msg + tag
    encrypted_msg_b64 = base64.b64encode(encrypted_payload).decode("utf-8")

    # Generate hash of admin message for integrity (optional use)
    digest = hashes.Hash(hashes.SHA256())
    digest.update(server_message.encode())
    server_msg_hash = digest.finalize().hex()

    return JSONResponse({
        "status": "OK",
        "encrypted_response": encrypted_msg_b64,
        "hash": server_msg_hash
    })

#####################################################################################################################
#####################################################################################################################

@app.post("/decrypt")
async def hybrid_decrypt(request: Request):
    """
    Decrypts AES key (via RSA-OAEP) and encrypted file (via AES-GCM).
    Validates nonce, timestamp, and hash.
    Forwards decrypted file to Flask backend and re-encrypts admin response for client.
    """
    global latest_admin_message, latest_decrypted_frontend_message, client_aes_key

    try:
        data = await request.json()

        # Extract required fields from request
        encrypted_key_b64 = data.get("encrypted_key")
        encrypted_data_b64 = data.get("encrypted_data")
        timestamp = data.get("timestamp")
        nonce = data.get("nonce")
        received_hash = data.get("hash")
        file_name = data.get("file_name", "unknown.bin")
        file_type = data.get("file_type", "application/octet-stream")

        # Ensure all required fields are present
        if not all([encrypted_key_b64, encrypted_data_b64, timestamp, nonce, received_hash]):
            return JSONResponse({"error": "Missing required fields"}, status_code=400)

        # Validate timestamp (protect against replay or clock skew)
        msg_time = float(timestamp) / 1000.0
        now = time.time()
        if abs(now - msg_time) > NONCE_EXPIRY_SECONDS:
            return JSONResponse({"error": "Timestamp out of range"}, status_code=400)

        # Check and purge replayed or expired nonces
        purge_expired_nonces()
        for n, t in RECENT_NONCES:
            if n == nonce:
                return JSONResponse({"error": "Replay detected"}, status_code=400)
        RECENT_NONCES.append((nonce, msg_time))

        # Decode base64 values
        encrypted_key = base64.b64decode(encrypted_key_b64)
        encrypted_data = base64.b64decode(encrypted_data_b64)
        if len(encrypted_data) < 28:
            return JSONResponse({"error": "Encrypted data too short"}, status_code=400)

        # Decrypt AES key using server's private RSA key
        private_key = serialization.load_pem_private_key(pr, password=None, backend=default_backend())
        aes_key = private_key.decrypt(
            encrypted_key,
            asym_padding.OAEP(
                mgf=asym_padding.MGF1(hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        client_aes_key = aes_key  # Save for encrypting response

        # AES-GCM decryption of file
        nonce_gcm = encrypted_data[:12]
        ciphertext = encrypted_data[12:-16]
        tag = encrypted_data[-16:]

        cipher = Cipher(algorithms.AES(aes_key), modes.GCM(nonce_gcm, tag), backend=default_backend())
        decryptor = cipher.decryptor()
        decrypted_bytes = decryptor.update(ciphertext) + decryptor.finalize()

        # Verify hash integrity
        file_hex_str = binascii.hexlify(decrypted_bytes).decode()
        digest = hashes.Hash(hashes.SHA256())
        digest.update(file_hex_str.encode() + timestamp.encode() + nonce.encode())
        computed_hash = digest.finalize().hex()

        if computed_hash != received_hash:
            return JSONResponse({"error": "Hash mismatch"}, status_code=400)

        # Log frontend message state
        latest_decrypted_frontend_message = f"Received binary file: {file_name} ({file_type})"

        # Forward decrypted file to Flask server for storage
        try:
            print("📤 Forwarding file to Flask...")
            flask_response = requests.post(
                "http://localhost:9000/receive-decrypted-file",
                files={"file": (file_name, decrypted_bytes, file_type)},
                data={"filename": file_name, "filetype": file_type},
                timeout=15
            )
            print(f"📥 Flask response: {flask_response.text}")

            # Update admin message based on Flask response
            if flask_response.status_code == 200:
                flask_data = flask_response.json()
                if "dummy_message" in flask_data:
                    latest_admin_message = flask_data["dummy_message"]
                    print(f"📝 Updated admin message: {latest_admin_message}")
        except Exception as e:
            print(f"❌ Flask error: {e}")

        # Re-encrypt the (possibly updated) admin message using AES-GCM
        resp_nonce = os.urandom(12)
        cipher_resp = Cipher(algorithms.AES(aes_key), modes.GCM(resp_nonce), backend=default_backend())
        encryptor = cipher_resp.encryptor()
        encrypted_resp = encryptor.update(latest_admin_message.encode()) + encryptor.finalize()
        tag_resp = encryptor.tag
        payload_resp = resp_nonce + encrypted_resp + tag_resp
        encrypted_resp_b64 = base64.b64encode(payload_resp).decode("utf-8")

        return JSONResponse({
            "status": "OK",
            "encrypted_response": encrypted_resp_b64,
            "decrypted_file_info": {
                "name": file_name,
                "type": file_type,
                "size": len(decrypted_bytes),
                "json_preview": None  # Optional: parse preview for JSON/text files
            }
        })

    except Exception as e:
        return JSONResponse(content={"error": str(e)}, status_code=400)

#####################################################################################################################
#####################################################################################################################

@app.get("/latest-client-message")
async def get_latest_client_message():
    """
    Endpoint to retrieve the most recent decrypted client message.
    """
    return JSONResponse(content={"message": latest_decrypted_frontend_message})

#####################################################################################################################
#####################################################################################################################

@app.get("/health")
async def health_check():
    """
    Simple health check endpoint for load balancers or monitoring tools.
    """
    return PlainTextResponse(content="Server is up", status_code=200)

#####################################################################################################################
#####################################################################################################################

if __name__ == "__main__":
    import uvicorn
    # Run the app with Uvicorn server (only used for standalone execution)
    uvicorn.run("main:app", host="0.0.0.0", port=8000)
