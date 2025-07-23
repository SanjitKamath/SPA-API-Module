import os, base64, time, binascii
from collections import deque
from fastapi import Request
from fastapi.responses import JSONResponse
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
from starlette.types import ASGIApp, Scope, Receive, Send

# Global variables for state sharing across middleware and routes
client_aes_key = None  # Stores decrypted AES key
latest_admin_message = ""  # Holds latest message returned to client
latest_decrypted_frontend_message = ""  # Holds latest frontend message
RECENT_NONCES = deque(maxlen=1000)  # For replay protection
NONCE_EXPIRY_SECONDS = 300  # 5 minutes timestamp validity window
handle_file_logic = None  # File handler callback injected at startup
private_key = None  # RSA private key for decrypting AES key

# Function to inject shared dependencies (private_key, handlers, etc.)
def inject_dependencies(config: dict):
    global handle_file_logic, private_key, latest_admin_message
    handle_file_logic = config["handle_file_logic"]
    private_key = config["private_key"]
    latest_admin_message = config["latest_admin_message"]

# Custom FastAPI middleware to handle encrypted POST requests
class EncryptionMiddleware:
    def __init__(self, app: ASGIApp):
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send):
        # Only handle HTTP requests
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        request = Request(scope, receive=receive)

        # Handle only specially marked encrypted POST requests
        if request.method == "POST" and request.headers.get("x-encrypted-request") == "true":
            response = await self.handle_encrypted_request(request)
            await response(scope, receive, send)
        else:
            await self.app(scope, receive, send)

    # Core logic: decrypt request, verify integrity, respond encrypted
    async def handle_encrypted_request(self, request: Request) -> JSONResponse:
        global client_aes_key, latest_admin_message, latest_decrypted_frontend_message

        try:
            # Parse and validate incoming JSON data
            data = await request.json()
            encrypted_key_b64 = data.get("encrypted_key")
            encrypted_data_b64 = data.get("encrypted_data")
            timestamp = data.get("timestamp")
            nonce = data.get("nonce")
            received_hash = data.get("hash")
            file_name = data.get("file_name", "unknown.bin")
            file_type = data.get("file_type", "application/octet-stream")

            if not all([encrypted_key_b64, encrypted_data_b64, timestamp, nonce, received_hash]):
                return JSONResponse({"error": "Missing required fields"}, status_code=400, headers={"Access-Control-Allow-Origin": "*"})

            # Anti-replay: Check if the timestamp is within the allowed window
            msg_time = float(timestamp) / 1000.0
            now = time.time()
            if abs(now - msg_time) > NONCE_EXPIRY_SECONDS:
                return JSONResponse({"error": "Timestamp out of range"}, status_code=400, headers={"Access-Control-Allow-Origin": "*"})

            # Cleanup old nonces
            while RECENT_NONCES and RECENT_NONCES[0][1] < now - NONCE_EXPIRY_SECONDS:
                RECENT_NONCES.popleft()

            # Check for nonce reuse
            for n, t in RECENT_NONCES:
                if n == nonce:
                    return JSONResponse({"error": "Replay detected"}, status_code=400, headers={"Access-Control-Allow-Origin": "*"})
            RECENT_NONCES.append((nonce, msg_time))

            # Decode base64-encoded AES key and file data
            encrypted_key = base64.b64decode(encrypted_key_b64)
            encrypted_data = base64.b64decode(encrypted_data_b64)
            if len(encrypted_data) < 28:  # 12 bytes nonce + 16 bytes tag
                return JSONResponse({"error": "Encrypted data too short"}, status_code=400, headers={"Access-Control-Allow-Origin": "*"})

            # Decrypt AES key using server’s RSA private key
            aes_key = serialization.load_pem_private_key(private_key, password=None, backend=default_backend()).decrypt(
                encrypted_key,
                asym_padding.OAEP(
                    mgf=asym_padding.MGF1(hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            client_aes_key = aes_key

            # Split encrypted_data into AES-GCM nonce, ciphertext, and tag
            nonce_gcm, ciphertext, tag = encrypted_data[:12], encrypted_data[12:-16], encrypted_data[-16:]

            # Decrypt file data using AES-GCM
            decryptor = Cipher(
                algorithms.AES(aes_key),
                modes.GCM(nonce_gcm, tag),
                backend=default_backend()
            ).decryptor()
            decrypted_bytes = decryptor.update(ciphertext) + decryptor.finalize()

            # Recompute hash to verify integrity
            digest = hashes.Hash(hashes.SHA256())
            digest.update(binascii.hexlify(decrypted_bytes) + timestamp.encode() + nonce.encode())
            computed_hash = digest.finalize().hex()

            if computed_hash != received_hash:
                return JSONResponse({"error": "Hash mismatch"}, status_code=400, headers={"Access-Control-Allow-Origin": "*"})

            # Record the decrypted message for internal monitoring
            latest_decrypted_frontend_message = f"Received binary file: {file_name} ({file_type})"

            # Delegate further processing to user-defined logic
            backend_response = handle_file_logic(file_name, file_type, decrypted_bytes)

            # If dummy message is present, store as latest admin message
            dummy = backend_response.get("dummy_message")
            if isinstance(dummy, dict):
                latest_admin_message = dummy.get("message", latest_admin_message)

            # Encrypt the admin message using AES-GCM with new nonce
            resp_nonce = os.urandom(12)
            encryptor = Cipher(
                algorithms.AES(aes_key),
                modes.GCM(resp_nonce),
                backend=default_backend()
            ).encryptor()
            ciphertext = encryptor.update(latest_admin_message.encode()) + encryptor.finalize()
            tag = encryptor.tag

            # Concatenate nonce, ciphertext, and tag
            encrypted_payload = resp_nonce + ciphertext + tag
            encrypted_resp_b64 = base64.b64encode(encrypted_payload).decode("utf-8")

            # Return encrypted server message + decrypted file metadata
            return JSONResponse({
                "status": "OK",
                "encrypted_response": encrypted_resp_b64,
                "decrypted_file_info": {
                    "name": file_name,
                    "type": file_type,
                    "size": len(decrypted_bytes),
                    "json_preview": None  # Reserved for future content introspection
                }
            }, headers={"Access-Control-Allow-Origin": "*"})

        except Exception as e:
            # In case of failure, return error in JSON format
            return JSONResponse({"error": str(e)}, status_code=400, headers={"Access-Control-Allow-Origin": "*"})
