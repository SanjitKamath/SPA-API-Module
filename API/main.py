from fastapi import FastAPI, Form, Request, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, PlainTextResponse
from RSA_Key_Gen import generate_rsa_keys
from encryption_middleware import EncryptionMiddleware, inject_dependencies
import os

# Generate RSA public and private keys
pr, pu = generate_rsa_keys()

# Global variables to track latest messages
latest_admin_message = "No admin message yet."
latest_decrypted_frontend_message = "No client message yet."

# Placeholder for storing AES key sent by the client
client_aes_key: bytes = b""

# Directory to store uploaded/received files
UPLOAD_DIR = "./received_files"
os.makedirs(UPLOAD_DIR, exist_ok=True)  # Ensure directory exists

# Initialize FastAPI application
app = FastAPI()

# Allow cross-origin requests from any domain (CORS setup)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173"],  
    allow_credentials=True,
    allow_methods=["*"],  # Allow all HTTP methods
    allow_headers=["*"],  # Allow all headers
)

# Custom handler function for storing and processing decrypted file data
def handle_dummy_file_logic(file_name: str, file_type: str, decrypted_bytes: bytes) -> dict:
    file_path = os.path.join(UPLOAD_DIR, os.path.basename(file_name)) # Gets the full file path
    with open(file_path, "wb") as f:
        f.write(decrypted_bytes)                                      # Saves raw bytes to a file
    return {                                                          # Returns a summary of the file and the dummy message
        "status": "✅ File received and processed",
        "file_name": file_name,
        "file_type": file_type,
        "file_size": os.path.getsize(file_path),
        "dummy_message": {"message": "You have sent an encrypted file!"}
    }

# Inject required dependencies into the encryption middleware for processing
inject_dependencies({
    "handle_file_logic": handle_dummy_file_logic,
    "private_key": pr,
    "latest_admin_message": latest_admin_message,
})

# Add custom encryption middleware to handle decryption of incoming data
app.add_middleware(EncryptionMiddleware)

# Endpoint to receive encrypted file/data (actual logic handled by middleware)
@app.post("/upload-encrypted")
async def upload_encrypted(request: Request):
    return JSONResponse("You have sent a file with no encryption!")

# Simple root endpoint for health or welcome page
@app.get("/")
async def index():
    return PlainTextResponse("Welcome to the Unified API Server")

# Public key endpoint to share the RSA public key with clients
@app.get("/get-public-key/")
async def get_public_key():
    return JSONResponse(content={"public_key": pu.decode("utf-8")})

# Basic health check endpoint to verify if server is up
@app.get("/health")
async def health_check():
    return PlainTextResponse(content="Server is up", status_code=200)

# Entry point for running the FastAPI app using Uvicorn
if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=False, log_level="info")
