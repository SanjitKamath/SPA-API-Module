from flask import Flask, request, jsonify
import os
from flask_cors import CORS

app = Flask(__name__)
CORS(app)  # Allow all cross-origin requests (CORS)

# Set maximum file upload size to 20 MB
app.config['MAX_CONTENT_LENGTH'] = 20 * 1024 * 1024  # 20 MB max file size

# Directory to save received files
UPLOAD_DIR = "./received_files"
os.makedirs(UPLOAD_DIR, exist_ok=True)  # Create directory if it doesn't exist

#####################################################################################################################
#####################################################################################################################

@app.route("/")
def index():
    """
    Root endpoint: used to verify that the server is running.
    """
    return "Welcome to the File Receiver API!"

#####################################################################################################################
#####################################################################################################################

@app.route("/direct-data", methods=["POST"])
def receive_direct_data():
    """
    Endpoint for receiving plain JSON data (no file or encryption).
    Useful for health checks, testing, or direct messaging.
    """
    try:
        data = request.get_json(force=True)
        print("📥 Direct data received:", data)

        return jsonify({
            "status": "success",
            "echo": data,  # Echoes back the received JSON
            "dummy_response": "Flask received your message cleanly."  # Simulated response
        })
    except Exception as e:
        print(f"❌ /direct-data error: {e}")
        return jsonify({"error": str(e)}), 500  # Internal server error if parsing fails

#####################################################################################################################
#####################################################################################################################

@app.route("/receive-decrypted-file", methods=["POST"])
def receive_file():
    """
    Endpoint for receiving a decrypted file (after AES decryption on frontend).
    Saves the file to disk and returns a dummy message as a response.
    """
    try:
        print("📥 Received request to /receive-decrypted-file")

        if 'file' not in request.files:
            print("❌ No file in request")
            return jsonify({"error": "Missing file in request"}), 400  # Bad request

        file = request.files['file']  # Get uploaded file from form-data

        # Extract file metadata
        filename = request.form.get("filename") or file.filename or "unnamed"
        filetype = request.form.get("filetype", "application/octet-stream")
        filename = os.path.basename(filename)  # Sanitize filename

        # Save the uploaded file to disk
        file_path = os.path.join(UPLOAD_DIR, filename)
        file.save(file_path)

        print(f"✅ File saved: {filename} ({filetype})")

        # Generate a dummy JSON message to simulate backend response
        dummy_message = '{"message": "Hello from Flask backend!"}'
        print(f"📝 Generated dummy message: {dummy_message}")

        return jsonify({
            "status": "✅ File received and message set in main.py",
            "file_name": filename,
            "file_type": filetype,
            "file_size": os.path.getsize(file_path),  # Return saved file size
            "dummy_message": dummy_message  # Dummy message sent back to frontend
        })

    except Exception as e:
        print(f"❌ Exception: {e}")
        return jsonify({"error": str(e)}), 500  # Catch-all for server-side exceptions

#####################################################################################################################
#####################################################################################################################

if __name__ == "__main__":
    # Run Flask app on host 0.0.0.0 (accessible from other devices) and port 9000
    app.run(host="0.0.0.0", port=9000)
