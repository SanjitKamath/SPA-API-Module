from flask import Flask, request, jsonify
import os
import requests
import time

app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 20 * 1024 * 1024  # 20 MB max file size

UPLOAD_DIR = "./received_files"
os.makedirs(UPLOAD_DIR, exist_ok=True)

@app.route("/")
def index():
    return "Welcome to the File Receiver API!"

@app.route("/receive-decrypted-file", methods=["POST"])
def receive_file():
    try:
        print("📥 Received request to /receive-decrypted-file")

        if 'file' not in request.files:
            print("❌ No file in request")
            return jsonify({"error": "Missing file in request"}), 400

        file = request.files['file']
        filename = request.form.get("filename") or file.filename or "unnamed"
        filetype = request.form.get("filetype", "application/octet-stream")
        filename = os.path.basename(filename)

        file_path = os.path.join(UPLOAD_DIR, filename)
        file.save(file_path)

        print("✅ File saved successfully")
        print(f"   → Filename: {filename}")
        print(f"   → Type:     {filetype}")
        print(f"   → Size:     {os.path.getsize(file_path)} bytes")
        print(f"   → Saved to: {file_path}")

        # ✅ Send dummy admin message
        try:
            dummy_message = '{"message": "Hello from Flask backend!"}'
            print("📤 Sending dummy message to FastAPI /encrypt-message...")
            response = requests.post(
                "http://localhost:8000/encrypt-message",
                data={"server_message": dummy_message},
                timeout=15
            )
            print(f"📤 FastAPI response status: {response.status_code}")
        except Exception as e:
            print(f"❌ Failed to send dummy message to FastAPI: {e}")

        return jsonify({
            "status": "✅ File received and message sent to main.py",
            "file_name": filename,
            "file_type": filetype,
            "file_size": os.path.getsize(file_path)
        })

    except Exception as e:
        print(f"❌ Exception during file processing: {e}")
        return jsonify({"error": str(e)}), 500

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=9000)
