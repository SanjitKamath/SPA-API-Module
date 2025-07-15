from flask import Flask, request, jsonify
import os

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

        print(f"✅ File saved: {filename} ({filetype})")

        # ✅ Return dummy message directly in response
        dummy_message = '{"message": "Hello from Flask backend!"}'
        print(f"📝 Generated dummy message: {dummy_message}")

        return jsonify({
            "status": "✅ File received and message set in main.py",
            "file_name": filename,
            "file_type": filetype,
            "file_size": os.path.getsize(file_path),
            "dummy_message": dummy_message  # Key addition
        })

    except Exception as e:
        print(f"❌ Exception: {e}")
        return jsonify({"error": str(e)}), 500

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=9000)