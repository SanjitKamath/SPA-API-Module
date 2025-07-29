import React, { useState, useEffect } from "react";

function HybridEncryptor() {
  const [file, setFile] = useState(null);
  const [status, setStatus] = useState("");
  const [rtt, setRtt] = useState(null);
  const [serverResponse, setServerResponse] = useState(null);
  const [publicKey, setPublicKey] = useState(null);
  const [decryptedAdminMessage, setDecryptedAdminMessage] = useState(null);

  useEffect(() => {
    fetch("http://localhost:8000/get-public-key/")
      .then(res => res.json())
      .then(data => setPublicKey(data.public_key))
      .catch(err => setStatus("❌ Failed to fetch public key: " + err.message));
  }, []);

  const toBase64 = async (buffer) => {
    return new Promise((resolve, reject) => {
      const reader = new FileReader();
      reader.onloadend = () => resolve(reader.result.split(',')[1]);
      reader.onerror = reject;
      reader.readAsDataURL(new Blob([buffer]));
    });
  };

  const hexlify = (buffer) => {
    return Array.from(new Uint8Array(buffer))
      .map(b => b.toString(16).padStart(2, "0"))
      .join("");
  };

  async function importRSAPublicKey(pem) {
    const binaryDer = Uint8Array.from(
      atob(pem.replace(/-----(BEGIN|END) PUBLIC KEY-----/g, "").replace(/\s/g, "")),
      c => c.charCodeAt(0)
    );
    return crypto.subtle.importKey(
      "spki",
      binaryDer.buffer,
      {
        name: "RSA-OAEP",
        hash: "SHA-256"
      },
      false,
      ["encrypt"]
    );
  }

  const handleUpload = async () => {
    if (!file || !publicKey) {
      setStatus("⚠️ File or RSA key missing.");
      return;
    }

    try {
      const fileBuffer = await file.arrayBuffer();

      const aesKey = await crypto.subtle.generateKey(
        { name: "AES-GCM", length: 256 },
        true,
        ["encrypt", "decrypt"]
      );

      const iv = crypto.getRandomValues(new Uint8Array(12));
      const encryptedData = await crypto.subtle.encrypt(
        { name: "AES-GCM", iv },
        aesKey,
        fileBuffer
      );

      const rawAES = await crypto.subtle.exportKey("raw", aesKey);
      const rsaKey = await importRSAPublicKey(publicKey);
      const encryptedAESKey = await crypto.subtle.encrypt(
        { name: "RSA-OAEP" },
        rsaKey,
        rawAES
      );

      const timestamp = Date.now().toString();
      const nonce = crypto.randomUUID();

      const hexEncoded = hexlify(fileBuffer);
      const fullString = hexEncoded + timestamp + nonce;
      const hashBuffer = await crypto.subtle.digest(
        "SHA-256",
        new TextEncoder().encode(fullString)
      );

      const fullEncryptedPayload = new Uint8Array([...iv, ...new Uint8Array(encryptedData)]);
      const encryptedKeyB64 = await toBase64(encryptedAESKey);
      const encryptedDataB64 = await toBase64(fullEncryptedPayload);

      const payload = {
        encrypted_key: encryptedKeyB64,
        encrypted_data: encryptedDataB64,
        timestamp,
        nonce,
        hash: Array.from(new Uint8Array(hashBuffer)).map(b => b.toString(16).padStart(2, '0')).join(""),
        file_name: file.name,
        file_type: file.type
      };

      const startTime = performance.now();

      const res = await fetch("http://localhost:8000/upload-encrypted", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "x-encrypted-request": "true"
        },
        body: JSON.stringify(payload)
      });

      const endTime = performance.now();
      setRtt(Math.round(endTime - startTime));

      const result = await res.json();
      if (result.status === "OK") {
        setServerResponse(result);
        setStatus("✅ File uploaded and decrypted successfully.");

        const encryptedRespBuffer = Uint8Array.from(atob(result.encrypted_response), c => c.charCodeAt(0));
        const respNonce = encryptedRespBuffer.slice(0, 12);
        const respCiphertext = encryptedRespBuffer.slice(12, -16);
        const respTag = encryptedRespBuffer.slice(-16);

        const decryptedAdminBuffer = await crypto.subtle.decrypt(
          {
            name: "AES-GCM",
            iv: respNonce,
            tagLength: 128
          },
          aesKey,
          new Uint8Array([...respCiphertext, ...respTag])
        );

        const adminMessage = new TextDecoder().decode(decryptedAdminBuffer);
        setDecryptedAdminMessage(adminMessage);
      } else {
        setStatus("❌ Server error: " + (result.error || "Unknown"));
      }
    } catch (err) {
      setStatus("❌ Upload failed: " + err.message);
    }
  };

  const handleRawUpload = async () => {
    if (!file) {
      setStatus("⚠️ No file selected.");
      return;
    }

    const formData = new FormData();
    formData.append("file", file);

    try {
      const startTime = performance.now();

      const res = await fetch("http://localhost:8000/upload-encrypted", {
        method: "POST",
        body: formData,
      });

      const endTime = performance.now();
      setRtt(Math.round(endTime - startTime));

      const text = await res.text();
      setStatus("📤 Raw Upload Response: " + text);
      setServerResponse(null);
      setDecryptedAdminMessage(null);
    } catch (err) {
      setStatus("❌ Raw upload failed: " + err.message);
    }
  };

  return (
    <div className="App">
      <h2 className="title">Hybrid Encryption Upload</h2>

      <div className="upload-section">
        <input
          type="file"
          className="file-input"
          onChange={e => setFile(e.target.files[0])}
        />
        <button className="upload-button" onClick={handleUpload} disabled={!file}>
          Encrypt & Upload
        </button>
        <button className="upload-button" onClick={handleRawUpload} disabled={!file}>
          Upload Without Encryption
        </button>
      </div>

      {status && <p className="status-message">{status}</p>}
      {rtt !== null && <p className="status-message">⏱️ RTT: {rtt/1000} seconds</p>}

      {serverResponse && (
        <div className="response-block">
          <h3>Decrypted File Info:</h3>
          <ul>
            <li><strong>Size:</strong> {serverResponse.decrypted_file_info.size} bytes</li>
          </ul>
          {decryptedAdminMessage && (
            <>
              <h3>🔓 Decrypted Admin Message:</h3>
              <pre className="decrypted-response">{decryptedAdminMessage}</pre>
            </>
          )}
        </div>
      )}
    </div>
  );
}

export default HybridEncryptor;
