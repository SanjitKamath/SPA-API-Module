import React, { useState, useRef } from "react";
import CryptoJS from "crypto-js";

const MAX_FILE_SIZE_MB = 5;
const MAX_FILE_BYTES = MAX_FILE_SIZE_MB * 1024 * 1024;

function pemToArrayBuffer(pem) {
  const b64 = pem.replace(/-----BEGIN PUBLIC KEY-----/, "")
    .replace(/-----END PUBLIC KEY-----/, "")
    .replace(/\s/g, "");
  const binary = atob(b64);
  const buffer = new ArrayBuffer(binary.length);
  const view = new Uint8Array(buffer);
  for (let i = 0; i < binary.length; i++) view[i] = binary.charCodeAt(i);
  return buffer;
}

function arrayBufferToBase64(buffer) {
  const bytes = new Uint8Array(buffer);
  let binary = "";
  for (let i = 0; i < bytes.byteLength; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary);
}

function base64ToArrayBuffer(base64) {
  const binary = atob(base64);
  const buffer = new ArrayBuffer(binary.length);
  const view = new Uint8Array(buffer);
  for (let i = 0; i < binary.length; i++) {
    view[i] = binary.charCodeAt(i);
  }
  return buffer;
}

function arrayBufferToWordArray(ab) {
  const u8 = new Uint8Array(ab);
  const words = [];
  for (let i = 0; i < u8.length; i += 4) {
    words.push(
      (u8[i] << 24) |
      (u8[i + 1] << 16) |
      (u8[i + 2] << 8) |
      (u8[i + 3] || 0)
    );
  }
  return CryptoJS.lib.WordArray.create(words, u8.length);
}

const HybridEncryptor = () => {
  const [file, setFile] = useState(null);
  const [status, setStatus] = useState("");
  const [decryptedResponse, setDecryptedResponse] = useState("");
  const [responseTime, setResponseTime] = useState(null);  // ⏱️ new state
  const aesCryptoKeyRef = useRef(null);

  const handleFileChange = (e) => {
    const selected = e.target.files[0];
    if (!selected) return;

    if (selected.size > MAX_FILE_BYTES) {
      setStatus(`❌ File too large. Max allowed: ${MAX_FILE_SIZE_MB} MB`);
      return;
    }

    setFile(selected);
    setStatus(`Selected: ${selected.name} (${(selected.size / 1024).toFixed(1)} KB)`);
  };

  const encryptAndSend = async () => {
    if (!file) {
      setStatus("Please select a file first.");
      return;
    }

    try {
      const aesKey = await window.crypto.subtle.generateKey(
        { name: "AES-GCM", length: 256 },
        true,
        ["encrypt", "decrypt"]
      );
      aesCryptoKeyRef.current = aesKey;

      const rawKey = await window.crypto.subtle.exportKey("raw", aesKey);

      const pubKeyRes = await fetch("http://localhost:8000/get-public-key/");
      const { public_key } = await pubKeyRes.json();

      const importedRSA = await window.crypto.subtle.importKey(
        "spki",
        pemToArrayBuffer(public_key),
        { name: "RSA-OAEP", hash: "SHA-256" },
        true,
        ["encrypt"]
      );

      const encryptedAESKey = await window.crypto.subtle.encrypt(
        { name: "RSA-OAEP" },
        importedRSA,
        rawKey
      );
      const encryptedAESKeyBase64 = arrayBufferToBase64(encryptedAESKey);

      const fileBuffer = await file.arrayBuffer();

      const iv = window.crypto.getRandomValues(new Uint8Array(12));
      const encrypted = await window.crypto.subtle.encrypt(
        { name: "AES-GCM", iv },
        aesKey,
        fileBuffer
      );

      const combined = new Uint8Array(iv.length + encrypted.byteLength);
      combined.set(iv, 0);
      combined.set(new Uint8Array(encrypted), iv.length);
      const encryptedFileBase64 = arrayBufferToBase64(combined);

      const timestamp = Date.now().toString();
      const nonce = CryptoJS.lib.WordArray.random(16).toString();

      const wordArray = arrayBufferToWordArray(fileBuffer);
      const hexString = CryptoJS.enc.Hex.stringify(wordArray);
      const payloadForHash = hexString + timestamp + nonce;
      const hash = CryptoJS.SHA256(payloadForHash).toString();

      const startTime = performance.now();  // ⏱️ Start timing

      const res = await fetch("http://localhost:8000/decrypt", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          encrypted_key: encryptedAESKeyBase64,
          encrypted_data: encryptedFileBase64,
          timestamp,
          nonce,
          hash,
          file_name: file.name,
          file_type: file.type || "application/octet-stream"
        }),
      });

      const result = await res.json();
      if (!res.ok) {
        setStatus(`❌ Error: ${result?.error || "Unknown error"}`);
        return;
      }

      const encryptedRespBase64 = result.encrypted_response;
      const encryptedRespBuffer = base64ToArrayBuffer(encryptedRespBase64);

      const respIv = encryptedRespBuffer.slice(0, 12);
      const respCiphertext = new Uint8Array(encryptedRespBuffer.slice(12, -16));
      const respTag = new Uint8Array(encryptedRespBuffer.slice(-16));

      const encryptedData = new Uint8Array(respCiphertext.length + respTag.length);
      encryptedData.set(respCiphertext, 0);
      encryptedData.set(respTag, respCiphertext.length);

      const decryptedBuffer = await window.crypto.subtle.decrypt(
        {
          name: "AES-GCM",
          iv: respIv,
          tagLength: 128
        },
        aesCryptoKeyRef.current,
        encryptedData
      );
      const decoder = new TextDecoder();
      const plaintext = decoder.decode(decryptedBuffer);

      const endTime = performance.now();  // ⏱️ Stop timing
      setResponseTime(((endTime - startTime)/1000).toFixed(2));  // ⏱in seconds

      setDecryptedResponse(plaintext);
      setStatus("✅ Success: File sent and response decrypted.");
    } catch (err) {
      console.error("Encryption failed:", err);
      setStatus("❌ Encryption failed: " + err.message);
    }
  };

  return (
    <div className="panel-container">
      <h1>Hybrid File Encryptor</h1>
      <div className="input-section">
        <input type="file" onChange={handleFileChange} />
        <button onClick={encryptAndSend} className="action-button">
          Encrypt & Send
        </button>
      </div>
      <div className="status-indicator">
        {status}
      </div>

      {responseTime && (
        <div className="timing-box">
          <strong>⏱️ Response time:</strong> {responseTime} seconds
        </div>
      )}

      {decryptedResponse && (
        <div className="response-box">
          <h3>🔓 Decrypted Admin Response</h3>
          <pre>{decryptedResponse}</pre>
        </div>
      )}
    </div>
  );
};

export default HybridEncryptor;
