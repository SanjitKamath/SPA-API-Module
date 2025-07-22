import React, { useState, useRef, useEffect } from "react";
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
  const [responseTime, setResponseTime] = useState(null);
  const [rsaPublicKey, setRsaPublicKey] = useState(null);
  const aesCryptoKeyRef = useRef(null);

  useEffect(() => {
    fetch("http://localhost:8000/get-public-key/")
      .then(res => res.json())
      .then(({ public_key }) => setRsaPublicKey(public_key))
      .catch(err => console.error("RSA key fetch error:", err));
  }, []);

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

  const sendDirectData = async () => {
    if (!file) {
      setStatus("❌ Please select a file first.");
      return;
    }

    try {
      const formData = new FormData();
      formData.append("file", file);

      const startTime = performance.now();
      const res = await fetch("http://localhost:8000/upload-unencrypted", {
        method: "POST",
        body: formData,
      });
      const result = await res.json();
      const endTime = performance.now();

      if (!res.ok) {
        setStatus(`❌ Server error: ${result?.error || "Unknown error"}`);
        return;
      }

      setDecryptedResponse(result?.dummy_message?.message || "❌ No message received.");
      setStatus("✅ File sent without encryption.");
      setResponseTime(((endTime - startTime) / 1000).toFixed(2));
    } catch (err) {
      setStatus("❌ Failed to send file directly: " + err.message);
    }
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

      const rawKeyPromise = window.crypto.subtle.exportKey("raw", aesKey);
      const fileBufferPromise = file.arrayBuffer();

      const [rawKey, fileBuffer] = await Promise.all([rawKeyPromise, fileBufferPromise]);

      const iv = window.crypto.getRandomValues(new Uint8Array(12));
      const encryptedFilePromise = window.crypto.subtle.encrypt(
        { name: "AES-GCM", iv },
        aesKey,
        fileBuffer
      );

      const importedRSAPromise = window.crypto.subtle.importKey(
        "spki",
        pemToArrayBuffer(rsaPublicKey),
        { name: "RSA-OAEP", hash: "SHA-256" },
        true,
        ["encrypt"]
      );

      const wordArray = arrayBufferToWordArray(fileBuffer);
      const hexString = CryptoJS.enc.Hex.stringify(wordArray);
      const timestamp = Date.now().toString();
      const nonce = CryptoJS.lib.WordArray.random(16).toString();
      const hash = CryptoJS.SHA256(hexString + timestamp + nonce).toString();

      const importedRSA = await importedRSAPromise;
      const encryptedAESKeyPromise = window.crypto.subtle.encrypt(
        { name: "RSA-OAEP" },
        importedRSA,
        rawKey
      );

      const [encrypted, encryptedAESKey] = await Promise.all([
        encryptedFilePromise,
        encryptedAESKeyPromise
      ]);

      const combined = new Uint8Array(iv.length + encrypted.byteLength);
      combined.set(iv, 0);
      combined.set(new Uint8Array(encrypted), iv.length);
      const encryptedFileBase64 = arrayBufferToBase64(combined);
      const encryptedAESKeyBase64 = arrayBufferToBase64(encryptedAESKey);

      const startTime = performance.now();

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
      const endTime = performance.now();
      setResponseTime(((endTime - startTime) / 1000).toFixed(2));

      if (!res.ok) {
        setStatus(`❌ Error: ${result?.error || "Unknown error"}`);
        return;
      }

      const encryptedRespBuffer = base64ToArrayBuffer(result.encrypted_response);
      const respIv = encryptedRespBuffer.slice(0, 12);
      const respCiphertext = new Uint8Array(encryptedRespBuffer.slice(12, -16));
      const respTag = new Uint8Array(encryptedRespBuffer.slice(-16));

      const encryptedData = new Uint8Array(respCiphertext.length + respTag.length);
      encryptedData.set(respCiphertext, 0);
      encryptedData.set(respTag, respCiphertext.length);

      const decryptedBuffer = await window.crypto.subtle.decrypt(
        { name: "AES-GCM", iv: respIv, tagLength: 128 },
        aesCryptoKeyRef.current,
        encryptedData
      );

      const plaintext = new TextDecoder().decode(decryptedBuffer);
      try {
        const parsed = JSON.parse(plaintext);
        setDecryptedResponse(parsed.message || parsed.dummy_message || plaintext);
      } catch {
        setDecryptedResponse(plaintext);
      }

      setStatus("✅ Success: File sent and response decrypted.");
    } catch (err) {
      setStatus("❌ Encryption failed: " + err.message);
    }
  };

  return (
    <div className="panel-container">
      <h1>Hybrid File Encryptor</h1>
      <div className="input-section">
        <input type="file" onChange={handleFileChange} />
        <button onClick={encryptAndSend} className="action-button">Encrypt & Send</button>
        <button onClick={sendDirectData} className="action-button">Send Direct Data (No Encryption)</button>
      </div>
      <div className="status-indicator">{status}</div>
      {responseTime && <div className="timing-box"><strong>Response time:</strong> {responseTime} seconds</div>}
      {decryptedResponse && <div className="response-box"><h3>Admin Response</h3><pre>{decryptedResponse}</pre></div>}
    </div>
  );
};

export default HybridEncryptor;
