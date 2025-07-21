import React, { useState, useRef } from "react";
import CryptoJS from "crypto-js";

// Constants for file size validation
const MAX_FILE_SIZE_MB = 0.01;
const MAX_FILE_BYTES = MAX_FILE_SIZE_MB * 1024 * 1024;

/* ----------------------------- Utility Functions ----------------------------- */

// Converts a PEM-formatted RSA public key to an ArrayBuffer
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

// Converts ArrayBuffer to base64 string
function arrayBufferToBase64(buffer) {
  const bytes = new Uint8Array(buffer);
  let binary = "";
  for (let i = 0; i < bytes.byteLength; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary);
}

// Converts base64 string back to ArrayBuffer
function base64ToArrayBuffer(base64) {
  const binary = atob(base64);
  const buffer = new ArrayBuffer(binary.length);
  const view = new Uint8Array(buffer);
  for (let i = 0; i < binary.length; i++) {
    view[i] = binary.charCodeAt(i);
  }
  return buffer;
}

// Converts ArrayBuffer to CryptoJS-compatible WordArray
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

/* ----------------------------- Main Component ----------------------------- */

const HybridEncryptor = () => {
  const [file, setFile] = useState(null);                     // Stores the selected file
  const [status, setStatus] = useState("");                   // User-friendly status message
  const [decryptedResponse, setDecryptedResponse] = useState(""); // Decrypted server response
  const [responseTime, setResponseTime] = useState(null);     // Server response timing
  const aesCryptoKeyRef = useRef(null);                       // Holds AES key for response decryption

  // Handle file selection and validate file size
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

  // Sends plain JSON data to backend (for testing or fallback purposes)
  const sendDirectData = async () => {
    const payload = {
      user: "ClientUser",
      action: "Direct Test"
    };

    try {
      const startTime = performance.now(); // Start timer

      const res = await fetch("http://localhost:9000/direct-data", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload)
      });

      const endTime = performance.now();   // End timer
      const result = await res.json();

      if (!res.ok) {
        setStatus(`❌ Flask error: ${result?.error || "Unknown error"}`);
        return;
      }

      setDecryptedResponse(result?.dummy_response || "❌ No message received.");
      setStatus("✅ Direct data sent successfully.");
      setResponseTime(((endTime - startTime) / 1000).toFixed(2)); // Convert to seconds
    } catch (err) {
      console.error("❌ Fetch error:", err);
      setStatus("❌ Failed to send direct data: " + err.message);
    }
  };

  // Encrypts file and AES key, sends to backend, and decrypts response
  const encryptAndSend = async () => {
    if (!file) {
      setStatus("Please select a file first.");
      return;
    }

    try {
      // Generate AES-GCM key
      const aesKey = await window.crypto.subtle.generateKey(
        { name: "AES-GCM", length: 256 },
        true,
        ["encrypt", "decrypt"]
      );
      aesCryptoKeyRef.current = aesKey;

      // Export raw AES key to be encrypted with RSA
      const rawKey = await window.crypto.subtle.exportKey("raw", aesKey);

      // Fetch server’s RSA public key
      const pubKeyRes = await fetch("http://localhost:8000/get-public-key/");
      const { public_key } = await pubKeyRes.json();

      // Import RSA public key for encryption
      const importedRSA = await window.crypto.subtle.importKey(
        "spki",
        pemToArrayBuffer(public_key),
        { name: "RSA-OAEP", hash: "SHA-256" },
        true,
        ["encrypt"]
      );

      // Encrypt AES key using RSA
      const encryptedAESKey = await window.crypto.subtle.encrypt(
        { name: "RSA-OAEP" },
        importedRSA,
        rawKey
      );
      const encryptedAESKeyBase64 = arrayBufferToBase64(encryptedAESKey);

      // Encrypt file using AES-GCM
      const fileBuffer = await file.arrayBuffer();
      const iv = window.crypto.getRandomValues(new Uint8Array(12)); // 96-bit IV for AES-GCM
      const encrypted = await window.crypto.subtle.encrypt(
        { name: "AES-GCM", iv },
        aesKey,
        fileBuffer
      );

      // Combine IV and ciphertext
      const combined = new Uint8Array(iv.length + encrypted.byteLength);
      combined.set(iv, 0);
      combined.set(new Uint8Array(encrypted), iv.length);
      const encryptedFileBase64 = arrayBufferToBase64(combined);

      // Generate hash for integrity check (fileHex + timestamp + nonce)
      const timestamp = Date.now().toString();
      const nonce = CryptoJS.lib.WordArray.random(16).toString();
      const wordArray = arrayBufferToWordArray(fileBuffer);
      const hexString = CryptoJS.enc.Hex.stringify(wordArray);
      const payloadForHash = hexString + timestamp + nonce;
      const hash = CryptoJS.SHA256(payloadForHash).toString();

      const startTime = performance.now(); // ⏱️ Start measuring server response time

      // Send encrypted payload to FastAPI server
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

      // Parse server’s AES-GCM encrypted response
      const encryptedRespBase64 = result.encrypted_response;
      const encryptedRespBuffer = base64ToArrayBuffer(encryptedRespBase64);
      const respIv = encryptedRespBuffer.slice(0, 12);
      const respCiphertext = new Uint8Array(encryptedRespBuffer.slice(12, -16));
      const respTag = new Uint8Array(encryptedRespBuffer.slice(-16));

      // Merge ciphertext and auth tag
      const encryptedData = new Uint8Array(respCiphertext.length + respTag.length);
      encryptedData.set(respCiphertext, 0);
      encryptedData.set(respTag, respCiphertext.length);

      // Decrypt server's response using the same AES key
      const decryptedBuffer = await window.crypto.subtle.decrypt(
        {
          name: "AES-GCM",
          iv: respIv,
          tagLength: 128
        },
        aesCryptoKeyRef.current,
        encryptedData
      );

      const endTime = performance.now();  // ⏱️ Stop timer
      setResponseTime(((endTime - startTime) / 1000).toFixed(2)); // Show in seconds

      const decoder = new TextDecoder();
      const plaintext = decoder.decode(decryptedBuffer);

      // Try to parse JSON response or fallback to plaintext
      try {
        const parsed = JSON.parse(plaintext);
        const messageOnly = parsed.message || parsed.dummy_message || plaintext;
        setDecryptedResponse(messageOnly);
      } catch (e) {
        setDecryptedResponse(plaintext);
      }

      setStatus("✅ Success: File sent and response decrypted.");
    } catch (err) {
      console.error("Encryption failed:", err);
      setStatus("❌ Encryption failed: " + err.message);
    }
  };

  /* ----------------------------- Render UI ----------------------------- */

  return (
    <div className="panel-container">
      <h1>Hybrid File Encryptor</h1>

      <div className="input-section">
        <input type="file" onChange={handleFileChange} />
        <button onClick={encryptAndSend} className="action-button">
          Encrypt & Send
        </button>
        <button onClick={sendDirectData} className="action-button">
          Send Direct Data (No Encryption)
        </button>
      </div>

      <div className="status-indicator">
        {status}
      </div>

      {responseTime && (
        <div className="timing-box">
          <strong>Response time:</strong> {responseTime} seconds
        </div>
      )}

      {decryptedResponse && (
        <div className="response-box">
          <h3>Admin Response</h3>
          <pre>{decryptedResponse}</pre>
        </div>
      )}
    </div>
  );
};

export default HybridEncryptor;
