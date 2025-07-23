import React, { useState, useRef } from "react";
import CryptoJS from "crypto-js";
import './App.css'

// Constants for maximum file size validation
const MAX_FILE_SIZE_MB = 5;
const MAX_FILE_BYTES = MAX_FILE_SIZE_MB * 1024 * 1024;

const HybridEncryptor = () => {
  // React state variables
  const [file, setFile] = useState(null);
  const [status, setStatus] = useState("");
  const [responseMessage, setResponseMessage] = useState("");
  const [timeTaken, setTimeTaken] = useState(null);

  // Refs for storing AES key and raw key buffer
  const aesCryptoKeyRef = useRef(null);
  const aesRawKeyRef = useRef(null);

  // Handle file selection and validate file size
  const handleFileChange = (event) => {
    const selected = event.target.files[0];
    if (selected && selected.size > MAX_FILE_BYTES) {
      setStatus(`File too large. Max: ${MAX_FILE_SIZE_MB} MB`);
      setFile(null);
    } else {
      setFile(selected);
    }
  };

  // Convert PEM RSA public key string to binary ArrayBuffer
  const pemToBinary = (pem) => {
    const b64 = pem.replace(/-----[^-]+-----/g, "").replace(/\s/g, "");
    const binary = atob(b64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i);
    }
    return bytes.buffer;
  };

  // Main encryption function: hybrid encryption + API submission
  const encryptAndSend = async () => {
    if (!file) {
      setStatus("Please select a file first.");
      return;
    }

    setTimeTaken(null);
    setResponseMessage("");
    const startTime = performance.now();

    try {
      // Generate AES-GCM symmetric key (256-bit)
      const aesKey = await window.crypto.subtle.generateKey(
        { name: "AES-GCM", length: 256 },
        true,
        ["encrypt", "decrypt"]
      );
      aesCryptoKeyRef.current = aesKey;

      // Export raw key for RSA encryption
      const rawKey = await window.crypto.subtle.exportKey("raw", aesKey);
      aesRawKeyRef.current = rawKey;

      // Fetch RSA public key from backend
      const publicKeyRes = await fetch("http://localhost:8000/get-public-key/");
      const { public_key } = await publicKeyRes.json();

      // Import public key for RSA-OAEP encryption
      const importedRSAPublicKey = await window.crypto.subtle.importKey(
        "spki",
        pemToBinary(public_key),
        { name: "RSA-OAEP", hash: "SHA-256" },
        false,
        ["encrypt"]
      );

      // Read file content into ArrayBuffer
      const fileBuffer = await file.arrayBuffer();

      // Generate AES-GCM IV (nonce)
      const nonce = window.crypto.getRandomValues(new Uint8Array(12));

      // Encrypt file content using AES-GCM
      const encryptedContent = await window.crypto.subtle.encrypt(
        { name: "AES-GCM", iv: nonce },
        aesKey,
        fileBuffer
      );

      // Combine nonce + ciphertext for transmission
      const encryptedData = new Uint8Array(nonce.length + encryptedContent.byteLength);
      encryptedData.set(nonce, 0);
      encryptedData.set(new Uint8Array(encryptedContent), nonce.length);

      // Generate integrity hash using CryptoJS
      const timestamp = Date.now().toString();
      const nonceStr = CryptoJS.lib.WordArray.random(8).toString();
      const hashInput = CryptoJS.enc.Hex.stringify(CryptoJS.lib.WordArray.create(new Uint8Array(fileBuffer))) + timestamp + nonceStr;
      const hash = CryptoJS.SHA256(hashInput).toString();

      // Encrypt AES key with RSA public key
      const encryptedKey = await window.crypto.subtle.encrypt(
        { name: "RSA-OAEP" },
        importedRSAPublicKey,
        rawKey
      );

      // Send encrypted payload to backend
      const res = await fetch("http://localhost:8000/upload-encrypted", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "X-Encrypted-Request": "true",
        },
        body: JSON.stringify({
          encrypted_key: btoa(String.fromCharCode(...new Uint8Array(encryptedKey))),
          encrypted_data: btoa(String.fromCharCode(...encryptedData)),
          timestamp,
          nonce: nonceStr,
          hash,
          file_name: file.name,
          file_type: file.type || "application/octet-stream",
        }),
      });

      const result = await res.json();

      // If server returns an encrypted response, decrypt it
      if (result.encrypted_response) {
        const decryptedMessage = await decryptAES(result.encrypted_response);
        setResponseMessage(`🔐 Server Message: ${decryptedMessage}`);
      } else {
        setResponseMessage(JSON.stringify(result));
      }

      const endTime = performance.now();
      setTimeTaken(endTime - startTime);
      setStatus("✅ Encrypted file sent successfully!");
    } catch (error) {
      console.error(error);
      const endTime = performance.now();
      setTimeTaken(endTime - startTime);
      setStatus("❌ Encryption or upload failed.");
    }
  };

  // Optional fallback: Send unencrypted file (testing/debug)
  const sendUnencrypted = async () => {
    if (!file) {
      setStatus("Please select a file first.");
      return;
    }

    setStatus("Uploading unencrypted file...");
    setResponseMessage("");
    const startTime = performance.now();

    try {
      const formData = new FormData();
      formData.append("file", file);

      const res = await fetch("http://localhost:8000/upload-encrypted", {
        method: "POST",
        body: formData,
      });

      const result = await res.json();
      setResponseMessage(`📤 Server Response: ${JSON.stringify(result, null, 2)}`);

      const endTime = performance.now();
      setTimeTaken(endTime - startTime);
      setStatus("✅ Unencrypted file sent successfully!");
    } catch (error) {
      console.error(error);
      const endTime = performance.now();
      setTimeTaken(endTime - startTime);
      setStatus("❌ Upload failed.");
    }
  };

  // AES-GCM decryption for encrypted server response
  const decryptAES = async (b64) => {
    const encryptedData = Uint8Array.from(atob(b64), c => c.charCodeAt(0));
    const nonce = encryptedData.slice(0, 12);
    const ciphertext = encryptedData.slice(12, -16);
    const tag = encryptedData.slice(-16);

    // Concatenate ciphertext and tag
    const combined = new Uint8Array(ciphertext.length + tag.length);
    combined.set(ciphertext);
    combined.set(tag, ciphertext.length);

    try {
      const decrypted = await window.crypto.subtle.decrypt(
        { name: "AES-GCM", iv: nonce },
        aesCryptoKeyRef.current,
        combined
      );
      return new TextDecoder().decode(decrypted);
    } catch {
      return "Failed to decrypt server message";
    }
  };

  // UI Rendering
  return (
    <div className="panel-container">
      <h1>Hybrid File Encryptor</h1>
      <div className="input-section">
        <input type="file" onChange={handleFileChange} />
        <button onClick={encryptAndSend} className="action-button">Encrypt & Send</button>
        <button onClick={sendUnencrypted} className="action-button">Send Direct Data (No Encryption)</button>
      </div>
      <div className="status-indicator">{status}</div>
      <div className="timing-box"><strong>Response time:</strong> {(timeTaken/1000).toFixed(2)} seconds</div>
      {responseMessage && <div className="response-box"><h3>Admin Response</h3><pre>{responseMessage}</pre></div>}
    </div>
  );
};

export default HybridEncryptor;
