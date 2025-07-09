// App.jsx

import React, { useState, useEffect, useRef } from "react";
import CryptoJS from "crypto-js";
import "./App.css";

// React component for hybrid RSA-AES communication
const HybridEncryptor = () => {
  // React state hooks
  const [message, setMessage] = useState("");                        // Message input by user
  const [status, setStatus] = useState("");                          // Status of encryption/decryption or connection
  const [decryptedResponse, setDecryptedResponse] = useState("");    // Decrypted response from backend/admin
  const [encryptedResponseRaw, setEncryptedResponseRaw] = useState(""); // Encrypted response received from backend
  const [inputSize, setInputSize] = useState(0);                     // Byte size of user input (optional metric)
  const [adminHash, setAdminHash] = useState("");                    // Hash of admin message for integrity check

  // Generate and store a 256-bit AES key (32 bytes) in a ref (constant across renders)
  const keyRef = useRef(CryptoJS.lib.WordArray.random(32));

  // Setup WebSocket connection on component mount
  useEffect(() => {
    const socket = new WebSocket("ws://localhost:8000/ws");

    // WebSocket connection established
    socket.onopen = () => {
      console.log("WebSocket connected");
      setStatus("Connection established");
    };

    // Handle incoming WebSocket messages from admin
    socket.onmessage = (event) => {
      const data = event.data;
      if (data.startsWith("new-message:")) {
        const encryptedMsg = data.replace("new-message:", "");
        try {
          // Attempt to decrypt using AES key
          const decryptedMsg = decryptAES(encryptedMsg, keyRef.current);
          setDecryptedResponse(decryptedMsg);
          setStatus("New message from admin:");
          if (adminHash) {
          const localHash = CryptoJS.SHA256(decryptedMsg).toString();
          if (localHash !== adminHash) {
            console.warn("Hash mismatch! Message integrity compromised.");
            setStatus("⚠️ Integrity check failed (hash mismatch).");
          }
        }
        } catch (e) {
          console.error("Decryption error:", e);
          setStatus("Failed to decrypt WebSocket message.");
        }
      }
      else if (data.startsWith("admin-hash:")) {
        const hash = data.replace("admin-hash:", "");
        console.log("Received hash from server:", hash);
        setAdminHash(hash);  // Save hash for integrity check
      }
  };

    // Handle WebSocket error
    socket.onerror = (err) => {
      console.error("WebSocket error:", err);
      setStatus("WebSocket error");
    };

    // Handle WebSocket close event
    socket.onclose = () => {
      console.warn("WebSocket connection closed");
      setStatus("WebSocket disconnected");
    };

    // Cleanup on component unmount
    return () => {
      socket.close();
    };
  }, []);

  // Function to handle full hybrid encryption and communication flow
  const handleEncryptSendReceive = async () => {
    try {
      // Generate timestamp and nonce for integrity check
      const timestamp = Date.now().toString();
      const nonce = CryptoJS.lib.WordArray.random(16).toString();

      // Compute hash of message + timestamp + nonce for integrity
      const messagePayload = message + timestamp + nonce;
      const hash = CryptoJS.SHA256(messagePayload).toString();

      // Encrypt user message with AES (ECB mode + PKCS7 padding)
      const encrypted = CryptoJS.AES.encrypt(message, keyRef.current, {
        mode: CryptoJS.mode.ECB,
        padding: CryptoJS.pad.Pkcs7,
      });
      const encryptedData = CryptoJS.enc.Base64.stringify(encrypted.ciphertext);

      // Fetch RSA public key from backend
      const pubKeyRes = await fetch("http://localhost:8000/get-public-key/");
      const pubKeyJson = await pubKeyRes.json();
      const publicKeyPEM = pubKeyJson.public_key;

      // Convert PEM to ArrayBuffer and import it for use with WebCrypto API
      const importedKey = await window.crypto.subtle.importKey(
        "spki",
        pemToArrayBuffer(publicKeyPEM),
        { name: "RSA-OAEP", hash: "SHA-256" },
        true,
        ["encrypt"]
      );

      // Convert AES key (WordArray) to Uint8Array
      const keyBytes = wordArrayToUint8Array(keyRef.current);

      // Encrypt the AES key using RSA public key
      const encryptedAESKeyBuffer = await window.crypto.subtle.encrypt(
        { name: "RSA-OAEP" },
        importedKey,
        keyBytes
      );

      // Convert encrypted key to base64
      const encryptedKey = btoa(String.fromCharCode(...new Uint8Array(encryptedAESKeyBuffer)));

      // Send encrypted AES key, encrypted message, and integrity metadata to backend
      const response = await fetch("http://localhost:8000/decrypt/", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          encrypted_key: encryptedKey,
          encrypted_data: encryptedData,
          timestamp,
          nonce,
          hash,
        }),
      });

      const result = await response.json();

      if (!response.ok) throw new Error(result?.error || JSON.stringify(result));

      // Store encrypted admin response (for display/debug if needed)
      const encryptedResp = result.encrypted_response;
      setEncryptedResponseRaw(encryptedResp);

      // Decrypt admin response using original AES key
      const decryptedResp = decryptAES(encryptedResp, keyRef.current);
      setDecryptedResponse(decryptedResp);
      setStatus("Sent successfully");
    } catch (err) {
      console.error(err);
      setStatus("Error: " + err.message);
    }
  };

  // --- JSX UI ---
  return (
    <div className="container">
      <h2>Client Panel</h2>
      <div className="input-group">
        <input
          type="text"
          value={message}
          onChange={(e) => {
            setMessage(e.target.value);
            setInputSize(new TextEncoder().encode(e.target.value).length); // Track input size in bytes
          }}
          placeholder="Type anything to trigger AES key exchange"
          className="text-input"
        />
        <button onClick={handleEncryptSendReceive} className="send-button">
          Fetch Admin Message
        </button>
      </div>

      <div className="status">{status}</div>

      {decryptedResponse && (
        <>
          <h3>Admin message:</h3>
          <pre>{decryptedResponse}</pre>
        </>
      )}
    </div>
  );
};

// Utility function to convert PEM-formatted public key to ArrayBuffer
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

// Utility to convert CryptoJS WordArray to Uint8Array for use with WebCrypto
function wordArrayToUint8Array(wordArray) {
  const words = wordArray.words;
  const sigBytes = wordArray.sigBytes;
  const u8 = new Uint8Array(sigBytes);
  for (let i = 0; i < sigBytes; i++) {
    u8[i] = (words[i >>> 2] >>> (24 - (i % 4) * 8)) & 0xff;
  }
  return u8;
}

// Utility to decrypt AES-encrypted base64 string using CryptoJS
function decryptAES(base64CipherText, aesKeyWordArray) {
  const decrypted = CryptoJS.AES.decrypt(
    { ciphertext: CryptoJS.enc.Base64.parse(base64CipherText) },
    aesKeyWordArray,
    {
      mode: CryptoJS.mode.ECB,
      padding: CryptoJS.pad.Pkcs7,
    }
  );
  return decrypted.toString(CryptoJS.enc.Utf8);
}

export default HybridEncryptor;