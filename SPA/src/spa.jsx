import React, { useEffect, useRef, useState } from "react";
import CryptoJS from "crypto-js";

// Converts a PEM-encoded RSA public key into an ArrayBuffer for Web Crypto API usage
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

// Encrypts plaintext using AES-GCM and returns base64-encoded result
async function encryptAESGCM(plaintext, key) {
  const iv = window.crypto.getRandomValues(new Uint8Array(12)); // 96-bit IV for GCM
  const enc = new TextEncoder();
  const encrypted = await window.crypto.subtle.encrypt(
    {
      name: "AES-GCM",
      iv: iv,
    },
    key,
    enc.encode(plaintext)
  );

  // Combine IV + ciphertext into one buffer for transport
  const combined = new Uint8Array(iv.length + encrypted.byteLength);
  combined.set(iv, 0);
  combined.set(new Uint8Array(encrypted), iv.length);

  return btoa(String.fromCharCode(...combined)); // Encode to base64 for transmission
}

// Decrypts base64-encoded AES-GCM ciphertext
async function decryptAESGCM(base64CipherText, key) {
  const combined = Uint8Array.from(atob(base64CipherText), (c) => c.charCodeAt(0));
  const iv = combined.slice(0, 12); // Extract IV
  const ciphertext = combined.slice(12); // Extract ciphertext
  const decrypted = await window.crypto.subtle.decrypt(
    {
      name: "AES-GCM",
      iv: iv,
    },
    key,
    ciphertext
  );
  return new TextDecoder().decode(decrypted); // Return UTF-8 plaintext
}

const HybridEncryptor = () => {
  const [message, setMessage] = useState(""); // User input
  const [status, setStatus] = useState("WebSocket disconnected"); // Status messages
  const [decryptedResponse, setDecryptedResponse] = useState(""); // Admin response
  const aesCryptoKeyRef = useRef(null); // AES key reference (in-memory session key)
  
  // Keep track of last decrypted message and its hash without triggering re-renders
  const lastAdminMessageRef = useRef({ message: "", hash: "" });
  const adminHashRef = useRef(""); // Latest admin hash received

  // Establish WebSocket connection on mount
  useEffect(() => {
    const socket = new WebSocket("ws://localhost:8000/ws");

    // Connection established
    socket.onopen = () => {
      console.log("WebSocket connected");
      setStatus("Connection established");
    };

    // Handle incoming WebSocket messages
    socket.onmessage = async (event) => {
      const data = event.data;

      // Case 1: Received new encrypted admin message
      if (data.startsWith("new-message:")) {
        const encryptedMsg = data.replace("new-message:", "").trim();
        try {
          if (!aesCryptoKeyRef.current) {
            setStatus("No AES key for decryption");
            return;
          }

          // Decrypt the message using stored AES key
          const decryptedMsg = await decryptAESGCM(encryptedMsg, aesCryptoKeyRef.current);
          
          // Hash the decrypted message for later verification
          const localHash = CryptoJS.SHA256(decryptedMsg).toString();
          lastAdminMessageRef.current = { 
            message: decryptedMsg, 
            hash: localHash 
          };
          
          setDecryptedResponse(decryptedMsg);

          // Compare with previously received admin hash for integrity verification
          if (adminHashRef.current && adminHashRef.current === localHash) {
            setStatus("New message from admin (✔ hash verified)");
          } else {
            setStatus("New message from admin (awaiting verification)");
          }
        } catch (e) {
          console.error("Decryption error:", e);
          setStatus("Failed to decrypt WebSocket message.");
        }

      // Case 2: Received hash of admin message
      } else if (data.startsWith("admin-hash:")) {
        const hash = data.replace("admin-hash:", "").trim();
        adminHashRef.current = hash;

        // Compare with last decrypted message's hash
        if (lastAdminMessageRef.current.hash === hash) {
          setStatus("New message from admin (✔ hash verified)");
        }

      // Case 3: Received new plaintext message from another client
      } else if (data.startsWith("new-client-message:")) {
        const clientMsg = data.replace("new-client-message:", "").trim();
        setDecryptedResponse(clientMsg);
        setStatus("New client message received");
      }
    };

    // Handle errors
    socket.onerror = (err) => {
      console.error("WebSocket error:", err);
      setStatus("WebSocket error");
    };

    // Handle connection close
    socket.onclose = () => {
      console.warn("WebSocket connection closed");
      setStatus("WebSocket disconnected");
    };

    // Cleanup function to close WebSocket on unmount
    return () => {
      if (socket.readyState === WebSocket.OPEN) {
        socket.close();
      }
    };
  }, []); // Run only once on mount

  // Handles AES key generation, hybrid encryption, and secure message sending
  const handleEncryptSendReceive = async () => {
    try {
      // Step 1: Generate AES-GCM symmetric key
      const aesKey = await window.crypto.subtle.generateKey(
        { name: "AES-GCM", length: 256 },
        true,
        ["encrypt", "decrypt"]
      );
      aesCryptoKeyRef.current = aesKey;

      // Step 2: Export AES key into raw binary format
      const keyBuffer = await window.crypto.subtle.exportKey("raw", aesKey);

      // Step 3: Fetch server’s RSA public key
      const pubKeyRes = await fetch("http://localhost:8000/get-public-key/");
      const pubKeyJson = await pubKeyRes.json();
      const publicKeyPEM = pubKeyJson.public_key;

      // Step 4: Import RSA public key for encryption
      const importedKey = await window.crypto.subtle.importKey(
        "spki",
        pemToArrayBuffer(publicKeyPEM),
        { name: "RSA-OAEP", hash: "SHA-256" },
        true,
        ["encrypt"]
      );

      // Step 5: Encrypt AES key with RSA-OAEP
      const encryptedAESKeyBuffer = await window.crypto.subtle.encrypt(
        { name: "RSA-OAEP" },
        importedKey,
        keyBuffer
      );
      const encryptedKey = btoa(String.fromCharCode(...new Uint8Array(encryptedAESKeyBuffer)));

      // Step 6: Encrypt the user message with AES-GCM
      const encryptedData = await encryptAESGCM(message, aesKey);

      // Step 7: Generate integrity metadata (timestamp + nonce + hash)
      const timestamp = Date.now().toString();
      const nonce = CryptoJS.lib.WordArray.random(16).toString();
      const messagePayload = message + timestamp + nonce;
      const hash = CryptoJS.SHA256(messagePayload).toString();

      // Step 8: Send all encrypted data + metadata to server
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

      // Step 9: Decrypt server’s response with same AES key
      const decryptedResp = await decryptAESGCM(result.encrypted_response, aesKey);
      setDecryptedResponse(decryptedResp);
      setStatus("Sent successfully");
    } catch (err) {
      console.error(err);
      setStatus("Error: " + err.message);
    }
  };

  return (
    <div className="panel-container">
      <h1>Client Panel</h1>

      {/* Input for user message */}
      <div className="input-section">
        <input
          type="text"
          value={message}
          onChange={(e) => setMessage(e.target.value)}
          placeholder="Type anything to trigger AES key exchange"
          className="text-input"
        />
        <button onClick={handleEncryptSendReceive} className="action-button">
          Fetch Admin Message
        </button>
      </div>

      {/* Display connection/status info */}
      <div className="status-indicator">
        {status}
      </div>

      {/* Display decrypted message if available */}
      {decryptedResponse && (
        <div className="message-container">
          <h3>Admin message:</h3>
          <div className="message-content">
            {decryptedResponse}
          </div>
        </div>
      )}
    </div>
  );
};

export default HybridEncryptor;
