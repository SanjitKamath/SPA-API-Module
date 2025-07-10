import React, { useEffect, useRef, useState } from "react";
import CryptoJS from "crypto-js";

// Utility functions for PEM and ArrayBuffer conversion
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

// GCM encryption using WebCrypto API
async function encryptAESGCM(plaintext, key) {
  const iv = window.crypto.getRandomValues(new Uint8Array(12));
  const enc = new TextEncoder();
  const encrypted = await window.crypto.subtle.encrypt(
    {
      name: "AES-GCM",
      iv: iv,
    },
    key,
    enc.encode(plaintext)
  );
  const combined = new Uint8Array(iv.length + encrypted.byteLength);
  combined.set(iv, 0);
  combined.set(new Uint8Array(encrypted), iv.length);
  return btoa(String.fromCharCode(...combined));
}

// GCM decryption using WebCrypto API
async function decryptAESGCM(base64CipherText, key) {
  const combined = Uint8Array.from(atob(base64CipherText), (c) => c.charCodeAt(0));
  const iv = combined.slice(0, 12);
  const ciphertext = combined.slice(12);
  const decrypted = await window.crypto.subtle.decrypt(
    {
      name: "AES-GCM",
      iv: iv,
    },
    key,
    ciphertext
  );
  return new TextDecoder().decode(decrypted);
}

const HybridEncryptor = () => {
  const [message, setMessage] = useState("");
  const [status, setStatus] = useState("WebSocket disconnected");
  const [decryptedResponse, setDecryptedResponse] = useState("");
  const aesCryptoKeyRef = useRef(null);
  
  // Refs to track state without causing re-renders
  const lastAdminMessageRef = useRef({ message: "", hash: "" });
  const adminHashRef = useRef("");

  // Setup WebSocket connection - runs only once
  useEffect(() => {
    const socket = new WebSocket("ws://localhost:8000/ws");

    socket.onopen = () => {
      console.log("WebSocket connected");
      setStatus("Connection established");
    };

    socket.onmessage = async (event) => {
      const data = event.data;
      if (data.startsWith("new-message:")) {
        const encryptedMsg = data.replace("new-message:", "").trim();
        try {
          if (!aesCryptoKeyRef.current) {
            setStatus("No AES key for decryption");
            return;
          }
          const decryptedMsg = await decryptAESGCM(encryptedMsg, aesCryptoKeyRef.current);
          
          // Store message and hash for verification
          const localHash = CryptoJS.SHA256(decryptedMsg).toString();
          lastAdminMessageRef.current = { 
            message: decryptedMsg, 
            hash: localHash 
          };
          
          setDecryptedResponse(decryptedMsg);
          
          // Verify against stored admin hash
          if (adminHashRef.current && adminHashRef.current === localHash) {
            setStatus("New message from admin (✔ hash verified)");
          } else {
            setStatus("New message from admin (awaiting verification)");
          }
        } catch (e) {
          console.error("Decryption error:", e);
          setStatus("Failed to decrypt WebSocket message.");
        }
      } else if (data.startsWith("admin-hash:")) {
        const hash = data.replace("admin-hash:", "").trim();
        adminHashRef.current = hash;
        
        // Verify against last message
        if (lastAdminMessageRef.current.hash === hash) {
          setStatus("New message from admin (✔ hash verified)");
        }
      } else if (data.startsWith("new-client-message:")) {
        const clientMsg = data.replace("new-client-message:", "").trim();
        setDecryptedResponse(clientMsg);
        setStatus("New client message received");
      }
    };

    socket.onerror = (err) => {
      console.error("WebSocket error:", err);
      setStatus("WebSocket error");
    };

    socket.onclose = () => {
      console.warn("WebSocket connection closed");
      setStatus("WebSocket disconnected");
    };

    return () => {
      if (socket.readyState === WebSocket.OPEN) {
        socket.close();
      }
    };
  }, []); // Empty dependency array = runs only once

  // Hybrid encryption handler
  const handleEncryptSendReceive = async () => {
    try {
      // Generate AES key
      const aesKey = await window.crypto.subtle.generateKey(
        { name: "AES-GCM", length: 256 },
        true,
        ["encrypt", "decrypt"]
      );
      aesCryptoKeyRef.current = aesKey;

      // Export raw key
      const keyBuffer = await window.crypto.subtle.exportKey("raw", aesKey);

      // Fetch RSA public key
      const pubKeyRes = await fetch("http://localhost:8000/get-public-key/");
      const pubKeyJson = await pubKeyRes.json();
      const publicKeyPEM = pubKeyJson.public_key;
      const importedKey = await window.crypto.subtle.importKey(
        "spki",
        pemToArrayBuffer(publicKeyPEM),
        { name: "RSA-OAEP", hash: "SHA-256" },
        true,
        ["encrypt"]
      );

      // Encrypt AES key with RSA
      const encryptedAESKeyBuffer = await window.crypto.subtle.encrypt(
        { name: "RSA-OAEP" },
        importedKey,
        keyBuffer
      );
      const encryptedKey = btoa(String.fromCharCode(...new Uint8Array(encryptedAESKeyBuffer)));

      // Encrypt message with AES-GCM
      const encryptedData = await encryptAESGCM(message, aesKey);

      // Prepare integrity metadata
      const timestamp = Date.now().toString();
      const nonce = CryptoJS.lib.WordArray.random(16).toString();
      const messagePayload = message + timestamp + nonce;
      const hash = CryptoJS.SHA256(messagePayload).toString();

      // Send to backend
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

      // Decrypt admin response
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
      
      <div className="status-indicator">
        {status}
      </div>
      
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