import React, { useState, useEffect, useRef } from "react";
import CryptoJS from "crypto-js";
import "./App.css";

const HybridEncryptor = () => {
  const [message, setMessage] = useState("");
  const [status, setStatus] = useState("");
  const [decryptedResponse, setDecryptedResponse] = useState("");
  const [encryptedResponseRaw, setEncryptedResponseRaw] = useState("");
  const [inputSize, setInputSize] = useState(0);

  const keyRef = useRef(CryptoJS.lib.WordArray.random(32)); // AES-256 key

  useEffect(() => {
    const socket = new WebSocket("ws://localhost:8000/ws");

    socket.onopen = () => {
      console.log("WebSocket connected");
      setStatus("Connection established");
    };

    socket.onmessage = (event) => {
      const data = event.data;
      if (data.startsWith("new-message:")) {
        const encryptedMsg = data.replace("new-message:", "");
        try {
          const decryptedMsg = decryptAES(encryptedMsg, keyRef.current);
          setDecryptedResponse(decryptedMsg);
          setStatus("New message from admin:");
        } catch (e) {
          console.error("Decryption error:", e);
          setStatus("Failed to decrypt WebSocket message.");
        }
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
      socket.close();
    };
  }, []);

  const handleEncryptSendReceive = async () => {
    try {
      const hash = CryptoJS.SHA256(message).toString();

      const encrypted = CryptoJS.AES.encrypt(message, keyRef.current, {
        mode: CryptoJS.mode.ECB,
        padding: CryptoJS.pad.Pkcs7,
      });
      const encryptedData = CryptoJS.enc.Base64.stringify(encrypted.ciphertext);

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

      const keyBytes = wordArrayToUint8Array(keyRef.current);
      const encryptedAESKeyBuffer = await window.crypto.subtle.encrypt(
        { name: "RSA-OAEP" },
        importedKey,
        keyBytes
      );
      const encryptedKey = btoa(String.fromCharCode(...new Uint8Array(encryptedAESKeyBuffer)));

      const response = await fetch("http://localhost:8000/decrypt/", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          encrypted_key: encryptedKey,
          encrypted_data: encryptedData,
          hash: hash,
        }),
      });

      const result = await response.json();

      if (!response.ok) throw new Error(result?.detail || JSON.stringify(result));

      const encryptedResp = result.encrypted_response;
      setEncryptedResponseRaw(encryptedResp);

      const decryptedResp = decryptAES(encryptedResp, keyRef.current);
      setDecryptedResponse(decryptedResp);
      setStatus("Admin message received.");
    } catch (err) {
      console.error(err);
      setStatus("Error: " + err.message);
    }
  };

  return (
    <div className="container">
      <h2>Client Panel</h2>

      <div className="input-group">
        <input
          type="text"
          value={message}
          onChange={(e) => {
            setMessage(e.target.value);
            setInputSize(new TextEncoder().encode(e.target.value).length);
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

function wordArrayToUint8Array(wordArray) {
  const words = wordArray.words;
  const sigBytes = wordArray.sigBytes;
  const u8 = new Uint8Array(sigBytes);
  for (let i = 0; i < sigBytes; i++) {
    u8[i] = (words[i >>> 2] >>> (24 - (i % 4) * 8)) & 0xff;
  }
  return u8;
}

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
