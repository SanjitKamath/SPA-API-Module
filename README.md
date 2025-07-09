# SPA-API-Module

This project is a full-stack encrypted messaging system designed for secure communication between a client Single Page Application (SPA) and an admin backend. The repository contains both a Python backend (API) and a React+Vite frontend (SPA), along with a Streamlit-based admin dashboard.

---

## Features

### Backend (Python/FastAPI)
- **End-to-End Encryption:** Uses hybrid RSA/AES cryptography for secure message transfer.
- **FastAPI REST API:** Handles message encryption, decryption, and key exchange endpoints.
- **WebSocket Support:** Real-time communication for broadcast messages.
- **CORS Enabled:** Allows frontend apps to securely communicate with the API.
- **RSA Key Generation:** Dynamically generates RSA key pairs for each session.
- **Admin Message Broadcast:** Admin panel can push encrypted messages to all connected clients.
- **Health Check Endpoint:** Easily verify server status.

### Admin Panel (Streamlit)
- **Modern Web UI:** Built using Streamlit for easy admin access.
- **Send Encrypted Messages:** Admins can send messages to clients via the backend.
- **View Client Messages:** Real-time updates of the latest client message.

### Frontend (React + Vite)
- **Hybrid Encryption Flow:** Client generates an AES key, encrypts messages, and exchanges keys with the backend using RSA.
- **WebSocket Client:** Receives real-time encrypted messages from the server.
- **User-Friendly Interface:** Clean UI for sending/receiving encrypted messages.
- **CryptoJS Integration:** Client-side AES encryption/decryption.

---

## Project Structure

```
.
├── API/                  # Python FastAPI backend and Streamlit admin panel
│   ├── main.py           # FastAPI server implementation
│   ├── app.py            # Streamlit admin panel
│   ├── RSA_Key_Gen.py    # RSA key generation utility
├── SPA/                  # React + Vite frontend client
│   ├── package.json
│   ├── src/
│   │   ├── spa.jsx       # Main client logic
│   │   └── ...
│   └── ...
├── requirements.txt      # Python dependencies
└── README.md             # Project documentation (this file)
```

---

## Setup & Installation

### 1. Clone the Repository

```bash
git clone https://github.com/SanjitKamath/SPA-API-Module.git
cd SPA-API-Module
```

---

### 2. Backend Setup (API + Admin Panel)

#### a. Install Python Dependencies

```bash
pip install -r requirements.txt
```

#### b. Run the FastAPI Server

```bash
cd API
uvicorn main:app --reload
```
- The API will be available at: `http://localhost:8000`
- WebSocket endpoint: `ws://localhost:8000/ws`

#### c. Run the Streamlit Admin Panel

In a separate terminal:

```bash
cd API
streamlit run app.py
```
- The admin panel will open in your browser.

---

### 3. Frontend Setup (SPA Client)

#### a. Install Node.js Dependencies

```bash
cd SPA
npm install
```

#### b. Start the Development Server

```bash
npm run dev
```
- The client SPA will be available at: `http://localhost:5173` (or as indicated in your terminal).

---

## Usage Workflow

1. **Start the FastAPI backend and Streamlit admin panel.**
2. **Start the SPA client.**
3. **Client connects to backend and exchanges keys.**
4. **Admin sends a message via the dashboard.**
5. **Client receives encrypted messages in real time and can send encrypted responses.**
6. **All communication is encrypted using hybrid RSA/AES encryption.**

---

## Technology Stack

- **Backend:** Python, FastAPI, Cryptography, PyCryptodome
- **Admin Panel:** Streamlit
- **Frontend:** React, Vite, CryptoJS, WebSockets

---

## Security Notes

- All messages between client and backend are encrypted.
- RSA key pairs are generated for each server session.
- AES keys are exchanged securely via RSA.
- Ensure to run all parts locally or over HTTPS for production.

---

## License

This project is provided for educational and demonstration purposes. Please review the repository license for more information.

---

## Author

[Sanjit Kamath](https://github.com/SanjitKamath)
