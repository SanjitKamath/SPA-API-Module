import streamlit as st
import streamlit.components.v1 as components

st.set_page_config(page_title="Admin Panel", layout="centered")
st.title("🔐 Admin Message Sender")

# Placeholder for the message
client_message = st.empty()

# Insert custom JS for WebSocket handling
components.html(f"""
<script>
const ws = new WebSocket("ws://localhost:8000/ws");

ws.onmessage = (event) => {{
    const data = event.data;
    
    if (data.startsWith("new-client-message:")) {{
        const msg = data.replace("new-client-message:", "");
        const msgBox = window.parent.document.querySelectorAll('pre');
        if (msgBox.length > 0) {{
            msgBox[0].textContent = msg;
        }}
    }}
}};
</script>
""", height=0)

# Initial client message
client_message.subheader("📩 Latest Client Message (Decrypted)")
client_message.code("Waiting for client message...", language="text")

# --- Static admin message input ---
st.subheader("✉️ Send Message to Client (React App)")

admin_message = st.text_area(
    "Enter message to send to frontend:",
    value=st.session_state.get("admin_message", ""),
    key="admin_message_input"
)

if st.button("Send Message to Client"):
    if not admin_message.strip():
        st.warning("Please enter a message before sending.")
    else:
        try:
            import requests
            res = requests.post(
                "http://localhost:8000/encrypt-message",
                data={"server_message": admin_message}
            )
            if res.ok:
                st.success("✅ Message submitted to backend successfully!")
                st.session_state.admin_message = ""
            else:
                st.error("❌ Failed to send message.")
        except Exception as e:
            st.error(f"❌ Backend error: {e}")
