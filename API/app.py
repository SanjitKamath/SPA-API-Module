# streamlit_admin_panel.py

import streamlit as st
import streamlit.components.v1 as components

# Set Streamlit page metadata and layout
st.set_page_config(page_title="Admin Panel", layout="centered")
st.title("Admin Panel")

# Placeholder for displaying messages from the client in real time
client_message = st.empty()

# Embed custom JavaScript for listening to WebSocket messages from FastAPI backend
components.html(f"""
<script>
// Establish a WebSocket connection to the FastAPI backend
const ws = new WebSocket("ws://localhost:8000/ws");

// Listen for incoming messages on the WebSocket
ws.onmessage = (event) => {{
    const data = event.data;

    // Check if the message is from the client
    if (data.startsWith("new-client-message:")) {{
        // Extract the actual message
        const msg = data.replace("new-client-message:", "");

        // Update the first <pre> element inside Streamlit iframe with the new message
        const msgBox = window.parent.document.querySelectorAll('pre');
        if (msgBox.length > 0) {{
            msgBox[0].textContent = msg;
        }}
    }}
}};
</script>
""", height=0)  # height=0 to hide the HTML component itself

# --- Static UI to display the latest client message ---
client_message.subheader("Latest Client Message")
client_message.code("Waiting for client message...", language="text")

# --- Admin input section to send message to the client ---
st.subheader("Send Message to Client")

# Text area for the admin to input their message
admin_message = st.text_area(
    "Enter message to send to frontend:",
    value=st.session_state.get("admin_message", ""),  # Restore previous input from session state
    key="admin_message_input"
)

# Submit button to send message
if st.button("Send Message to Client"):
    if not admin_message.strip():
        st.warning("Please enter a message before sending.")
    else:
        try:
            # Make a POST request to the FastAPI backend to encrypt and broadcast the message
            import requests
            res = requests.post(
                "http://localhost:8000/encrypt-message",
                data={"server_message": admin_message}
            )
            if res.ok:
                st.success("Message sent")
                st.session_state.admin_message = ""  # Clear message from session state after sending
            else:
                st.error("Failed to send message.")
        except Exception as e:
            # Display any connection or backend-related errors
            st.error(f"Backend error: {e}")
