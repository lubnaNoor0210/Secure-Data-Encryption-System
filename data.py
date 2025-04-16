import streamlit as st
import hashlib
from cryptography.fernet import Fernet

st.markdown("""
    <style>
    body {
        background-color: #ADD8E6;
    }
    .stApp {
        background-color: #ADD8E6;
    }
    </style>
    """, unsafe_allow_html=True)

if "failed_attempts" not in st.session_state:
    st.session_state.failed_attempts = 0

if "key" not in st.session_state:
    st.session_state.key = Fernet.generate_key()

if "stored_data" not in st.session_state:
    st.session_state.stored_data = None

if "login_mode" not in st.session_state:
    st.session_state.login_mode = False

if "is_logged_in" not in st.session_state:
    st.session_state.is_logged_in = False

cipher = Fernet(st.session_state.key)

def hash_passkey(passkey):
    return hashlib.sha256(passkey.encode()).hexdigest()

def encrypt_data(text):
    return cipher.encrypt(text.encode()).decode()

def decrypt_data(ciphertext):
    return cipher.decrypt(ciphertext.encode()).decode()

st.title("🛡️Secure Data Encryption System")

menu = ["Home", "Store Data", "Retrieve Data", "Login"]
choice = st.sidebar.selectbox("Navigation", menu)

if choice == "Home":
    st.markdown("<h2 style='text-align: center;'>Welcome</h2>", unsafe_allow_html=True)
    st.markdown("<div style='text-align: center;'>Securely <strong>store</strong> and <strong>retrieve</strong> encrypted data using a secret passkey.</div>", unsafe_allow_html=True)
    
    st.markdown("<br><br>", unsafe_allow_html=True)
    key_concepts = [
        "Session State Management", 
        "Fernet Encryption System", 
        "Password Security Mechanism", 
        "Authentication Flow Control", 
        "Key Generation Strategy"
    ]
    st.markdown('''
  <div style='
        background-color: #ADD8E6;
        color:  #032B44;
        padding: 10px;
        border-radius: 10px;
        border: 2px solid #FFA07A;
        font-weight: semi-bold;
        margin-top: 30 px;
    '>Key Concepts Used:</div>
''', unsafe_allow_html=True)
    for concept in key_concepts:
        st.markdown(f"• {concept}")

elif choice == "Store Data":
    st.subheader("📂 Store New Data")
    user_text = st.text_area("Enter your text:")
    passkey = st.text_input("Enter a secret passkey:", type="password")

    if st.button("Encrypt & Save"):
        if user_text and passkey:
            encrypted = encrypt_data(user_text)
            hashed_key = hash_passkey(passkey)
            st.session_state.stored_data = {
                "encrypted_text": encrypted,
                "passkey": hashed_key
            }
            st.success("✅ Your data has been encrypted and saved securely.")
        else:
            st.warning("Please enter both text and passkey.")

elif choice == "Retrieve Data":
    if st.session_state.login_mode and not st.session_state.is_logged_in:
        st.warning("🔐 You must login to continue after multiple failed attempts.")
        st.stop()

    st.subheader("🔍 Retrieve Your Stored Data")
    if not st.session_state.stored_data:
        st.info("No data stored yet. Please store data first.")
    else:
        passkey = st.text_input("Enter your passkey to decrypt:", type="password")

        if st.button("Decrypt"):
            entered_hash = hash_passkey(passkey)
            stored = st.session_state.stored_data

            if entered_hash == stored["passkey"]:
                decrypted = decrypt_data(stored["encrypted_text"])
                st.success(f"✅ Decrypted Data: {decrypted}")
                st.session_state.failed_attempts = 0
            else:
                st.session_state.failed_attempts += 1
                remaining = 3 - st.session_state.failed_attempts
                st.error(f"❌ Wrong passkey! Attempts remaining: {remaining}")

                if st.session_state.failed_attempts >= 3:
                    st.session_state.login_mode = True
                    st.warning("🚨 Too many failed attempts. Please login to continue.")
                    st.rerun()
elif choice == "Login":
    st.subheader("🔐 Login")
    username = st.text_input("Choose your Username:")
    password = st.text_input("Choose your Password:", type="password")

    if st.button("Login"):
        if username and password:
            st.success(f"✅ Welcome, {username}! You're now logged in.")
            st.session_state.is_logged_in = True
            st.session_state.login_mode = False
            st.session_state.failed_attempts = 0
        else:
            st.warning("Please enter both a username and a password.")
