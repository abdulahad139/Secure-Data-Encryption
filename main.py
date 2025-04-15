import streamlit as st
import hashlib
import json
import os
import time
from cryptography.fernet import Fernet
from base64 import urlsafe_b64encode
from hashlib import pbkdf2_hmac

# === Constants ===
DATA_FILE = "secure_data.json"
SALT = b"secure_salt_value"  # In production, this should be stored securely
LOCKOUT_DURATION = 60  # in seconds

# === Session State Initialization ===
if "authenticated_user" not in st.session_state:
    st.session_state.authenticated_user = None
if "failed_attempts" not in st.session_state:
    st.session_state.failed_attempts = 0
if "lockout_time" not in st.session_state:
    st.session_state.lockout_time = 0

# === Utility Functions ===

def load_data():
    if os.path.exists(DATA_FILE):
        with open(DATA_FILE, "r") as f:
            return json.load(f)
    return {}

def save_data(data):
    with open(DATA_FILE, "w") as f:
        json.dump(data, f)

def generate_key(passkey):
    # Derive a key using PBKDF2
    key = pbkdf2_hmac('sha256', passkey.encode(), SALT, 100000)
    return urlsafe_b64encode(key)

def hash_password(password):
    return hashlib.pbkdf2_hmac('sha256', password.encode(), SALT, 100000).hex()

def encrypt_text(text, key):
    cipher = Fernet(generate_key(key))
    return cipher.encrypt(text.encode()).decode()

def decrypt_text(encrypted_text, key):
    try:
        cipher = Fernet(generate_key(key))
        return cipher.decrypt(encrypted_text.encode()).decode()
    except:
        return None

# === Load stored data from JSON ===
stored_data = load_data()

# === Navigation ===
st.title("🔐 Secure Multi-User Data System")
menu = ["Home", "Register", "Login", "Store Data", "Retrieve Data"]
choice = st.sidebar.selectbox("Navigation", menu)

# === Home ===
if choice == "Home":
    st.subheader("🏠 Welcome!")
    st.markdown("Securely store & retrieve your data with encryption. Each user has their own protected data.")
    st.info("How to use this app:")
    st.markdown("""
    1. Register a new account
    2. Login with your credentials
    3. Store your sensitive data with a passkey
    4. Retrieve and decrypt your data when needed
    """)

# === Register ===
elif choice == "Register":
    st.subheader("📝 Register New User")
    username = st.text_input("Choose Username")
    password = st.text_input("Choose Password", type="password")

    if st.button("Register"):
        if username and password:
            if username in stored_data:
                st.warning("⚠️ Username already exists.")
            else:
                stored_data[username] = {
                    "password": hash_password(password),
                    "data": []
                }
                save_data(stored_data)
                st.success("✅ User registered successfully!")
        else:
            st.error("Both fields are required.")

# === Login ===
elif choice == "Login":
    st.subheader("🔑 User Login")
    
    # Lockout check
    if time.time() < st.session_state.lockout_time:
        remaining = int(st.session_state.lockout_time - time.time())
        st.error(f"⏳ Too many failed attempts. Please wait {remaining} seconds.")
        st.stop()

    username = st.text_input("Username")
    password = st.text_input("Password", type="password")

    if st.button("Login"):
        if username in stored_data and stored_data[username]["password"] == hash_password(password):
            st.session_state.authenticated_user = username
            st.session_state.failed_attempts = 0
            st.success(f"✅ Welcome {username}!")
        else:
            st.session_state.failed_attempts += 1
            remaining = 3 - st.session_state.failed_attempts
            st.error(f"❌ Invalid credentials! Attempts left: {remaining}")

            if st.session_state.failed_attempts >= 3:
                st.session_state.lockout_time = time.time() + LOCKOUT_DURATION
                st.error("🔒 Too many failed attempts. Locked for 60 seconds.")
                st.stop()

# === Store Data ===
elif choice == "Store Data":
    if not st.session_state.authenticated_user:
        st.warning("🔒 Please login first.")
    else:
        st.subheader("📦 Store Encrypted Data")
        data = st.text_area("Enter data to encrypt")
        passkey = st.text_input("Encryption Key (passphrase)", type="password")
        
        if st.button("Encrypt & Save"):
            if data and passkey:
                encrypted = encrypt_text(data, passkey)
                stored_data[st.session_state.authenticated_user]["data"].append(encrypted)
                save_data(stored_data)
                st.success("✅ Data encrypted and saved!")
            else:
                st.error("All fields are required.")

# === Retrieve Data ===
elif choice == "Retrieve Data":
    if not st.session_state.authenticated_user:
        st.warning("🔒 Please login first.")
    else:
        st.subheader("🔎 Retrieve Data")
        user_data = stored_data.get(st.session_state.authenticated_user, {}).get("data", [])

        if not user_data:
            st.info("ℹ️ No data found.")
        else:
            st.write(f"🔐 You have {len(user_data)} encrypted data entries:")
            
            # Display entries with indexes for better reference
            for i, item in enumerate(user_data):
                st.text(f"Entry #{i+1}")
                st.code(item[:50] + "..." if len(item) > 50 else item, language="text")
                st.write("")

            # Allow user to select which entry to decrypt
            entry_index = st.number_input("Select entry number to decrypt", 
                                        min_value=1, 
                                        max_value=len(user_data), 
                                        value=1)
            
            selected_entry = user_data[entry_index-1]
            st.text_area("Selected encrypted text", value=selected_entry, height=100, disabled=True)
            
            passkey = st.text_input("Enter Passkey to Decrypt", type="password")

            if st.button("Decrypt"):
                result = decrypt_text(selected_entry, passkey)
                if result:
                    st.success("✅ Successfully decrypted!")
                    st.text_area("Decrypted content", value=result, height=150)
                else:
                    st.error("❌ Incorrect passkey or corrupted data.")

