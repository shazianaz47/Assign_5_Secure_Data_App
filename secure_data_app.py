import streamlit as st
import hashlib
import json
import time
from cryptography.fernet import Fernet
import base64


# initilize session state variables if they don't exist
if 'failed_attempts' not in st.session_state:
    st.session_state.failed_attempts = 0
if 'stored_data' not in st.session_state:
    st.session_state.stored_data = {}
if 'current_page' not in st.session_state:
    st.session_state.current_page = 'Home'
if 'last_attempt_time' not in st.session_state:
    st.session_state.last_attempt_time = 0

# Function to hash passkey
def hash_passkey(passkey):
    return hashlib.sha256(passkey.encode()).hexdigest()

# Function to generate a key from passkey(for encryption)
def generate_key_from_passkey(passkey):
    hashed = hashlib.sha256(passkey.encode()).digest()
    return base64.urlsafe_b64encode(hashed[:32])

#function to encrypt data
def encrypt_data(text, passkey):
    key = generate_key_from_passkey(passkey)
    cipher = Fernet(key)
    encrypted_data = cipher.encrypt(text.encode()).decode()
    return encrypted_data

#function to decrypt data
def decrypt_data(encrypted_text, passkey, data_id):
    try:
        #check if the passkey is correct
        hashed_passkey = hash_passkey(passkey)
        if data_id in st.session_state.stored_data and st.session_state.stored_data[data_id]['passkey'] == hashed_passkey:
            key = generate_key_from_passkey(passkey)
            cipher = Fernet(key)
            decrypted = cipher.decrypt(encrypted_text.encode()).decode()
            st.session_state.failed_attempts= 0
            return decrypted
        else:
            st.session_state.failed_attempts += 1
            st.session_state.last_attempt_time = time.time()
            return None
    except Exception as e:
        st.session_state.failed_attempts += 1
        st.session_state.last_attempt_time = time.time()
        return None
    
    # Function to generate a unique data ID
def generate_data_id():
    import uuid
    return str(uuid.uuid4())

    #Function to reset failed attempts
def reset_failed_attempts():
    st.session_state.failed_attempts = 0

    # Function to chage page
def change_page(page):
    st.session_state.current_page = page

    #Streamlit UI
st.title("Secure Data Eccryption App")

#Navigation
menu=["Home", "Store Data", "Retrieve Data", "Login"]
choice=st.sidebar.selectbox("Navigation",menu,index=menu.index(st.session_state.current_page))

#Updat e the current page based on selection
st.session_state.current_page = choice

#check if too many failed attempts
if st.session_state.failed_attempts >= 3:
    st.session_state.current_page = "Login"
    st.warning("Too many failed attempts. Please wait before trying again.")
   
# Display current page
if st.session_state.current_page == "Home":
    st.subheader("Welcome to the Secure Data Encryption App")
    st.write("This app allows you to securely store and retrieve data using encryption.")   

    col1,col2 = st.columns(2)
    with col1:
       if st.button("Store New Data",use_container_width=True):
           change_page("Store Data")
    with col2:
       if st.button("Retrieve Data",use_container_width=True):
           change_page("Retrieve Data")

# Display Store Data count
    st.info(f"Currently storing {len(st.session_state.stored_data)} encrypted data entries.")

elif st.session_state.current_page == "Store Data":
    st.subheader("Store Data Securely")
    user_data =st.text_area("Enter Data:")
    passkey = st.text_input("Enter Passkey:", type="password")
    confirmed_passkey = st.text_input("Confirm Passkey:", type="password")

    if st.button("Encrypt & Save"):
        if user_data and passkey and confirmed_passkey:
            if passkey != confirmed_passkey:
                st.error("Passkeys do not match.")
            else:
                data_id = generate_data_id()

            #Hash the passkey
                hashed_passkey = hash_passkey(passkey)

            #Encrypt the data
                encrypted_text=encrypt_data(user_data, passkey)

            #Store the encrypted data and passkey in session state
                st.session_state.stored_data[data_id] = {
                    'encrypted_text': encrypted_text,
                    'passkey': hashed_passkey
                }
                st.success(f"Data stored successfully with ID: {data_id}")
                       
            #Display the data ID for retrieval)
                st.code(data_id,language="text")
                st.info("save data ID ! you will need it to retrieve your data later.")
        else:
            st.error("Please fill in all fields.")
        
elif st.session_state.current_page == "Retrieve Data":
    st.subheader("Retrieve Data")
     
     #show attempts remaining
    attempts_remaining = 3 - st.session_state.failed_attempts
    st.info(f"Attempts remaining: {attempts_remaining}")

    data_id = st.text_input("Enter Data ID:")   
    passkey = st.text_input("Enter Passkey:", type="password")  

    if st.button("Decrypt"):
        if data_id and passkey:
            #Check if the data ID exists in session state
            if data_id in st.session_state.stored_data:
                encrypted_text = st.session_state.stored_data[data_id]['encrypted_text']
                #Decrypt the data using the passkey
                decrypted_text = decrypt_data(encrypted_text, passkey, data_id)
                
                if decrypted_text:
                    st.success("Decryption sucessful!")
                    st.markdown("### Your Decrypted Data:")
                    st.code(decrypted_text, language="text")
                else:
                    st.error("Incorrect passkey or data ID.")
            else:
                st.error("Data ID not found.")
            
            #Check if too many failed attempts after this attempt
            if st.session_state.failed_attempts >= 3:
                st.session_state.current_page = "Login"
                st.warning("Too many failed attempts. Please wait before trying again.")
                st.rerun()
        else:
            st.error("Please fill in all fields.")

elif st.session_state.current_page == "Login":
    st.subheader("Reauthorization required")

    #Add a simple time out mechanism
    if time.time()-st.session_state.last_attempt_time < 10 and st.session_state.failed_attempts >= 3:
      remaining_time = int(10 - (time.time()-st.session_state.last_attempt_time))
      st.warning(f"Please wait {remaining_time} seconds before trying again.")
    else:
        login_pass =st.text_input ("Enter Passkey:", type="password")

        if st.button("Login"):
            if login_pass == "admin123":
                st.success("Login successful!")
                st.session_state.current_page = "Home"
                reset_failed_attempts()
                st.rerun()
            else:
                st.error("Incorrect passkey. Please try again.")

# Add a footer
st.markdown("...")
st.markdown("**Secure Data Encryption App | Design-o-Pedia***")




                   


            





 