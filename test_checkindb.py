from pymongo import MongoClient
from Crypto.Cipher import AES
import base64

# Set up MongoDB connection
client = MongoClient('mongodb://localhost:27017/')
db = client['institution_portal']
users = db['users']

AES_KEY = b'vV5KznJbWxR8rSC4'


def decrypt_password(encrypted_password):
    if encrypted_password is None:
        print("Error: Encrypted password is None.")
        return None
    try:
        encrypted_data = base64.b64decode(encrypted_password)
        nonce = encrypted_data[:16]
        ciphertext = encrypted_data[16:]
        cipher = AES.new(AES_KEY, AES.MODE_EAX, nonce=nonce)
        decrypted_password = cipher.decrypt(ciphertext).decode('utf-8')
        return decrypted_password
    except Exception as e:
        print(f"Error decrypting password: {e}")
        return None

def check_login(udise_code, password):
    user = users.find_one({'udise_code': udise_code})

    if user:
        encrypted_password_from_db = user['password']
        if encrypted_password_from_db is None:
            print("Error: No password found in the database.")
            return

        print(f"Encrypted password from DB: {encrypted_password_from_db}")
        decrypted_password = decrypt_password(encrypted_password_from_db)

        if decrypted_password is None:
            print("Error: Decryption failed.")
            return

        if decrypted_password == password:
            print("Login successful!")
            # Set session data, redirect to dashboard, etc.
        else:
            print("Invalid password.")
            # Handle failed login
    else:
        print("User not found.")
        # Handle user not found


# Example: Checking login
check_login('1234567890', '1234')
