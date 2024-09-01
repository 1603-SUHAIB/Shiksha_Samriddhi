from Crypto.Cipher import AES
import base64

AES_KEY = b'vV5KznJbWxR8rSC4'  # Ensure this is 16, 24, or 32 bytes long


def encrypt_password(password):
    try:
        cipher = AES.new(AES_KEY, AES.MODE_EAX)
        nonce = cipher.nonce
        ciphertext, tag = cipher.encrypt_and_digest(password.encode('utf-8'))

        # Combine nonce and ciphertext, then encode to base64
        encrypted_password = base64.b64encode(nonce + ciphertext).decode('utf-8')
        print(f"Encrypted Password: {encrypted_password}")
        return encrypted_password
    except Exception as e:
        print(f"Error encrypting password: {e}")
        return None


if __name__ == "__main__":
    test_password = "1234"
    encrypted_password = encrypt_password(test_password)
    print(f"Original: {test_password}")
    print(f"Encrypted: {encrypted_password}")
