import os
import sqlite3
import win32crypt  # Install via 'pip install pypiwin32'
import json
import base64
import shutil
from Crypto.Cipher import AES  # Install via 'pip install pycryptodome'

def list_chrome_profiles():
    base_path = os.path.join(os.environ['LOCALAPPDATA'], r"Google\Chrome\User Data")
    
    if not os.path.exists(base_path):
        print("Chrome User Data directory not found.")
        return []
    
    # List all profiles
    profiles = [d for d in os.listdir(base_path) if os.path.isdir(os.path.join(base_path, d)) and (d.startswith('Profile') or d == 'Default')]
    
    # Display profiles to user
    print("Available Chrome profiles:")
    for index, profile in enumerate(profiles, start=1):
        print(f"{index}. {profile}")
    
    return profiles

def get_selected_profile(profiles):
    # Prompt user to select a profile
    choice = input("Enter the number corresponding to the profile you want to access: ")
    
    try:
        profile_index = int(choice) - 1
        if profile_index < 0 or profile_index >= len(profiles):
            print("Invalid selection. Please try again.")
            return None
        return profiles[profile_index]
    except ValueError:
        print("Please enter a valid number.")
        return None

def get_chrome_cookies(profile, domain=None):
    # Chrome profile path
    db_path = os.path.join(os.environ['LOCALAPPDATA'], f"Google\\Chrome\\User Data\\{profile}\\Cookies")
    
    if not os.path.exists(db_path):
        print(f"No cookies database found for profile: {profile}")
        return {}
    
    # Make a temporary copy of the cookies database
    db_copy = db_path + "_copy"
    shutil.copyfile(db_path, db_copy)
    
    # Connect to the copied database and retrieve cookies
    conn = sqlite3.connect(db_copy)
    cursor = conn.cursor()
    
    query = "SELECT host_key, name, encrypted_value FROM cookies"
    if domain:
        query += " WHERE host_key LIKE ?"
        cursor.execute(query, ('%' + domain + '%',))
    else:
        cursor.execute(query)
    
    cookies = {}
    
    for host_key, name, encrypted_value in cursor.fetchall():
        # Decrypt the encrypted cookie value
        decrypted_value = decrypt_chrome_cookie(encrypted_value)
        if decrypted_value:
            cookies[name] = decrypted_value
    
    # Close the database and remove the temporary copy
    conn.close()
    os.remove(db_copy)
    
    return cookies

def decrypt_chrome_cookie(encrypted_value):
    try:
        # Trim the 'v10' prefix and decrypt using DPAPI
        if os.name == 'nt':
            decrypted_value = win32crypt.CryptUnprotectData(encrypted_value, None, None, None, 0)[1]
            return decrypted_value.decode('utf-8')
        else:
            # On non-Windows systems, use AES decryption
            key = get_chrome_aes_key()
            iv = encrypted_value[3:15]
            encrypted_value = encrypted_value[15:]
            cipher = AES.new(key, AES.MODE_GCM, iv)
            decrypted_value = cipher.decrypt(encrypted_value)[:-16].decode('utf-8')
            return decrypted_value
    except Exception as e:
        print("Failed to decrypt cookie:", e)
        return None

def get_chrome_aes_key():
    # Fetch AES key used by Chrome from Local State file
    local_state_path = os.path.join(os.environ['LOCALAPPDATA'], r"Google\Chrome\User Data\Local State")
    with open(local_state_path, 'r', encoding='utf-8') as f:
        local_state = json.load(f)
    
    encrypted_key = base64.b64decode(local_state['os_crypt']['encrypted_key'])[5:]
    key = win32crypt.CryptUnprotectData(encrypted_key, None, None, None, 0)[1]
    return key

# Main program flow
profiles = list_chrome_profiles()
if profiles:
    selected_profile = None
    while selected_profile is None:
        selected_profile = get_selected_profile(profiles)
    
    # Get cookies for selected profile
    domain = input("Enter the domain to filter cookies (or leave empty for all): ")
    cookies = get_chrome_cookies(selected_profile, domain if domain else None)
    print(f"Cookies for profile {selected_profile}:")
    for name, value in cookies.items():
        print(f"  {name}: {value}")
else:
    print("No Chrome profiles found.")
