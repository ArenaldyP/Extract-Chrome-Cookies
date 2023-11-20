import os
import json
import base64
import sqlite3
import shutil
from datetime import datetime, timedelta
import win32crypt  # pip install pypiwin32
from Crypto.Cipher import AES  # pip install pycryptodome

def get_chrome_datetime(chromedate):
    """Mengembalikan objek `datetime.datetime` dari format waktu Chrome.
    Karena `chromedate` diformat sebagai jumlah mikrodetik sejak
    Januari 1601"""
    if chromedate != 86400000000 and chromedate:
        try:
            return datetime(1601, 1, 1) + timedelta(microseconds=chromedate)
        except Exception as e:
            print(f"Error: {e}, chromedate: {chromedate}")
            return chromedate
    else:
        return ""

def get_encryption_key():
    local_state_path = os.path.join(os.environ["USERPROFILE"],
                                    "AppData", "Local", "Google", "Chrome",
                                    "User Data", "Local State")
    with open(local_state_path, "r", encoding="UTF-8") as f:
        local_state = f.read()
        local_state = json.loads(local_state)

    key = base64.b64decode(local_state["os_crypt"]["encrypted_key"])
    key = key[5:]
    return win32crypt.CryptUnprotectData(key, None, None, None, 0)[1]

def decrypt_data(data, key):
    try:
        iv = data[3:15]
        data = data[15:]
        cipher = AES.new(key, AES.MODE_GCM, iv)
        return cipher.decrypt(data)[:-16].decode()
    except:
        try:
            return str(win32crypt.CryptUnprotectData(data, None, None, None, 0)[1])
        except:
            return ""

def main():
    # Path database kuki Chrome lokal
    db_path = os.path.join(os.environ["USERPROFILE"], "AppData",
                           "Local", "Google", "Chrome", "User Data", "Default",
                           "Network", "Cookies")
    # File tujuan di direktori saat ini
    # karena database akan terkunci jika Chrome sedang terbuka
    filename = "Cookies.db"

    try:
        if not os.path.isfile(filename):
            # Salin file jika tidak ada di direktori saat ini
            shutil.copyfile(db_path, filename)

        # Sambungkan ke database
        db = sqlite3.connect(filename)
        # Abaikan kesalahan dekoding
        db.text_factory = lambda b: b.decode(errors="ignore")
        cursor = db.cursor()

        # Ambil kuki dari tabel `Cookies`
        cursor.execute("""
        SELECT host_key, name, value, creation_utc, last_access_utc,
        expires_utc, encrypted_value
        FROM Cookies""")

        # Dapatkan kunci AES
        key = get_encryption_key()
        for host_key, name, value, creation_utc, last_access_utc, expires_utc, encrypted_value in cursor.fetchall():
            if not value:
                decrypted_value = decrypt_data(encrypted_value, key)
            else:
                # Sudah didekripsi
                decrypted_value = value
            print(f""
                  f"Host : {host_key}\n"
                  f"Cookie Name : {name}\n"
                  f"Cookie Value(decrypted) : {decrypted_value}\n"
                  f"Creation Datetime(UTC): {get_chrome_datetime(creation_utc)}\n"
                  f"Last Access Datetime(UTC) : {get_chrome_datetime(last_access_utc)}\n"
                  f"Expires Datetime (UTC) : {get_chrome_datetime(expires_utc)}\n"
                  f"========================================================================================")

            # Perbarui tabel kuki dengan nilai yang sudah didekripsi
            # dan buat kuki sesi agar persisten
            cursor.execute("""
            UPDATE Cookies SET value = ?, has_expires = 1, expires_utc = 99999999999999999,
            is_persistent = 1, is_secure = 0
            WHERE host_key = ?
            AND name = ?""", (decrypted_value, host_key, name))

        # Terapkan perubahan
        db.commit()
        # Tutup koneksi
        db.close()

    except PermissionError as e:
        print(f"IzinError: {e}")

if __name__ == "__main__":
    main()
