import os
import sys
import hashlib
import subprocess
import platform
import time
import shutil
import tempfile
import requests
import urllib.request
import zipfile
import io
from io import BytesIO


show_me = "VenomStrike - Malware Scanner by 5kidRo0t ver. 0.2\n"
script = os.path.dirname(os.path.abspath(__file__))
hashes_file = os.path.join(script, "modules/full_sha256.txt")

def download_and_extract_sha256(dest_folder):
    url = "https://bazaar.abuse.ch/export/txt/sha256/full/"
    print("The full_sha256.txt file was not found.")
    answer = input("Do you want to download it now so the tool can work properly? (y/n): ").strip().lower()
    if answer != 'y':
        print("The file was not downloaded. The tool will not work properly.")
        sys.exit(1)
    print("Downloading the file, please wait...")
    try:
        response = requests.get(url)
        response.raise_for_status()
        # The content comes as a ZIP, so we decompress it in memory
        with zipfile.ZipFile(BytesIO(response.content)) as z:
            # Extract the full_sha256.txt file into the destination folder
            z.extract("full_sha256.txt", path=dest_folder)
        print(f"File downloaded and extracted to {dest_folder}\n ")
        time.sleep(5)
    except Exception as e:
        print(f"[Error] Could not download or extract the file: {e}")
        sys.exit(1)

def update_script():
    print("[!] WARNING: This update will overwrite existing files.")
    confirm = input("Do you want to continue? [y/N]: ").strip().lower()
    if confirm != 'y':
        print("[*] Update cancelled.")
        sys.exit(0)
    print("[*] Downloading latest version...")
    repo_url = "https://github.com/5kidRo0t/VenomStrike/archive/refs/heads/main.zip"

    try:
        with urllib.request.urlopen(repo_url) as response:
            with zipfile.ZipFile(io.BytesIO(response.read())) as zip_file:
                temp_dir = tempfile.mkdtemp()
                zip_file.extractall(temp_dir)

                extracted_folder = os.path.join(temp_dir, "VenomStrike-main")
                current_dir = os.path.dirname(os.path.abspath(__file__))

                print("[*] Replacing current files...")

                for item in os.listdir(current_dir):
                    if item not in ["venomstrike.py", "__pycache__"]:  # keep the updater alive during overwrite
                        item_path = os.path.join(current_dir, item)
                        if os.path.isfile(item_path) or os.path.islink(item_path):
                            os.remove(item_path)
                        elif os.path.isdir(item_path):
                            shutil.rmtree(item_path)

                for item in os.listdir(extracted_folder):
                    src = os.path.join(extracted_folder, item)
                    dst = os.path.join(current_dir, item)
                    if os.path.isdir(src):
                        shutil.copytree(src, dst)
                    else:
                        shutil.copy2(src, dst)

                print("[+] Update completed successfully.")
                sys.exit(0)

    except Exception as e:
        print(f"[Error] Update failed: {e}")
        sys.exit(1)

def scan_with_yara_binary(yara_rules_folder, target_file):
    matches = []
    for rule_file in os.listdir(yara_rules_folder):
        if rule_file.endswith(".yara") or rule_file.endswith(".yar"):
            rule_path = os.path.join(yara_rules_folder, rule_file)
            try:
                result = subprocess.run(
                    ["yara", rule_path, target_file],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True
                )
                if result.stdout:
                    matches.append((rule_file, result.stdout.strip()))
                if result.stderr:
                    print(f"[!] Error in rule {rule_file}: {result.stderr.strip()}")
            except FileNotFoundError:
                print("[!] YARA binary not found. Install it with 'sudo apt install yara'")
                sys.exit(1)
    return matches

def clean_screen():
    cleaning = "cls" if platform.system() == "Windows" else "clear"
    subprocess.call(cleaning, shell=True)

def scanning_animation(file_path):
    print(f"[*] Scanning file: {file_path}", end="", flush=True)
    for _ in range(6):
        time.sleep(0.5)
        print(".", end="", flush=True)
    print("done!")

def show_help():
    print(f"Usage: python3 venomstrike.py [file path]\nExample: python3 venomstrike.py suspicious_file.exe")
    sys.exit(0)

def calculate_sha256(path):
    sha256 = hashlib.sha256()
    try:
        with open(path, 'rb') as f:
            for block in iter(lambda: f.read(4096), b""):
                sha256.update(block)
    except IOError as e:
        print(f"[Error] Could not open or read the file '{path}': {e}")
        sys.exit(1)
    return sha256.hexdigest()

def load_hashes(path):
    try:
        with open(path, 'r') as f:
            return set(line.strip().lower() for line in f if line.strip())
    except IOError as e:
        download_and_extract_sha256(os.path.dirname(path))
        # After download, try loading again
        with open(path, 'r') as f:
            return set(line.strip().lower() for line in f if line.strip())

def main():
    if len(sys.argv) != 2:
        show_help()

    file_path = sys.argv[1]

    if not os.path.isfile(file_path):
        print(f"[Error] File '{file_path}' does not exist or was not found.")
        sys.exit(1)

    file_hash = calculate_sha256(file_path)
    malicious_hashes = load_hashes(hashes_file)

    print(f"[*] SHA-256: {file_hash}")

    yara_rules_folder = os.path.join(script, "modules/yara_skido/")
    yara_matches = scan_with_yara_binary(yara_rules_folder, file_path)
    scanning_animation(file_path)

    if yara_matches:
        print(f"[!] YARA rules matched:")
        for rule_file, output in yara_matches:
            print(f"Rule '{rule_file}' matched: {output}")
    else:
        print("[+] No YARA rules matched.")
    
    if file_hash in malicious_hashes:
        print(f"[!] Match found by SHA-256 hash: {file_hash}")
    else:
        print(f"[+] No match found by SHA-256")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        show_help()

    if sys.argv[1].lower() == "update":
        update_script()
    clean_screen()
    print(show_me)
    main()
