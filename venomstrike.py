# VenomStrike - Malware scanner
# Copyright (c) 2025 5kidRo0t
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program. If not, see <https://www.gnu.org/licenses/>.

import threading
import os
import sys
import hashlib
import subprocess
import platform
import time
import requests
import zipfile
import io
import argparse
from io import BytesIO

show_me = "▗▖  ▗▖▗▞▀▚▖▄▄▄▄   ▄▄▄  ▄▄▄▄   ▗▄▄▖ ■   ▄▄▄ ▄ █  ▄ ▗▞▀▚▖    \n▐▌  ▐▌▐▛▀▀▘█   █ █   █ █ █ █ ▐▌ ▗▄▟▙▄▖█    ▄ █▄▀  ▐▛▀▀▘    \n▐▌  ▐▌▝▚▄▄▖█   █ ▀▄▄▄▀ █   █  ▝▀▚▖▐▌  █    █ █ ▀▄ ▝▚▄▄▖    \n ▝▚▞▘                        ▗▄▄▞▘▐▌       █ █  █          \n                                  ▐▌                       \n----------------------------------------------------------\nVenomStrike - Malware Scanner by 5kidRo0t ver. 1.1\n----------------------------------------------------------\n"
script = os.path.dirname(os.path.abspath(__file__))
hashes_file = os.path.join(script, "modules/full_sha256.txt")
hashes_file_2 = os.path.join(script, "modules/full_md5.txt")
md5_flag = os.path.join(script, ".md5_prompted.flag")

class CustomArgumentParser(argparse.ArgumentParser):
    def error(self, message):
        clean_screen()
        print(show_me)
        print(f"[ERROR] {message}\n")
        self.print_help()
        print("\nExample: python3 venomstrike.py suspicious.exe")
        sys.exit(2)

def parse_args():
    parser = CustomArgumentParser(description="VenomStrike - Malware Scanner")
    parser.add_argument("file", nargs="?", help="Path to the file to scan")
    parser.add_argument("-md5", action="store_true", help="Download and use optional MD5 hash check")
    parser.add_argument("-update", action="store_true", help="Force re-download of hash databases")
    return parser.parse_args()

def download_and_extract_md5(dest_folder):
    url = "https://bazaar.abuse.ch/export/txt/md5/full/"
    stop_event = threading.Event()
    loader_thread = threading.Thread(target=downloading_animation, args=(stop_event,))
    loader_thread.start()

    try:
        response = requests.get(url)
        response.raise_for_status()
        with zipfile.ZipFile(BytesIO(response.content)) as z:
            z.extract("full_md5.txt", path=dest_folder)
        stop_event.set()
        loader_thread.join()
        print(f"File downloaded and extracted to {dest_folder}\n ")
        time.sleep(5)
        clean_screen()
        print(show_me)
    except Exception as e:
        stop_event.set()
        loader_thread.join()
        print(f"[Error] Could not download or extract the file: {e}")
        sys.exit(1)

def download_and_extract_sha256(dest_folder):
    url = "https://bazaar.abuse.ch/export/txt/sha256/full/"
    print("The full_sha256.txt file was not found.")
    answer = input("Do you want to download it now so the tool can work properly? (y/n): ").strip().lower()

    backup_path = os.path.join(dest_folder, "backup_sha256.txt")

    if answer != 'y':
        print("The file was not downloaded.")
        if os.path.exists(backup_path):
            print("[+] Using local backup file (backup_sha256.txt).")
            return
        else:
            print("[!] No backup file found. The tool cannot continue without hashes.")
            sys.exit(1)
    stop_event = threading.Event()
    loader_thread = threading.Thread(target=downloading_animation, args=(stop_event,))
    loader_thread.start()

    try:
        response = requests.get(url)
        response.raise_for_status()
        with zipfile.ZipFile(BytesIO(response.content)) as z:
            z.extract("full_sha256.txt", path=dest_folder)
        stop_event.set()
        loader_thread.join()
        print(f"File downloaded and extracted to {dest_folder}\n ")
        time.sleep(2)
        clean_screen()
        print(show_me)
        md5_path = os.path.join(dest_folder, "full_md5.txt")
        if not os.path.exists(md5_path):
            md5_answer = input("Do you also want to download the optional MD5 hash database? (y/n): ").strip().lower()
            if md5_answer == 'y':
                download_and_extract_md5(dest_folder)
            else:
                with open(md5_flag, 'w') as f:
                    f.write("User Declined MD5 download.\n")
                print("The MD5 database was not downloaded.\n")

    except Exception as e:
        stop_event.set()
        loader_thread.join()
        print(f"[Error] Could not download or extract the file: {e}")
        if os.path.exists(backup_path):
            print("[+] Using local backup file (backup_sha256.txt).")
            time.sleep(2)
            clean_screen()
            print(show_me)
            return
        else:
            print("[!] No backup file found. The tool cannot continue without hashes.")
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
                if result.returncode not in (0, 1):
                    print(f"[!] YARA execution failed on rule {rule_file}. Code: {result.returncode}")
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
    print("done!\n \n>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>")

def downloading_animation(stop_event):
    chars ="|/-\\"
    idx = 0
    while not stop_event.is_set():
        print(f"\rDownloading the file, please wait... {chars[idx % len(chars)]}", end="", flush=True)
        idx += 1
        time.sleep(0.1)
    print("\rDownload completed.                                ")

def show_help():
    clean_screen()
    print(f"Usage: python3 venomstrike.py [file path]\nExample: python3 venomstrike.py suspicious_file.exe")
    sys.exit(0)

def show_help_2():
    print(f"Usage: python3 venomstrike.py [file path]\nExample: python3 venomstrike.py suspicious_file.exe")
    sys.exit(1)

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

def calculate_md5(path):
    md5 = hashlib.md5()
    try:
        with open(path, 'rb') as f:
            for block in iter(lambda: f.read(4096), b""):
                md5.update(block)
    except IOError as e:
        print(f"[Error] Could not open or read the file '{path}': {e}")
        sys.exit(1)
    return md5.hexdigest()

def load_hashes(path):
    backup_path = os.path.join(os.path.dirname(path), "backup_sha256.txt")
    if os.path.exists(path):
        with open(path, 'r') as f:
            return set(line.strip().lower() for line in f if line.strip())
    elif os.path.exists(backup_path):
        with open(backup_path, 'r') as f:
            return set(line.strip().lower() for line in f if line.strip())
    else:
        print("[!] No hash database (full_sha256.txt or backup_sha256.txt) available.")
        sys.exit(1)



def load_hashes_2(path):
    try:
        with open(path, 'r') as f:
            return set(line.strip().lower() for line in f if line.strip())
    except IOError as e:
        download_and_extract_md5(os.path.dirname(path))
        with open(path, 'r') as f:
            return set(line.strip().lower() for line in f if line.strip())

def main():
    args = parse_args()
    file_path = args.file
    use_md5 = args.md5
    force_update = args.update
    if force_update:
        for f in [hashes_file, hashes_file_2, md5_flag]:
            if os.path.exists(f):
                os.remove(f)

        print("[*] Hash databases deleted for update.")
        download_and_extract_sha256(os.path.dirname(hashes_file))
        answer = input("Do you want to download the optional MD5 hash database? (y/n): ").strip().lower()

        if answer == 'y':
            download_and_extract_md5(os.path.dirname(hashes_file_2))
        else:
            with open(md5_flag, 'w') as f:
                f.write("User Declined MD5 download.\n")
            print("The file was not downloaded.")
        sys.exit(0)

    if use_md5:
        answer = input("Do you want to download the optional MD5 hash database? (y/n): ").strip().lower()
        if answer == 'y':
            download_and_extract_md5(os.path.dirname(hashes_file_2))
        else:
            print("The file was not downloaded.")
        sys.exit(0)

    if not file_path:
        print("[Error] No file was provided.\n")
        show_help_2()
    if not os.path.isfile(file_path):
        print(f"[Error] File '{file_path}' does not exist or was not found.\n")
        show_help_2()
    if not os.path.exists(hashes_file):
        download_and_extract_sha256(os.path.dirname(hashes_file))

    malicious_hashes = load_hashes(hashes_file)
    file_hash = calculate_sha256(file_path)

    file_hash_md5 = None
    malicious_hashes_md5 = set()

    if os.path.exists(hashes_file_2):
        file_hash_md5 = calculate_md5(file_path)
        malicious_hashes_md5 = load_hashes_2(hashes_file_2)
    print(f"[*] SHA-256: {file_hash}")

    if file_hash_md5:
        print(f"[*] MD5: {file_hash_md5}")
    else:
        print("[*] MD5 check skipped (hash database not present)\nYou can download it with: python3 venomstrike.py -md5\n")

    yara_rules_folder = os.path.join(script, "modules/yar_rules/")
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
    if file_hash_md5:
        if file_hash_md5 in malicious_hashes_md5:
            print(f"[!] Match found by MD5 hash: {file_hash_md5}")
        else:
            print(f"[+] No match found by MD5")


if __name__ == "__main__":
    clean_screen()
    print(show_me)
    main()
