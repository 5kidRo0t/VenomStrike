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

import os
import sys
import hashlib
import subprocess
import platform
import time
import argparse

show_me = "▗▖  ▗▖▗▞▀▚▖▄▄▄▄   ▄▄▄  ▄▄▄▄   ▗▄▄▖ ■   ▄▄▄ ▄ █  ▄ ▗▞▀▚▖    \n▐▌  ▐▌▐▛▀▀▘█   █ █   █ █ █ █ ▐▌ ▗▄▟▙▄▖█    ▄ █▄▀  ▐▛▀▀▘    \n▐▌  ▐▌▝▚▄▄▖█   █ ▀▄▄▄▀ █   █  ▝▀▚▖▐▌  █    █ █ ▀▄ ▝▚▄▄▖    \n ▝▚▞▘                        ▗▄▄▞▘▐▌       █ █  █          \n                                  ▐▌                       \n----------------------------------------------------------\nVenomStrike - Malware Scanner by 5kidRo0t ver. 1.3\n----------------------------------------------------------\n"
script = os.path.dirname(os.path.abspath(__file__))
hashes_file = os.path.join(script, "modules/full_sha256.txt")
hashes_file_2 = os.path.join(script, "modules/full_md5.txt")

class CustomArgumentParser(argparse.ArgumentParser):
    def error(self, message):
        clean_screen()
        print(show_me)
        print(f"[ERROR] {message}\n")
        self.print_help()
        sys.exit(2)

def parse_args():
    parser = CustomArgumentParser(
        description=(
            "VenomStrike - Malware Scanner. Hash databases must be supplied "
            "manually in modules/: full_sha256.txt (SHA-256) and, optionally, "
            "full_md5.txt (MD5). Use one hexadecimal hash per line."
        ),
        epilog=(
            "Hash files: modules/full_sha256.txt (64 hexadecimal characters "
            "per line) and modules/full_md5.txt (32 hexadecimal characters "
            "per line). The MD5 file is optional."
        )
    )
    parser.add_argument("file", nargs="?", help="Path to the file to scan")
    return parser.parse_args()

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

def load_hashes(path, expected_length):
    hashes = set()
    try:
        with open(path, "r", encoding="utf-8") as f:
            for line_number, line in enumerate(f, start=1):
                value = line.strip().lower()
                if not value or value.startswith("#"):
                    continue
                if len(value) != expected_length or any(c not in "0123456789abcdef" for c in value):
                    print(
                        f"[!] Invalid hash in {os.path.basename(path)}, "
                        f"line {line_number}. Expected {expected_length} hexadecimal characters."
                    )
                    continue
                hashes.add(value)
    except OSError as e:
        print(f"[!] Could not read hash file '{path}': {e}")
        return set()
    return hashes

def main():
    args = parse_args()
    file_path = args.file

    if not file_path:
        print("[Error] No file was provided.\n")
        print("Usage: python3 venomstrike.py [file path]")
        print("Example: python3 venomstrike.py suspicious_file.exe")
        sys.exit(1)

    if not os.path.isfile(file_path):
        print(f"[Error] File '{file_path}' does not exist or was not found.\n")
        sys.exit(1)

    # Hash databases are supplied and maintained by the user.
    malicious_hashes = load_hashes(hashes_file, 64) if os.path.exists(hashes_file) else set()
    malicious_hashes_md5 = load_hashes(hashes_file_2, 32) if os.path.exists(hashes_file_2) else set()

    file_hash = calculate_sha256(file_path)
    file_hash_md5 = calculate_md5(file_path) if malicious_hashes_md5 else None

    print(f"[*] SHA-256: {file_hash}")
    if not os.path.exists(hashes_file):
        print("[*] SHA-256 hash check skipped: modules/full_sha256.txt was not found.")
    elif not malicious_hashes:
        print("[*] SHA-256 hash check skipped: no valid hashes were found in the database.")

    if file_hash_md5:
        print(f"[*] MD5: {file_hash_md5}")
    else:
        print("[*] MD5 hash check skipped (optional modules/full_md5.txt not found or empty).")

    yara_rules_folder = os.path.join(script, "modules/yar_rules/")
    yara_matches = scan_with_yara_binary(yara_rules_folder, file_path)
    scanning_animation(file_path)

    if yara_matches:
        print("[!] YARA rules matched:")
        for rule_file, output in yara_matches:
            print(f"Rule '{rule_file}' matched: {output}")
    else:
        print("[+] No YARA rules matched.")

    if malicious_hashes:
        if file_hash in malicious_hashes:
            print(f"[!] Match found by SHA-256 hash: {file_hash}")
        else:
            print("[+] No match found by SHA-256.")
    if malicious_hashes_md5 and file_hash_md5:
        if file_hash_md5 in malicious_hashes_md5:
            print(f"[!] Match found by MD5 hash: {file_hash_md5}")
        else:
            print("[+] No match found by MD5.")


if __name__ == "__main__":
    clean_screen()
    print(show_me)
    print("Hash database files (user-provided):")
    print("  modules/full_sha256.txt  - SHA-256, one 64-character hash per line (optional)")
    print("  modules/full_md5.txt     - MD5, one 32-character hash per line (optional)")
    print("Lines beginning with # and blank lines are ignored.\n")
    main()