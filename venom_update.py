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
import shutil
import tempfile
import urllib.request
import zipfile
from io import BytesIO
import sys

def download_and_extract_zip(repo_url):
    try:
        print("[*] Downloading latest version...")
        response = urllib.request.urlopen(repo_url)
        with zipfile.ZipFile(BytesIO(response.read())) as zip_file:
            temp_dir = tempfile.mkdtemp()
            zip_file.extractall(temp_dir)
            return temp_dir
    except Exception as e:
        print(f"[Error] Failed to download or extract update: {e}")
        sys.exit(1)

def update_files(temp_dir, current_dir, exclude_file):
    extracted_folder = None
    for item in os.listdir(temp_dir):
        if os.path.isdir(os.path.join(temp_dir, item)):
            extracted_folder = os.path.join(temp_dir, item)
            break
    if not extracted_folder:
        print("[Error] Could not locate extracted folder.")
        sys.exit(1)

    print("[*] Replacing current files...")

    for item in os.listdir(current_dir):
        if item != exclude_file:
            item_path = os.path.join(current_dir, item)
            try:
                if os.path.isfile(item_path) or os.path.islink(item_path):
                    os.remove(item_path)
                elif os.path.isdir(item_path):
                    shutil.rmtree(item_path)
            except Exception as e:
                print(f"[Warning] Could not remove {item_path}: {e}")

    for item in os.listdir(extracted_folder):
        src = os.path.join(extracted_folder, item)
        dst = os.path.join(current_dir, item)
        try:
            if os.path.isdir(src):
                shutil.copytree(src, dst)
            else:
                shutil.copy2(src, dst)
        except Exception as e:
            print(f"[Warning] Could not copy {src} to {dst}: {e}")

    print("[+] Update completed successfully.")

def main():
    print("[!] WARNING: This update will overwrite existing files.")
    confirm = input("Do you want to continue? [y/N]: ").strip().lower()
    if confirm != 'y':
        print("[*] Update cancelled.")
        sys.exit(0)

    repo_zip_url = "https://github.com/5kidRo0t/VenomStrike/archive/refs/heads/main.zip"
    current_dir = os.path.dirname(os.path.abspath(__file__))
    updater_name = os.path.basename(__file__)

    temp_dir = download_and_extract_zip(repo_zip_url)
    update_files(temp_dir, current_dir, updater_name)

    # Cleanup
    shutil.rmtree(temp_dir, ignore_errors=True)

if __name__ == "__main__":
    main()
