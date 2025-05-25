<p align="center">
  <img src="https://media.giphy.com/media/YRDuN32tiOevbMTNMK/giphy.gif?cid=ecf05e479otb19ifyhrsabvn4sfkl9m6g8jjdgto7vdz2zmj&ep=v1_stickers_search&rid=giphy.gif&ct=s" width="400" />
</p>

<br>

# VenomStrike by 5kidRo0t ver. 0.2 🏴‍☠️

//////////////////////////////////////////////////////////////////

La versión 0.2 trae mejoras y arregla problemas con respecto a la versión 0.1, ahora si no dispones del archivo full_sha256.txt el script te preguntará
si quieres descargarlo, además he añadido una opción para actualizar la herramienta usando el script venom_update, ejemplo: *python3 venom_update.py*,
aún tengo que testear que funcione bien por eso te recomiendo no usar el script venom_update.py en esta versión de la herramienta, seguiré trabajando en mejorar
esta herramienta, gracias.

Version 0.2 brings improvements and fixes issues from version 0.1.
Now, if the full_sha256.txt file is missing, the script will ask if you want to download it.
I've also added an option to update the tool using the venom_update script, example: *python3 venom_update.py*
However, I still need to test it thoroughly, so I recommend not using the venom_update.py script in this version of the tool.
I’ll keep working to improve this project — thank you!

//////////////////////////////////////////////////////////////////


## ✅ Requirements
To run VenomStrike - Malware Scanner, your system must meet the following requirements:

Python 3.8 or higher installed and accessible from the command line.
YARA command-line tool installed and properly configured in your system PATH. This is required for the scanner to perform rule-based malware detection using your .yara rules.

-------------------------------------------------------------------------------------------------------------------------------------

## 🐧 Linux:
Depending on your distribution, YARA can be installed using your package manager.

### Debian/Ubuntu-based:

sudo apt update  
sudo apt install yara

### Fedora/Red Hat/CentOS:

sudo dnf install yara

### Arch Linux/Manjaro:

sudo pacman -S yara

### openSUSE:

sudo zypper install yara

-------------------------------------------------------------------------------------------------------------------------------------

## 🍎 macOS:
Install YARA using Homebrew:

brew install yara

-------------------------------------------------------------------------------------------------------------------------------------

## 🪟 Windows:
Download the YARA Windows binaries from the official GitHub repository: https://github.com/VirusTotal/yara/releases
Extract the ZIP and copy the contents (including yara.exe) to a directory, for example: C:\YARA\
Add that directory to your system’s PATH:

Open the Start menu and search for "Environment Variables"

Click "Environment Variables…"

Under "System Variables", find and edit the Path variable

Add a new entry: C:\YARA\

------------------------------------------------------------------------------------------------------------------------------------

## To verify the installation, run:

yara --version

If it returns the version number, you’re good to go.

---

#### This project is licensed under the GNU General Public License v3.0 — see the LICENSE file for details.
