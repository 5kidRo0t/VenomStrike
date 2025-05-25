<p align="center">
  <img src="https://media.giphy.com/media/YRDuN32tiOevbMTNMK/giphy.gif?cid=ecf05e479otb19ifyhrsabvn4sfkl9m6g8jjdgto7vdz2zmj&ep=v1_stickers_search&rid=giphy.gif&ct=s" width="400" />
</p>

<br>

# VenomStrike by 5kidRo0t ver. 0.3 🏴‍☠️

//////////////////////////////////////////////////////////////////

La versión 0.3 ya está lista y trae nuevas mejoras como una renovación en el aspecto de la herramienta, también he implementado la descarga automática de hashes MD5
que se incluirán además en los análisis para una mayor rigurosidad, decir también que ya podéis usar vuestras propias reglas yara tanto si están en .yar como .yara
simplemente deben dejar sus reglas yara en la carpeta /modules/yar_rules/, por último he añadido algunas animaciones durante la descarga de los hashes debido
a que si no parecía que el script estaba congelado. Gracias.

Version 0.3 is now ready and includes new improvements such as a redesign of the tool’s appearance. 
I have also implemented automatic downloading of MD5 hashes, which will be included in the analyses for greater accuracy. 
Additionally, you can now use your own YARA rules, whether in .yar or .yara format — just place your YARA rules in the /modules/yar_rules/ folder, finally, I added some animations during the hash download because otherwise it looked like the script was frozen. Thanks.

![Captura desde 2025-05-25 10-49-30](https://github.com/user-attachments/assets/7cbb0081-7b56-4e96-9f79-8d65865ece22)

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
