<p align="center">
  <img src="https://media.giphy.com/media/YRDuN32tiOevbMTNMK/giphy.gif?cid=ecf05e479otb19ifyhrsabvn4sfkl9m6g8jjdgto7vdz2zmj&ep=v1_stickers_search&rid=giphy.gif&ct=s" width="400" />
</p>

<br>

# VenomStrike by 5kidRo0t ver. 1.0 🏴‍☠️

//////////////////////////////////////////////////////////////////

🇪🇸 [Español]

# La versión 1.0 ya está disponible.<img src="https://media.giphy.com/media/jvQdgWel96thK/giphy.gif?cid=ecf05e47tpp0fslmjz4wcqe4hwozctqiqd0p5s8r7h3xxwok&ep=v1_stickers_search&rid=giphy.gif&ct=s" width="90" />
</p>
Ya no es obligatorio descargar la base de datos de hashes MD5 para usar la herramienta, aunque los hashes SHA256 siguen siendo necesarios para que el script funcione correctamente.

La herramienta puede seguir actualizándose ejecutando el script venom_update.py, pero ahora también puedes actualizar las bases de datos de hashes SHA256 y MD5 usando el parámetro -update (ejemplo: python3 venomstrike.py -update).

Si en algún momento decidiste no descargar los hashes MD5, puedes hacerlo más adelante con el parámetro -md5 (ejemplo: python3 venomstrike.py -md5).

Sigo trabajando para mejorar esta herramienta y hacerla lo más sencilla posible de usar.
Si tienes cualquier duda o problema, no dudes en escribirme a:
📩 skidoroot@gmail.com

Por ahora, la herramienta funciona correctamente mientras no se la fuerce a fallar.
En caso de que ocurra un problema grave, puedes solucionarlo ejecutando el script venom_update.py (ejemplo: python3 venom_update.py), 
el cual reemplazará todos los archivos descargándolos directamente desde mi repositorio oficial.
Este proceso es seguro y puede ayudarte a recuperar la herramienta si sufre un fallo.

Aún no he probado VenomStrike en Windows, macOS ni en distribuciones GNU/Linux que no estén basadas en Debian.
Si tienes inconvenientes al ejecutar el script, por favor contáctame.

Gracias por usar VenomStrike.

---

🇬🇧 [English]

# Version 1.0 is now available. <img src="https://media.giphy.com/media/13xxoHrXk4Rrdm/giphy.gif?cid=ecf05e479weh4ruvl8qie683dkjostlruvsvcti52a9l1e37&ep=v1_stickers_search&rid=giphy.gif&ct=s" width="90" />
</p>

Downloading the MD5 hashes is no longer mandatory to use the tool, although SHA256 hashes are still required for the script to function properly.

The tool can still be updated by running the venom_update.py script, but now there's also an option to update both SHA256 and MD5 hash databases using the -update parameter (example: python3 venomstrike.py -update).

If you chose not to download the MD5 hashes at first, you can still do it anytime using the -md5 parameter (example: python3 venomstrike.py -md5).

I'm constantly working on improving this tool to make it easier to use.
If you have any questions or issues, feel free to contact me at:
📩 skidoroot@gmail.com

So far, the tool seems to work fine as long as it's not forced into an error state.
If you run into any serious problems, you can fix them by executing the venom_update.py script (example:python3 venom_update.py), 
which will replace all files by downloading them from my official repository.
It’s safe to use this script in case VenomStrike crashes.

I haven’t tested the tool yet on Windows, macOS, or non-Debian-based GNU/Linux distributions.
If you experience any issues while trying to run the script, please don’t hesitate to contact me.

Thanks for using VenomStrike!

![Captura desde 2025-05-26 20-25-46](https://github.com/user-attachments/assets/57392bbd-a2d9-436e-942f-305fcdefad92)

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
