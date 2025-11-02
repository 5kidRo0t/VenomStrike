<p align="center">
  <img src="https://media.giphy.com/media/YRDuN32tiOevbMTNMK/giphy.gif?cid=ecf05e479otb19ifyhrsabvn4sfkl9m6g8jjdgto7vdz2zmj&ep=v1_stickers_search&rid=giphy.gif&ct=s" width="400" />
</p>

<br>

# VenomStrike by 5kidRo0t ver. 1.1 🏴‍☠️

## 🇪🇸 Descripción: 

VenomStrike es una herramienta de análisis estático diseñada para facilitar la identificación de malware. Su funcionamiento se basa en dos pilares fundamentales:

1. Cálculo de hashes: Extrae los hashes SHA-256 y MD5 de cualquier archivo proporcionado y los compara automáticamente con la base de datos pública de MalwareBazaar, permitiendo detectar amenazas conocidas de forma rápida y eficiente.


2. Análisis con reglas YARA: Utiliza un conjunto de reglas ubicadas en la carpeta yar_rules, donde se pueden almacenar archivos .yar o .yara. VenomStrike escanea el archivo objetivo buscando coincidencias con estas reglas, ofreciendo una capa adicional de detección basada en patrones definidos por el analista.



Esta herramienta es ideal para analistas de malware, investigadores de ciberseguridad y entusiastas que deseen integrar detección por firmas y heurística básica en sus flujos de análisis.

---

## 🇬🇧 Description:

VenomStrike is a static analysis tool designed to aid in malware identification. It operates based on two core features:

1. Hash Calculation: It extracts the SHA-256 and MD5 hashes of any given file and automatically checks them against the public MalwareBazaar database, allowing for quick detection of known threats.


2. YARA Rule Scanning: It leverages a set of YARA rules located in the yar_rules folder, where users can store .yar or .yara files. VenomStrike scans the target file against these rules, providing an additional layer of detection based on custom or community-defined patterns.



This tool is ideal for malware analysts, cybersecurity researchers, and enthusiasts looking to incorporate basic signature-based and heuristic detection into their analysis workflows.

//////////////////////////////////////////////////////////////////

## 🇪🇸 Información sobre la última actualización:

### La versión 1.1 ya está disponible.<img src="https://media.giphy.com/media/jvQdgWel96thK/giphy.gif?cid=ecf05e47tpp0fslmjz4wcqe4hwozctqiqd0p5s8r7h3xxwok&ep=v1_stickers_search&rid=giphy.gif&ct=s" width="90" />
</p>

Se ha eliminado la dependencia que VenomStrike tenía con MalwareBazaar, ahora la herramienta funciona sin necesidad de descargar las bases de datos de MalwareBazaar, esto se ha realizado
para que la herramienta siga siendo funcional en el caso de que algún día los servidores de MalwareBazaar dejen de ofrecer sus bases de datos de manera pública o cambien sus dominios. Aunque en el 
caso de no usar las bases de datos de MalwareBazaar deberás usar tus propias bases de datos SHA-256 o MD5 si quieres que la herramienta tenga más alcance de análisis. Para ello deberás guardar tus bases
de datos SHA-256 y/o MD5 con los nombres correspondientes para que la herramienta pueda usarlos dentro de la carpeta "modules", los nombres que debes usar son **full_sha256.txt** y **full_md5.txt**, la estructura que se debe usar tiene que ser similar a la que encontrarás en el archivo **backup_sha256.txt** el cual se usará en caso de que no existan las bases de datos antes mencionadas.

La herramienta puede seguir actualizándose ejecutando el script venom_update.py, pero ahora puedes actualizar únicamente las bases de datos de hashes SHA256 y MD5 usando el parámetro -update (ejemplo:
python3 venomstrike.py -update).

Si en algún momento decidiste no descargar los hashes MD5, puedes hacerlo más adelante con el parámetro -md5 (ejemplo:
python3 venomstrike.py -md5).

Si tienes cualquier duda o problema, no dudes en escribirme a:
📩 skidoroot@gmail.com

Gracias por usar VenomStrike.

---

## 🇬🇧 Information about the latest update:

### Version 1.1 is now available. <img src="https://media.giphy.com/media/13xxoHrXk4Rrdm/giphy.gif?cid=ecf05e479weh4ruvl8qie683dkjostlruvsvcti52a9l1e37&ep=v1_stickers_search&rid=giphy.gif&ct=s" width="90" />
</p>

The dependency that VenomStrike had on MalwareBazaar has been removed. The tool now works without needing to download MalwareBazaar’s databases. This change was made to ensure that the tool remains functional in case MalwareBazaar’s servers ever stop offering their databases publicly or change their domains.
However, if you choose not to use MalwareBazaar’s databases, you’ll need to use your own SHA-256 or MD5 databases if you want the tool to have broader analysis capabilities. To do this, you must save your SHA-256 and/or MD5 databases with the corresponding names so that the tool can use them inside the "modules" folder. The names you should use are **full_sha256.txt** and **full_md5.txt**. The structure should be similar to the one found in the **backup_sha256.txt** file, which will be used in case the aforementioned databases are not present.

The tool can still be updated by running the venom_update.py script, but now you can update only the SHA256 and MD5 hash databases using the -update parameter (example:
python3 venomstrike.py -update).

If at any point you decided not to download the MD5 hashes, you can do so later with the -md5 parameter (example:
python3 venomstrike.py -md5).

If you have any questions or issues, feel free to contact me at:
📩 skidoroot@gmail.com

Thank you for using VenomStrike.


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
