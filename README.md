<p align="center">
  <img src="https://media.giphy.com/media/YRDuN32tiOevbMTNMK/giphy.gif?cid=ecf05e479otb19ifyhrsabvn4sfkl9m6g8jjdgto7vdz2zmj&ep=v1_stickers_search&rid=giphy.gif&ct=s" width="400" />
</p>

<br>

# VenomStrike by 5kidRo0t ver. 1.3 🏴‍☠️

## 🇪🇸 Descripción: 

VenomStrike es una herramienta de análisis estático diseñada para facilitar la identificación de malware. Su funcionamiento se basa en dos pilares fundamentales:

1. Cálculo de hashes: Extrae los hashes SHA-256 y MD5 de cualquier archivo proporcionado y los compara automáticamente, permitiendo detectar amenazas conocidas de forma rápida y eficiente.


2. Análisis con reglas YARA: Utiliza un conjunto de reglas ubicadas en la carpeta yar_rules, donde se pueden almacenar archivos .yar o .yara. VenomStrike escanea el archivo objetivo buscando coincidencias con estas reglas, ofreciendo una capa adicional de detección basada en patrones definidos por el analista.



Esta herramienta es ideal para analistas de malware, investigadores de ciberseguridad y entusiastas que deseen integrar detección por firmas y heurística básica en sus flujos de análisis.

---

## 🇬🇧 Description:

VenomStrike is a static analysis tool designed to aid in malware identification. It operates based on two core features:

1. Hash Calculation: It extracts the SHA-256 and MD5 hashes of any given file and automatically checks, allowing for quick detection of known threats.


2. YARA Rule Scanning: It leverages a set of YARA rules located in the yar_rules folder, where users can store .yar or .yara files. VenomStrike scans the target file against these rules, providing an additional layer of detection based on custom or community-defined patterns.



This tool is ideal for malware analysts, cybersecurity researchers, and enthusiasts looking to incorporate basic signature-based and heuristic detection into their analysis workflows.

//////////////////////////////////////////////////////////////////

## 🇪🇸 Información sobre la última actualización:

### La versión 1.3 ya está disponible.<img src="https://media.giphy.com/media/jvQdgWel96thK/giphy.gif?cid=ecf05e47tpp0fslmjz4wcqe4hwozctqiqd0p5s8r7h3xxwok&ep=v1_stickers_search&rid=giphy.gif&ct=s" width="90" />
</p>

Se ha eliminado toda vinculación con MalwareBazaar debido a cambios de políticas en su plataforma, la herramienta trae un archivo "example_sha256.txt" que contiene algunos hashes sha256 pero sería recomendable usar las propias, para ello solo debes guardar los hashes con el mismo formato
que dejo de ejemplo y guardarlo en la carpeta /modules como "full_sha256.txt" y/o "full_md5.txt" para que la herramienta pueda reconocerlos, por otro lado también puedes hacer tu mismo los cambios que quieras.

La herramienta puede seguir actualizándose ejecutando el script venom_update.py

Si tienes cualquier duda o problema, no dudes en escribirme a:
📩 skidoroot@gmail.com

Gracias por usar VenomStrike.

---

## 🇬🇧 Information about the latest update:

### Version 1.3 is now available. <img src="https://media.giphy.com/media/13xxoHrXk4Rrdm/giphy.gif?cid=ecf05e479weh4ruvl8qie683dkjostlruvsvcti52a9l1e37&ep=v1_stickers_search&rid=giphy.gif&ct=s" width="90" />

</p>

All integration with MalwareBazaar has been removed due to policy changes on their platform. The tool now includes an example_sha256.txt file containing a few SHA-256 hashes. However, it is recommended that you use your own hash databases.
To do so, simply save your hashes using the same format as the provided example and place the files in the /modules directory under the following names full_sha256.txt and full_md5.txt

You can use either file or both. VenomStrike will automatically recognize them. You are also free to modify the tool according to your own needs.

The tool can still be updated by running the venom_update.py script.

If you have any questions or encounter any issues, feel free to contact me: 📩 skidoroot@gmail.com

Thank you for using VenomStrike!


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
