VenomStrike by 5kidRo0t ver. 0.1

//////////////////////////////////////////////////////////////////

La herramienta aún no se puede usar porque falta la base de datos de MalwareBazaar, si quieres puedes descargar la base de datos SHA-256 tu mismo
en la siguiente dirección >> https://bazaar.abuse.ch/export

IMPORTANTE descarga solo >> ""SHA256 hashes: Full data dump ( download - zip compressed) Plain Text"" y deja el archivo full_sha256.txt en la carpeta modules con eso
debería funcionar sin problemas, más adelante ya arreglaré esto mismo.


The tool is still unusable because the MalwareBazaar database is missing. If you want, you can download the SHA-256 database yourself at the following address: >> https://bazaar.abuse.ch/export

IMPORTANT: Download only >> "SHA256 hashes: Full data dump (download - zip compressed) Plain Text" and leave the full_sha256.txt file in the modules folder.
It should work without any problems. I'll fix this later.

//////////////////////////////////////////////////////////////////


✅ Requirements
To run VenomStrike - Malware Scanner, your system must meet the following requirements:

Python 3.8 or higher installed and accessible from the command line.

YARA command-line tool installed and properly configured in your system PATH. This is required for the scanner to perform rule-based malware detection using your .yara rules.

🐧 Linux (Debian/Ubuntu-based):
YARA can be installed easily using your system package manager:

sudo apt update
sudo apt install yara

To verify the installation:

yara --version
If the command returns the version number, you're good to go.

🪟 Windows:
Download the YARA Windows binaries from the official GitHub repository:
👉 https://github.com/VirusTotal/yara/releases

Extract the ZIP and copy the contents (including yara.exe) to a directory, for example:
C:\YARA\

Add that directory to your system’s PATH:
Open the Start menu and search for "Environment Variables".
Click "Environment Variables…".
Under "System Variables", find and edit the Path variable.
Add a new entry: C:\YARA\

Open cmd and test it with:

yara --version
You should see the version number printed if everything is set up correctly.


