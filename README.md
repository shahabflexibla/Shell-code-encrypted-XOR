XOR Shellcode Encryptor

(Educational Project)

📌 About

A simple Python tool that XOR-encrypts raw shellcode and exports it in multiple formats.
Created for educational and security research purposes, with AI assistance (ChatGPT).

The tool demonstrates basic payload obfuscation techniques commonly used in red teaming, loader development, and malware research.

✨ Features

Reads raw shellcode from file

XOR encryption using a byte or string key

Multiple output formats:

Raw binary

Python byte array

C unsigned char array

Fully CLI-based using argparse

Simple, lightweight, and beginner-friendly

⚙ Requirements

Python 3.x
(No external dependencies required)

📂 Project Structure
.
├── xorcrypt.py
├── raw.bin
├── encrypted.bin
├── encrypted.py
├── encrypted.h
└── README.md

🧪 Generate Shellcode (Example)
msfvenom -p windows/exec CMD=calc.exe -f raw -o raw.bin

🚀 Usage
python3 xorcrypt.py --in INPUT --out OUTPUT --key KEY --format FORMAT

Examples

Raw encrypted output

python3 xorcrypt.py --in raw.bin --out encrypted.bin --key 0x42 --format raw


Python array

python3 xorcrypt.py --in raw.bin --out encrypted.py --key 0x42 --format python


C array

python3 xorcrypt.py --in raw.bin --out encrypted.h --key 0x42 --format c

⚠ Disclaimer

This project is intended only for learning and authorized security research.
Do not use this tool on systems you do not own or have explicit permission to test.
