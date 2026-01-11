#!/usr/bin/env python3
"""
XOR Shellcode Encryptor
 
Reads raw shellcode from file, XOR-encrypts it using a user-supplied key,
and outputs the encrypted shellcode in multiple formats suitable for loaders.
"""
 
import argparse
import sys
from pathlib import Path
 
 
def parse_key(key_str: str) -> bytes:
    """
    Parse XOR key from hex (0x41) or string ("KEY")
    """
    if key_str.startswith("0x"):
        return bytes([int(key_str, 16)])
    return key_str.encode()
 
 
def xor_encrypt(data: bytes, key: bytes) -> bytes:
    """
    XOR-encrypt data with a repeating key
    """
    encrypted = bytearray()
    for i, b in enumerate(data):
        encrypted.append(b ^ key[i % len(key)])
    return bytes(encrypted)
 
 
def format_output(data: bytes, fmt: str) -> str:
    """
    Format encrypted shellcode for output
    """
    if fmt == "raw":
        return data
 
    if fmt == "python":
        return f"shellcode = {list(data)}"
 
    if fmt == "c":
        hex_bytes = ", ".join(f"0x{b:02X}" for b in data)
        return f"unsigned char buf[] = {{ {hex_bytes} }};"
 
    raise ValueError("Unsupported format")
 
 
def main():
    parser = argparse.ArgumentParser(
        description="XOR encrypt shellcode for loader obfuscation"
    )
    parser.add_argument("--in", dest="input", required=True, help="Input shellcode file")
    parser.add_argument("--out", dest="output", required=True, help="Output file")
    parser.add_argument("--key", required=True, help="XOR key (hex 0xNN or string)")
    parser.add_argument(
        "--format",
        choices=["raw", "python", "c"],
        default="raw",
        help="Output format",
    )
 
    args = parser.parse_args()
 
    input_path = Path(args.input)
    output_path = Path(args.output)
 
    if not input_path.exists():
        print("[!] Input file not found")
        sys.exit(1)
 
    shellcode = input_path.read_bytes()
    key = parse_key(args.key)
    encrypted = xor_encrypt(shellcode, key)
    formatted = format_output(encrypted, args.format)
 
    if args.format == "raw":
        output_path.write_bytes(formatted)
    else:
        output_path.write_text(formatted)
 
    print(f"[+] Encrypted {len(shellcode)} bytes")
    print(f"[+] Key: {args.key}")
    print(f"[+] Format: {args.format}")
    print(f"[+] Output written to {output_path}")
 
 
if __name__ == "__main__":
    main()
