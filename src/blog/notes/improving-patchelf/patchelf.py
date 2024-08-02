from pwnc.minelf import *
from argparse import ArgumentParser
from pathlib import Path

def err(msg: str):
    print(f"[-] {msg}")
    exit(1)

def warn(msg: str):
    print(f"[*] {msg}")

parser = ArgumentParser()
parser.add_argument("--bits", choices=[32, 64])
parser.add_argument("--endian", choices=["big", "little"])
parser.add_argument("--rpath", type=str)
parser.add_argument("--needed", type=str, action="append", nargs=2, default=[])
parser.add_argument("path")

args = parser.parse_args()
path = Path(args.path)

try:
    raw_elf_bytes = open(path, "rb").read()
except Exception as e:
    err(f"failed to read file: {e}")

little_endian = None
match args.endian:
    case "big":
        little_endian = False
    case _:
        little_endian = True 
elf = ELF(raw_elf_bytes, args.bits, little_endian)

