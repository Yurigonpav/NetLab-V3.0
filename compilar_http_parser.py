#!/usr/bin/env python3
"""
compilar_http_parser.py
=======================
Detecta o compilador disponível (MinGW gcc ou MSVC cl.exe) e compila
http_parser.c → http_parser.dll  (Windows)
              → http_parser.so   (Linux/macOS)

Uso:
    python compilar_http_parser.py

Coloque http_parser.c e este script na RAIZ do projeto NetLab,
ao lado de analisador_pacotes.py.
"""

import subprocess
import sys
import shutil
import platform
from pathlib import Path

SRC  = Path(__file__).parent / "http_parser.c"
OUT_WIN   = Path(__file__).parent / "http_parser.dll"
OUT_POSIX = Path(__file__).parent / "http_parser.so"


def compilar_mingw():
    out = OUT_WIN
    cmd = ["gcc", "-O2", "-shared", "-o", str(out), str(SRC)]
    print(f"[gcc]  {' '.join(cmd)}")
    resultado = subprocess.run(cmd, capture_output=True, text=True)
    if resultado.returncode != 0:
        print("ERRO gcc:\n", resultado.stderr)
        return False
    print(f"OK → {out}")
    return True


def compilar_msvc():
    out = OUT_WIN
    cmd = ["cl", "/O2", "/LD", str(SRC), f"/Fe:{out}",
           "/nologo", "/W3"]
    print(f"[cl]   {' '.join(cmd)}")
    resultado = subprocess.run(cmd, capture_output=True, text=True)
    if resultado.returncode != 0:
        print("ERRO cl:\n", resultado.stderr)
        return False
    print(f"OK → {out}")
    return True


def compilar_posix():
    out = OUT_POSIX
    cmd = ["gcc", "-O2", "-shared", "-fPIC", "-o", str(out), str(SRC)]
    print(f"[gcc]  {' '.join(cmd)}")
    resultado = subprocess.run(cmd, capture_output=True, text=True)
    if resultado.returncode != 0:
        print("ERRO gcc:\n", resultado.stderr)
        return False
    print(f"OK → {out}")
    return True


def main():
    if not SRC.exists():
        print(f"ERRO: {SRC} não encontrado. Coloque http_parser.c na raiz do projeto.")
        sys.exit(1)

    sistema = platform.system()

    if sistema == "Windows":
        if shutil.which("gcc"):
            ok = compilar_mingw()
        elif shutil.which("cl"):
            ok = compilar_msvc()
        else:
            print(
                "ERRO: Nenhum compilador C encontrado.\n"
                "Instale MinGW (https://winlibs.com/) e adicione ao PATH,\n"
                "ou instale Visual Studio Build Tools."
            )
            sys.exit(1)
    else:
        ok = compilar_posix()

    if ok:
        print("\nCompilação concluída. Reinicie o NetLab para usar o parser C.")
    else:
        print("\nFalha na compilação. O NetLab usará o parser Python como fallback.")
        sys.exit(1)


if __name__ == "__main__":
    main()
