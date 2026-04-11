"""
Compila todos os modulos C nativos do NetLab.

Uso:
    python utils/compilar_c.py
"""

from __future__ import annotations

import platform
import shutil
import subprocess
import sys
from pathlib import Path

RAIZ = Path(__file__).resolve().parent.parent

MODULOS_C = [
    {
        "fonte": RAIZ / "http_parser.c",
        "saida_win": RAIZ / "http_parser.dll",
        "saida_posix": RAIZ / "http_parser.so",
    },
    {
        "fonte": RAIZ / "netlab_core_lib.c",
        "saida_win": RAIZ / "netlab_core_lib.dll",
        "saida_posix": RAIZ / "netlab_core_lib.so",
    },
]


def compilar(modulo: dict) -> bool:
    """Compila um modulo C e retorna True/False."""
    caminho_fonte = modulo["fonte"]
    if not caminho_fonte.exists():
        print(f"[AVISO] Fonte nao encontrada: {caminho_fonte}")
        return False

    sistema = platform.system()
    if sistema == "Windows":
        caminho_saida = modulo["saida_win"]
        if shutil.which("gcc"):
            comando = ["gcc", "-O2", "-shared", "-o", str(caminho_saida), str(caminho_fonte)]
        elif shutil.which("cl"):
            comando = ["cl", "/O2", "/LD", str(caminho_fonte), f"/Fe:{caminho_saida}", "/nologo"]
        else:
            print("[ERRO] Nenhum compilador C encontrado (gcc ou cl).")
            return False
    else:
        caminho_saida = modulo["saida_posix"]
        comando = ["gcc", "-O2", "-shared", "-fPIC", "-o", str(caminho_saida), str(caminho_fonte)]

    print(f"Compilando {caminho_fonte.name} -> {caminho_saida.name}")
    processo = subprocess.run(comando, capture_output=True, text=True)
    if processo.returncode != 0:
        erro = (processo.stderr or processo.stdout or "").strip()
        print(f"[ERRO] Falha ao compilar {caminho_fonte.name}:\n{erro}")
        return False

    print(f"[OK] {caminho_saida.name} gerado com sucesso.")
    return True


def main() -> int:
    """Compila todos os modulos da lista."""
    total_sucesso = sum(compilar(modulo) for modulo in MODULOS_C)
    total_modulos = len(MODULOS_C)
    print(f"\n{total_sucesso}/{total_modulos} modulo(s) compilado(s).")
    return 0 if total_sucesso == total_modulos else 1


if __name__ == "__main__":
    sys.exit(main())

