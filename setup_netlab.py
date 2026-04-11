"""
Wrapper de compatibilidade para compilacao de netlab_core_lib.c.

Uso recomendado:
    python utils/compilar_c.py
"""

from __future__ import annotations

import sys

from utils.compilar_c import MODULOS_C, compilar


def main() -> int:
    if len(sys.argv) > 1 and sys.argv[1] not in {"build_gcc", "build_ext"}:
        print(f"[AVISO] Modo '{sys.argv[1]}' nao reconhecido. Usando build_gcc.")

    modulo_core = next((m for m in MODULOS_C if m["fonte"].name == "netlab_core_lib.c"), None)
    if not modulo_core:
        print("[ERRO] Modulo netlab_core_lib.c nao encontrado na lista de compilacao.")
        return 1

    if compilar(modulo_core):
        return 0
    return 1


if __name__ == "__main__":
    sys.exit(main())

