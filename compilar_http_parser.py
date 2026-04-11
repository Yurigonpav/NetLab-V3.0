#!/usr/bin/env python3
"""
Wrapper de compatibilidade para compilacao do http_parser.

Uso recomendado:
    python utils/compilar_c.py
"""

from __future__ import annotations

import sys

from utils.compilar_c import MODULOS_C, compilar


def main() -> int:
    modulo_http = next((m for m in MODULOS_C if m["fonte"].name == "http_parser.c"), None)
    if not modulo_http:
        print("[ERRO] Modulo http_parser.c nao encontrado na lista de compilacao.")
        return 1

    if compilar(modulo_http):
        print("\nCompilacao concluida. Reinicie o NetLab para usar o parser C.")
        return 0

    print("\nFalha na compilacao. O NetLab seguira com fallback em Python.")
    return 1


if __name__ == "__main__":
    sys.exit(main())

