"""
setup_netlab.py
Script de compilação da extensão C netlab_core_lib.

USO
───
  # Compilar com gcc diretamente (recomendado para Windows/MinGW e Linux):
  python setup_netlab.py build_gcc

  # Compilar via distutils (alternativa multiplataforma):
  python setup_netlab.py build_ext --inplace

RESULTADO
─────────
  Windows : netlab_core_lib.dll  (pasta atual)
  Linux   : netlab_core_lib.so   (pasta atual)
  macOS   : netlab_core_lib.so   (pasta atual)
"""

import os
import sys
import subprocess
import shutil

SRC  = "netlab_core_lib.c"
BASE = os.path.splitext(SRC)[0]


def _compilar_gcc():
    """Compila diretamente com gcc, sem distutils."""
    if sys.platform == "win32":
        saida = f"{BASE}.dll"
        cmd   = ["gcc", "-O2", "-shared", "-o", saida, SRC]
    elif sys.platform == "darwin":
        saida = f"{BASE}.so"
        cmd   = ["gcc", "-O2", "-shared", "-fPIC", "-o", saida, SRC]
    else:
        saida = f"{BASE}.so"
        cmd   = ["gcc", "-O2", "-shared", "-fPIC", "-o", saida, SRC]

    print(f"[setup_netlab] Compilando: {' '.join(cmd)}")
    resultado = subprocess.run(cmd, capture_output=True, text=True)
    if resultado.returncode == 0:
        print(f"[setup_netlab] ✓ Biblioteca gerada: {saida}")
    else:
        print("[setup_netlab] ✗ Erro de compilação:")
        print(resultado.stderr)
        sys.exit(1)


def _compilar_distutils():
    """Compila via distutils como extensão Python (gera .pyd/.so importável)."""
    try:
        from distutils.core import setup, Extension
    except ImportError:
        from setuptools import setup, Extension

    ext = Extension(
        name    = "netlab_core_ext",
        sources = [SRC],
        extra_compile_args = ["/O2"] if sys.platform == "win32" else ["-O2"],
    )
    # Invoca o build diretamente
    import sys as _sys
    _sys.argv = ["setup_netlab.py", "build_ext", "--inplace"]
    setup(name="netlab_core_ext", ext_modules=[ext])


if __name__ == "__main__":
    modo = sys.argv[1] if len(sys.argv) > 1 else "build_gcc"

    if not os.path.isfile(SRC):
        print(f"[setup_netlab] Arquivo fonte não encontrado: {SRC}")
        sys.exit(1)

    if modo == "build_gcc":
        _compilar_gcc()
    else:
        _compilar_distutils()
