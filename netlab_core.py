"""
netlab_core.py
Wrapper ctypes para netlab_core_lib (.dll / .so).

Se a biblioteca nativa não estiver compilada ou acessível, a classe
NetlabCore usa automaticamente a implementação Python pura — garantindo
que o restante do código nunca precise de import condicional.

COMPILAÇÃO DA BIBLIOTECA NATIVA
────────────────────────────────
  Windows (MinGW):
    gcc -O2 -shared -o netlab_core_lib.dll netlab_core_lib.c

  Windows (MSVC):
    cl /O2 /LD netlab_core_lib.c /Fe:netlab_core_lib.dll

  Linux / macOS:
    gcc -O2 -shared -fPIC -o netlab_core_lib.so netlab_core_lib.c

ÍNDICES DE PROTOCOLO
─────────────────────
  0=TCP  1=UDP  2=DNS  3=HTTP  4=HTTPS  5=ARP
  6=ICMP 7=DHCP 8=TCP_SYN  9=OUTRO  (restantes: sem uso)
"""

import ctypes
import os
import sys
import time
import threading
from collections import deque
from typing import Tuple, List

# ─── Localização automática da biblioteca nativa ─────────────────────────────

def _encontrar_lib() -> str:
    """Procura netlab_core_lib na mesma pasta do módulo e no CWD."""
    candidatos = []
    base_dir   = os.path.dirname(os.path.abspath(__file__))
    nomes = (
        ["netlab_core_lib.dll"]           if sys.platform == "win32"  else
        ["netlab_core_lib.so",
         "netlab_core_lib.dylib"]
    )
    for nome in nomes:
        candidatos.append(os.path.join(base_dir, nome))
        candidatos.append(os.path.join(os.getcwd(), nome))

    for caminho in candidatos:
        if os.path.isfile(caminho):
            return caminho
    return ""


def _carregar_lib():
    """Tenta carregar a biblioteca nativa. Retorna None em caso de falha."""
    caminho = _encontrar_lib()
    if not caminho:
        return None
    try:
        lib = ctypes.CDLL(caminho)

        # Configura assinaturas das funções exportadas
        lib.nl_inicializar.restype  = None
        lib.nl_inicializar.argtypes = []

        lib.nl_resetar.restype      = None
        lib.nl_resetar.argtypes     = []

        lib.nl_adicionar_pacote.restype  = None
        lib.nl_adicionar_pacote.argtypes = [ctypes.c_uint8, ctypes.c_uint32]

        lib.nl_bytes_por_segundo.restype  = ctypes.c_double
        lib.nl_bytes_por_segundo.argtypes = [ctypes.c_uint32]

        lib.nl_obter_estatisticas.restype  = None
        lib.nl_obter_estatisticas.argtypes = [
            ctypes.POINTER(ctypes.c_uint32),
            ctypes.POINTER(ctypes.c_uint64),
        ]

        lib.nl_total_pacotes.restype  = ctypes.c_uint32
        lib.nl_total_pacotes.argtypes = []

        lib.nl_total_bytes.restype  = ctypes.c_uint64
        lib.nl_total_bytes.argtypes = []

        lib.nl_inicializar()
        return lib
    except Exception as exc:
        print(f"[netlab_core] Biblioteca nativa não carregada: {exc}. "
              "Usando fallback Python puro.", flush=True)
        return None


_lib_global = _carregar_lib()

# ─── Fallback Python puro ────────────────────────────────────────────────────

_MAX_PROTO = 16
_CBUF_CAP  = 8_192  # potência de 2

class _FallbackCore:
    """
    Implementação Python pura com buffer circular de tamanho fixo.
    Mesma interface que a versão C; usada quando a lib nativa é indisponível.
    """
    __slots__ = (
        "_buf", "_head", "_count",
        "_total_bytes", "_total_pacotes",
        "_cont", "_bytes_proto",
        "_ts_inicio", "_lock",
    )

    def __init__(self):
        self._buf           = [(0, 0, 0)] * _CBUF_CAP  # (tamanho, proto, ts_ms_rel)
        self._head          = 0
        self._count         = 0
        self._total_bytes   = 0
        self._total_pacotes = 0
        self._cont          = [0] * _MAX_PROTO
        self._bytes_proto   = [0] * _MAX_PROTO
        self._ts_inicio     = time.monotonic()
        self._lock          = threading.Lock()

    def resetar(self):
        with self._lock:
            self._buf           = [(0, 0, 0)] * _CBUF_CAP
            self._head          = 0
            self._count         = 0
            self._total_bytes   = 0
            self._total_pacotes = 0
            self._cont          = [0] * _MAX_PROTO
            self._bytes_proto   = [0] * _MAX_PROTO
            self._ts_inicio     = time.monotonic()

    def adicionar_pacote(self, proto_idx: int, tamanho: int):
        if proto_idx >= _MAX_PROTO:
            proto_idx = 9
        agora_ms  = int((time.monotonic() - self._ts_inicio) * 1000)
        with self._lock:
            self._buf[self._head] = (tamanho, proto_idx, agora_ms)
            self._head  = (self._head + 1) & (_CBUF_CAP - 1)
            if self._count < _CBUF_CAP:
                self._count += 1
            self._total_bytes          += tamanho
            self._total_pacotes        += 1
            self._cont[proto_idx]      += 1
            self._bytes_proto[proto_idx] += tamanho

    def bytes_por_segundo(self, janela_ms: int = 1000) -> float:
        if janela_ms <= 0:
            return 0.0
        agora_rel = int((time.monotonic() - self._ts_inicio) * 1000)
        corte     = max(0, agora_rel - janela_ms)
        with self._lock:
            count    = self._count
            head     = self._head
            mais_antigo = 0 if count < _CBUF_CAP else head
            soma = sum(
                self._buf[(mais_antigo + i) & (_CBUF_CAP - 1)][0]
                for i in range(count)
                if self._buf[(mais_antigo + i) & (_CBUF_CAP - 1)][2] >= corte
            )
        return soma / (janela_ms / 1000.0)

    def obter_estatisticas(self) -> Tuple[List[int], List[int]]:
        with self._lock:
            return list(self._cont), list(self._bytes_proto)

    def total_pacotes(self) -> int:
        return self._total_pacotes

    def total_bytes(self) -> int:
        return self._total_bytes


# ─── Classe pública — seleciona backend automaticamente ─────────────────────

class NetlabCore:
    """
    Interface unificada para o núcleo de métricas.
    Usa a biblioteca C se disponível; caso contrário usa o fallback Python.

    Exemplo de uso:
        core = NetlabCore()
        core.adicionar_pacote(proto_idx=2, tamanho=128)   # DNS, 128 bytes
        bps  = core.bytes_por_segundo(janela_ms=1000)
        cont, byt = core.obter_estatisticas()
    """

    PROTO_TCP     = 0
    PROTO_UDP     = 1
    PROTO_DNS     = 2
    PROTO_HTTP    = 3
    PROTO_HTTPS   = 4
    PROTO_ARP     = 5
    PROTO_ICMP    = 6
    PROTO_DHCP    = 7
    PROTO_TCP_SYN = 8
    PROTO_OUTRO   = 9

    _NOMES = {
        0: "TCP", 1: "UDP", 2: "DNS", 3: "HTTP", 4: "HTTPS",
        5: "ARP", 6: "ICMP", 7: "DHCP", 8: "TCP_SYN", 9: "Outro",
    }

    def __init__(self):
        if _lib_global is not None:
            self._nativo  = True
            self._lib     = _lib_global
            self._fallback = None
            self._lib.nl_inicializar()
        else:
            self._nativo   = False
            self._lib      = None
            self._fallback = _FallbackCore()

    @property
    def usando_nativo(self) -> bool:
        return self._nativo

    def resetar(self):
        """Reinicia todos os contadores e o buffer circular."""
        if self._nativo:
            self._lib.nl_resetar()
        else:
            self._fallback.resetar()

    def adicionar_pacote(self, proto_idx: int, tamanho: int):
        """
        Registra um pacote no buffer circular.

        Args:
            proto_idx: índice do protocolo (use constantes PROTO_*)
            tamanho:   tamanho do pacote em bytes
        """
        if self._nativo:
            self._lib.nl_adicionar_pacote(
                ctypes.c_uint8(proto_idx),
                ctypes.c_uint32(tamanho),
            )
        else:
            self._fallback.adicionar_pacote(proto_idx, tamanho)

    def bytes_por_segundo(self, janela_ms: int = 1_000) -> float:
        """
        Taxa média de transferência na janela deslizante de `janela_ms` ms.

        Args:
            janela_ms: largura da janela em milissegundos (padrão: 1000)

        Returns:
            bytes/segundo como float
        """
        if self._nativo:
            return self._lib.nl_bytes_por_segundo(ctypes.c_uint32(janela_ms))
        else:
            return self._fallback.bytes_por_segundo(janela_ms)

    def obter_estatisticas(self) -> Tuple[List[int], List[int]]:
        """
        Retorna (contadores_por_proto, bytes_por_proto) como listas de inteiros.
        Cada índice corresponde a PROTO_*.
        """
        if self._nativo:
            arr_cont  = (ctypes.c_uint32 * _MAX_PROTO)()
            arr_bytes = (ctypes.c_uint64 * _MAX_PROTO)()
            self._lib.nl_obter_estatisticas(arr_cont, arr_bytes)
            return list(arr_cont), list(arr_bytes)
        else:
            return self._fallback.obter_estatisticas()

    def total_pacotes(self) -> int:
        if self._nativo:
            return int(self._lib.nl_total_pacotes())
        else:
            return self._fallback.total_pacotes()

    def total_bytes(self) -> int:
        if self._nativo:
            return int(self._lib.nl_total_bytes())
        else:
            return self._fallback.total_bytes()

    def estatisticas_protocolos(self) -> List[dict]:
        """
        Retorna lista de dicts {'protocolo': str, 'pacotes': int, 'bytes': int}
        ordenada por número de pacotes decrescente.
        Útil para popular tabelas na UI.
        """
        cont, byt = self.obter_estatisticas()
        resultado = []
        for idx, nome in self._NOMES.items():
            if cont[idx] > 0:
                resultado.append({
                    "protocolo": nome,
                    "pacotes":   cont[idx],
                    "bytes":     byt[idx],
                })
        resultado.sort(key=lambda x: x["pacotes"], reverse=True)
        return resultado


# ─── Diagnóstico rápido (executar diretamente) ───────────────────────────────

if __name__ == "__main__":
    core = NetlabCore()
    modo = "C nativo" if core.usando_nativo else "Python puro (fallback)"
    print(f"NetlabCore inicializado — backend: {modo}")

    import random
    for _ in range(10_000):
        core.adicionar_pacote(random.randint(0, 9), random.randint(40, 1500))

    bps = core.bytes_por_segundo(1000)
    print(f"Total pacotes : {core.total_pacotes():,}")
    print(f"Total bytes   : {core.total_bytes():,}")
    print(f"BPS (1 s)     : {bps:,.0f}")
    print()
    print("Estatísticas por protocolo:")
    for s in core.estatisticas_protocolos():
        print(f"  {s['protocolo']:10s}  {s['pacotes']:6d} pkt  {s['bytes']:10d} B")
