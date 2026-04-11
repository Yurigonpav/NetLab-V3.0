"""
Utilitarios de rede compartilhados pelo projeto NetLab.
Centraliza funcoes que estavam duplicadas em multiplos modulos.
"""

from __future__ import annotations

import socket

# Cache simples para classificacao de IP local.
_CACHE_LOCAL: dict[str, bool] = {}


def obter_ip_local() -> str:
    """
    Retorna o IP local da interface ativa.
    Usa socket UDP sem envio de dados reais.
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as socket_udp:
            socket_udp.connect(("8.8.8.8", 80))
            return socket_udp.getsockname()[0]
    except Exception:
        return "127.0.0.1"


def _calcular_eh_local(ip: str) -> bool:
    """Calcula se o IP pertence as faixas privadas RFC 1918."""
    try:
        partes = ip.split(".", 2)
        primeiro = int(partes[0])
        if primeiro == 10:
            return True
        if primeiro == 192:
            return len(partes) >= 2 and int(partes[1]) == 168
        if primeiro == 172:
            return len(partes) >= 2 and 16 <= int(partes[1]) <= 31
    except Exception:
        pass
    return False


def eh_ip_local(ip: str) -> bool:
    """
    Retorna se o IP eh local (RFC 1918), com cache interno.
    """
    resultado_cache = _CACHE_LOCAL.get(ip)
    if resultado_cache is not None:
        return resultado_cache

    resultado = _calcular_eh_local(ip)
    if len(_CACHE_LOCAL) < 8192:
        _CACHE_LOCAL[ip] = resultado
    return resultado


def eh_endereco_valido(ip: str) -> bool:
    """
    Filtra enderecos invalidos para visualizacao na topologia.
    Remove loopback, multicast, link-local, broadcast e 0.x.x.x.
    """
    if not ip:
        return False
    try:
        partes = [int(parte) for parte in ip.split(".")]
        if len(partes) != 4:
            return False
        primeiro, segundo, ultimo = partes[0], partes[1], partes[3]
        return not (
            primeiro in (0, 127)
            or (primeiro == 169 and segundo == 254)
            or 224 <= primeiro <= 239
            or ultimo == 255
            or ip == "255.255.255.255"
        )
    except Exception:
        return False


def formatar_bytes(bytes_totais: int) -> str:
    """Converte bytes para representacao legivel."""
    if bytes_totais >= 1_073_741_824:
        return f"{bytes_totais / 1_073_741_824:.2f} GB"
    if bytes_totais >= 1_048_576:
        return f"{bytes_totais / 1_048_576:.1f} MB"
    if bytes_totais >= 1_024:
        return f"{bytes_totais / 1_024:.1f} KB"
    return f"{bytes_totais} B"


def corrigir_mojibake(texto: str):
    """
    Tenta recuperar textos com encoding quebrado (cp1252/latin1 -> utf-8).
    """
    if not isinstance(texto, str):
        return texto
    for encoding in ("cp1252", "latin1"):
        try:
            return texto.encode(encoding, errors="ignore").decode("utf-8")
        except Exception:
            continue
    return texto

