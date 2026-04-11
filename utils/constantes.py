"""
Constantes compartilhadas entre paineis e analisador.
Evita duplicacao de cores, classificacoes e portas conhecidas.
"""

from __future__ import annotations

CORES_PROTOCOLO: dict[str, str] = {
    "HTTP": "#E74C3C",
    "HTTPS": "#2ECC71",
    "DNS": "#3498DB",
    "TCP": "#9B59B6",
    "UDP": "#F39C12",
    "ICMP": "#1ABC9C",
    "ARP": "#E67E22",
    "SSH": "#2980B9",
    "FTP": "#E91E63",
    "SMB": "#795548",
    "RDP": "#FF5722",
    "DHCP": "#16A085",
    "Outro": "#7F8C8D",
}

CLASSIFICACAO_USO: dict[str, tuple[str, str]] = {
    "DNS": ("Navegação", CORES_PROTOCOLO["DNS"]),
    "HTTP": ("Transferência HTTP", CORES_PROTOCOLO["HTTP"]),
    "HTTPS": ("Conexão Segura", CORES_PROTOCOLO["HTTPS"]),
    "TCP_SYN": ("Nova Conexão", CORES_PROTOCOLO["TCP"]),
    "ARP": ("Descoberta Local", CORES_PROTOCOLO["ARP"]),
    "ICMP": ("Diagnóstico/Ping", CORES_PROTOCOLO["ICMP"]),
    "DHCP": ("Config. de Rede", CORES_PROTOCOLO["DHCP"]),
    "SSH": ("Acesso Remoto", CORES_PROTOCOLO["SSH"]),
    "FTP": ("Transfer. Arquivo", CORES_PROTOCOLO["FTP"]),
    "SMB": ("Compartilhamento", CORES_PROTOCOLO["SMB"]),
    "RDP": ("Desktop Remoto", CORES_PROTOCOLO["RDP"]),
    "NOVO_DISPOSITIVO": ("Novo Dispositivo", "#F39C12"),
}

PORTAS_HTTP: frozenset[int] = frozenset({80, 8080, 8000})
PORTAS_HTTPS: frozenset[int] = frozenset({443, 8443})
PORTAS_DHCP: frozenset[int] = frozenset({67, 68})
