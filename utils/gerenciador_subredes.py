"""
Gerenciador de sub-redes com classificacao de visibilidade.

Funcionamento breve:
- Mantem sub-redes conhecidas sem inventar hosts.
- Separa o que foi confirmado por evidencias reais do que foi apenas inferido.
- Usa a tabela de rotas para descobrir segmentos alcancaveis.

Exemplo de uso:
    gerenciador = GerenciadorSubRedes()
    gerenciador.adicionar_subrede(
        "192.168.0.0/24",
        gateway="192.168.0.1",
        visibilidade=Visibilidade.PARCIAL,
        local=True,
    )
    subrede, eh_local = gerenciador.classificar_ip("192.168.0.10")
    print(subrede.cidr if subrede else "fora", eh_local)
"""

from __future__ import annotations

import ipaddress
import platform
import re
import subprocess
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Set, Tuple


class Visibilidade(str, Enum):
    """Nivel de conhecimento sobre uma sub-rede."""

    TOTAL = "total"
    PARCIAL = "parcial"
    INFERIDA = "inferida"
    DESCONHECIDA = "desconhecida"

    @property
    def prioridade(self) -> int:
        """Permite promover visibilidade sem depender de ordem alfabetica."""
        ordem = {
            Visibilidade.DESCONHECIDA: 0,
            Visibilidade.INFERIDA: 1,
            Visibilidade.PARCIAL: 2,
            Visibilidade.TOTAL: 3,
        }
        return ordem[self]


@dataclass
class SubRede:
    """Representa uma sub-rede com metadados de descoberta."""

    cidr: str
    gateway: Optional[str] = None
    visibilidade: Visibilidade = Visibilidade.INFERIDA
    local: bool = False
    hosts: Set[str] = field(default_factory=set)

    def __post_init__(self):
        self._rede = ipaddress.ip_network(self.cidr, strict=False)
        self.cidr = str(self._rede)
        if self.gateway and not self.contem(self.gateway):
            self.gateway = None

    def contem(self, ip: str) -> bool:
        """Verifica se um IP pertence a esta sub-rede."""
        try:
            return ipaddress.ip_address(ip) in self._rede
        except ValueError:
            return False

    def adicionar_host(self, ip: str, confirmado: bool = False) -> bool:
        """
        Adiciona um host confirmado a esta sub-rede.

        O metodo nunca cria hosts ficticios: so registra IPs realmente
        observados pelo sistema.
        """
        if not self.contem(ip):
            return False

        self.hosts.add(ip)

        # Apenas o gateway conhecido mantem a classificacao PARCIAL.
        apenas_gateway = bool(self.gateway) and self.hosts == {self.gateway}

        if self.hosts and not apenas_gateway:
            self.visibilidade = Visibilidade.TOTAL
        elif confirmado and self.visibilidade.prioridade < Visibilidade.PARCIAL.prioridade:
            self.visibilidade = Visibilidade.PARCIAL

        return True

    @property
    def prefixo(self) -> int:
        return self._rede.prefixlen

    def __repr__(self) -> str:
        return (
            "SubRede("
            f"{self.cidr}, gateway={self.gateway}, local={self.local}, "
            f"visibilidade={self.visibilidade.value}, hosts={len(self.hosts)})"
        )


class GerenciadorSubRedes:
    """Gerencia descoberta, classificacao e sincronizacao de sub-redes."""

    _REDE_PADRAO = ipaddress.ip_network("0.0.0.0/0")

    def __init__(self):
        self.subredes: Dict[str, SubRede] = {}
        self._ip_para_subrede: Dict[str, str] = {}
        self._cidr_local_preferencial: Optional[str] = None

    def adicionar_subrede(
        self,
        cidr: str,
        gateway: Optional[str] = None,
        visibilidade: Visibilidade = Visibilidade.INFERIDA,
        local: bool = False,
    ) -> SubRede:
        """Adiciona ou atualiza uma sub-rede conhecida."""
        rede = ipaddress.ip_network(cidr, strict=False)
        cidr_normalizado = str(rede)

        if cidr_normalizado in self.subredes:
            subrede = self.subredes[cidr_normalizado]
            if gateway and subrede.contem(gateway):
                subrede.gateway = gateway
            if visibilidade.prioridade > subrede.visibilidade.prioridade:
                subrede.visibilidade = visibilidade
            if local:
                subrede.local = True
        else:
            subrede = SubRede(
                cidr=cidr_normalizado,
                gateway=gateway,
                visibilidade=visibilidade,
                local=local,
            )
            self.subredes[cidr_normalizado] = subrede

        if local:
            self._cidr_local_preferencial = cidr_normalizado

        return subrede

    def classificar_ip(self, ip: str) -> Tuple[Optional[SubRede], bool]:
        """
        Retorna (subrede, eh_local) para o IP informado.

        Quando houver sobreposicao de rotas, a sub-rede mais especifica vence.
        """
        if not ip:
            return None, False

        cidr_em_cache = self._ip_para_subrede.get(ip)
        if cidr_em_cache:
            subrede_cache = self.subredes.get(cidr_em_cache)
            if subrede_cache and subrede_cache.contem(ip):
                return subrede_cache, (subrede_cache.cidr == self._cidr_local())
            self._ip_para_subrede.pop(ip, None)

        candidatas = [subrede for subrede in self.subredes.values() if subrede.contem(ip)]
        if not candidatas:
            return None, False

        subrede = max(candidatas, key=lambda item: item.prefixo)
        self._ip_para_subrede[ip] = subrede.cidr
        return subrede, (subrede.cidr == self._cidr_local())

    def _cidr_local(self) -> Optional[str]:
        """Retorna o CIDR da sub-rede considerada local."""
        if self._cidr_local_preferencial in self.subredes:
            return self._cidr_local_preferencial
        for cidr, subrede in self.subredes.items():
            if subrede.local:
                self._cidr_local_preferencial = cidr
                return cidr
        for cidr in self.subredes:
            return cidr
        return None

    def detectar_subredes_via_rotas(self) -> List[SubRede]:
        """Descobre sub-redes alcancaveis via tabela de rotas."""
        novas_subredes: List[SubRede] = []

        for destino, gateway, mascara in self._obter_tabela_rotas():
            try:
                rede = ipaddress.ip_network(f"{destino}/{mascara}", strict=False)
            except ValueError:
                continue

            if not self._rota_eh_relevante(rede):
                continue

            cidr = str(rede)
            gateway_normalizado = gateway or None

            if cidr in self.subredes:
                subrede = self.subredes[cidr]
                if gateway_normalizado and not subrede.gateway and subrede.contem(gateway_normalizado):
                    subrede.gateway = gateway_normalizado
                continue

            subrede = self.adicionar_subrede(
                cidr=cidr,
                gateway=gateway_normalizado,
                visibilidade=Visibilidade.INFERIDA,
                local=False,
            )
            novas_subredes.append(subrede)

        return novas_subredes

    def _rota_eh_relevante(self, rede: ipaddress.IPv4Network) -> bool:
        """Filtra rotas que nao representam segmentos IPv4 relevantes para a UI."""
        if rede == self._REDE_PADRAO:
            return False
        if rede.prefixlen >= 31:
            return False
        if rede.network_address.is_loopback or rede.network_address.is_multicast:
            return False
        if rede.network_address.is_unspecified:
            return False
        if rede.network_address.is_link_local:
            return False
        return True

    def _obter_tabela_rotas(self) -> List[Tuple[str, str, str]]:
        """
        Extrai rotas IPv4 do sistema.

        Retorna tuplas no formato (destino, gateway, mascara).
        """
        if platform.system() == "Windows":
            return self._obter_rotas_windows()
        return self._obter_rotas_linux()

    def _obter_rotas_windows(self) -> List[Tuple[str, str, str]]:
        rotas: List[Tuple[str, str, str]] = []
        try:
            saida = subprocess.check_output(
                ["route", "print", "-4"],
                text=True,
                timeout=5,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
        except Exception as erro:
            print(f"[GerenciadorSubRedes] Erro ao ler rotas no Windows: {erro}")
            return rotas

        em_ipv4 = False
        padrao_rota = re.compile(
            r"^\s*(\d+\.\d+\.\d+\.\d+)\s+"
            r"(\d+\.\d+\.\d+\.\d+)\s+"
            r"(\S+)\s+"
            r"(\d+\.\d+\.\d+\.\d+)\s+\d+\s*$"
        )

        for linha in saida.splitlines():
            texto = linha.strip()
            if "IPv4 Route Table" in texto:
                em_ipv4 = True
                continue
            if not em_ipv4:
                continue
            if texto.startswith("Persistent Routes:"):
                break

            correspondencia = padrao_rota.match(linha)
            if not correspondencia:
                continue

            destino, mascara, gateway, _interface = correspondencia.groups()
            if gateway.lower() == "on-link":
                gateway = ""
            rotas.append((destino, gateway, mascara))

        return rotas

    def _obter_rotas_linux(self) -> List[Tuple[str, str, str]]:
        rotas: List[Tuple[str, str, str]] = []
        try:
            saida = subprocess.check_output(
                ["ip", "-4", "route", "show"],
                text=True,
                timeout=5,
            )
        except Exception as erro:
            print(f"[GerenciadorSubRedes] Erro ao ler rotas no Linux: {erro}")
            return rotas

        for linha in saida.splitlines():
            partes = linha.split()
            if not partes:
                continue
            if partes[0] == "default" or "/" not in partes[0]:
                continue

            try:
                rede = ipaddress.ip_network(partes[0], strict=False)
            except ValueError:
                continue

            gateway = ""
            if "via" in partes:
                indice_via = partes.index("via")
                if indice_via + 1 < len(partes):
                    gateway = partes[indice_via + 1]

            rotas.append((str(rede.network_address), gateway, str(rede.netmask)))

        return rotas

    def todas_subredes(self) -> List[SubRede]:
        """Retorna as sub-redes em ordem estavel para a interface."""
        return sorted(
            self.subredes.values(),
            key=lambda item: (
                0 if item.cidr == self._cidr_local() else 1,
                item.prefixo,
                item.cidr,
            ),
        )

    def limpar(self):
        """Remove todo o estado conhecido pelo gerenciador."""
        self.subredes.clear()
        self._ip_para_subrede.clear()
        self._cidr_local_preferencial = None


if __name__ == "__main__":
    gerenciador = GerenciadorSubRedes()
    gerenciador.adicionar_subrede(
        "192.168.10.0/24",
        gateway="192.168.10.1",
        visibilidade=Visibilidade.PARCIAL,
        local=True,
    )
    gerenciador.detectar_subredes_via_rotas()
    for subrede in gerenciador.todas_subredes():
        print(subrede)
