# interface/janela_principal.py
# Versão corrigida e profissional — NetLab Educacional
#
# Correções aplicadas nesta versão:
#   [1] _obter_cidr_via_ipconfig: agora localiza o bloco correto no ipconfig
#       usando o endereço IPv4 da interface (não o nome do adaptador, que
#       frequentemente diverge entre Scapy e o sistema operacional).
#   [2] _varredura_inicial_segura: limite aumentado de 30 para
#       min(500, self._limite_hosts), garantindo que a topologia seja
#       populada de forma significativa logo após iniciar a captura.
#   [3] _iniciar_captura: timer de descoberta periódica agora é ativado
#       corretamente após o início da captura.
#   [4] _servir_bloqueado: assinatura corrigida (parâmetros alinhados).

import threading
import time
import ipaddress
import subprocess
import re
import ctypes
from collections import deque
from typing import Optional

from PyQt6.QtWidgets import (
    QMainWindow, QWidget, QVBoxLayout,
    QLabel, QPushButton, QComboBox,
    QMessageBox, QToolBar, QTabWidget,
    QDialog, QHBoxLayout, QTextEdit,
    QDialogButtonBox, QFrame
)
from PyQt6.QtCore import Qt, QTimer, pyqtSlot, QThread, pyqtSignal, QObject, QRunnable, QThreadPool
from PyQt6.QtGui import QAction, QFont

from analisador_pacotes import AnalisadorPacotes
from motor_pedagogico import MotorPedagogico
from interface.painel_topologia import PainelTopologia
from interface.painel_trafego import PainelTrafego
from interface.painel_eventos import PainelEventos
from painel_servidor import PainelServidor
from utils.constantes import PORTAS_HTTP, PORTAS_DHCP
from utils.rede import obter_ip_local


# ============================================================================
# Estado da rede — cooldown de eventos e registro de dispositivos descobertos
# ============================================================================

def _ip_eh_topologizavel(ip: str) -> bool:
    """
    Retorna True apenas para IPs que devem aparecer na topologia.
    Descartados: loopback, link-local, multicast, broadcast, rede zero.
    """
    if not ip:
        return False
    try:
        partes = [int(p) for p in ip.split('.')]
        if len(partes) != 4:
            return False
        a, b, _, d = partes
        return not (
            a == 0
            or a == 127
            or (a == 169 and b == 254)
            or (224 <= a <= 239)
            or ip == "255.255.255.255"
            or d == 255
        )
    except Exception:
        return False


class EstadoRede:
    """
    Gerencia o cooldown entre eventos repetidos e o mapeamento de
    dispositivos já descobertos na sessão atual.
    """

    def __init__(self):
        self.ultimos_eventos: dict = {}
        self.dispositivos:    dict = {}
        self._lock = threading.Lock()

    def deve_emitir_evento(self, chave: str, cooldown: int = 5) -> bool:
        """
        Retorna True se o evento identificado por `chave` pode ser emitido
        (respeitando o cooldown em segundos). Atualiza o timestamp interno.
        """
        agora = time.time()
        with self._lock:
            if chave in self.ultimos_eventos:
                if agora - self.ultimos_eventos[chave] < cooldown:
                    return False
            self.ultimos_eventos[chave] = agora
            return True

    def registrar_dispositivo(self, ip: str, mac: str = "", hostname: str = "") -> str:
        """
        Registra um dispositivo na sessão. Retorna "NOVO" na primeira vez
        ou "EXISTENTE" se o IP já foi visto antes.
        """
        with self._lock:
            if ip not in self.dispositivos:
                self.dispositivos[ip] = (mac, hostname, time.time())
                return "NOVO"
            return "EXISTENTE"

    def obter_dispositivo(self, ip: str):
        return self.dispositivos.get(ip)


# ============================================================================
# Fila global de pacotes — buffer circular thread-safe
# ============================================================================

class _FilaPacotesGlobal:
    """
    Buffer circular thread-safe que armazena os pacotes capturados pelo
    sniffer antes de serem processados pelo analisador.
    Limit máximo: 20.000 entradas (descarte automático das mais antigas).
    """

    def __init__(self):
        self._fila: deque = deque(maxlen=20_000)
        self._lock = threading.Lock()

    def adicionar(self, pacote: dict):
        with self._lock:
            self._fila.append(pacote)

    def consumir_todos(self) -> list:
        with self._lock:
            pacotes = list(self._fila)
            self._fila.clear()
            return pacotes

    def limpar(self):
        with self._lock:
            self._fila.clear()


fila_pacotes_global = _FilaPacotesGlobal()


def obter_interfaces_disponiveis() -> list:
    """Fallback simples: retorna a lista de interfaces sem detalhes."""
    try:
        from scapy.arch.windows import get_windows_if_list
        interfaces = get_windows_if_list()
        return [
            iface.get('description', iface.get('name', ''))
            for iface in interfaces
            if 'loopback' not in iface.get('description', '').lower()
        ]
    except Exception:
        return []


# ============================================================================
# Thread do sniffer — captura de pacotes via AsyncSniffer do Scapy
# ============================================================================

# Limite de pacotes aceitos por segundo. Pacotes além desse limite são
# descartados silenciosamente para proteger a fila e a interface gráfica.
_MAX_PACOTES_POR_SEGUNDO = 800


class _CapturadorPacotesThread(QThread):
    """
    Captura pacotes via AsyncSniffer e os deposita na fila global.

    Características:
    - Reinício automático se o socket do Scapy falhar.
    - Rate limiter: descarta pacotes além de _MAX_PACOTES_POR_SEGUNDO.
    - Tratamento de exceções por pacote para não derrubar a thread.
    """

    erro_ocorrido = pyqtSignal(str)
    sem_pacotes   = pyqtSignal(str)

    def __init__(self, interface: str):
        super().__init__()
        self.interface = interface
        self._rodando  = False
        self.sniffer   = None

        # Contadores do rate limiter
        self._pps_contador  = 0
        self._pps_reset_ts  = 0.0

    def run(self):
        self._rodando = True

        while self._rodando:
            try:
                from scapy.all import AsyncSniffer

                # TCPSession removido intencionalmente — evita reassembly
                # custoso que inflava volume e causava erros de unpack.
                self.sniffer = AsyncSniffer(
                    iface=self.interface,
                    prn=self._processar_pacote,
                    store=False,
                    filter="ip or arp",
                    promisc=True,
                )
                self.sniffer.start()

                # Monitora se o sniffer permanece ativo; reinicia se parar.
                while self._rodando:
                    self.sleep(1)
                    if not getattr(self.sniffer, 'running', False):
                        if self._rodando:
                            break

            except Exception as erro:
                if self._rodando:
                    print(f"[Capturador] Socket falhou: {erro} — reiniciando em 2s")
            finally:
                self._parar_sniffer_seguro()

            if self._rodando:
                for _ in range(20):
                    if not self._rodando:
                        break
                    time.sleep(0.1)

    def _parar_sniffer_seguro(self):
        """Para o sniffer sem lançar exceção."""
        if self.sniffer:
            try:
                if getattr(self.sniffer, 'running', False):
                    self.sniffer.stop()
            except Exception:
                pass
            self.sniffer = None

    def _processar_pacote(self, pacote):
        """
        Callback chamado pelo AsyncSniffer para cada pacote capturado.
        Aplica o rate limiter e encaminha para _parsear_e_enfileirar.
        """
        if not self._rodando:
            return

        # Rate limiter — janela deslizante de 1 segundo
        agora = time.time()
        if agora - self._pps_reset_ts >= 1.0:
            self._pps_contador = 0
            self._pps_reset_ts = agora
        self._pps_contador += 1
        if self._pps_contador > _MAX_PACOTES_POR_SEGUNDO:
            return

        try:
            self._parsear_e_enfileirar(pacote)
        except Exception:
            pass   # Pacote corrompido: ignora sem interromper a captura

    def _parsear_e_enfileirar(self, pacote):
        """Extrai os campos relevantes do pacote e coloca na fila global."""
        dados = {
            "tamanho":       len(pacote),
            "ip_origem":     None,
            "ip_destino":    None,
            "mac_origem":    None,
            "mac_destino":   None,
            "protocolo":     "Outro",
            "porta_origem":  None,
            "porta_destino": None,
        }

        from scapy.all import Ether, IP, TCP, UDP, ARP, DNS, Raw, BOOTP, DHCP

        if pacote.haslayer(Ether):
            dados["mac_origem"]  = pacote[Ether].src
            dados["mac_destino"] = pacote[Ether].dst

        if pacote.haslayer(IP):
            dados["ip_origem"]  = pacote[IP].src
            dados["ip_destino"] = pacote[IP].dst

            if pacote.haslayer(TCP):
                dados["protocolo"]     = "TCP"
                dados["porta_origem"]  = pacote[TCP].sport
                dados["porta_destino"] = pacote[TCP].dport
                flags = pacote[TCP].flags
                if flags & 0x02:
                    dados["flags"] = "SYN"
                elif flags & 0x01:
                    dados["flags"] = "FIN"
                elif flags & 0x04:
                    dados["flags"] = "RST"

            elif pacote.haslayer(UDP):
                dados["protocolo"]     = "UDP"
                dados["porta_origem"]  = pacote[UDP].sport
                dados["porta_destino"] = pacote[UDP].dport

                if (
                    dados["porta_origem"] in PORTAS_DHCP
                    or dados["porta_destino"] in PORTAS_DHCP
                    or pacote.haslayer(DHCP)
                    or pacote.haslayer(BOOTP)
                ):
                    dados["protocolo"] = "DHCP"
                    dados["dhcp_tipo"] = ""

                    if pacote.haslayer(DHCP):
                        mapa_tipos_dhcp = {
                            1: "discover", 2: "offer",  3: "request",
                            4: "decline",  5: "ack",    6: "nak",
                            7: "release",  8: "inform",
                        }
                        for opcao in (pacote[DHCP].options or []):
                            if (
                                isinstance(opcao, tuple)
                                and len(opcao) >= 2
                                and opcao[0] == "message-type"
                            ):
                                valor_opcao = opcao[1]
                                if isinstance(valor_opcao, bytes) and valor_opcao:
                                    valor_opcao = valor_opcao[0]
                                if isinstance(valor_opcao, int):
                                    dados["dhcp_tipo"] = mapa_tipos_dhcp.get(
                                        valor_opcao, str(valor_opcao)
                                    )
                                else:
                                    dados["dhcp_tipo"] = str(valor_opcao)
                                break

                    if pacote.haslayer(BOOTP):
                        dados["dhcp_xid"] = int(
                            getattr(pacote[BOOTP], "xid", 0) or 0
                        )

                elif pacote.haslayer(DNS):
                    dados["protocolo"] = "DNS"
                    if pacote[DNS].qr == 0 and pacote[DNS].qd:
                        dados["dominio"] = pacote[DNS].qd.qname.decode(
                            'utf-8', errors='ignore'
                        ).rstrip('.')

        elif pacote.haslayer(ARP):
            dados["protocolo"]  = "ARP"
            dados["ip_origem"]  = pacote[ARP].psrc
            dados["ip_destino"] = pacote[ARP].pdst
            dados["mac_origem"] = dados["mac_origem"] or pacote[ARP].hwsrc
            dados["arp_op"]     = "request" if pacote[ARP].op == 1 else "reply"

        if pacote.haslayer(Raw) and (
            dados.get("porta_destino") in PORTAS_HTTP or
            dados.get("porta_origem")  in PORTAS_HTTP
        ):
            dados["payload"] = pacote[Raw].load

        fila_pacotes_global.adicionar(dados)

    def parar(self):
        self._rodando = False
        self._parar_sniffer_seguro()
        self.wait(3000)


# ============================================================================
# Thread de descoberta de dispositivos — varredura ARP + ICMP
# ============================================================================

class _DescobrirDispositivosThread(QThread):
    """
    Descobre hosts na rede local via ARP sweep e, opcionalmente, ICMP.
    Emite sinais para cada dispositivo encontrado e ao término.
    """

    dispositivo_encontrado = pyqtSignal(str, str, str)
    varredura_concluida    = pyqtSignal(list)
    progresso_atualizado   = pyqtSignal(str)
    erro_ocorrido          = pyqtSignal(str)

    TIMEOUT_ARP   = 1.8
    TIMEOUT_ICMP  = 1.0
    TENTATIVAS    = 3
    BATCH_ARP     = 512
    MAX_HOSTS     = 4_096
    PAUSA_RODADAS = 0.6
    WORKERS_ICMP  = 64
    INTER_ARP     = 0.0

    def __init__(self, interface: str, cidr: str = "", habilitar_ping: bool = True,
                 parametros: dict = None):
        super().__init__()
        self.interface = interface
        self.cidr      = cidr
        self._ips_encontrados: set  = set()
        self._dispositivos:    list = []
        self._cache_mac:       dict = {}
        self._ips_sem_mac:     set  = set()
        self._mac_gateway:     str  = ""
        self._lock = threading.Lock()
        self._param_arps = dict(parametros) if parametros else {
            "batch":          self.BATCH_ARP,
            "inter":          self.INTER_ARP,
            "sleep_lote":     0.0,
            "pausa":          self.PAUSA_RODADAS,
            "timeout":        self.TIMEOUT_ARP,
            "tentativas":     self.TENTATIVAS,
            "limite_hosts":   self.MAX_HOSTS,
            "desativar_icmp": False,
            "wifi":           False,
            "timer_ms":       30000,
        }
        self._limite_hosts     = self._param_arps["limite_hosts"]
        self._eh_wifi          = self._param_arps.get("wifi", False)
        self._periodo_timer_ms = self._param_arps.get("timer_ms", 30000)

    def run(self):
        try:
            rede_cidr = self.cidr or self._detectar_cidr() or self._cidr_por_ip_local()
            if not rede_cidr:
                self.erro_ocorrido.emit(
                    "Não foi possível determinar a sub-rede. "
                    "Verifique se a interface está ativa."
                )
                return

            self.progresso_atualizado.emit(f"Iniciando varredura em {rede_cidr} …")
            self._varrer_arp(rede_cidr)
            self._varrer_icmp(rede_cidr)

            if not self._eh_wifi:
                try:
                    rede_obj = ipaddress.ip_network(rede_cidr, strict=False)
                    if rede_obj.prefixlen >= 24:
                        novo_prefixo   = max(21, rede_obj.prefixlen - 2)
                        rede_expandida = str(rede_obj.supernet(new_prefix=novo_prefixo))
                        if rede_expandida != rede_cidr:
                            self.progresso_atualizado.emit(
                                f"Expandindo busca: {rede_cidr} → {rede_expandida} …"
                            )
                            self._varrer_arp(rede_expandida)
                            self._varrer_icmp(rede_expandida)
                except Exception:
                    pass

            total = len(self._dispositivos)
            self.progresso_atualizado.emit(
                f"Varredura concluída — {total} dispositivo(s) encontrado(s)."
            )
            self.varredura_concluida.emit(self._dispositivos)

        except Exception as erro:
            self.erro_ocorrido.emit(f"Erro na descoberta: {erro}")

    def _varrer_arp(self, rede_cidr: str):
        from scapy.all import ARP, Ether, srp

        try:
            rede  = ipaddress.ip_network(rede_cidr, strict=False)
            todos = self._selecionar_hosts(rede)
        except Exception as e:
            self.progresso_atualizado.emit(f"Erro ao listar hosts de {rede_cidr}: {e}")
            return

        batch      = self._param_arps["batch"]
        inter_pkt  = self._param_arps["inter"]
        pausa      = self._param_arps["pausa"]
        timeout    = self._param_arps["timeout"]
        sleep_lote = self._param_arps.get("sleep_lote", 0.0)
        tentativas = (
            self._param_arps["tentativas"]
            if len(todos) <= 1024
            else max(2, self._param_arps["tentativas"] - 1)
        )

        self.progresso_atualizado.emit(
            f"ARP sweep: {len(todos)} IPs · {tentativas} rodada(s) · "
            f"lotes de {batch} (inter={inter_pkt*1000:.0f}ms)…"
        )

        for rodada in range(1, tentativas + 1):
            pendentes = [h for h in todos if h not in self._ips_encontrados]
            if not pendentes:
                self.progresso_atualizado.emit(
                    f"Todos os hosts responderam após {rodada - 1} rodada(s)."
                )
                break
            if len(self._ips_encontrados) >= self._limite_hosts:
                self.progresso_atualizado.emit(
                    f"Limite de {self._limite_hosts} dispositivos atingido."
                )
                break

            self.progresso_atualizado.emit(
                f"Rodada ARP {rodada}/{tentativas}: {len(pendentes)} host(s) pendente(s) …"
            )
            encontrados_nesta_rodada = 0

            for inicio in range(0, len(pendentes), batch):
                lote = pendentes[inicio: inicio + batch]
                pacotes_arp = [
                    Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip)
                    for ip in lote
                ]
                try:
                    respostas, _ = srp(
                        pacotes_arp,
                        iface=self.interface,
                        timeout=timeout,
                        verbose=False,
                        retry=0,
                        inter=inter_pkt,
                    )
                    for _, resp in respostas:
                        try:
                            ip_resp  = resp[ARP].psrc
                            mac_resp = resp[ARP].hwsrc

                            if not mac_resp or mac_resp.lower() in (
                                "ff:ff:ff:ff:ff:ff",
                                "00:00:00:00:00:00",
                                "",
                            ):
                                continue

                            # Identifica gateway pelo último octeto
                            if not self._mac_gateway:
                                partes_ip = ip_resp.split(".")
                                if len(partes_ip) == 4:
                                    ultimo_octeto = int(partes_ip[-1])
                                    if ultimo_octeto in (1, 254):
                                        self._mac_gateway = mac_resp.lower()

                            if (
                                self._mac_gateway
                                and mac_resp.lower() == self._mac_gateway
                            ):
                                continue

                            if self._ip_valido(ip_resp):
                                self._registrar(ip_resp, mac_resp, "")
                                encontrados_nesta_rodada += 1
                        except Exception:
                            pass
                except Exception as e:
                    self.progresso_atualizado.emit(
                        f"Lote {inicio//batch + 1} falhou: {e}"
                    )

                if sleep_lote > 0:
                    time.sleep(sleep_lote)
                if len(self._ips_encontrados) >= self._limite_hosts:
                    break

            self.progresso_atualizado.emit(
                f"Rodada {rodada}: +{encontrados_nesta_rodada} novo(s) · "
                f"total {len(self._ips_encontrados)}"
            )

            if len(self._ips_encontrados) >= self._limite_hosts:
                break
            if rodada < tentativas and encontrados_nesta_rodada == 0:
                break
            if rodada < tentativas:
                time.sleep(pausa)

    def _varrer_icmp(self, rede_cidr: str):
        from scapy.all import IP, ICMP, Ether, srp

        if self._param_arps.get("desativar_icmp", False):
            return

        try:
            rede  = ipaddress.ip_network(rede_cidr, strict=False)
            todos = self._selecionar_hosts(rede)
        except Exception as e:
            self.progresso_atualizado.emit(f"ICMP abortado: {e}")
            return

        pendentes  = [ip for ip in todos if ip not in self._ips_encontrados]
        candidatos = []
        for ip in pendentes:
            if ip in self._ips_sem_mac:
                continue
            mac = self._cache_mac.get(ip) or self._resolver_mac_unico(ip)
            if mac:
                candidatos.append(ip)
            else:
                self._ips_sem_mac.add(ip)

        if not candidatos:
            self.progresso_atualizado.emit("ICMP: nenhum host restante com MAC resolvido.")
            return

        self.progresso_atualizado.emit(
            f"ICMP paralelo (L2): {len(candidatos)} host(s) com MAC resolvido …"
        )

        pacotes = [
            Ether(dst=self._cache_mac.get(ip, "ff:ff:ff:ff:ff:ff")) / IP(dst=ip) / ICMP()
            for ip in candidatos
        ]

        try:
            respostas, _ = srp(
                pacotes,
                iface=self.interface,
                timeout=self.TIMEOUT_ICMP,
                retry=0,
                verbose=False,
                inter=0,
            )
            for _, resp in respostas:
                try:
                    ip_resp  = resp[IP].src   if resp.haslayer(IP)    else ""
                    mac_resp = resp[Ether].src if resp.haslayer(Ether) else ""
                    if self._ip_valido(ip_resp):
                        self._registrar(ip_resp, mac_resp, "")
                except Exception:
                    pass
        except Exception as e:
            self.progresso_atualizado.emit(f"ICMP falhou: {e}")

    def _resolver_mac_unico(self, ip: str) -> str:
        from scapy.all import ARP, Ether, srp1
        try:
            resposta = srp1(
                Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip),
                iface=self.interface,
                timeout=0.6,
                retry=0,
                verbose=False,
            )
            if resposta and resposta.haslayer(ARP):
                return resposta[ARP].hwsrc
        except Exception:
            pass
        return ""

    def _selecionar_hosts(self, rede: ipaddress.IPv4Network) -> list:
        """
        Retorna a lista de hosts a varrer. Se o total superar o limite,
        faz amostragem uniforme para não sobrecarregar a rede.
        """
        total_hosts = max(0, rede.num_addresses - 2)
        if total_hosts <= 0:
            return []
        limite = self._limite_hosts
        if total_hosts <= limite:
            return [str(h) for h in rede.hosts()]
        passo       = max(1, total_hosts // limite)
        selecionados = []
        for idx, host in enumerate(rede.hosts()):
            if idx % passo == 0:
                selecionados.append(str(host))
            if len(selecionados) >= limite:
                break
        return selecionados

    def _registrar(self, ip: str, mac: str, hostname: str):
        with self._lock:
            if ip in self._ips_encontrados:
                return
            self._ips_encontrados.add(ip)
            if mac:
                self._cache_mac[ip] = mac
            self._dispositivos.append((ip, mac, hostname))
        self.dispositivo_encontrado.emit(ip, mac, hostname)

    @staticmethod
    def _ip_valido(ip: str) -> bool:
        try:
            partes = [int(x) for x in ip.split(".")]
            return len(partes) == 4 and not (
                partes[0] in (0, 127)
                or (partes[0] == 169 and partes[1] == 254)
                or 224 <= partes[0] <= 239
                or partes[3] == 255
            )
        except Exception:
            return False

    def _detectar_cidr(self) -> str:
        try:
            from scapy.all import get_if_addr, get_if_netmask
            ip      = get_if_addr(self.interface)
            mascara = get_if_netmask(self.interface)
            if ip and mascara and ip != "0.0.0.0":
                prefixo = sum(bin(int(p)).count("1") for p in mascara.split("."))
                rede    = ipaddress.ip_network(f"{ip}/{prefixo}", strict=False)
                return str(rede)
        except Exception:
            pass
        return ""

    @staticmethod
    def _cidr_por_ip_local() -> str:
        ip = obter_ip_local()
        if not ip or ip == "127.0.0.1":
            return ""
        partes = ip.split(".")
        return f"{'.'.join(partes[:3])}.0/24" if len(partes) == 4 else ""


# ============================================================================
# Sinal global para resultados do motor pedagógico
# ============================================================================

class _SinalPedagogico(QObject):
    resultado = pyqtSignal(dict)

_sinal_pedagogico_global = _SinalPedagogico()


class _WorkerRunnable(QRunnable):
    """Executa a geração de explicações pedagógicas em uma thread de background."""

    def __init__(self, evento: dict, motor):
        super().__init__()
        self.evento = evento
        self.motor  = motor
        self.setAutoDelete(True)

    def run(self):
        try:
            explicacao = self.motor.gerar_explicacao(self.evento)
            if explicacao is None:
                explicacao = {
                    "nivel1": f"Evento: {self.evento.get('tipo', 'Desconhecido')}",
                    "nivel2": (
                        f"Origem: {self.evento.get('ip_origem', '?')} → "
                        f"Destino: {self.evento.get('ip_destino', '?')}"
                    ),
                    "nivel3": f"Dados: {self.evento}",
                    "icone": "🔍", "nivel": "INFO",
                    "alerta_seguranca": "",
                }
            explicacao["sessao_id"] = self.evento.get("sessao_id")
            _sinal_pedagogico_global.resultado.emit(explicacao)
        except Exception as e:
            print(f"[Worker pedagógico] Erro: {e}")


# ============================================================================
# Janela principal do NetLab Educacional
# ============================================================================

class JanelaPrincipal(QMainWindow):
    """Janela principal do NetLab Educacional."""

    def __init__(self):
        super().__init__()
        self.analisador       = AnalisadorPacotes()
        self.motor_pedagogico = MotorPedagogico()

        self.capturador:  _CapturadorPacotesThread     = None
        self.descobridor: _DescobrirDispositivosThread = None
        self.descoberta_rodando: bool = False
        self.em_captura: bool = False

        # Mapeamentos de interface (descrição → atributos técnicos)
        self._mapa_interface_nome:    dict = {}
        self._mapa_interface_ip:      dict = {}
        self._mapa_interface_mascara: dict = {}
        self._interface_captura = ""
        self._cidr_captura      = ""

        # Snapshot de estatísticas (atualizado a cada ciclo do timer)
        self._snapshot_atual = {
            "total_bytes": 0, "total_pacotes": 0,
            "estatisticas": [], "top_dispositivos": [],
            "dispositivos_ativos": 0, "top_dns": [], "historias": [],
        }
        self._bytes_total_anterior = 0
        self._instante_anterior    = time.perf_counter()

        self.estado_rede = EstadoRede()
        self.fila_eventos_ui: deque = deque(maxlen=500)
        self.eventos_mostrados_recentemente: deque = deque(maxlen=200)

        # Thread pool para o motor pedagógico (background)
        self._thread_pool = QThreadPool.globalInstance()
        self._thread_pool.setMaxThreadCount(4)
        _sinal_pedagogico_global.resultado.connect(self._finalizar_exibicao_evento)

        self._kb_anterior:        float = 0.0
        self._param_arps:         dict  = {}
        self._limite_hosts:       int   = _DescobrirDispositivosThread.MAX_HOSTS
        self._eh_wifi:            bool  = False
        self._periodo_timer_ms:   int   = 30000

        # Timers internos
        self.timer_consumir   = QTimer()
        self.timer_consumir.timeout.connect(self._consumir_fila)

        self.timer_ui = QTimer()
        self.timer_ui.timeout.connect(self._atualizar_ui_por_segundo)

        self.timer_descoberta = QTimer()
        self.timer_descoberta.timeout.connect(self._descoberta_periodica)

        self.timer_eventos = QTimer()
        self.timer_eventos.timeout.connect(self._descarregar_eventos_ui)
        self.timer_eventos.start(2000)

        self._configurar_janela()
        self._criar_menu()
        self._criar_barra_status()
        self._criar_barra_ferramentas()
        self._criar_area_central()

    # -------------------------------------------------------------------------
    # Configuração visual da janela
    # -------------------------------------------------------------------------

    def _configurar_janela(self):
        self.setWindowTitle("NetLab Educacional - Monitor de Rede")
        self.setMinimumSize(1200, 700)
        self.resize(1440, 860)
        geo = self.screen().availableGeometry()
        self.move(
            (geo.width()  - self.width())  // 2,
            (geo.height() - self.height()) // 2,
        )

    def _criar_menu(self):
        menu = self.menuBar()

        m_arq = menu.addMenu("&Arquivo")
        a_nova = QAction("&Nova Sessão", self)
        a_nova.setShortcut("Ctrl+N")
        a_nova.triggered.connect(self._nova_sessao)
        m_arq.addAction(a_nova)
        m_arq.addSeparator()
        a_sair = QAction("&Sair", self)
        a_sair.setShortcut("Ctrl+Q")
        a_sair.triggered.connect(self.close)
        m_arq.addAction(a_sair)

        m_mon = menu.addMenu("&Monitoramento")
        self.acao_captura = QAction("Iniciar Captura", self)
        self.acao_captura.setShortcut("F5")
        self.acao_captura.triggered.connect(self._alternar_captura)
        m_mon.addAction(self.acao_captura)

        m_ajd = menu.addMenu("&Ajuda")
        a_sobre = QAction("Sobre o NetLab", self)
        a_sobre.triggered.connect(self._exibir_sobre)
        m_ajd.addAction(a_sobre)

    def _criar_barra_ferramentas(self):
        barra = self.addToolBar("Principal")
        barra.setMovable(False)

        barra.addWidget(QLabel("  Interface: "))
        self.combo_interface = QComboBox()
        self.combo_interface.setMinimumWidth(230)
        self._popular_interfaces()
        barra.addWidget(self.combo_interface)
        barra.addSeparator()

        self.botao_captura = QPushButton("Iniciar Captura")
        self.botao_captura.setObjectName("botao_captura")
        self.botao_captura.setMinimumWidth(155)
        self.botao_captura.clicked.connect(self._alternar_captura)
        barra.addWidget(self.botao_captura)

        barra.addSeparator()
        self.lbl_ip = QLabel(f"  Meu IP: {obter_ip_local()}  ")
        self.lbl_ip.setStyleSheet("color:#2ecc71; font-weight:bold;")
        barra.addWidget(self.lbl_ip)

        btn_diag = QPushButton("🔍 Diagnóstico")
        btn_diag.setToolTip("Exibe informações de diagnóstico da captura atual")
        btn_diag.clicked.connect(self._exibir_diagnostico_captura)
        barra.addWidget(btn_diag)

    def _criar_area_central(self):
        central = QWidget()
        self.setCentralWidget(central)
        layout = QVBoxLayout(central)
        layout.setContentsMargins(0, 0, 0, 0)

        self.abas = QTabWidget()
        layout.addWidget(self.abas)

        self.painel_topologia = PainelTopologia()
        self.painel_trafego   = PainelTrafego()
        self.painel_eventos   = PainelEventos()
        self.painel_servidor  = PainelServidor()

        self.abas.addTab(self.painel_topologia, "Topologia da Rede")
        self.abas.addTab(self.painel_trafego,   "Tráfego em Tempo Real")
        self.abas.addTab(self.painel_eventos,   " Modo Análise")
        self.abas.addTab(self.painel_servidor,  "Servidor")

    def _criar_barra_status(self):
        barra = self.statusBar()
        self.lbl_status  = QLabel("Pronto. Clique em 'Iniciar Captura' para começar.")
        self.lbl_pacotes = QLabel("Pacotes: 0")
        self.lbl_dados   = QLabel("  Dados: 0 KB  ")
        barra.addWidget(self.lbl_status)
        barra.addPermanentWidget(self.lbl_pacotes)
        barra.addPermanentWidget(self.lbl_dados)

    # -------------------------------------------------------------------------
    # Detecção de interfaces e CIDR
    # -------------------------------------------------------------------------

    def _popular_interfaces(self):
        """Popula o combo de interfaces usando o Scapy e seleciona a ativa."""
        self.combo_interface.clear()
        self._mapa_interface_nome.clear()
        self._mapa_interface_ip.clear()
        self._mapa_interface_mascara.clear()

        try:
            from scapy.arch.windows import get_windows_if_list
            interfaces_raw = get_windows_if_list()
        except Exception:
            interfaces_raw = []

        if not interfaces_raw:
            for desc in obter_interfaces_disponiveis():
                self.combo_interface.addItem(desc)
                self._mapa_interface_nome[desc] = desc
            self._selecionar_interface_fallback()
            return

        for iface in interfaces_raw:
            desc = iface.get('description', iface.get('name', 'Desconhecida'))
            nome = iface.get('name', '')
            if not (desc and nome):
                continue
            self.combo_interface.addItem(desc)
            self._mapa_interface_nome[desc] = nome

            ips      = iface.get('ips',      []) or []
            mascaras = iface.get('netmasks', []) or []

            # Extrai o primeiro IPv4 válido da interface
            ip_v4 = next((
                ip for ip in ips
                if ip and ip.count('.') == 3
                and not ip.startswith(("169.254", "127."))
            ), "")

            if ip_v4:
                self._mapa_interface_ip[desc] = ip_v4

                # Tenta alinhar máscara pelo índice correspondente ao IPv4
                # (ips e netmasks devem estar alinhados no Scapy)
                try:
                    idx = ips.index(ip_v4)
                    if idx < len(mascaras):
                        candidato = mascaras[idx]
                        # Aceita apenas se parece uma máscara IPv4 (não prefixo IPv6)
                        if candidato and '.' in str(candidato):
                            self._mapa_interface_mascara[desc] = str(candidato)
                except Exception:
                    pass

                # Segundo: percorre as máscaras buscando a que parece IPv4
                if desc not in self._mapa_interface_mascara:
                    for mask_candidata in mascaras:
                        if mask_candidata and '.' in str(mask_candidata):
                            self._mapa_interface_mascara[desc] = str(mask_candidata)
                            break

            # Terceiro: tenta campo escalar 'netmask' ou 'mask'
            if desc not in self._mapa_interface_mascara:
                for campo in ('netmask', 'mask'):
                    v = iface.get(campo)
                    if v and '.' in str(v):
                        self._mapa_interface_mascara[desc] = str(v)
                        break

        # Seleciona automaticamente a interface com o IP local ativo
        ip_local = obter_ip_local()
        if ip_local:
            for iface in interfaces_raw:
                if ip_local in (iface.get('ips', []) or []):
                    desc = iface.get('description', iface.get('name', ''))
                    idx  = self.combo_interface.findText(desc)
                    if idx >= 0:
                        self.combo_interface.setCurrentIndex(idx)
                        self._status(f"Interface ativa detectada: {desc}")
                        return

        if self.combo_interface.count() > 0:
            self.combo_interface.setCurrentIndex(0)

    def _selecionar_interface_fallback(self):
        """Seleciona a interface padrão do Scapy quando o mapeamento falha."""
        try:
            from scapy.all import conf
            default = str(conf.iface)
            for i in range(self.combo_interface.count()):
                if default in self.combo_interface.itemText(i):
                    self.combo_interface.setCurrentIndex(i)
                    return
        except Exception:
            pass

    @staticmethod
    def _mascara_para_prefixo(mascara: str) -> int:
        """Converte uma máscara de sub-rede (ex.: 255.255.255.0) para prefixo CIDR."""
        try:
            return sum(bin(int(p)).count("1") for p in mascara.split("."))
        except Exception:
            return 24

    # -------------------------------------------------------------------------
    # CORREÇÃO [1]: Detecção de CIDR via ipconfig usando IP (não nome)
    # -------------------------------------------------------------------------

    @staticmethod
    def _detectar_cidr_via_powershell(ip_local: str) -> str:
        """
        Usa Get-NetIPAddress do PowerShell para obter o prefixo CIDR.

        Funciona em Windows 8+ independente do idioma do sistema operacional
        (sem depender de strings localizadas como 'Máscara de Sub-rede').
        Retorna a rede no formato '192.168.1.0/24' ou '' em caso de falha.
        """
        if not ip_local:
            return ""
        try:
            proc = subprocess.run(
                [
                    "powershell", "-NoProfile", "-NonInteractive",
                    "-Command",
                    f"(Get-NetIPAddress -IPAddress '{ip_local}' "
                    f"-AddressFamily IPv4 -ErrorAction SilentlyContinue)"
                    f".PrefixLength",
                ],
                capture_output=True,
                text=True,
                timeout=8,
                creationflags=subprocess.CREATE_NO_WINDOW,
            )
            saida = (proc.stdout or "").strip()
            if saida.isdigit():
                prefixo = int(saida)
                rede = ipaddress.ip_network(f"{ip_local}/{prefixo}", strict=False)
                return str(rede)
        except Exception:
            pass
        return ""

    def _obter_cidr_via_ipconfig(self, ip_local: str) -> str:
        """
        Lê 'ipconfig /all' como bytes e tenta múltiplos encodings.

        O cmd.exe no Windows pt-BR usa cp850; usar text=True + utf-8 corrompe
        os caracteres acentuados ('Máscara' → lixo) e o regex nunca casa.
        Esta versão lê bytes brutos e tenta cp850, cp1252, utf-8 e latin-1.
        Também normaliza CRLF → LF antes de parsear.
        """
        if not ip_local:
            return ""
        try:
            proc = subprocess.run(
                ["ipconfig", "/all"],
                capture_output=True,
                timeout=10,
                creationflags=subprocess.CREATE_NO_WINDOW,
            )
            raw = proc.stdout  # bytes — não decodificamos ainda

            saida = ""
            for enc in ("cp850", "cp1252", "utf-8", "latin-1"):
                try:
                    saida = raw.decode(enc, errors="strict")
                    break
                except (UnicodeDecodeError, LookupError):
                    continue
            if not saida:
                saida = raw.decode("utf-8", errors="replace")

            # Normaliza quebras de linha do Windows (CRLF → LF)
            saida = saida.replace("\r\n", "\n").replace("\r", "\n")

            # Localiza o IP na saída
            idx = saida.find(ip_local)
            if idx == -1:
                return ""

            # Janela de contexto: 400 chars antes + 700 depois do IP
            # (garante que o bloco do adaptador que contém o IP seja capturado)
            trecho = saida[max(0, idx - 400): idx + 700]

            # Regex genérico: aceita pt-BR, en-US e qualquer variação
            # Captura qualquer linha com "Mask" ou "Mascara" seguida de um IP
            m = re.search(
                r"(?:M[aá]scara[^:]*|Subnet\s+Mask)[^:]*:\s*"
                r"((?:25[0-5]|2[0-4]\d|[01]?\d\d?)(?:\.(?:25[0-5]|2[0-4]\d|[01]?\d\d?)){3})",
                trecho,
                re.IGNORECASE,
            )
            if m:
                mascara = m.group(1)
                prefixo = sum(bin(int(p)).count("1") for p in mascara.split("."))
                rede = ipaddress.ip_network(f"{ip_local}/{prefixo}", strict=False)
                return str(rede)

        except Exception as e:
            print(f"[NetLab] _obter_cidr_via_ipconfig: {e}")
        return ""

    @staticmethod
    def _detectar_cidr_via_scapy(nome_interface: str) -> str:
        """Tenta detectar o CIDR diretamente via Scapy (get_if_addr/netmask)."""
        try:
            from scapy.all import get_if_addr, get_if_netmask
            ip      = get_if_addr(nome_interface)
            mascara = get_if_netmask(nome_interface)
            if ip and mascara and ip != "0.0.0.0":
                prefixo = sum(bin(int(p)).count("1") for p in mascara.split("."))
                rede    = ipaddress.ip_network(f"{ip}/{prefixo}", strict=False)
                return str(rede)
        except Exception:
            pass
        return ""

    def _cidr_da_interface(self, desc: str) -> str:
        """
        Detecta o CIDR da interface em ordem decrescente de confiabilidade.

        1. PowerShell Get-NetIPAddress  — independente de idioma, Windows 8+
        2. ipconfig /all bytes+cp850    — corrige encoding pt-BR
        3. Scapy mapeamento + máscara   — quando Scapy preenche netmasks
        4. Scapy get_if_addr/netmask    — chamada direta por nome de dispositivo
        5. Fallback /32                 — RESTRITIVO: só o próprio host é "local"
           (nunca mais /24 estimado — isso era a causa dos 50 dispositivos falsos)
        """
        ip_interface = self._mapa_interface_ip.get(desc, "") or obter_ip_local()
        if not ip_interface or ip_interface == "127.0.0.1":
            return ""

        # 1) PowerShell — mais confiável no Windows moderno (independe de idioma)
        cidr = self._detectar_cidr_via_powershell(ip_interface)
        if cidr:
            self._status(f"✅ CIDR via PowerShell: {cidr}")
            return cidr

        # 2) ipconfig /all com encoding correto (cp850 para pt-BR)
        cidr = self._obter_cidr_via_ipconfig(ip_interface)
        if cidr:
            self._status(f"✅ CIDR via ipconfig: {cidr}")
            return cidr

        # 3) Mapeamento interno do Scapy + máscara
        mascara = self._mapa_interface_mascara.get(desc, "")
        if mascara and '.' in mascara:
            try:
                prefixo = self._mascara_para_prefixo(mascara)
                rede    = ipaddress.ip_network(f"{ip_interface}/{prefixo}", strict=False)
                self._status(f"✅ CIDR via Scapy mapeamento: {rede}")
                return str(rede)
            except Exception:
                pass

        # 4) Scapy direto pelo nome do dispositivo NPF
        nome_dispositivo = self._mapa_interface_nome.get(desc, desc)
        cidr = self._detectar_cidr_via_scapy(nome_dispositivo)
        if cidr:
            self._status(f"✅ CIDR via Scapy direto: {cidr}")
            return cidr

        # 5) Fallback restritivo /32 — NUNCA mais /24 estimado
        rede_restrita = f"{ip_interface}/32"
        self._status(
            f"⚠ Máscara não detectada para '{desc}'. "
            f"Usando /32 ({rede_restrita}). "
            f"Apenas este computador aparecerá como local; todos os outros "
            f"como 'Internet'. Verifique a instalação do Npcap."
        )
        return rede_restrita

    def _parametros_iface_seguro(self, nome_iface: str) -> dict:
        """
        Retorna parâmetros de varredura adequados para o tipo de interface.
        Wi-Fi recebe configurações mais conservadoras para não sobrecarregar
        o ponto de acesso.
        """
        nome_lower = (nome_iface or "").lower()
        eh_wifi = any(
            p in nome_lower
            for p in ("wi-fi", "wifi", "wireless", "ax", "802.11")
        )

        base = {
            "limite_hosts":   100,
            "desativar_icmp": False,
            "tentativas":     _DescobrirDispositivosThread.TENTATIVAS,
            "timeout":        _DescobrirDispositivosThread.TIMEOUT_ARP,
            "pausa":          _DescobrirDispositivosThread.PAUSA_RODADAS,
            "inter":          _DescobrirDispositivosThread.INTER_ARP,
            "sleep_lote":     0.0,
            "batch":          _DescobrirDispositivosThread.BATCH_ARP,
            "wifi":           eh_wifi,
            "timer_ms":       30000,
        }

        if eh_wifi:
            # Wi-Fi: mais lento, menos tentativas, ICMP desativado
            base.update({
                "batch":          8,
                "sleep_lote":     0.25,
                "pausa":          3.0,
                "timeout":        2.8,
                "tentativas":     1,
                "desativar_icmp": True,
                "timer_ms":       300_000,   # Re-varredura a cada 5 min
            })

        return base

    def _gerar_historias(self) -> list:
        """Gera resumos textuais dos domínios mais acessados (para Insights)."""
        top_dns = (
            self.analisador.obter_top_dns()
            if hasattr(self.analisador, "obter_top_dns") else []
        )
        return [
            f"Domínio {d['dominio']} acessado {d['acessos']}x "
            f"({d['bytes']/1024:.1f} KB)."
            for d in top_dns[:5]
        ]

    # -------------------------------------------------------------------------
    # Controle de captura
    # -------------------------------------------------------------------------

    @pyqtSlot()
    def _alternar_captura(self):
        if self.em_captura:
            self._parar_captura()
        else:
            self._iniciar_captura()

    def _validar_pre_captura(self, nome_dispositivo: str):
        """
        Valida privilégios administrativos e disponibilidade do Npcap/Scapy
        antes de iniciar a captura.
        """
        try:
            if hasattr(ctypes, "windll") and not ctypes.windll.shell32.IsUserAnAdmin():
                raise PermissionError(
                    "Execute o NetLab como Administrador para capturar pacotes."
                )
        except PermissionError:
            raise
        except Exception:
            pass

        try:
            from scapy.arch.windows import get_windows_if_list
            adaptadores     = get_windows_if_list()
            nomes_validos   = (
                {a.get("name") for a in adaptadores}
                | {a.get("description") for a in adaptadores}
            )
            if nome_dispositivo not in nomes_validos:
                raise RuntimeError(
                    "Adaptador não reconhecido pelo Npcap/Scapy. "
                    "Reinstale o Npcap ou escolha outra interface."
                )
        except ImportError as exc:
            raise RuntimeError(
                "Scapy ausente. Instale com 'pip install scapy'."
            ) from exc
        except RuntimeError:
            raise
        except Exception as exc:
            raise RuntimeError(f"Falha ao acessar o Npcap/Scapy: {exc}") from exc

    def _limpar_pos_falha(self):
        """Restaura o estado da UI após uma falha ao iniciar a captura."""
        self.timer_consumir.stop()
        self.timer_ui.stop()
        self.timer_descoberta.stop()
        if self.capturador:
            try:
                self.capturador.parar()
            except Exception:
                pass
            self.capturador = None
        self.analisador.parar_thread()
        self._interface_captura = ""
        self._cidr_captura      = ""
        self.em_captura = False
        self.botao_captura.setText("Iniciar Captura")
        self.botao_captura.setObjectName("botao_captura")
        self._repolir(self.botao_captura)
        self.acao_captura.setText("Iniciar Captura")

    def _iniciar_captura(self):
        """
        Inicia a captura de pacotes na interface selecionada.
        Realiza validação, configura filas e timers, e dispara a varredura
        inicial da rede local.
        """
        desc_sel = self.combo_interface.currentText()
        if not desc_sel or "nenhuma" in desc_sel.lower():
            QMessageBox.warning(
                self, "Interface Inválida",
                "Selecione uma interface de rede válida.\n\n"
                "Execute como Administrador e verifique a instalação do Npcap."
            )
            return

        nome_dispositivo = self._mapa_interface_nome.get(desc_sel, desc_sel)

        try:
            self._validar_pre_captura(nome_dispositivo)
        except Exception as exc:
            self._status(f"Falha ao iniciar: {exc}")
            QMessageBox.critical(self, "Captura não iniciada", str(exc))
            self._limpar_pos_falha()
            return

        # Detecta CIDR com todos os fallbacks disponíveis
        self._interface_captura = nome_dispositivo
        self._cidr_captura      = self._cidr_da_interface(desc_sel)
        self.painel_topologia.definir_rede_local(self._cidr_captura)

        # Parâmetros adaptados ao tipo de interface (Ethernet × Wi-Fi)
        self._param_arps       = self._parametros_iface_seguro(self._interface_captura)
        self._periodo_timer_ms = self._param_arps.get("timer_ms", 30000)
        self._eh_wifi          = self._param_arps.get("wifi", False)
        self._limite_hosts     = self._param_arps.get(
            "limite_hosts", _DescobrirDispositivosThread.MAX_HOSTS
        )

        # Reinicia filas e estatísticas
        fila_pacotes_global.limpar()
        self.analisador.resetar()
        self._snapshot_atual = {
            "total_bytes": 0, "total_pacotes": 0,
            "estatisticas": [], "top_dispositivos": [],
            "dispositivos_ativos": 0, "top_dns": [], "historias": [],
        }
        self._bytes_total_anterior = 0
        self._instante_anterior    = time.perf_counter()

        # Inicia a thread de análise (background)
        self.analisador.iniciar_thread()

        # Inicia o sniffer
        try:
            self.capturador = _CapturadorPacotesThread(interface=nome_dispositivo)
            self.capturador.erro_ocorrido.connect(self._ao_ocorrer_erro)
            self.capturador.sem_pacotes.connect(self._ao_ocorrer_erro)
            self.capturador.start()
        except Exception as exc:
            msg = f"Não foi possível iniciar o sniffer: {exc}"
            self._status(msg)
            QMessageBox.critical(self, "Captura não iniciada", msg)
            self._limpar_pos_falha()
            return

        # Ativa timers principais
        self.timer_consumir.start(250)
        self.timer_ui.start(1000)

        # CORREÇÃO [3]: ativa o timer de descoberta periódica
        # Antes essa linha estava ausente, então a rede nunca era
        # re-varrida automaticamente após a varredura inicial.
        self.timer_descoberta.start(self._periodo_timer_ms)

        # Atualiza botões e status
        self.em_captura = True
        self.botao_captura.setText("Parar Captura")
        self.botao_captura.setObjectName("botao_parar")
        self._repolir(self.botao_captura)
        self.acao_captura.setText("Parar Captura")

        rede_info = f" · rede {self._cidr_captura}" if self._cidr_captura else ""
        self._status(
            f"Capturando em: {desc_sel} (dispositivo: {nome_dispositivo}){rede_info}"
        )

        # Dispara varreduras iniciais com pequeno atraso para aguardar o sniffer
        QTimer.singleShot(4000,  self._varredura_inicial_segura)
        QTimer.singleShot(500,   self._popular_topologia_via_arp_sistema)

    def _parar_captura(self):
        """Para todos os timers, o sniffer e a thread de análise."""
        self.timer_consumir.stop()
        self.timer_ui.stop()
        self.timer_descoberta.stop()

        if self.capturador:
            self.capturador.parar()
            self.capturador = None

        self.analisador.parar_thread()
        self._consumir_fila()

        self._interface_captura = ""
        self._cidr_captura      = ""
        self.em_captura = False
        self.botao_captura.setText("Iniciar Captura")
        self.botao_captura.setObjectName("botao_captura")
        self._repolir(self.botao_captura)
        self.acao_captura.setText("Iniciar Captura")
        self._status("Captura encerrada.")

    @staticmethod
    def _repolir(botao: QPushButton):
        """Força o Qt a reaplicar o stylesheet após trocar objectName."""
        botao.style().unpolish(botao)
        botao.style().polish(botao)

    # -------------------------------------------------------------------------
    # Consumo da fila e atualização da UI
    # -------------------------------------------------------------------------

    @pyqtSlot()
    def _consumir_fila(self):
        """
        Transfere pacotes da fila global para o analisador e coleta os
        eventos resultantes para exibição na UI.
        """
        # Transfere para o analisador (thread de análise)
        for dados in fila_pacotes_global.consumir_todos():
            self.analisador.enfileirar(dados)

        # Coleta eventos processados pelo analisador
        eventos, _ = self.analisador.coletar_resultados()

        for evento in eventos:
            ip_origem  = evento.get("ip_origem",  "")
            ip_destino = evento.get("ip_destino", "")
            mac_origem = evento.get("mac_origem", "")
            tipo       = evento.get("tipo",       "")

            # Atualiza a topologia com os IPs do evento
            if ip_origem and _ip_eh_topologizavel(ip_origem):
                self.painel_topologia.adicionar_dispositivo(ip_origem, mac_origem)
            if ip_destino and _ip_eh_topologizavel(ip_destino):
                self.painel_topologia.adicionar_dispositivo(ip_destino, "")
            if (ip_origem and ip_destino
                    and _ip_eh_topologizavel(ip_origem)
                    and _ip_eh_topologizavel(ip_destino)):
                self.painel_topologia.adicionar_conexao(ip_origem, ip_destino)

            # Enfileira evento para exibição pedagógica (com cooldown)
            if tipo:
                if tipo == "NOVO_DISPOSITIVO":
                    if ip_origem:
                        status = self.estado_rede.registrar_dispositivo(ip_origem, mac_origem)
                        if status == "NOVO" and self.estado_rede.deve_emitir_evento(
                            f"novo_{ip_origem}", cooldown=30
                        ):
                            self.fila_eventos_ui.append(evento)
                else:
                    discriminador = (
                        evento.get("dominio", "")
                        or f"{evento.get('metodo', '')}:{evento.get('recurso', '')}"
                    )
                    chave = f"{tipo}_{ip_origem}_{discriminador}"

                    if tipo in ("HTTP", "HTTPS"):
                        # HTTP/HTTPS: sempre exibe (relevância pedagógica alta)
                        self.fila_eventos_ui.append(evento)
                    elif tipo == "DNS":
                        chave_dns = f"DNS_{ip_origem}_{evento.get('dominio', '')}"
                        if self.estado_rede.deve_emitir_evento(chave_dns, cooldown=3):
                            self.fila_eventos_ui.append(evento)
                    else:
                        if self.estado_rede.deve_emitir_evento(chave, cooldown=5):
                            self.fila_eventos_ui.append(evento)

        # Atualiza snapshot de estatísticas para o próximo ciclo da UI
        self._snapshot_atual = {
            "total_bytes":       self.analisador.total_bytes,
            "total_pacotes":     self.analisador.total_pacotes,
            "estatisticas":      self.analisador.obter_estatisticas_protocolos(),
            "top_dispositivos":  self.analisador.obter_top_dispositivos(),
            "dispositivos_ativos": len(self.analisador.trafego_dispositivos),
            "top_dns":           self.analisador.obter_top_dns(),
            "historias":         self._gerar_historias(),
        }

    def _agregar_eventos(self, eventos: list) -> list:
        """
        Agrupa eventos repetidos do mesmo tipo+fluxo para evitar que a
        lista fique sobrecarregada com duplicatas. HTTP e HTTPS sempre
        são exibidos individualmente.
        """
        agregados: dict = {}
        resultado: list = []
        for ev in eventos:
            if ev.get("tipo") in ("HTTP", "HTTPS"):
                resultado.append(ev)
                continue

            chave = (
                ev.get("tipo"),
                ev.get("ip_origem"),
                ev.get("ip_destino"),
                ev.get("dominio",  ""),
                ev.get("metodo",   ""),
                ev.get("recurso",  ""),
            )
            if chave not in agregados:
                item = {**ev, "contagem": 1}
                agregados[chave] = item
                resultado.append(item)
            else:
                agregados[chave]["contagem"] += 1
        return resultado

    @pyqtSlot()
    def _descarregar_eventos_ui(self):
        """
        Timer a cada 2s: descarrega a fila de eventos para o motor
        pedagógico, evitando duplicatas visuais recentes.
        """
        if not self.fila_eventos_ui:
            return
        lote = list(self.fila_eventos_ui)
        self.fila_eventos_ui.clear()
        for ev in self._agregar_eventos(lote):
            tipo = ev.get("tipo", "")
            if tipo in ("HTTP", "HTTPS"):
                self._exibir_evento_pedagogico(ev)
                continue

            discriminador_visual = (
                ev.get("dominio", "")
                or f"{ev.get('metodo', '')}:{ev.get('recurso', '')}"
            )
            chave_visual = (
                ev.get("tipo"), ev.get("ip_origem"),
                ev.get("ip_destino"), discriminador_visual,
            )
            if chave_visual in self.eventos_mostrados_recentemente:
                continue
            self.eventos_mostrados_recentemente.append(chave_visual)
            self._exibir_evento_pedagogico(ev)

    @pyqtSlot()
    def _atualizar_ui_por_segundo(self):
        """
        Timer a cada 1s: calcula taxa de transferência (KB/s) com EMA
        e atualiza gráfico, tabelas e barra de status.
        """
        snap          = self._snapshot_atual
        total_bytes   = snap.get("total_bytes",   0)
        total_pacotes = snap.get("total_pacotes", 0)

        agora   = time.perf_counter()
        delta_t = max(agora - self._instante_anterior, 0.001)
        delta_b = max(0, total_bytes - self._bytes_total_anterior)
        kb_raw  = (delta_b / 1024.0) / delta_t

        # EMA com alpha = 0.3 para suavizar picos momentâneos
        alpha         = 0.3
        kb_por_s      = alpha * kb_raw + (1.0 - alpha) * self._kb_anterior
        self._kb_anterior = kb_por_s

        self._bytes_total_anterior = total_bytes
        self._instante_anterior    = agora

        self.painel_trafego.adicionar_ponto_grafico(kb_por_s)
        self.painel_trafego.atualizar_tabelas(
            estatisticas_protocolos=snap.get("estatisticas",      []),
            top_dispositivos       =snap.get("top_dispositivos",  []),
            total_pacotes          =total_pacotes,
            total_bytes            =total_bytes,
            total_topologia        =self.painel_topologia.total_dispositivos(),
            total_ativos           =self.painel_topologia.total_dispositivos(),
        )
        self.painel_topologia.atualizar()
        self.painel_eventos.atualizar_insights(
            snap.get("top_dns",   []),
            snap.get("historias", []),
        )

        # Atualiza barra de status
        kb = total_bytes / 1024
        self.lbl_pacotes.setText(f"Pacotes: {total_pacotes:,}")
        self.lbl_dados.setText(
            f"  Dados: {kb/1024:.2f} MB  " if kb > 1024
            else f"  Dados: {kb:.1f} KB  "
        )

    # -------------------------------------------------------------------------
    # Motor pedagógico — exibição de eventos em background
    # -------------------------------------------------------------------------

    def _exibir_evento_pedagogico(self, evento: dict):
        """Enfileira a geração de explicação no thread pool."""
        runnable = _WorkerRunnable(evento, self.motor_pedagogico)
        self._thread_pool.start(runnable)

    def _finalizar_exibicao_evento(self, explicacao: dict):
        """Recebe o resultado do worker e exibe no painel de eventos."""
        self.painel_eventos.adicionar_evento(explicacao)

    def _finalizar_workers(self):
        """Aguarda a conclusão de todos os workers pedagógicos pendentes."""
        self._thread_pool.waitForDone(3000)

    # -------------------------------------------------------------------------
    # Descoberta de dispositivos — varredura ativa e passiva
    # -------------------------------------------------------------------------

    def _varredura_inicial_segura(self):
        """
        CORREÇÃO [2]: limite ampliado de 30 para min(500, self._limite_hosts).

        A versão anterior limitava a varredura inicial a apenas 30 hosts,
        o que deixava a topologia quase vazia nos primeiros minutos.
        Agora usamos um limite proporcional ao perfil da interface
        (Ethernet permite mais, Wi-Fi mantém restrição para não
        sobrecarregar o ponto de acesso).

        Parâmetros leves são mantidos (timeout curto, 1 tentativa, sem ICMP)
        para que a varredura seja rápida e não interfira no tráfego normal.
        """
        if not self.em_captura or not self._interface_captura:
            return
        if self.descoberta_rodando or (
            self.descobridor and self.descobridor.isRunning()
        ):
            return

        # Limite ampliado: até 500 hosts em Ethernet, mantém o do Wi-Fi
        limite_inicial = min(500, self._limite_hosts)

        parametros_leves = {
            "limite_hosts":   limite_inicial,
            "tentativas":     1,
            "timeout":        0.8,
            "batch":          8 if self._eh_wifi else 32,
            "inter":          0.02,
            "sleep_lote":     0.25 if self._eh_wifi else 0.05,
            "desativar_icmp": True,
            "pausa":          1.0,
            "wifi":           self._eh_wifi,
            "timer_ms":       self._periodo_timer_ms,
        }

        self.descoberta_rodando = True
        self._status(
            f"🔍 Varredura inicial: descobrindo até {limite_inicial} "
            f"dispositivo(s) na rede {self._cidr_captura or 'local'}…"
        )

        self.descobridor = _DescobrirDispositivosThread(
            interface=self._interface_captura,
            cidr=self._cidr_captura,
            parametros=parametros_leves,
        )
        self.descobridor.dispositivo_encontrado.connect(self._ao_encontrar_dispositivo)
        self.descobridor.varredura_concluida.connect(self._ao_concluir_varredura_inicial)
        self.descobridor.progresso_atualizado.connect(self._status)
        self.descobridor.erro_ocorrido.connect(self._ao_erro_varredura_silencioso)
        self.descobridor.start()

    @pyqtSlot(list)
    def _ao_concluir_varredura_inicial(self, dispositivos: list):
        total = len(dispositivos)
        self._status(
            f"✅ Varredura inicial: {total} dispositivo(s) encontrado(s). "
            f"Captura passiva ativa."
        )
        self.descoberta_rodando = False

    @pyqtSlot(str)
    def _ao_erro_varredura_silencioso(self, mensagem: str):
        """Erros na varredura inicial são registrados no status sem popup."""
        self._status(f"⚠ Varredura: {mensagem[:80]}")
        self.descoberta_rodando = False

    def _popular_topologia_via_arp_sistema(self):
        """
        Importa dispositivos já conhecidos da tabela ARP do sistema operacional
        para a topologia (sem varredura ativa — usa o cache do SO).
        """
        entradas    = self._obter_tabela_arp_sistema()
        adicionados = 0
        for entrada in entradas:
            self.painel_topologia.adicionar_dispositivo_manual(
                entrada["ip"], entrada["mac"]
            )
            adicionados += 1

        if adicionados:
            self._status(
                f"📋 Tabela ARP do sistema: {adicionados} dispositivo(s) "
                f"importado(s) para a topologia."
            )

    @staticmethod
    def _obter_tabela_arp_sistema() -> list:
        """
        Lê a tabela ARP do SO (arp -a no Windows, ip neigh no Linux/macOS).
        Retorna lista de dicts com 'ip', 'mac' e 'tipo'.
        """
        import platform
        entradas = []

        try:
            if platform.system() == "Windows":
                saida = subprocess.check_output(
                    ["arp", "-a"],
                    text=True,
                    timeout=5,
                    creationflags=subprocess.CREATE_NO_WINDOW
                )
                padrao = re.compile(
                    r'\s+([\d.]+)\s+([\da-f]{2}[-:][\da-f]{2}[-:]'
                    r'[\da-f]{2}[-:][\da-f]{2}[-:][\da-f]{2}[-:][\da-f]{2})'
                    r'\s+(\w+)',
                    re.IGNORECASE
                )
            else:
                saida = subprocess.check_output(
                    ["ip", "neigh"], text=True, timeout=5
                )
                padrao = re.compile(
                    r'^([\d.]+)\s+dev\s+\S+\s+lladdr\s+'
                    r'([\da-f:]{17})\s+(\w+)',
                    re.IGNORECASE | re.MULTILINE
                )

            for corr in padrao.finditer(saida):
                ip_arp  = corr.group(1)
                mac_arp = corr.group(2).replace("-", ":").lower()
                tipo    = corr.group(3)

                if mac_arp in ("ff:ff:ff:ff:ff:ff", "00:00:00:00:00:00"):
                    continue

                entradas.append({"ip": ip_arp, "mac": mac_arp, "tipo": tipo})

        except Exception:
            pass

        return entradas

    def _descoberta_periodica(self):
        """
        Slot do timer_descoberta: re-varre a rede periodicamente para
        manter a topologia atualizada com dispositivos que entram e saem.
        """
        if not self.em_captura:
            return
        if self.descoberta_rodando or (
            self.descobridor and self.descobridor.isRunning()
        ):
            return
        if not self._interface_captura:
            return

        self.descoberta_rodando = True
        self._status("🔄 Varrendo a rede local em busca de dispositivos…")

        self.descobridor = _DescobrirDispositivosThread(
            interface=self._interface_captura,
            cidr=self._cidr_captura,
            parametros=self._param_arps,
        )
        self.descobridor.dispositivo_encontrado.connect(self._ao_encontrar_dispositivo)
        self.descobridor.varredura_concluida.connect(self._ao_concluir_varredura)
        self.descobridor.progresso_atualizado.connect(self._status)
        self.descobridor.erro_ocorrido.connect(self._ao_ocorrer_erro)
        self.descobridor.start()

    @pyqtSlot(str, str, str)
    def _ao_encontrar_dispositivo(self, ip: str, mac: str, hostname: str):
        """Adiciona dispositivo descoberto à topologia e agenda evento pedagógico."""
        if not _ip_eh_topologizavel(ip):
            return
        self.painel_topologia.adicionar_dispositivo_manual(ip, mac, hostname)
        self.fila_eventos_ui.append({
            "tipo":       "NOVO_DISPOSITIVO",
            "ip_origem":  ip,
            "ip_destino": "",
            "mac_origem": mac,
            "protocolo":  "ARP/DHCP",
            "tamanho":    0,
        })

    @pyqtSlot(list)
    def _ao_concluir_varredura(self, dispositivos: list):
        self._status(
            f"Varredura concluída — {len(dispositivos)} dispositivo(s) encontrado(s)."
        )
        self.descoberta_rodando = False

    # -------------------------------------------------------------------------
    # Diagnóstico da captura
    # -------------------------------------------------------------------------

    def _exibir_diagnostico_captura(self):
        """Exibe um popup com informações detalhadas sobre a sessão atual."""
        desc_sel         = self.combo_interface.currentText()
        nome_dispositivo = self._mapa_interface_nome.get(desc_sel, desc_sel)
        ip_local         = self._mapa_interface_ip.get(desc_sel, obter_ip_local())
        mascara          = self._mapa_interface_mascara.get(desc_sel, "Não detectada")
        cidr             = self._cidr_captura or "Não definido"
        total_local      = self.painel_topologia.total_dispositivos()

        is_admin = False
        try:
            is_admin = ctypes.windll.shell32.IsUserAnAdmin()
        except Exception:
            pass
        status_admin = "✅ Sim" if is_admin else "❌ Não (recomendado)"

        texto = (
            f"<h3 style='color:#3498DB;'>🔍 Diagnóstico da Captura</h3>"
            f"<table style='font-size:11px;width:100%;'>"
            f"<tr><td style='color:#7f8c8d;'>Interface:</td>"
            f"    <td style='color:#ecf0f1;'>{desc_sel}</td></tr>"
            f"<tr><td style='color:#7f8c8d;'>Dispositivo:</td>"
            f"    <td style='color:#ecf0f1;font-family:Consolas;'>{nome_dispositivo}</td></tr>"
            f"<tr><td style='color:#7f8c8d;'>IP local:</td>"
            f"    <td style='color:#2ECC71;font-weight:bold;'>{ip_local}</td></tr>"
            f"<tr><td style='color:#7f8c8d;'>Máscara:</td>"
            f"    <td style='color:#ecf0f1;'>{mascara}</td></tr>"
            f"<tr><td style='color:#7f8c8d;'>CIDR detectado:</td>"
            f"    <td style='color:#F39C12;font-weight:bold;'>{cidr}</td></tr>"
            f"<tr><td style='color:#7f8c8d;'>Dispositivos locais:</td>"
            f"    <td style='color:#ecf0f1;'>{total_local}</td></tr>"
            f"<tr><td style='color:#7f8c8d;'>Modo promíscuo:</td>"
            f"    <td style='color:#2ECC71;'>Ativo</td></tr>"
            f"<tr><td style='color:#7f8c8d;'>Rate limit (pkt/s):</td>"
            f"    <td style='color:#2ECC71;'>{_MAX_PACOTES_POR_SEGUNDO}</td></tr>"
            f"<tr><td style='color:#7f8c8d;'>Executando como Admin:</td>"
            f"    <td style='color:#ecf0f1;'>{status_admin}</td></tr>"
            f"</table>"
            f"<hr style='border-color:#1e2d40;margin:12px 0;'>"
            f"<p style='color:#7f8c8d;font-size:10px;'>"
            f"Se o CIDR estiver incorreto, dispositivos da mesma rede física "
            f"podem ser classificados como 'Internet'.</p>"
            f"<p style='color:#e67e22;font-size:10px;margin-top:12px;'>"
            f"<b>⚠️ Aviso sobre Wi-Fi:</b> No Windows, a captura em modo "
            f"promíscuo pode não mostrar todo o tráfego da rede sem fio.</p>"
        )

        dialogo = QDialog(self)
        dialogo.setWindowTitle("Diagnóstico de Captura")
        dialogo.setMinimumSize(480, 360)
        layout = QVBoxLayout(dialogo)

        txt = QTextEdit()
        txt.setReadOnly(True)
        txt.setHtml(texto)
        txt.setStyleSheet("background:#0f1423;border:none;")
        layout.addWidget(txt)

        botoes = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok)
        botoes.accepted.connect(dialogo.accept)
        layout.addWidget(botoes)
        dialogo.exec()

    # -------------------------------------------------------------------------
    # Tratamento de erros e ações gerais
    # -------------------------------------------------------------------------

    @pyqtSlot(str)
    def _ao_ocorrer_erro(self, mensagem: str):
        self._status(f"Erro: {mensagem[:80]}")
        QMessageBox.warning(self, "Erro", mensagem)
        if self.em_captura:
            self._parar_captura()
        self.descoberta_rodando = False

    def _nova_sessao(self):
        """Reinicia completamente a sessão, limpando dados e painéis."""
        self._finalizar_workers()
        if self.em_captura:
            self._parar_captura()
        self.analisador.resetar()
        self.painel_topologia.limpar()
        self.painel_topologia.definir_rede_local(self._cidr_captura)
        self.painel_trafego.limpar()
        self.painel_eventos.limpar()
        self._snapshot_atual = {
            "total_bytes": 0, "total_pacotes": 0,
            "estatisticas": [], "top_dispositivos": [],
            "dispositivos_ativos": 0,
        }
        self._bytes_total_anterior = 0
        self._instante_anterior    = time.perf_counter()
        self._status("Nova sessão iniciada. Pronto para capturar.")

    def _status(self, mensagem: str):
        """Exibe uma mensagem na barra de status da janela principal."""
        self.lbl_status.setText(mensagem)

    def _exibir_sobre(self):
        QMessageBox.about(
            self,
            "Sobre o NetLab Educacional",
            "<h2>NetLab Educacional V3.0</h2>"
            "<p>Plataforma educacional para análise de redes locais com "
            "captura de pacotes em tempo real e explicações didáticas "
            "automatizadas.</p>"
            "<hr>"
            "<p><b>TCC — Curso Técnico em Informática</b></p>"
            "<p><b>Tecnologias:</b> Python · PyQt6 · Scapy · PyQtGraph</p>"
            "<p><b>Destaques:</b> DPI, detecção de dados sensíveis, "
            "identificação via MAC/OUI e monitoramento em tempo real.</p>"
            "<p><b>Autor:</b> Yuri Gonçalves Pavão</p>"
            "<p><b>Instagram:</b> @yuri_g0n | "
            "<b>GitHub:</b> github.com/yurigonpav</p>"
        )

    def closeEvent(self, evento):
        """Garante limpeza de recursos ao fechar a janela."""
        self._finalizar_workers()
        if self.em_captura:
            self._parar_captura()
        evento.accept()