# analisador_pacotes.py
# ============================================================
# VERSÃO ALTA PERFORMANCE  —  NetLab Educacional
#
# Arquitetura de 3 camadas:
#
#   CAMADA 1 — Parser C (ctypes)
#     http_parser.dll/so compilado de http_parser.c.
#     Se não encontrado, cai silenciosamente para o parser Python.
#     Hot-path HTTP: ate 10x mais rapido que re.match() em Python.
#
#   CAMADA 2 — Thread de analise dedicada (ThreadAnalisador)
#     A analise NAO ocorre mais no timer do Qt (UI thread).
#     Um thread daemon consome a fila de entrada continuamente,
#     analisa em lotes e deposita eventos numa fila de saida.
#     O Qt timer apenas le a fila de saida — operacao O(1).
#
#   CAMADA 3 — Filas limitadas (zero OOM, descarte controlado)
#     fila_entrada  : deque(maxlen=MAXQ_ENTRADA)
#     fila_saida    : deque(maxlen=MAXQ_SAIDA)
#     Quando cheias, o pacote/evento mais antigo e descartado
#     automaticamente — PC nunca trava por falta de memoria.
#
# Integracao com janela_principal.py
# -----------------------------------
# Substitua _consumir_fila() por:
#
#     def _consumir_fila(self):
#         eventos, _ = self.analisador.coletar_resultados()
#         for evento in eventos:
#             ip_origem  = evento.get("ip_origem",  "")
#             ip_destino = evento.get("ip_destino", "")
#             mac_origem = evento.get("mac_origem", "")
#             if ip_origem:
#                 self.painel_topologia.adicionar_dispositivo(ip_origem, mac_origem)
#                 self.banco.salvar_dispositivo(ip_origem, mac_origem)
#             if ip_origem and ip_destino:
#                 self.painel_topologia.adicionar_conexao(ip_origem, ip_destino)
#             if evento.get("tipo"):
#                 self._exibir_evento_pedagogico(evento)
#
# Em _iniciar_captura(), apos criar o capturador:
#     self.analisador.iniciar_thread()
#
# Em _parar_captura():
#     self.analisador.parar_thread()
#
# No capturador_rede.py, no lugar de fila_pacotes_global.put():
#     self.analisador.enfileirar(dados)   <- modo async
#     OU manter fila_pacotes_global e chamar processar_pacote() <- modo sync
#
# API PUBLICA MANTIDA 100% COMPATIVEL:
#   resetar(), processar_pacote(), processar_lote()
#   obter_estatisticas_protocolos(), obter_top_dispositivos()
#   obter_top_dns(), total_pacotes, total_bytes
# ============================================================

import re
import ctypes
import platform
import threading
import time
from collections import defaultdict, deque
from pathlib import Path
from typing import Optional

# ── Configuracao das filas ───────────────────────────────────
MAXQ_ENTRADA = 8_000   # pacotes aguardando analise
MAXQ_SAIDA   = 2_000   # eventos aguardando consumo pelo Qt
BATCH_SIZE   = 100     # pacotes processados por iteracao do thread
SLEEP_VAZIO  = 0.005   # segundos de sleep quando fila vazia (5ms)

# ── Regex pre-compiladas (fallback Python) ───────────────────
_RE_HTTP_METHOD = re.compile(rb"^(GET|POST|PUT|DELETE|HEAD|OPTIONS) ")
_RE_CREDENTIALS = re.compile(
    rb'(user|login|email|pass|password)=([^&\s]+)', re.I
)

# Portas conhecidas como frozenset para O(1) lookup
_PORTAS_HTTP  = frozenset({80, 8080, 8000})
_PORTAS_HTTPS = frozenset({443, 8443})

# Cache de classificacao de IP local (evita re-parse de IPs repetidos)
_CACHE_LOCAL: dict = {}


# ── Funcoes de cache de IP ───────────────────────────────────

def _calcular_eh_local(ip: str) -> bool:
    try:
        p = ip.split(".", 2)
        a = int(p[0])
        if a == 10:
            return True
        if a == 192:
            return len(p) >= 2 and int(p[1]) == 168
        if a == 172:
            return len(p) >= 2 and 16 <= int(p[1]) <= 31
    except Exception:
        pass
    return False


def _eh_local_rapido(ip: str) -> bool:
    cached = _CACHE_LOCAL.get(ip)
    if cached is not None:
        return cached
    resultado = _calcular_eh_local(ip)
    if len(_CACHE_LOCAL) < 8192:
        _CACHE_LOCAL[ip] = resultado
    return resultado


# ════════════════════════════════════════════════════════════
# CAMADA 1 — Parser HTTP em C via ctypes
# ════════════════════════════════════════════════════════════

class _HttpResult(ctypes.Structure):
    """Espelho exato de HttpResult em http_parser.c"""
    _fields_ = [
        ("method",     ctypes.c_char * 16),
        ("resource",   ctypes.c_char * 512),
        ("is_http",    ctypes.c_int),
        ("cred_count", ctypes.c_int),
        ("cred_keys",  (ctypes.c_char * 64) * 8),
        ("cred_vals",  (ctypes.c_char * 128) * 8),
    ]


def _carregar_parser_c():
    sistema = platform.system()
    nome    = "http_parser.dll" if sistema == "Windows" else "http_parser.so"
    caminho = Path(__file__).parent / nome

    if not caminho.exists():
        print(
            f"[NetLab] {nome} nao encontrado — usando parser Python.\n"
            f"         Execute: python compilar_http_parser.py"
        )
        return None

    try:
        lib = ctypes.CDLL(str(caminho))
        fn  = lib.parse_http_request
        fn.argtypes = [
            ctypes.POINTER(ctypes.c_uint8),
            ctypes.c_int,
            ctypes.POINTER(_HttpResult),
        ]
        fn.restype = None
        print(f"[NetLab] Parser C carregado: {caminho}")
        return fn
    except Exception as e:
        print(f"[NetLab] Falha ao carregar {nome}: {e} — usando Python.")
        return None


_c_parse_http = _carregar_parser_c()


def _parse_http_c(payload: bytes, ip_origem, ip_destino):
    result = _HttpResult()
    buf    = (ctypes.c_uint8 * len(payload)).from_buffer_copy(payload)
    _c_parse_http(buf, len(payload), ctypes.byref(result))

    if not result.is_http:
        return None, "TCP"

    metodo  = result.method.decode("utf-8",  errors="ignore")
    recurso = result.resource.decode("utf-8", errors="ignore")
    credenciais = [
        (
            result.cred_keys[i].decode("utf-8", errors="ignore"),
            result.cred_vals[i].decode("utf-8", errors="ignore"),
        )
        for i in range(result.cred_count)
    ]
    return {
        "tipo":          "HTTP",
        "ip_origem":     ip_origem,
        "ip_destino":    ip_destino,
        "metodo":        metodo,
        "recurso":       recurso,
        "credenciais":   credenciais,
        "payload_bruto": payload[:500].decode("utf-8", errors="ignore"),
        "protocolo":     "HTTP",
    }, "HTTP"


def _parse_http_python(payload: bytes, ip_origem, ip_destino):
    if not payload or not _RE_HTTP_METHOD.match(payload):
        return None, "TCP"
    try:
        nl     = payload.index(b"\r\n") if b"\r\n" in payload else 200
        linha  = payload[:nl].decode("utf-8", errors="ignore").split(" ", 2)
        metodo = linha[0] if linha else "HTTP"
        recurso= linha[1] if len(linha) > 1 else "/"

        credenciais = []
        if metodo == "POST":
            sep = payload.find(b"\r\n\r\n")
            if sep != -1:
                for m in _RE_CREDENTIALS.finditer(payload[sep + 4:]):
                    credenciais.append((
                        m.group(1).decode("utf-8", errors="ignore"),
                        m.group(2).decode("utf-8", errors="ignore"),
                    ))
        return {
            "tipo":          "HTTP",
            "ip_origem":     ip_origem,
            "ip_destino":    ip_destino,
            "metodo":        metodo,
            "recurso":       recurso,
            "credenciais":   credenciais,
            "payload_bruto": payload[:500].decode("utf-8", errors="ignore"),
            "protocolo":     "HTTP",
        }, "HTTP"
    except Exception:
        return None, "TCP"


_parse_http = _parse_http_c if _c_parse_http else _parse_http_python


# ════════════════════════════════════════════════════════════
# Funcao de parsing sem estado (nivel de modulo — picklable)
# ════════════════════════════════════════════════════════════

def _parsear_pacote(dados: dict):
    """
    Detecta o tipo de pacote. Sem estado — seguro para qualquer thread.
    Retorna (evento_ou_None, protocolo_efetivo, tamanho, ip_origem, ip_destino).
    """
    tamanho    = dados.get("tamanho") or 0
    proto      = dados.get("protocolo") or "Outro"
    ip_origem  = dados.get("ip_origem")
    ip_destino = dados.get("ip_destino")
    porta_dest = dados.get("porta_destino")
    porta_orig = dados.get("porta_origem")

    evento            = None
    protocolo_efetivo = proto

    if proto == "DNS":
        dominio = dados.get("dominio")
        if dominio:
            evento = {
                "tipo":       "DNS",
                "ip_origem":  ip_origem,
                "ip_destino": ip_destino,
                "dominio":    dominio,
                "protocolo":  "DNS",
            }

    elif proto == "TCP":
        if dados.get("flags") == "SYN":
            evento = {
                "tipo":          "TCP_SYN",
                "ip_origem":     ip_origem,
                "ip_destino":    ip_destino,
                "porta_origem":  porta_orig,
                "porta_destino": porta_dest,
                "protocolo":     "TCP",
            }
        elif porta_dest in _PORTAS_HTTP or porta_orig in _PORTAS_HTTP:
            evento, protocolo_efetivo = _parse_http(
                dados.get("payload", b""), ip_origem, ip_destino
            )
            # --- ENRIQUECIMENTO PARA O MOTOR PEDAGÓGICO ---
            if evento and evento.get("tipo") == "HTTP":
                payload_bruto = dados.get("payload", b"")
                if payload_bruto:
                    try:
                        payload_texto = payload_bruto.decode('utf-8', errors='ignore')
                        # Separa cabeçalho e corpo
                        if '\r\n\r\n' in payload_texto:
                            cabecalho, corpo = payload_texto.split('\r\n\r\n', 1)
                            linhas_cabecalho = cabecalho.split('\r\n')
                            # Extrai headers
                            headers = {}
                            for linha in linhas_cabecalho[1:]:
                                if ': ' in linha:
                                    chave, valor = linha.split(': ', 1)
                                    headers[chave] = valor
                            evento["http_headers"] = headers
                            evento["http_corpo"] = corpo
                            # Garante método e caminho já existentes
                            if "metodo" in evento:
                                evento["http_metodo"] = evento["metodo"]
                            if "recurso" in evento:
                                evento["http_caminho"] = evento["recurso"]
                    except Exception:
                        pass
            # -------------------------------------------
        elif porta_dest in _PORTAS_HTTPS or porta_orig in _PORTAS_HTTPS:
            protocolo_efetivo = "HTTPS"
            evento = {
                "tipo":       "HTTPS",
                "ip_origem":  ip_origem,
                "ip_destino": ip_destino,
                "protocolo":  "HTTPS",
            }

    elif proto == "ICMP":
        evento = {
            "tipo":       "ICMP",
            "ip_origem":  ip_origem,
            "ip_destino": ip_destino,
            "protocolo":  "ICMP",
        }

    elif proto == "ARP":
        evento = {
            "tipo":       "ARP",
            "ip_origem":  ip_origem,
            "ip_destino": ip_destino,
            "mac_origem": dados.get("mac_origem"),
            "protocolo":  "ARP",
        }

    return evento, protocolo_efetivo, tamanho, ip_origem, ip_destino


# ════════════════════════════════════════════════════════════
# CAMADA 2 — Thread de analise dedicada
# ════════════════════════════════════════════════════════════

class ThreadAnalisador(threading.Thread):
    """
    Thread daemon que consome pacotes da fila de entrada,
    analisa em lotes e deposita resultados na fila de saida.
    O Qt timer le apenas a fila de saida — nunca bloqueia a UI.
    """

    def __init__(self, fila_entrada: deque, fila_saida: deque,
                 analisador: "AnalisadorPacotes"):
        super().__init__(name="NetLab-Analisador", daemon=True)
        self._fila_entrada = fila_entrada
        self._fila_saida   = fila_saida
        self._analisador   = analisador
        self._rodando      = threading.Event()

    def run(self):
        self._rodando.set()
        fila_in  = self._fila_entrada
        fila_out = self._fila_saida
        processar = self._analisador._processar_dados_brutos

        while self._rodando.is_set():
            if not fila_in:
                time.sleep(SLEEP_VAZIO)
                continue

            lote = []
            try:
                while fila_in and len(lote) < BATCH_SIZE:
                    lote.append(fila_in.popleft())
            except IndexError:
                pass

            for dados in lote:
                evento = processar(dados)
                if evento:
                    fila_out.append(evento)

    def parar(self):
        self._rodando.clear()


# ════════════════════════════════════════════════════════════
# CAMADA 3 — AnalisadorPacotes com filas limitadas
# ════════════════════════════════════════════════════════════

class AnalisadorPacotes:
    """
    Analisador de pacotes de alta performance para o NetLab Educacional.

    Modo assincrono (recomendado — zero travamento na UI):
        analisador.iniciar_thread()             # em _iniciar_captura()
        analisador.enfileirar(dados)            # no capturador_rede
        eventos, _ = analisador.coletar_resultados()  # no _consumir_fila()
        analisador.parar_thread()               # em _parar_captura()

    Modo sincrono (compativel com o original):
        evento = analisador.processar_pacote(dados)
    """

    def __init__(self):
        self._fila_entrada: deque = deque(maxlen=MAXQ_ENTRADA)
        self._fila_saida:   deque = deque(maxlen=MAXQ_SAIDA)
        self._thread: Optional[ThreadAnalisador] = None
        self._lock = threading.Lock()
        self.resetar()

    # ── Ciclo de vida ────────────────────────────────────────

    def iniciar_thread(self):
        """Inicia a thread de analise. Chamar em _iniciar_captura()."""
        if self._thread and self._thread.is_alive():
            return
        self._thread = ThreadAnalisador(
            self._fila_entrada, self._fila_saida, self
        )
        self._thread.start()

    def parar_thread(self):
        """Para a thread de analise. Chamar em _parar_captura()."""
        if self._thread:
            self._thread.parar()
            self._thread.join(timeout=2.0)
            self._thread = None

    def enfileirar(self, dados: dict):
        """
        Enfileira pacote para analise assincrona.
        Se a fila estiver cheia (8000 itens), o mais antigo e descartado
        automaticamente pelo deque(maxlen=) — sem travar, sem OOM.
        """
        self._fila_entrada.append(dados)

    def coletar_resultados(self):
        """
        Retorna (lista_eventos, stats) consumindo toda a fila de saida.
        Chamado pelo Qt timer — operacao O(n_eventos), nunca bloqueia.
        """
        eventos = []
        try:
            while self._fila_saida:
                eventos.append(self._fila_saida.popleft())
        except IndexError:
            pass
        return eventos, {"total_pacotes": self.total_pacotes,
                         "total_bytes":   self.total_bytes}

    # ── Reset ────────────────────────────────────────────────

    def resetar(self):
        with self._lock:
            self.total_pacotes: int = 0
            self.total_bytes:   int = 0
            self.estatisticas_protocolos: defaultdict = defaultdict(int)
            self.bytes_por_protocolo:     defaultdict = defaultdict(int)
            self._enviado:  defaultdict = defaultdict(int)
            self._recebido: defaultdict = defaultdict(int)
            self._top_dns:  defaultdict = defaultdict(lambda: [0, 0])
            self._fila_entrada.clear()
            self._fila_saida.clear()
            _CACHE_LOCAL.clear()

    # ── Compatibilidade ──────────────────────────────────────

    @property
    def trafego_dispositivos(self) -> dict:
        """Compatibilidade com codigo legado. Nao chamar no hot-path."""
        ips = set(self._enviado) | set(self._recebido)
        return {
            ip: {"enviado": self._enviado[ip], "recebido": self._recebido[ip]}
            for ip in ips
        }

    # ── Hot-path interno (chamado pela thread) ───────────────

    def _processar_dados_brutos(self, dados: dict) -> Optional[dict]:
        """
        Atualiza contadores e retorna evento.
        int += int e atomico no CPython (GIL) — sem lock no hot-path.
        """
        evento, proto_ef, tamanho, ip_orig, ip_dest = _parsear_pacote(dados)

        self.total_pacotes += 1
        self.total_bytes   += tamanho
        self.estatisticas_protocolos[proto_ef] += 1
        self.bytes_por_protocolo[proto_ef]     += tamanho

        if ip_orig:
            self._enviado[ip_orig]  += tamanho
        if ip_dest:
            self._recebido[ip_dest] += tamanho

        if proto_ef == "DNS" and evento and evento.get("dominio"):
            entrada = self._top_dns[evento["dominio"]]
            entrada[0] += 1
            entrada[1] += tamanho

        return evento

    # ── API publica compativel com o original ────────────────

    def processar_pacote(self, dados: dict) -> Optional[dict]:
        """Modo sincrono — mantido para compatibilidade total."""
        return self._processar_dados_brutos(dados)

    def processar_lote(self, lista_dados: list) -> list:
        """Processa lista de pacotes de uma vez. Retorna lista de eventos."""
        return [self._processar_dados_brutos(d) for d in lista_dados]

    def obter_estatisticas_protocolos(self) -> list:
        resultado = [
            {
                "protocolo": proto,
                "pacotes":   pacotes,
                "bytes":     self.bytes_por_protocolo.get(proto, 0),
            }
            for proto, pacotes in self.estatisticas_protocolos.items()
        ]
        resultado.sort(key=lambda x: x["pacotes"], reverse=True)
        return resultado

    def obter_top_dispositivos(self, top_n: int = 10) -> list:
        agregado_env: defaultdict = defaultdict(int)
        agregado_rec: defaultdict = defaultdict(int)

        for ip, v in self._enviado.items():
            chave = ip if _eh_local_rapido(ip) else "internet"
            agregado_env[chave] += v

        for ip, v in self._recebido.items():
            chave = ip if _eh_local_rapido(ip) else "internet"
            agregado_rec[chave] += v

        ips = set(agregado_env) | set(agregado_rec)
        ordenados = sorted(
            ips,
            key=lambda ip: agregado_env[ip] + agregado_rec[ip],
            reverse=True,
        )
        return [
            {
                "ip":       ip,
                "enviado":  agregado_env[ip],
                "recebido": agregado_rec[ip],
                "total":    agregado_env[ip] + agregado_rec[ip],
            }
            for ip in ordenados[:top_n]
        ]

    def obter_top_dns(self, top_n: int = 10) -> list:
        ordenados = sorted(
            self._top_dns.items(),
            key=lambda x: x[1][0],
            reverse=True,
        )
        return [
            {"dominio": dom, "acessos": info[0], "bytes": info[1]}
            for dom, info in ordenados[:top_n]
        ]

    @staticmethod
    def _eh_local(ip: str) -> bool:
        return _eh_local_rapido(ip)
