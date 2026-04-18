"""
utils/identificador.py
──────────────────────
Gerenciador de identificação de fabricantes de dispositivos de rede.

Utiliza a base OUI oficial do Wireshark (biblioteca `manuf`) para
identificação 100% local, com atualização automática em background
e persistência de apelidos personalizados em JSON.

Instalação:
    pip install manuf

Uso básico:
    from utils.identificador import GerenciadorDispositivos

    gerenciador = GerenciadorDispositivos()
    fabricante  = gerenciador.identificar_fabricante("aa:bb:cc:dd:ee:ff")
    apelido     = gerenciador.obter_apelido("aa:bb:cc:dd:ee:ff")
"""

from __future__ import annotations

import json
import logging
import threading
import time
import urllib.request
import urllib.error
from pathlib import Path
from typing import Callable, Optional, Dict, Union

logger = logging.getLogger(__name__)

# ── Configurações globais ─────────────────────────────────────────────────────

# Cache local da base OUI (pasta oculta no diretório do usuário)
CAMINHO_CACHE_DIR  = Path.home() / ".cache" / "manuf"
CAMINHO_CACHE_BASE = CAMINHO_CACHE_DIR / "manuf"

# Apelidos personalizados (persistidos entre reinicializações)
CAMINHO_ALIASES = Path("dados") / "aliases.json"

# Fontes oficiais da base OUI do Wireshark (tenta a principal; fallback para alternativa)
URL_BASE_PRINCIPAL    = "https://gitlab.com/wireshark/wireshark/-/raw/master/manuf"
URL_BASE_ALTERNATIVA  = "https://www.wireshark.org/download/automated/data/manuf"

# Tempo máximo de vida da base local antes de solicitar atualização
VALIDADE_BASE_DIAS = 30

# Timeouts de rede (em segundos)
TIMEOUT_DOWNLOAD = 30   # Download completo da base OUI
TIMEOUT_FALLBACK = 2    # Consulta pontual à API online

# Limite do cache de lookups em RAM (evita crescimento ilimitado)
CAPACIDADE_CACHE_RAM = 10_000


class GerenciadorDispositivos:
    """
    Singleton thread-safe para identificação de fabricantes via endereço MAC.

    ┌─────────────────────────────────────────────────────────┐
    │  Fluxo de identificação (em ordem de prioridade):       │
    │                                                         │
    │  1. Cache RAM   →  O(1), nanosegundos                   │
    │  2. MacParser   →  < 1 ms, 100% local                   │
    │  3. Online API  →  só se habilitado explicitamente       │
    └─────────────────────────────────────────────────────────┘

    Atualização automática da base OUI:
      • Ao iniciar: verifica se a base tem mais de 30 dias
      • Sob demanda: chamar atualizar_base_wireshark()
      • Nunca bloqueia a thread da UI (PyQt6)

    Persistência de apelidos:
      • Arquivo JSON em dados/aliases.json
      • Escrita atômica (sem risco de corrupção)
      • Chave: MAC normalizado (12 hex maiúsculos, sem separadores)
    """

    # ── Estado do Singleton ───────────────────────────────────────────────────
    _instancia: Optional["GerenciadorDispositivos"] = None
    _lock_singleton = threading.Lock()

    # ─────────────────────────────────────────────────────────────────────────
    # Ciclo de vida
    # ─────────────────────────────────────────────────────────────────────────

    def __new__(cls) -> "GerenciadorDispositivos":
        """Garante exatamente uma instância em toda a aplicação."""
        with cls._lock_singleton:
            if cls._instancia is None:
                instancia = super().__new__(cls)
                instancia._inicializado = False
                cls._instancia = instancia
        return cls._instancia

    def __init__(self):
        """
        Inicializa o gerenciador apenas na primeira chamada.
        Chamadas subsequentes são ignoradas (padrão Singleton).
        """
        if self._inicializado:
            return

        self._inicializado = True

        # Lock principal para operações thread-safe
        self._lock = threading.Lock()

        # MacParser carregado em thread daemon (nunca bloqueia a UI)
        self._parser = None

        # Cache de lookups em RAM: {mac_normalizado → fabricante}
        self._cache_lookup: dict[str, str] = {}

        # Apelidos personalizados: {mac_normalizado → apelido}
        self._aliases: dict[str, str] = {}

        # Fallback online desabilitado por padrão
        self._fallback_habilitado = False

        # Garante que os diretórios necessários existam
        CAMINHO_CACHE_DIR.mkdir(parents=True, exist_ok=True)
        CAMINHO_ALIASES.parent.mkdir(parents=True, exist_ok=True)

        # Carrega apelidos do disco (operação rápida — apenas leitura local)
        self._carregar_aliases()

        # Inicializa o parser OUI em thread daemon para não travar a UI
        threading.Thread(
            target=self._inicializar_em_background,
            name="NetLab-OUI-Init",
            daemon=True,
        ).start()

    # ─────────────────────────────────────────────────────────────────────────
    # Inicialização em background
    # ─────────────────────────────────────────────────────────────────────────

    def _inicializar_em_background(self):
        """
        Carrega o MacParser e verifica se a base OUI precisa de atualização.
        Sempre executado em thread daemon — nunca bloqueia a UI.
        """
        self._carregar_parser()

        if self._base_esta_desatualizada():
            logger.info(
                "[OUI] Base com mais de %d dias — atualizando automaticamente.",
                VALIDADE_BASE_DIAS,
            )
            self._executar_download(callback=None)

    def _carregar_parser(self):
        """
        Carrega o MacParser da biblioteca `manuf`.

        Ordem de preferência:
        1. Base local em cache (~/.cache/manuf/manuf) — mais recente
        2. Base padrão instalada com o pacote manuf — sempre disponível offline
        """
        try:
            from manuf import MacParser

            if CAMINHO_CACHE_BASE.exists() and CAMINHO_CACHE_BASE.stat().st_size > 0:
                parser = MacParser(manuf_name=str(CAMINHO_CACHE_BASE))
                logger.info("[OUI] MacParser carregado do cache local: %s", CAMINHO_CACHE_BASE)
            else:
                parser = MacParser()
                logger.info("[OUI] MacParser carregado da base padrão do pacote.")

            with self._lock:
                self._parser = parser
                # Invalida cache após carregar novo parser
                self._cache_lookup.clear()

        except ImportError:
            logger.warning(
                "[OUI] Biblioteca 'manuf' não encontrada.\n"
                "       Instale com: pip install manuf"
            )
        except Exception as erro:
            logger.error("[OUI] Falha ao carregar MacParser: %s", erro)

    # ─────────────────────────────────────────────────────────────────────────
    # Atualização da base OUI
    # ─────────────────────────────────────────────────────────────────────────

    def _base_esta_desatualizada(self) -> bool:
        """
        Verifica se a base OUI local está desatualizada ou ausente.

        Returns:
            True se a base não existe ou tem mais de VALIDADE_BASE_DIAS dias.
        """
        if not CAMINHO_CACHE_BASE.exists():
            return True

        try:
            idade_dias = (time.time() - CAMINHO_CACHE_BASE.stat().st_mtime) / 86_400
            return idade_dias > VALIDADE_BASE_DIAS
        except OSError:
            return True

    def atualizar_base_wireshark(
        self,
        callback_conclusao: Optional[Callable[[bool, str], None]] = None,
    ):
        """
        Inicia o download da base OUI do Wireshark em thread daemon.

        Args:
            callback_conclusao:
                Função chamada ao término do download.
                Assinatura: callback(sucesso: bool, mensagem: str)

                ATENÇÃO: o callback é chamado em uma thread daemon,
                não na thread da UI. Use QMetaObject.invokeMethod() ou
                sinais PyQt6 para atualizar a interface com segurança.

        Exemplo de uso com PyQt6:
            gerenciador.atualizar_base_wireshark(
                callback_conclusao=lambda ok, msg: self._ao_concluir_atualizacao(ok, msg)
            )
        """
        threading.Thread(
            target=self._executar_download,
            args=(callback_conclusao,),
            name="NetLab-OUI-Update",
            daemon=True,
        ).start()

    def _executar_download(
        self,
        callback: Optional[Callable[[bool, str], None]],
    ):
        """
        Baixa a base OUI e recarrega o parser.
        Tenta a URL principal primeiro; usa a alternativa se falhar.
        """
        sucesso  = False
        mensagem = "Falha desconhecida."

        for url in (URL_BASE_PRINCIPAL, URL_BASE_ALTERNATIVA):
            try:
                logger.info("[OUI] Baixando base de: %s", url)

                req = urllib.request.Request(
                    url,
                    headers={"User-Agent": "NetLab-Educacional/3.1"},
                )
                with urllib.request.urlopen(req, timeout=TIMEOUT_DOWNLOAD) as resposta:
                    conteudo = resposta.read()

                # Sanidade: arquivo muito pequeno indica erro na resposta
                if len(conteudo) < 10_000:
                    mensagem = f"Arquivo recebido parece incompleto ({len(conteudo)} bytes)."
                    logger.warning("[OUI] %s Tentando próxima URL.", mensagem)
                    continue

                # Salva no cache local de forma atômica
                caminho_temp = CAMINHO_CACHE_BASE.with_suffix(".tmp")
                caminho_temp.write_bytes(conteudo)
                caminho_temp.replace(CAMINHO_CACHE_BASE)

                tamanho_kb = len(conteudo) // 1024
                logger.info("[OUI] Base salva (%d KB) em: %s", tamanho_kb, CAMINHO_CACHE_BASE)

                # Recarrega o parser com a base atualizada
                self._carregar_parser()

                sucesso  = True
                mensagem = f"Base OUI atualizada com sucesso ({tamanho_kb} KB)."
                logger.info("[OUI] %s", mensagem)
                break

            except urllib.error.URLError as erro:
                mensagem = f"Falha de rede ao acessar {url}: {erro.reason}"
                logger.warning("[OUI] %s", mensagem)

            except Exception as erro:
                mensagem = f"Erro inesperado: {erro}"
                logger.error("[OUI] Falha no download (%s): %s", url, mensagem)

        # Notifica o chamador (geralmente para atualizar a UI)
        if callback:
            try:
                callback(sucesso, mensagem)
            except Exception as erro_cb:
                logger.warning("[OUI] Erro ao executar callback: %s", erro_cb)

    # ─────────────────────────────────────────────────────────────────────────
    # Identificação de fabricante
    # ─────────────────────────────────────────────────────────────────────────

    def identificar_fabricante(self, mac: str) -> str:
        """
        Identifica o fabricante do dispositivo a partir do endereço MAC.

        Lookup em cascata (ordem de prioridade):
          1. Cache RAM       → O(1), nanosegundos
          2. MacParser local → < 1 ms, sem rede

        Args:
            mac: endereço MAC em qualquer formato:
                 "aa:bb:cc:dd:ee:ff", "AA-BB-CC-DD-EE-FF",
                 "aabb.ccdd.eeff", "aabbccddeeff", etc.

        Returns:
            Nome do fabricante (ex.: "Apple", "Samsung") ou "Desconhecido".
        """
        if not mac or not isinstance(mac, str):
            return "Desconhecido"

        mac_normalizado = self._normalizar_mac(mac)
        if not mac_normalizado:
            return "Desconhecido"

        # ── Etapa 1: cache em RAM ─────────────────────────────────────────
        with self._lock:
            resultado_cache = self._cache_lookup.get(mac_normalizado)
        if resultado_cache is not None:
            return resultado_cache

        # ── Etapa 2: MacParser local ──────────────────────────────────────
        fabricante = self._consultar_parser(mac_normalizado)

        # Armazena no cache para próximas consultas
        self._armazenar_no_cache(mac_normalizado, fabricante)

        return fabricante

    def _consultar_parser(self, mac_normalizado: str) -> str:
        """Consulta o MacParser com o MAC normalizado (thread-safe)."""
        with self._lock:
            parser = self._parser

        if parser is None:
            return "Desconhecido"

        try:
            # O manuf espera o formato com dois-pontos
            mac_formatado = ":".join(
                mac_normalizado[i : i + 2]
                for i in range(0, min(12, len(mac_normalizado)), 2)
            )

            # Prefere nome longo (mais descritivo); usa nome curto como fallback
            resultado = (
                parser.get_manuf_long(mac_formatado)
                or parser.get_manuf(mac_formatado)
            )
            return resultado if resultado else "Desconhecido"

        except Exception as erro:
            logger.debug("[OUI] Lookup falhou para %s: %s", mac_normalizado, erro)
            return "Desconhecido"

    def _armazenar_no_cache(self, mac_normalizado: str, fabricante: str):
        """
        Armazena resultado no cache RAM com controle de capacidade.
        Remove os 20% mais antigos quando o limite é atingido.
        """
        with self._lock:
            if len(self._cache_lookup) >= CAPACIDADE_CACHE_RAM:
                remover = list(self._cache_lookup.keys())[: CAPACIDADE_CACHE_RAM // 5]
                for chave in remover:
                    del self._cache_lookup[chave]
            self._cache_lookup[mac_normalizado] = fabricante

    def identificar_fabricante_online(self, mac: str) -> str:
        """
        Identifica o fabricante via API online (api.macvendors.com).

        AVISO: operação bloqueante — nunca chamar na thread da UI (PyQt6).
               Só funciona se o fallback online estiver explicitamente habilitado.

        Args:
            mac: endereço MAC em qualquer formato.

        Returns:
            Nome do fabricante ou "Desconhecido".
        """
        if not self._fallback_habilitado:
            return "Desconhecido"

        mac_normalizado = self._normalizar_mac(mac)
        if not mac_normalizado:
            return "Desconhecido"

        try:
            # Consulta apenas pelo OUI (3 primeiros bytes)
            oui = mac_normalizado[:6]
            url = f"https://api.macvendors.com/{oui}"

            req = urllib.request.Request(
                url, headers={"User-Agent": "NetLab-Educacional/3.1"}
            )
            with urllib.request.urlopen(req, timeout=TIMEOUT_FALLBACK) as resposta:
                resultado = resposta.read().decode("utf-8", errors="ignore").strip()
                return resultado or "Desconhecido"

        except Exception:
            return "Desconhecido"

    def habilitar_fallback_online(self, habilitar: bool = True):
        """
        Habilita ou desabilita a consulta online como fallback de identificação.

        Args:
            habilitar: True para habilitar consultas à API online.
        """
        self._fallback_habilitado = bool(habilitar)

    # ─────────────────────────────────────────────────────────────────────────
    # Gestão de apelidos personalizados
    # ─────────────────────────────────────────────────────────────────────────

    def salvar_apelido(self, mac: str, apelido: str):
        """
        Salva um apelido personalizado para o dispositivo.

        O apelido é persistido em JSON e sobrevive a reinicializações.
        Passar apelido vazio remove o apelido existente.

        Args:
            mac:    endereço MAC do dispositivo (qualquer formato).
            apelido: nome amigável definido pelo usuário.
        """
        mac_normalizado = self._normalizar_mac(mac)
        if not mac_normalizado:
            return

        apelido_limpo = apelido.strip()

        with self._lock:
            if apelido_limpo:
                self._aliases[mac_normalizado] = apelido_limpo
            else:
                # Apelido vazio = remoção do apelido
                self._aliases.pop(mac_normalizado, None)

        self._persistir_aliases()
        logger.debug("[OUI] Apelido salvo: %s → '%s'", mac_normalizado, apelido_limpo)

    def obter_apelido(self, mac: str) -> str:
        """
        Recupera o apelido personalizado de um dispositivo.

        Args:
            mac: endereço MAC do dispositivo (qualquer formato).

        Returns:
            Apelido definido pelo usuário ou "" se não houver.
        """
        mac_normalizado = self._normalizar_mac(mac)
        if not mac_normalizado:
            return ""

        with self._lock:
            return self._aliases.get(mac_normalizado, "")

    def remover_apelido(self, mac: str):
        """Remove o apelido personalizado de um dispositivo."""
        self.salvar_apelido(mac, "")

    def listar_aliases(self) -> dict[str, str]:
        """
        Retorna cópia de todos os apelidos cadastrados.

        Returns:
            Dicionário {mac_normalizado → apelido}.
        """
        with self._lock:
            return dict(self._aliases)

    # ─────────────────────────────────────────────────────────────────────────
    # Persistência de aliases (escrita atômica)
    # ─────────────────────────────────────────────────────────────────────────

    def _carregar_aliases(self):
        """Lê aliases do arquivo JSON na inicialização."""
        if not CAMINHO_ALIASES.exists():
            return

        try:
            with open(CAMINHO_ALIASES, "r", encoding="utf-8") as arq:
                dados_brutos: dict = json.load(arq)

            # Normaliza todas as chaves para garantir consistência
            aliases_normalizados = {}
            for chave, valor in dados_brutos.items():
                if not (isinstance(chave, str) and isinstance(valor, str)):
                    continue
                mac_norm = self._normalizar_mac(chave)
                if mac_norm and valor.strip():
                    aliases_normalizados[mac_norm] = valor.strip()

            with self._lock:
                self._aliases = aliases_normalizados

            logger.info("[OUI] %d apelido(s) carregado(s) de %s.", len(self._aliases), CAMINHO_ALIASES)

        except json.JSONDecodeError:
            logger.warning("[OUI] Arquivo de aliases corrompido — iniciando com lista vazia.")
        except Exception as erro:
            logger.warning("[OUI] Falha ao carregar aliases: %s", erro)

    def _persistir_aliases(self):
        """
        Salva aliases no arquivo JSON de forma atômica.

        Estratégia: escreve em arquivo temporário e renomeia atomicamente,
        eliminando risco de corrupção em caso de falha durante a escrita.
        """
        try:
            CAMINHO_ALIASES.parent.mkdir(parents=True, exist_ok=True)

            with self._lock:
                aliases_copia = dict(self._aliases)

            caminho_temp = CAMINHO_ALIASES.with_suffix(".tmp")

            with open(caminho_temp, "w", encoding="utf-8") as arq:
                json.dump(aliases_copia, arq, ensure_ascii=False, indent=2)

            # Renomeação atômica (os.replace é atômico no POSIX e Windows)
            caminho_temp.replace(CAMINHO_ALIASES)

        except Exception as erro:
            logger.warning("[OUI] Falha ao persistir aliases: %s", erro)

    # ─────────────────────────────────────────────────────────────────────────
    # Utilitários
    # ─────────────────────────────────────────────────────────────────────────

    @staticmethod
    def _normalizar_mac(mac: str) -> str:
        """
        Normaliza um endereço MAC para o formato interno padrão.

        Remove separadores (: - .) e converte para maiúsculas.
        Valida que contém apenas caracteres hexadecimais válidos.

        Returns:
            String de até 12 caracteres hex maiúsculos, ou "" se inválido.
        """
        if not mac or not isinstance(mac, str):
            return ""

        mac_limpo = (
            mac.upper()
               .replace(":", "")
               .replace("-", "")
               .replace(".", "")
               .strip()
        )

        # Precisa de pelo menos 6 caracteres para o OUI
        if len(mac_limpo) < 6:
            return ""

        hex_valido = frozenset("0123456789ABCDEF")
        if not all(c in hex_valido for c in mac_limpo[:12]):
            return ""

        return mac_limpo[:12]

    @property
    def parser_disponivel(self) -> bool:
        """True se o MacParser foi carregado com sucesso."""
        with self._lock:
            return self._parser is not None

    @property
    def data_ultima_atualizacao(self) -> Optional[float]:
        """
        Timestamp Unix da última atualização da base OUI.
        Retorna None se a base ainda não foi baixada.
        """
        if not CAMINHO_CACHE_BASE.exists():
            return None
        try:
            return CAMINHO_CACHE_BASE.stat().st_mtime
        except OSError:
            return None

    def obter_status(self) -> dict:
        """
        Retorna um resumo do estado atual do gerenciador.
        Útil para painéis de diagnóstico e depuração.

        Returns:
            Dicionário com campos:
            - parser_disponivel  (bool)
            - data_atualizacao   (str)
            - base_desatualizada (bool)
            - total_aliases      (int)
            - total_cache_ram    (int)
            - fallback_habilitado (bool)
        """
        import datetime

        timestamp = self.data_ultima_atualizacao
        if timestamp:
            data_formatada = datetime.datetime.fromtimestamp(timestamp).strftime(
                "%d/%m/%Y %H:%M"
            )
        else:
            data_formatada = "Nunca atualizada"

        with self._lock:
            total_aliases  = len(self._aliases)
            total_cache    = len(self._cache_lookup)

        return {
            "parser_disponivel":   self.parser_disponivel,
            "data_atualizacao":    data_formatada,
            "base_desatualizada":  self._base_esta_desatualizada(),
            "total_aliases":       total_aliases,
            "total_cache_ram":     total_cache,
            "fallback_habilitado": self._fallback_habilitado,
        }


# ==============================================================================
# FUNÇÕES AUXILIARES PARA O PAINEL DE TOPOLOGIA
# ==============================================================================
# As funções abaixo são usadas por painel_topologia.py para gerenciar aliases
# e inferir tipos de dispositivos sem depender diretamente do singleton.
# Elas foram adicionadas para resolver o erro de importação.

def obter_caminho_aliases_padrao() -> Path:
    """Retorna o caminho padrão do arquivo de aliases."""
    return CAMINHO_ALIASES


def carregar_aliases(caminho: Optional[Path] = None) -> Dict[str, str]:
    """
    Carrega os aliases do arquivo JSON.

    Args:
        caminho: Caminho opcional do arquivo. Se None, usa CAMINHO_ALIASES.

    Returns:
        Dicionário com chave (mac_normalizado ou ip) -> apelido.
    """
    caminho = caminho or CAMINHO_ALIASES
    if not caminho.exists():
        return {}

    try:
        with open(caminho, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}


def salvar_aliases(aliases: Dict[str, str], caminho: Optional[Path] = None) -> bool:
    """
    Salva os aliases no arquivo JSON de forma atômica.

    Args:
        aliases: Dicionário de aliases.
        caminho: Caminho opcional do arquivo. Se None, usa CAMINHO_ALIASES.

    Returns:
        True se salvou com sucesso, False caso contrário.
    """
    caminho = caminho or CAMINHO_ALIASES
    try:
        caminho.parent.mkdir(parents=True, exist_ok=True)
        caminho_temp = caminho.with_suffix(".tmp")
        with open(caminho_temp, "w", encoding="utf-8") as f:
            json.dump(aliases, f, ensure_ascii=False, indent=2)
        caminho_temp.replace(caminho)
        return True
    except Exception:
        return False


def chave_alias_dispositivo(mac: str = "", ip: str = "") -> str:
    """
    Gera uma chave única para armazenar o alias de um dispositivo.
    Prioriza o MAC (mais estável) e usa o IP como fallback.

    Args:
        mac: Endereço MAC (opcional).
        ip:  Endereço IP (opcional).

    Returns:
        String no formato "mac:XXXXXXXXXXXX" ou "ip:xxx.xxx.xxx.xxx" ou "" se ambos vazios.
    """
    if mac:
        mac_norm = GerenciadorDispositivos._normalizar_mac(mac)
        if mac_norm:
            return f"mac:{mac_norm}"
    if ip:
        return f"ip:{ip}"
    return ""


def obter_alias_persistido(aliases: Dict[str, str], mac: str = "", ip: str = "") -> str:
    """
    Busca um alias no dicionário de aliases usando a chave apropriada.

    Args:
        aliases: Dicionário carregado via carregar_aliases().
        mac:     Endereço MAC do dispositivo.
        ip:      Endereço IP do dispositivo.

    Returns:
        Alias encontrado ou "" se nenhum.
    """
    chave_mac = chave_alias_dispositivo(mac=mac)
    if chave_mac and chave_mac in aliases:
        return aliases[chave_mac]

    chave_ip = chave_alias_dispositivo(ip=ip)
    if chave_ip and chave_ip in aliases:
        return aliases[chave_ip]

    return ""


def obter_fabricante(mac: str) -> str:
    """
    Função de conveniência para obter o fabricante a partir do MAC,
    utilizando o singleton GerenciadorDispositivos.

    Args:
        mac: Endereço MAC.

    Returns:
        Nome do fabricante ou "Desconhecido".
    """
    return GerenciadorDispositivos().identificar_fabricante(mac)


def inferir_tipo_dispositivo(
    ip: str,
    mac: str,
    hostname: str,
    fabricante: str,
    eh_gateway: bool,
    eh_local: bool,
) -> str:
    """
    Heurística para classificar o tipo de dispositivo com base nas informações disponíveis.

    Args:
        ip:         Endereço IP.
        mac:        Endereço MAC.
        hostname:   Nome de host (pode ser vazio).
        fabricante: Fabricante obtido via OUI.
        eh_gateway: True se o IP é identificado como gateway da sub-rede.
        eh_local:   True se é o IP da própria máquina.

    Returns:
        String descritiva do tipo (ex.: "Gateway", "Servidor", "Dispositivo móvel", etc.)
    """
    if eh_local:
        return "Este computador"
    if eh_gateway:
        return "Gateway / Roteador"
    if fabricante and fabricante != "Desconhecido":
        fab_lower = fabricante.lower()
        if any(p in fab_lower for p in ("cisco", "juniper", "mikrotik", "ubiquiti")):
            return "Equipamento de rede"
        if any(p in fab_lower for p in ("apple", "samsung", "xiaomi", "huawei")):
            return "Dispositivo móvel"
        if any(p in fab_lower for p in ("intel", "dell", "hp", "lenovo")):
            return "Computador"
        if any(p in fab_lower for p in ("sony", "lg", "samsung")):
            return "Smart TV / Eletrônico"
    if hostname:
        host_lower = hostname.lower()
        if "server" in host_lower or "srv" in host_lower:
            return "Servidor"
        if "printer" in host_lower or "impressora" in host_lower:
            return "Impressora"
    # Fallback: analisa IP
    ultimo_octeto = int(ip.split(".")[-1]) if ip.count(".") == 3 else 0
    if ultimo_octeto in (1, 254):
        return "Gateway / Roteador"
    return "Dispositivo local"