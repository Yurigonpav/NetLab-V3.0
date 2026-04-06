# interface/painel_eventos.py
# Painel do Modo Análise — três níveis de explicação + Insights com dados reais.
#
# OTIMIZAÇÕES v3.0:
#   - "Dispositivos Mais Ativos" removido dos Insights
#   - atualizar_insights() armazena dados e renderiza apenas se houve mudança
#   - _todos_eventos usa deque(maxlen=LIMITE_EVENTOS) → O(1) em ambas as pontas
#   - Renderização baseada em chave de versão: evita trabalho redundante

from collections import defaultdict, deque
import time
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel,
    QScrollArea, QFrame, QPushButton, QTextEdit,
    QSplitter, QTabWidget, QLineEdit, QComboBox,
    QTableWidget, QTableWidgetItem, QHeaderView,
    QProgressBar, QGridLayout, QListWidget, QListWidgetItem
)
from PyQt6.QtCore import Qt, QTimer, pyqtSlot
from PyQt6.QtGui import QFont, QColor


# ─────────────────────────────────────────────────────────────
# Constantes visuais
# ─────────────────────────────────────────────────────────────

ESTILOS_NIVEL = {
    "INFO":    {"borda": "#3498DB", "fundo": "#0d1a2a", "badge": "#1a4a6b"},
    "AVISO":   {"borda": "#E67E22", "fundo": "#1f1200", "badge": "#5a3000"},
    "CRITICO": {"borda": "#E74C3C", "fundo": "#200a0a", "badge": "#5a0000"},
}

ROTULOS_NIVEL = [
    ("", "Simples",      "Linguagem do dia a dia"),
    ("", "Técnico",      "Detalhes do protocolo"),
    ("", "Pacote Bruto", "Conteúdo exato como trafegou na rede"),
]

# Domínios conhecidos → nome amigável
DOMINIOS_CONHECIDOS = {
    "google.com": "Google",           "googleapis.com": "Google APIs",
    "gstatic.com": "Google Static",   "youtube.com": "YouTube",
    "youtu.be": "YouTube",            "googlevideo.com": "YouTube Vídeo",
    "facebook.com": "Facebook",       "instagram.com": "Instagram",
    "fbcdn.net": "Facebook CDN",      "whatsapp.com": "WhatsApp",
    "whatsapp.net": "WhatsApp",       "twitter.com": "Twitter/X",
    "twimg.com": "Twitter CDN",       "x.com": "X (Twitter)",
    "netflix.com": "Netflix",         "nflxvideo.net": "Netflix Vídeo",
    "amazon.com": "Amazon",           "amazonaws.com": "Amazon AWS",
    "microsoft.com": "Microsoft",     "office.com": "Microsoft Office",
    "live.com": "Microsoft Live",     "outlook.com": "Outlook",
    "windows.com": "Windows Update",  "windowsupdate.com": "Windows Update",
    "apple.com": "Apple",             "icloud.com": "iCloud",
    "spotify.com": "Spotify",         "twitch.tv": "Twitch",
    "tiktok.com": "TikTok",           "reddit.com": "Reddit",
    "wikipedia.org": "Wikipedia",     "github.com": "GitHub",
    "steamcontent.com": "Steam",      "steampowered.com": "Steam",
    "discord.com": "Discord",         "discordapp.com": "Discord CDN",
    "cloudflare.com": "Cloudflare",   "akamai.net": "Akamai CDN",
    "akamaized.net": "Akamai CDN",    "globo.com": "Globo",
    "uol.com.br": "UOL",              "terra.com.br": "Terra",
    "zoom.us": "Zoom",                "teams.microsoft.com": "MS Teams",
    "slack.com": "Slack",             "dropbox.com": "Dropbox",
    "drive.google.com": "Google Drive",
}

# Classificação de tipo de uso por evento
CLASSIFICACAO_USO = {
    "DNS":              ("Navegação",          "#3498DB"),
    "HTTP":             ("Transferência HTTP",  "#E74C3C"),
    "HTTPS":            ("Conexão Segura",      "#2ECC71"),
    "TCP_SYN":          ("Nova Conexão",        "#9B59B6"),
    "ARP":              ("Descoberta Local",    "#E67E22"),
    "ICMP":             ("Diagnóstico/Ping",    "#1ABC9C"),
    "DHCP":             ("Config. de Rede",     "#16A085"),
    "SSH":              ("Acesso Remoto",        "#2980B9"),
    "FTP":              ("Transfer. Arquivo",   "#E91E63"),
    "SMB":              ("Compartilhamento",    "#795548"),
    "RDP":              ("Desktop Remoto",      "#FF5722"),
    "NOVO_DISPOSITIVO": ("Novo Dispositivo",    "#F39C12"),
}


# ─────────────────────────────────────────────────────────────
# Cartão de evento (lista lateral)
# ─────────────────────────────────────────────────────────────

class CartaoEvento(QFrame):
    """Cartão compacto para a lista lateral de eventos capturados."""

    def __init__(self, dados: dict, parent=None):
        super().__init__(parent)
        nivel  = dados.get("nivel", "INFO")
        estilo = ESTILOS_NIVEL.get(nivel, ESTILOS_NIVEL["INFO"])

        self.setStyleSheet(f"""
            QFrame {{
                background-color: {estilo['fundo']};
                border-left: 4px solid {estilo['borda']};
                border-radius: 3px;
                margin: 1px 2px;
            }}
            QFrame:hover {{ background-color: #1a2540; }}
        """)
        self.setCursor(Qt.CursorShape.PointingHandCursor)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(10, 5, 10, 5)
        layout.setSpacing(2)

        cabecalho = QHBoxLayout()
        icone_titulo = QLabel(
            f"{dados.get('icone', '')} {dados.get('titulo', 'Evento')}".strip()
        )
        icone_titulo.setStyleSheet(
            f"color:{estilo['borda']};font-weight:bold;"
            f"font-size:10px;border:none;"
        )
        icone_titulo.setWordWrap(False)

        hora = QLabel(dados.get("timestamp", ""))
        hora.setStyleSheet("color:#7f8c8d;font-size:9px;border:none;")

        cabecalho.addWidget(icone_titulo, 1)
        cabecalho.addWidget(hora)
        layout.addLayout(cabecalho)

        ip_src   = dados.get("ip_envolvido", "")
        ip_dst   = dados.get("ip_destino", "")
        ip_texto = ip_src
        if ip_dst and ip_dst != ip_src:
            ip_texto += f" → {ip_dst}"

        lbl_ip = QLabel(ip_texto)
        lbl_ip.setStyleSheet(
            "color:#95a5a6;font-size:9px;font-family:Consolas;border:none;"
        )
        layout.addWidget(lbl_ip)

        if dados.get("alerta_seguranca"):
            badge = QLabel("⚠ Risco de segurança")
            badge.setStyleSheet(
                f"color:#E74C3C;font-size:8px;font-weight:bold;"
                f"background:{estilo['badge']};border-radius:2px;"
                f"padding:1px 4px;border:none;"
            )
            layout.addWidget(badge)


# ─────────────────────────────────────────────────────────────
# Barra de contadores por tipo de evento
# ─────────────────────────────────────────────────────────────

class PainelContadores(QWidget):
    """Barra horizontal com contadores por tipo de evento."""

    TIPOS_MONITORADOS = [
        ("DNS",     "#3498DB"),
        ("HTTP",    "#E74C3C"),
        ("HTTPS",   "#2ECC71"),
        ("TCP_SYN", "#9B59B6"),
        ("ICMP",    "#1ABC9C"),
        ("ARP",     "#E67E22"),
        ("DHCP",    "#16A085"),
    ]

    def __init__(self, parent=None):
        super().__init__(parent)
        self._contadores: dict = defaultdict(int)
        self._labels:     dict = {}

        layout = QHBoxLayout(self)
        layout.setContentsMargins(4, 2, 4, 2)
        layout.setSpacing(8)

        titulo = QLabel("Eventos nesta sessão:")
        titulo.setStyleSheet("color:#7f8c8d;font-size:9px;")
        layout.addWidget(titulo)

        for tipo, cor in self.TIPOS_MONITORADOS:
            lbl = QLabel(f"{tipo}: 0")
            lbl.setStyleSheet(
                f"color:{cor};font-size:9px;font-family:Consolas;"
                f"background:#0d1a2a;border:1px solid {cor}33;"
                f"border-radius:3px;padding:1px 6px;"
            )
            self._labels[tipo] = lbl
            layout.addWidget(lbl)

        layout.addStretch()

    def incrementar(self, tipo: str):
        self._contadores[tipo] += 1
        if tipo in self._labels:
            self._labels[tipo].setText(f"{tipo}: {self._contadores[tipo]}")

    def resetar(self):
        self._contadores.clear()
        for tipo, _ in self.TIPOS_MONITORADOS:
            if tipo in self._labels:
                self._labels[tipo].setText(f"{tipo}: 0")

    def obter_contagens(self) -> dict:
        """Retorna cópia dos contadores para uso nos insights."""
        return dict(self._contadores)


# ─────────────────────────────────────────────────────────────
# Painel principal de Eventos
# ─────────────────────────────────────────────────────────────

class PainelEventos(QWidget):
    """
    Painel completo do Modo Análise com três níveis de explicação.
    Aba Insights: Sites Acessados (DNS real) + Tipo de Uso + Alertas.

    OTIMIZAÇÕES v3.0
    ─────────────────
    • _todos_eventos é um deque(maxlen=LIMITE_EVENTOS): O(1) nas duas pontas,
      sem cópia de lista ao atingir o limite.
    • atualizar_insights() armazena dados e renderiza apenas se houve mudança,
      evitando trabalho redundante (diff incremental).
    • "Dispositivos Mais Ativos" removido (dados de tráfego real ficam no
      painel de Tráfego em Tempo Real).
    """

    LIMITE_EVENTOS = 300

    def __init__(self, parent=None):
        super().__init__(parent)
        # Buffer circular: O(1) append/pop, sem cópia ao atingir limite
        self._todos_eventos:     deque = deque(maxlen=self.LIMITE_EVENTOS)
        self._eventos_filtrados: list  = []
        self._evento_atual:      dict  = {}
        self._nivel_atual:       int   = 0
        self._filtro_protocolo:  str   = "Todos"
        self._filtro_texto:      str   = ""
        self._contagem_sessao:   dict  = defaultdict(lambda: defaultdict(int))

        # Atributos para insights e alertas
        self._alertas_seguranca = []
        self._volume_bytes_total = 0
        self._ultimo_top_dns = []
        self._ultimo_historias = []
        self._ultima_chave_dns = ''
        self._chave_render_anterior = ''

        self._montar_layout()

    # ──────────────────────────────────────────────
    # Montagem da interface
    # ──────────────────────────────────────────────

    def _montar_layout(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(8, 8, 8, 4)
        layout.setSpacing(4)

        # Cabeçalho
        cab = QHBoxLayout()
        fonte_titulo = QFont("Arial", 12)
        fonte_titulo.setBold(True)
        titulo = QLabel("  Modo Análise — Eventos de Rede em Tempo Real")
        titulo.setFont(fonte_titulo)
        cab.addWidget(titulo)
        cab.addStretch()
        layout.addLayout(cab)

        sep = QFrame()
        sep.setFrameShape(QFrame.Shape.HLine)
        sep.setStyleSheet("color:#2c3e50;")
        layout.addWidget(sep)

        layout.addLayout(self._criar_barra_filtros())

        self.painel_contadores = PainelContadores()
        layout.addWidget(self.painel_contadores)

        self.abas = QTabWidget()
        layout.addWidget(self.abas)

        self.abas.addTab(self._criar_aba_eventos(),  "Eventos ao Vivo")
        self.abas.addTab(self._criar_aba_insights(), "Insights")

        self.lbl_rodape = QLabel("Nenhum evento registrado.")
        self.lbl_rodape.setStyleSheet("color:#7f8c8d;font-size:10px;padding:2px;")
        layout.addWidget(self.lbl_rodape)

        self._trocar_nivel(0)
        self._exibir_boas_vindas()

    # ──────────────────────────────────────────────
    # Aba de Eventos ao Vivo
    # ──────────────────────────────────────────────

    def _criar_barra_filtros(self) -> QHBoxLayout:
        row = QHBoxLayout()
        row.setSpacing(6)

        lbl = QLabel("Filtrar:")
        lbl.setStyleSheet("color:#7f8c8d;font-size:10px;")
        row.addWidget(lbl)

        self.combo_protocolo = QComboBox()
        self.combo_protocolo.setMaximumWidth(140)
        self.combo_protocolo.addItems([
            "Todos", "DNS", "HTTP", "HTTPS", "TCP_SYN", "TCP_FIN",
            "TCP_RST", "ICMP", "ARP", "DHCP", "SSH", "FTP",
            "SMB", "RDP", "NOVO_DISPOSITIVO",
        ])
        self.combo_protocolo.currentTextChanged.connect(self._ao_mudar_filtro_protocolo)
        row.addWidget(self.combo_protocolo)

        self.campo_busca = QLineEdit()
        self.campo_busca.setPlaceholderText("Buscar por IP, domínio ou palavra-chave")
        self.campo_busca.setMaximumWidth(280)
        self.campo_busca.textChanged.connect(self._ao_mudar_filtro_texto)
        row.addWidget(self.campo_busca)

        row.addStretch()
        return row

    def _criar_aba_eventos(self) -> QWidget:
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(0, 4, 0, 0)
        layout.setSpacing(0)

        splitter = QSplitter(Qt.Orientation.Horizontal)
        layout.addWidget(splitter)

        # ── Lista lateral de eventos ──────────────
        w_lista = QWidget()
        l_lista = QVBoxLayout(w_lista)
        l_lista.setContentsMargins(0, 0, 4, 0)
        l_lista.setSpacing(2)

        fonte_label = QFont("Arial", 10)
        fonte_label.setBold(True)
        lbl_lista = QLabel("Eventos Capturados")
        lbl_lista.setStyleSheet("color:#7f8c8d;padding-bottom:4px;")
        lbl_lista.setFont(fonte_label)
        l_lista.addWidget(lbl_lista)

        self._scroll = QScrollArea()
        self._scroll.setWidgetResizable(True)
        self._scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)

        self.lista_eventos = QListWidget()
        self.lista_eventos.setSpacing(2)
        self.lista_eventos.setWordWrap(True)

        self._scroll.setWidget(self.lista_eventos)
        l_lista.addWidget(self._scroll)
        splitter.addWidget(w_lista)

        # ── Painel de explicação ──────────────────
        w_expl = QWidget()
        l_expl = QVBoxLayout(w_expl)
        l_expl.setContentsMargins(4, 0, 0, 0)
        l_expl.setSpacing(4)

        lbl_expl = QLabel("📖  Explicação Didática")
        lbl_expl.setStyleSheet("font-weight:bold;font-size:11px;color:#bdc3c7;")
        l_expl.addWidget(lbl_expl)

        row_niveis = QHBoxLayout()
        self.botoes_nivel = []
        for icone, rotulo, dica in ROTULOS_NIVEL:
            btn = QPushButton(f"{icone} {rotulo}")
            btn.setCheckable(True)
            btn.setMaximumHeight(26)
            btn.setToolTip(dica)
            idx = len(self.botoes_nivel)
            btn.clicked.connect(lambda _, n=idx: self._trocar_nivel(n))
            self.botoes_nivel.append(btn)
            row_niveis.addWidget(btn)
        row_niveis.addStretch()
        l_expl.addLayout(row_niveis)

        self.texto_explicacao = QTextEdit()
        self.texto_explicacao.setReadOnly(True)
        self.texto_explicacao.setStyleSheet("""
            QTextEdit {
                background-color: #0f1423;
                color: #ecf0f1;
                border: 1px solid #1e2d40;
                border-radius: 6px;
                padding: 14px;
                font-size: 11px;
            }
        """)
        l_expl.addWidget(self.texto_explicacao)

        splitter.addWidget(w_expl)
        splitter.setSizes([400, 580])
        return widget

    # ──────────────────────────────────────────────
    # Aba Insights — dados reais
    # ──────────────────────────────────────────────

    def _criar_aba_insights(self) -> QWidget:
        widget = QWidget()
        layout_externo = QVBoxLayout(widget)
        layout_externo.setContentsMargins(0, 0, 0, 0)
        layout_externo.setSpacing(0)

        # Barra de resumo rápido no topo
        self._barra_resumo = self._criar_barra_resumo()
        layout_externo.addWidget(self._barra_resumo)

        # Área rolável com os cards
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        scroll.setStyleSheet("QScrollArea { border: none; background: transparent; }")

        self._container_insights = QWidget()
        self._layout_insights    = QVBoxLayout(self._container_insights)
        self._layout_insights.setContentsMargins(8, 6, 8, 8)
        self._layout_insights.setSpacing(10)
        self._layout_insights.addStretch()

        scroll.setWidget(self._container_insights)
        layout_externo.addWidget(scroll)

        return widget

    def _criar_barra_resumo(self) -> QFrame:
        """Faixa de métricas rápidas no topo da aba Insights."""
        frame = QFrame()
        frame.setFixedHeight(44)
        frame.setStyleSheet(
            "QFrame { background:#0a0f1a; border-bottom:1px solid #1e2d40; }"
            "QLabel { border:none; background:transparent; }"
        )
        layout = QHBoxLayout(frame)
        layout.setContentsMargins(12, 4, 12, 4)
        layout.setSpacing(0)

        def _metrica(rotulo: str, cor: str) -> QLabel:
            lbl = QLabel(rotulo)
            lbl.setStyleSheet(
                f"color:{cor};font-size:10px;font-family:Consolas;"
                "padding: 0 14px 0 0;border:none;background:transparent;"
            )
            return lbl

        lbl_label = QLabel("  Sessão atual:  ")
        lbl_label.setStyleSheet(
            "color:#566573;font-size:10px;border:none;background:transparent;"
        )

        self._lbl_resumo_eventos = _metrica("0 eventos",        "#3498DB")
        self._lbl_resumo_dns     = _metrica("0 consultas DNS",  "#2ECC71")
        self._lbl_resumo_volume  = _metrica("0 B trafegados",   "#9B59B6")
        self._lbl_resumo_alertas = _metrica("0 alertas",        "#566573")
        self._lbl_resumo_insights = _metrica("Aguardando dados de captura...", "#7f8c8d")
        self._lbl_total_insights = _metrica("", "#7f8c8d")

        layout.addWidget(lbl_label)
        layout.addWidget(self._lbl_resumo_eventos)
        layout.addWidget(self._lbl_resumo_dns)
        layout.addWidget(self._lbl_resumo_volume)
        layout.addWidget(self._lbl_resumo_alertas)
        layout.addWidget(self._lbl_resumo_insights)
        layout.addWidget(self._lbl_total_insights)
        layout.addStretch()

        return frame

    # ──────────────────────────────────────────────
    # Renderização dos Insights (diff incremental)
    # ──────────────────────────────────────────────

    def _renderizar_insights(self):
        total_ev = len(self._todos_eventos)
        top_dns = getattr(self, '_ultimo_top_dns', [])
        total_dns = sum(d.get('acessos', 0) for d in top_dns)
        
        # Atualiza a barra de resumo diretamente
        self._lbl_resumo_eventos.setText(f"{total_ev:,} eventos")
        self._lbl_resumo_dns.setText(f"{total_dns:,} consultas DNS")
        self._lbl_resumo_insights.setText(f"{total_ev} eventos · {total_dns} consultas DNS")
        self._lbl_total_insights.setText(f"{total_ev:,} eventos analisados")
        
        # Evita recriar widgets sem necessidade
        chave_render = f"{total_ev}:{total_dns}:{len(top_dns)}"
        if chave_render == self._chave_render_anterior:
            return
        self._chave_render_anterior = chave_render

        # Limpa e recria os cards
        self._limpar_layout_insights()
        if total_ev == 0:
            self._exibir_mensagem_insights_vazio()
            return

        self._layout_insights.addWidget(self._card_dominios(top_dns))
        self._layout_insights.addWidget(self._card_tipo_uso())
        self._layout_insights.addStretch()

    def _limpar_layout_insights(self):
        while self._layout_insights.count() > 0:
            item = self._layout_insights.takeAt(0)
            w = item.widget()
            if w:
                w.deleteLater()

    def _exibir_mensagem_insights_vazio(self):
        lbl = QLabel(
            "Os insights aparecerão aqui durante a captura.\n\n"
            "Inicie a captura e navegue pela internet para\n"
            "ver os dados de tráfego em tempo real."
        )
        lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        lbl.setStyleSheet("color:#4a5a6b;font-size:12px;padding:50px;")
        self._layout_insights.addWidget(lbl)
        self._layout_insights.addStretch()
        self._lbl_resumo_insights.setText("Aguardando dados de captura...")
        self._lbl_total_insights.setText("")

    def _atualizar_barra_resumo(self, eventos: int, consultas_dns: int,
                                volume_bytes: int, alertas: int):
        """Atualiza apenas os labels da faixa superior de métricas."""
        self._lbl_resumo_eventos.setText(f"{eventos:,} eventos")
        self._lbl_resumo_dns.setText(f"{consultas_dns:,} consultas DNS")
        self._lbl_resumo_volume.setText(f"{self._formatar_bytes(volume_bytes)} trafegados")
        cor_alerta = "#E74C3C" if alertas > 0 else "#566573"
        self._lbl_resumo_alertas.setStyleSheet(
            f"color:{cor_alerta};font-size:10px;font-family:Consolas;padding:0 14px 0 0;"
        )
        self._lbl_resumo_alertas.setText(
            f"{'⚠ ' if alertas > 0 else ''}{alertas} alerta(s)"
        )
        # Corrigir texto: não somar eventos + DNS
        self._lbl_resumo_insights.setText(f"{eventos} eventos · {consultas_dns} consultas DNS")

    # ──────────────────────────────────────────────
    # Card — Sites Acessados (DNS real)
    # ──────────────────────────────────────────────

    def _card_sites_acessados(self, top_dns: list) -> QFrame:
        """Usa top_dns vindo de analisador_pacotes.obter_top_dns()."""
        frame = self._criar_frame_card("#1a3a5f", "#2a5a70")
        layout = QVBoxLayout(frame)
        layout.setContentsMargins(14, 12, 14, 12)
        layout.setSpacing(8)

        cab = QHBoxLayout()
        titulo = QLabel("  Sites Mais Acessados")
        titulo.setStyleSheet("color:#2ECC71;font-weight:bold;font-size:11px;")
        cab.addWidget(titulo)
        cab.addStretch()
        total_consultas = sum(d.get("acessos", 0) for d in top_dns)
        cab.addWidget(self._lbl_info(
            f"{len(top_dns)} domínio(s) · {total_consultas} consultas DNS"
        ))
        layout.addLayout(cab)

        sub = QLabel("Baseado em consultas DNS reais capturadas na rede")
        sub.setStyleSheet("color:#4a6a8a;font-size:9px;")
        layout.addWidget(sub)

        if not top_dns:
            layout.addWidget(self._lbl_vazio("Nenhum domínio DNS capturado ainda."))
            return frame

        max_acessos = max((d.get("acessos", 1) for d in top_dns[:15]), default=1)

        for i, dom in enumerate(top_dns[:15]):
            dominio  = dom.get("dominio", "?")
            acessos  = dom.get("acessos", 0)
            bytes_d  = dom.get("bytes",   0)

            # Nome amigável por sufixo de domínio
            nome = dominio
            for sufixo, apelido in DOMINIOS_CONHECIDOS.items():
                if dominio == sufixo or dominio.endswith("." + sufixo):
                    nome = apelido
                    break

            row = QHBoxLayout()
            row.setSpacing(6)

            lbl_num = QLabel(f"{i + 1}.")
            lbl_num.setFixedWidth(20)
            lbl_num.setStyleSheet("color:#566573;font-size:9px;")

            lbl_dom = QLabel(dominio)
            lbl_dom.setFixedWidth(180)
            lbl_dom.setToolTip(nome)
            lbl_dom.setStyleSheet("color:#ecf0f1;font-size:9px;font-family:Consolas;")

            barra = QProgressBar()
            barra.setRange(0, max(max_acessos, 1))
            barra.setValue(acessos)
            barra.setFixedHeight(12)
            barra.setTextVisible(False)
            barra.setStyleSheet("""
                QProgressBar { background:#0d1520; border-radius:3px; }
                QProgressBar::chunk { background:#2ECC71; border-radius:3px; }
            """)

            lbl_cnt = QLabel(f"{acessos}x")
            lbl_cnt.setFixedWidth(36)
            lbl_cnt.setAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
            lbl_cnt.setStyleSheet("color:#2ECC71;font-size:9px;font-family:Consolas;")

            lbl_vol = QLabel(self._formatar_bytes(bytes_d))
            lbl_vol.setFixedWidth(52)
            lbl_vol.setAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
            lbl_vol.setStyleSheet("color:#9B59B6;font-size:8px;font-family:Consolas;")

            row.addWidget(lbl_num)
            row.addWidget(lbl_dom)
            row.addWidget(barra, 1)
            row.addWidget(lbl_cnt)
            row.addWidget(lbl_vol)
            layout.addLayout(row)

        return frame

    # ──────────────────────────────────────────────
    # Card — Tipo de Uso
    # ──────────────────────────────────────────────

    def _card_tipo_uso(self) -> QFrame:
        frame = self._criar_frame_card("#1a2a1f", "#2a4030")
        layout = QVBoxLayout(frame)
        layout.setContentsMargins(14, 12, 14, 12)
        layout.setSpacing(8)

        cab = QHBoxLayout()
        titulo = QLabel("  Classificação de Uso da Rede")
        titulo.setStyleSheet("color:#F39C12;font-weight:bold;font-size:11px;")
        cab.addWidget(titulo)
        cab.addStretch()
        layout.addLayout(cab)

        contagens = self.painel_contadores.obter_contagens()
        total_eventos = sum(contagens.values()) or 1

        if not contagens:
            layout.addWidget(self._lbl_vazio("Nenhum evento classificado ainda."))
            return frame

        # Agrupa por categoria
        categorias: dict = defaultdict(int)
        for tipo, qtd in contagens.items():
            cat, _ = CLASSIFICACAO_USO.get(tipo, ("Outro", "#7f8c8d"))
            categorias[cat] += qtd

        sorted_cats = sorted(categorias.items(), key=lambda x: x[1], reverse=True)
        max_qtd = sorted_cats[0][1] if sorted_cats else 1

        grid = QGridLayout()
        grid.setSpacing(6)

        for idx, (cat, qtd) in enumerate(sorted_cats[:8]):
            tipo_orig = next(
                (t for t, (c, _) in CLASSIFICACAO_USO.items() if c == cat), ""
            )
            _, cor = CLASSIFICACAO_USO.get(tipo_orig, ("", "#7f8c8d"))
            pct = (qtd / total_eventos) * 100

            lbl_cat = QLabel(cat)
            lbl_cat.setStyleSheet(f"color:{cor};font-size:9px;font-weight:bold;")

            barra = QProgressBar()
            barra.setRange(0, max(max_qtd, 1))
            barra.setValue(qtd)
            barra.setFixedHeight(10)
            barra.setTextVisible(False)
            barra.setStyleSheet(f"""
                QProgressBar {{ background:#0d1520; border-radius:3px; }}
                QProgressBar::chunk {{ background:{cor}; border-radius:3px; }}
            """)

            lbl_pct = QLabel(f"{pct:.0f}%")
            lbl_pct.setFixedWidth(36)
            lbl_pct.setAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
            lbl_pct.setStyleSheet(f"color:{cor};font-size:9px;font-family:Consolas;")

            grid.addWidget(lbl_cat,  idx, 0)
            grid.addWidget(barra,    idx, 1)
            grid.addWidget(lbl_pct,  idx, 2)

        layout.addLayout(grid)
        return frame

    # ──────────────────────────────────────────────
    # Card — Alertas de Segurança
    # ──────────────────────────────────────────────

    def _card_alertas(self) -> QFrame:
        frame = self._criar_frame_card("#2a0a00", "#400f00")
        layout = QVBoxLayout(frame)
        layout.setContentsMargins(14, 12, 14, 12)
        layout.setSpacing(6)

        cab = QHBoxLayout()
        titulo = QLabel(f"⚠  Alertas de Segurança ({len(self._alertas_seguranca)})")
        titulo.setStyleSheet("color:#E74C3C;font-weight:bold;font-size:11px;")
        cab.addWidget(titulo)
        cab.addStretch()
        layout.addLayout(cab)

        for alerta in self._alertas_seguranca[-10:]:
            lbl = QLabel(alerta[:120])
            lbl.setWordWrap(True)
            lbl.setStyleSheet("color:#e88080;font-size:9px;font-family:Consolas;")
            layout.addWidget(lbl)

        return frame

    # ──────────────────────────────────────────────
    # Card — Talkers (IPs mais ativos)
    # ──────────────────────────────────────────────

    def _card_talkers(self, talkers: list, total_ev: int) -> QFrame:
        """Card para os IPs mais ativos (talkers)."""
        frame = self._criar_frame_card("#1a2a3f", "#2a3a50")
        layout = QVBoxLayout(frame)
        layout.setContentsMargins(14, 12, 14, 12)
        layout.setSpacing(8)

        cab = QHBoxLayout()
        titulo = QLabel("  Dispositivos Mais Ativos")
        titulo.setStyleSheet("color:#3498DB;font-weight:bold;font-size:11px;")
        cab.addWidget(titulo)
        cab.addStretch()
        total_contagem = sum(t.get("contagem", 0) for t in talkers)
        cab.addWidget(self._lbl_info(
            f"{len(talkers)} dispositivo(s) · {total_contagem} eventos"
        ))
        layout.addLayout(cab)

        sub = QLabel("Baseado em atividade de rede por IP")
        sub.setStyleSheet("color:#4a6a8a;font-size:9px;")
        layout.addWidget(sub)

        if not talkers:
            layout.addWidget(self._lbl_vazio("Nenhum dispositivo ativo ainda."))
            return frame

        max_contagem = max((t.get("contagem", 1) for t in talkers[:15]), default=1)

        for i, talker in enumerate(talkers[:15]):
            ip       = talker.get("ip", "?")
            contagem = talker.get("contagem", 0)

            row = QHBoxLayout()
            row.setSpacing(6)

            lbl_num = QLabel(f"{i + 1}.")
            lbl_num.setFixedWidth(20)
            lbl_num.setStyleSheet("color:#566573;font-size:9px;")

            lbl_ip = QLabel(ip)
            lbl_ip.setFixedWidth(140)
            lbl_ip.setStyleSheet("color:#ecf0f1;font-size:9px;font-family:Consolas;")

            barra = QProgressBar()
            barra.setRange(0, max(max_contagem, 1))
            barra.setValue(contagem)
            barra.setFixedHeight(12)
            barra.setTextVisible(False)
            barra.setStyleSheet("""
                QProgressBar { background:#0d1520; border-radius:3px; }
                QProgressBar::chunk { background:#3498DB; border-radius:3px; }
            """)

            lbl_cnt = QLabel(f"{contagem}")
            lbl_cnt.setFixedWidth(36)
            lbl_cnt.setAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
            lbl_cnt.setStyleSheet("color:#3498DB;font-size:9px;font-family:Consolas;")

            row.addWidget(lbl_num)
            row.addWidget(lbl_ip)
            row.addWidget(barra, 1)
            row.addWidget(lbl_cnt)
            layout.addLayout(row)

        return frame

    # ──────────────────────────────────────────────
    # Card — Domínios
    # ──────────────────────────────────────────────

    def _card_dominios(self, dominios: list) -> QFrame:
        """Card para os domínios mais acessados."""
        frame = self._criar_frame_card("#1a3a5f", "#2a5a70")
        layout = QVBoxLayout(frame)
        layout.setContentsMargins(14, 12, 14, 12)
        layout.setSpacing(8)

        cab = QHBoxLayout()
        titulo = QLabel("  Domínios Mais Acessados")
        titulo.setStyleSheet("color:#2ECC71;font-weight:bold;font-size:11px;")
        cab.addWidget(titulo)
        cab.addStretch()
        total_acessos = sum(d.get("acessos", 0) for d in dominios)
        cab.addWidget(self._lbl_info(
            f"{len(dominios)} domínio(s) · {total_acessos} acessos"
        ))
        layout.addLayout(cab)

        sub = QLabel("Baseado em consultas DNS reais")
        sub.setStyleSheet("color:#4a6a8a;font-size:9px;")
        layout.addWidget(sub)

        if not dominios:
            layout.addWidget(self._lbl_vazio("Nenhum domínio acessado ainda."))
            return frame

        max_acessos = max((d.get("acessos", 1) for d in dominios[:15]), default=1)

        for i, dom in enumerate(dominios[:15]):
            dominio = dom.get("dominio", "?")
            acessos = dom.get("acessos", 0)

            # Nome amigável por sufixo de domínio
            nome = dominio
            for sufixo, apelido in DOMINIOS_CONHECIDOS.items():
                if dominio == sufixo or dominio.endswith("." + sufixo):
                    nome = apelido
                    break

            row = QHBoxLayout()
            row.setSpacing(6)

            lbl_num = QLabel(f"{i + 1}.")
            lbl_num.setFixedWidth(20)
            lbl_num.setStyleSheet("color:#566573;font-size:9px;")

            lbl_dom = QLabel(dominio)
            lbl_dom.setFixedWidth(180)
            lbl_dom.setToolTip(nome)
            lbl_dom.setStyleSheet("color:#ecf0f1;font-size:9px;font-family:Consolas;")

            barra = QProgressBar()
            barra.setRange(0, max(max_acessos, 1))
            barra.setValue(acessos)
            barra.setFixedHeight(12)
            barra.setTextVisible(False)
            barra.setStyleSheet("""
                QProgressBar { background:#0d1520; border-radius:3px; }
                QProgressBar::chunk { background:#2ECC71; border-radius:3px; }
            """)

            lbl_cnt = QLabel(f"{acessos}x")
            lbl_cnt.setFixedWidth(36)
            lbl_cnt.setAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
            lbl_cnt.setStyleSheet("color:#2ECC71;font-size:9px;font-family:Consolas;")

            row.addWidget(lbl_num)
            row.addWidget(lbl_dom)
            row.addWidget(barra, 1)
            row.addWidget(lbl_cnt)
            layout.addLayout(row)

        return frame

    # ──────────────────────────────────────────────
    # Auxiliares visuais (widgets e formatação)
    # ──────────────────────────────────────────────

    @staticmethod
    def _criar_frame_card(cor_fundo: str, cor_borda: str) -> QFrame:
        frame = QFrame()
        frame.setStyleSheet(f"""
            QFrame {{
                background-color: {cor_fundo};
                border: 1px solid {cor_borda};
                border-radius: 8px;
            }}
        """)
        return frame

    @staticmethod
    def _lbl_info(texto: str) -> QLabel:
        lbl = QLabel(texto)
        lbl.setStyleSheet("color:#566573;font-size:9px;font-family:Consolas;")
        return lbl

    @staticmethod
    def _lbl_vazio(texto: str) -> QLabel:
        lbl = QLabel(texto)
        lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        lbl.setStyleSheet("color:#4a5a6b;font-size:10px;padding:20px;")
        return lbl

    @staticmethod
    def _criar_tabela(colunas: list, n_linhas: int) -> QTableWidget:
        t = QTableWidget(n_linhas, len(colunas))
        t.setHorizontalHeaderLabels(colunas)
        t.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        t.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        t.verticalHeader().setVisible(False)
        t.setAlternatingRowColors(True)
        t.setStyleSheet("""
            QTableWidget {
                background:#0a0f1a; color:#ecf0f1;
                gridline-color:#1e2d40; border:none;
                alternate-background-color:#0d1520;
                font-size:9px; font-family:Consolas;
            }
            QHeaderView::section {
                background:#0d1520; color:#7f8c8d;
                border:none; padding:4px; font-size:9px;
            }
        """)
        t.horizontalHeader().setStretchLastSection(True)
        return t

    @staticmethod
    def _formatar_bytes(n: int) -> str:
        if n >= 1_073_741_824:
            return f"{n / 1_073_741_824:.2f} GB"
        if n >= 1_048_576:
            return f"{n / 1_048_576:.1f} MB"
        if n >= 1_024:
            return f"{n / 1_024:.1f} KB"
        return f"{n} B"

    @staticmethod
    def _eh_ip_local(ip: str) -> bool:
        try:
            partes = [int(p) for p in ip.split(".")]
            if len(partes) != 4:
                return False
            if partes[0] == 10:
                return True
            if partes[0] == 172 and 16 <= partes[1] <= 31:
                return True
            if partes[0] == 192 and partes[1] == 168:
                return True
        except Exception:
            pass
        return False

    # ──────────────────────────────────────────────
    # API pública — chamada pela janela principal
    # ──────────────────────────────────────────────

    def atualizar_insights(self, top_dns: list, historias: list):
        # Armazena os dados mais recentes do analisador
        self._ultimo_top_dns = top_dns
        self._ultimo_historias = historias
        
        # Verifica se houve mudança significativa
        chave = f"{len(top_dns)}:{sum(d.get('acessos',0) for d in top_dns)}"
        if chave == getattr(self, '_ultima_chave_dns', ''):
            return  # sem mudança, não renderiza
        self._ultima_chave_dns = chave
        
        # Agora renderiza com os dados reais
        self._renderizar_insights()

    def atualizar_insights_correlacionados(self, insights: list, estatisticas: dict,
                                            top_dominios: list, narrativas: list):
        """Compatibilidade com MotorCorrelacao externo."""
        self.atualizar_insights([], [])

    def adicionar_evento(self, dados: dict):
        """Recebe um evento do motor pedagógico e exibe na interface."""
        def _corrigir_encoding(txt: str) -> str:
            if not isinstance(txt, str):
                return txt
            for enc in ("cp1252", "latin1"):
                try:
                    return txt.encode(enc, errors="ignore").decode("utf-8")
                except Exception:
                    continue
            return txt

        # deque(maxlen) descarta automaticamente o mais antigo — sem pop(0)
        sessao = dados.get("sessao_id", "sessao_default")
        tipo   = dados.get("tipo", "")
        self._contagem_sessao[sessao][tipo] += 1
        dados["contador_sessao"] = self._contagem_sessao[sessao][tipo]

        for campo in ("titulo", "nivel1", "nivel2", "nivel3", "nivel4",
                      "alerta_seguranca", "fluxo_visual"):
            if campo in dados:
                dados[campo] = _corrigir_encoding(dados[campo])

        self._todos_eventos.append(dados)
        self.painel_contadores.incrementar(tipo)

        # Coleta alertas de segurança (cap. 50 para não inflar a deque)
        alerta = dados.get("alerta_seguranca", "")
        if alerta and len(self._alertas_seguranca) < 50:
            ts    = dados.get("timestamp", "")
            ip    = dados.get("ip_envolvido", "")
            texto = f"[{ts}] {ip} — {alerta[:100]}"
            if texto not in self._alertas_seguranca:
                self._alertas_seguranca.append(texto)

        if self._passa_filtro(dados):
            self._adicionar_cartao(dados)
            self._eventos_filtrados.append(dados)

        self._evento_atual = dados
        self._renderizar_explicacao()
        self._atualizar_rodape()

    def limpar(self):
        """Limpa todos os eventos e reinicia a interface."""
        self._todos_eventos.clear()
        self._eventos_filtrados.clear()
        self._evento_atual = {}
        self._contagem_sessao.clear()
        self.painel_contadores.resetar()

        # Remove cartões de eventos
        self.lista_eventos.clear()

        # Limpa aba de insights
        self._limpar_layout_insights()
        self._exibir_mensagem_insights_vazio()

        self._lbl_resumo_insights.setText("Aguardando dados de captura...")
        self._lbl_total_insights.setText("")

        self.lbl_rodape.setText("Nenhum evento registrado.")
        self._exibir_boas_vindas()

        # Reseta dados externos
        self._ultimo_top_dns.clear()
        self._ultimo_historias.clear()
        self._ultima_chave_dns = ""
        self._chave_render_anterior = ""

    # ──────────────────────────────────────────────
    # Filtros
    # ──────────────────────────────────────────────

    @pyqtSlot(str)
    def _ao_mudar_filtro_protocolo(self, valor: str):
        self._filtro_protocolo = valor
        self._reaplicar_filtros()

    @pyqtSlot(str)
    def _ao_mudar_filtro_texto(self, texto: str):
        self._filtro_texto = texto.lower().strip()
        self._reaplicar_filtros()

    def _passa_filtro(self, dados: dict) -> bool:
        if (self._filtro_protocolo and
                self._filtro_protocolo != "Todos" and
                dados.get("tipo", "").upper() != self._filtro_protocolo.upper()):
            return False
        if self._filtro_texto:
            campos = " ".join([
                dados.get("ip_envolvido", ""),
                dados.get("ip_destino",   ""),
                dados.get("titulo",       ""),
                dados.get("nivel1",       ""),
                dados.get("tipo",         ""),
            ]).lower()
            if self._filtro_texto not in campos:
                return False
        return True

    def _reaplicar_filtros(self):
        self.lista_eventos.clear()

        self._eventos_filtrados = [
            e for e in self._todos_eventos if self._passa_filtro(e)
        ]
        for evento in self._eventos_filtrados:
            self._adicionar_cartao(evento)
        self._atualizar_rodape()

        if self._eventos_filtrados:
            self._evento_atual = self._eventos_filtrados[-1]
            self._renderizar_explicacao()
        else:
            self._evento_atual = {}
            self._exibir_boas_vindas()

    def _atualizar_rodape(self):
        total = len(self._todos_eventos)
        visiveis = len(self._eventos_filtrados)
        # Mostrar apenas total, sem duplicação
        self.lbl_rodape.setText(f"{visiveis} exibido(s) de {total} total (filtro ativo).")

    # ──────────────────────────────────────────────
    # Cartões e renderização de explicações
    # ──────────────────────────────────────────────

    def _adicionar_cartao(self, dados: dict):
        item = QListWidgetItem()
        widget = CartaoEvento(dados)
        item.setSizeHint(widget.sizeHint())
        self.lista_eventos.addItem(item)
        self.lista_eventos.setItemWidget(item, widget)

        # Conecta o clique
        dados_ref = dados
        widget.mousePressEvent = lambda _: self._ao_clicar_cartao(dados_ref)

        # Rola para o final
        barra = self._scroll.verticalScrollBar()
        barra.setValue(barra.maximum())

    def _ao_clicar_cartao(self, dados: dict):
        self._evento_atual = dados
        self._renderizar_explicacao()

    def _trocar_nivel(self, nivel: int):
        self._nivel_atual = nivel
        for i, btn in enumerate(self.botoes_nivel):
            btn.setChecked(i == nivel)
        if self._evento_atual:
            self._renderizar_explicacao()

    def _renderizar_explicacao(self):
        if not self._evento_atual or not self._evento_atual.get("titulo"):
            return

        e      = self._evento_atual
        titulo = e.get("titulo", "Evento")
        nivel  = e.get("nivel", "INFO")
        hora   = e.get("timestamp", "")
        ip_src = e.get("ip_envolvido", "")
        ip_dst = e.get("ip_destino", "")
        cont   = e.get("contador", 1)
        cont_s = e.get("contador_sessao", cont)
        fluxo  = e.get("fluxo_visual", "")
        alerta = e.get("alerta_seguranca", "")

        estilo = ESTILOS_NIVEL.get(nivel, ESTILOS_NIVEL["INFO"])
        cor    = estilo["borda"]

        chaves_nivel = ["nivel1", "nivel2", "nivel4"]
        rotulo       = ROTULOS_NIVEL[self._nivel_atual]

        if self._nivel_atual == 2:
            conteudo = e.get("nivel4", "")
            if not conteudo:
                conteudo = (
                    "<div style='text-align:center;padding:40px;color:#7f8c8d;'>"
                    "<b>Pacote Bruto</b> está disponível apenas para eventos HTTP.<br><br>"
                    "Acesse um site HTTP (porta 80) e envie um formulário para "
                    "visualizar o conteúdo exato do pacote."
                    "</div>"
                )
        else:
            conteudo = e.get(chaves_nivel[self._nivel_atual], "Indisponível.")

        ip_linha = ip_src
        if ip_dst and ip_dst != ip_src:
            ip_linha += f" → {ip_dst}"

        bloco_fluxo = ""
        if fluxo:
            bloco_fluxo = (
                f"<div style='font-family:Consolas;font-size:11px;"
                f"background:#0d1520;padding:8px 14px;"
                f"border-radius:5px;color:#ecf0f1;margin:8px 0;"
                f"border-left:3px solid {cor};'>"
                f"{fluxo}</div>"
            )

        bloco_alerta = ""
        if alerta:
            bloco_alerta = (
                f"<div style='background:#2a0a00;border:1px solid #E74C3C;"
                f"border-radius:5px;padding:10px 14px;margin:8px 0;'>"
                f"<b style='color:#E74C3C;'>⚠ ALERTA DE SEGURANÇA:</b><br>"
                f"<span style='color:#ecf0f1;'>{alerta}</span>"
                f"</div>"
            )

        html = f"""
        <div style="font-family:Arial,sans-serif;font-size:11px;
                    line-height:1.7;color:#ecf0f1;">
          <h3 style="color:{cor};margin:0 0 4px 0;">{titulo}</h3>
          <p style="color:#7f8c8d;font-size:10px;margin:0 0 10px 0;">
            🕐 {hora} &nbsp;·&nbsp;
            <code style="color:#3498DB;">{ip_linha}</code>
            &nbsp;·&nbsp; Ocorrências: <b>{cont}</b>
            &nbsp;·&nbsp; Nesta sessão: <b>{cont_s}</b>
          </p>
          {bloco_fluxo}
          {bloco_alerta}
          <div style="background:#0d1520;border-left:3px solid {cor};
                      border-radius:4px;padding:12px 16px;margin:8px 0;">
            <b style="color:{cor};font-size:10px;">
              {rotulo[0]} {rotulo[1]} — {rotulo[2]}
            </b><br><br>
            {conteudo}
          </div>
        </div>
        """
        self.texto_explicacao.setHtml(html)

    def _exibir_boas_vindas(self):
        self.texto_explicacao.setHtml("""
        <div style="font-family:Arial,sans-serif;font-size:11px;
                    line-height:1.7;color:#ecf0f1;padding:4px;">
          <h3 style="color:#3498DB;margin:0 0 10px 0;">
            👋 Bem-vindo ao Modo Análise
          </h3>
          <p>Este painel transforma pacotes reais capturados da rede em
          <b>explicações didáticas automáticas</b> em três níveis de
          profundidade.</p>
          <p><b>Como usar:</b><br>
          1. Clique em <b>Iniciar Captura</b> na barra superior<br>
          2. Acesse sites no navegador para gerar tráfego<br>
          3. Os eventos aparecerão aqui automaticamente<br>
          4. Clique em qualquer evento para ver a explicação<br>
          5. Use os botões abaixo para trocar o nível de detalhe</p>
          <p><b>Os três níveis de explicação:</b><br>
          <b>Simples</b> — linguagem do dia a dia, sem jargão técnico<br>
          <b>Técnico</b> — protocolos, portas, vulnerabilidades<br>
          <b>Pacote Bruto</b> — conteúdo exato transmitido na rede
          (exclusivo para HTTP)</p>
          <p style="color:#7f8c8d;font-size:10px;">
            Acesse a aba <b>Insights</b> para ver quais sites foram
            acessados e o tipo de uso da rede (atualizado a cada 30 s).
          </p>
        </div>
        """)
