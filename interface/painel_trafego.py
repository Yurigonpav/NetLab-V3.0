# interface/painel_trafego.py  —  v2.0
# =============================================================================
# Melhorias em relação à v1:
#
#   Buffer histórico   deque(maxlen=7200) armazena ~2 horas de amostras (1 Hz).
#                      Persiste durante toda a sessão; só apagado em limpar()
#                      (nova sessão explícita via "Nova Sessão" no menu).
#
#   Suavização EMA     Filtro exponencial:  ema_t = α·x_t + (1−α)·ema_{t−1}
#                      α ajustável de 0.05 (muito suave) a 0.50 (pouco suave).
#                      Reduz ruído de picos momentâneos sem esconder tendências
#                      reais e sem introduzir latência perceptível.
#                      Ao alterar α, recomputa todo o histórico EMA — vista
#                      consistente independente de quando o slider foi movido.
#
#   Duas curvas        – Bruta (cinza-azul, fina, baixa opacidade): mostra a
#                        volatilidade real do tráfego.
#                      – EMA (azul brilhante, fill sutil): tendência limpa,
#                        fácil de interpretar.
#
#   Navegação temporal Barra de controles abaixo do gráfico:
#                        ⏮ / ◀30s / ◀10s / [⏸ Pausar] / 10s▶ / 30s▶ / ▶▶ Ao Vivo
#                      Em modo "ao_vivo" novos pontos atualizam continuamente.
#                      Em modo "navegação" o gráfico fica congelado no offset
#                      escolhido; os buffers continuam sendo preenchidos.
#
#   Crosshair + tooltip  Linhas tracejadas seguem o mouse sobre o gráfico e
#                        exibem o valor EMA exato do ponto apontado.
#
#   Transição suave do teto Y  O limite superior do eixo Y interpola em direção
#                              ao valor alvo a cada frame — sem saltos bruscos.
#
# API pública (100% compatível com v1):
#   adicionar_ponto_grafico(kb_por_segundo: float) → None
#   atualizar_tabelas(estatisticas_protocolos, top_dispositivos,
#                     total_pacotes, total_bytes,
#                     total_topologia=None, total_ativos=None) → None
#   limpar() → None
# =============================================================================

from collections import deque

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel,
    QTableWidget, QTableWidgetItem, QHeaderView,
    QFrame, QSplitter, QPushButton, QSlider,
)
from PyQt6.QtCore import Qt
from PyQt6.QtGui import QFont, QColor

try:
    import pyqtgraph as pg
    PYQTGRAPH_DISPONIVEL = True
except ImportError:
    PYQTGRAPH_DISPONIVEL = False


# ── Constantes ─────────────────────────────────────────────────────────────────

CORES_PROTOCOLOS = {
    "HTTP":  "#E74C3C", "HTTPS": "#2ECC71", "DNS":   "#3498DB",
    "TCP":   "#9B59B6", "UDP":   "#F39C12", "ICMP":  "#1ABC9C",
    "ARP":   "#E67E22", "SSH":   "#2980B9", "FTP":   "#E91E63",
    "SMB":   "#795548", "RDP":   "#FF5722", "DHCP":  "#16A085",
    "Outro": "#7f8c8d",
}

JANELA_GRAFICO   = 60       # segundos exibidos por vez no gráfico
MAX_HISTORICO    = 7_200    # amostras máximas (≈ 2 horas a 1 amostra/s)
ALPHA_EMA_PADRAO = 0.20     # fator EMA padrão (0 → sem suavização; 1 → sem memória)


# ── Card de estatística ────────────────────────────────────────────────────────

class CardEstatistica(QFrame):
    def __init__(self, titulo: str, valor_inicial: str, cor: str):
        super().__init__()
        self.setFrameShape(QFrame.Shape.Box)
        self.setStyleSheet(f"""
            QFrame {{
                background-color: #12162a;
                border: 1px solid {cor};
                border-radius: 8px;
            }}
        """)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(12, 10, 12, 10)

        lbl_t = QLabel(titulo)
        lbl_t.setStyleSheet(
            f"color:{cor}; font-size:9px; font-weight:bold; border:none;"
        )
        lbl_t.setAlignment(Qt.AlignmentFlag.AlignCenter)

        self.lbl_v = QLabel(valor_inicial)
        self.lbl_v.setStyleSheet(
            "color:#ecf0f1; font-size:20px; font-weight:bold; border:none;"
        )
        self.lbl_v.setAlignment(Qt.AlignmentFlag.AlignCenter)

        layout.addWidget(lbl_t)
        layout.addWidget(self.lbl_v)

    def definir_valor(self, v: str):
        self.lbl_v.setText(v)


# ── Painel principal ───────────────────────────────────────────────────────────

class PainelTrafego(QWidget):
    """
    Painel de tráfego em tempo real — v2.0.
    Combina visualização ao vivo com navegação histórica, suavização EMA,
    duas curvas sobrepostas e crosshair interativo.
    """

    def __init__(self, parent=None):
        super().__init__(parent)

        # ── Buffers de dados ─────────────────────────────────────────────────
        # Crescem em paralelo; deque(maxlen) descarta automaticamente
        # o mais antigo quando o limite é atingido — zero OOM.
        self._buffer_raw: deque = deque(maxlen=MAX_HISTORICO)  # KB/s brutos
        self._buffer_ema: deque = deque(maxlen=MAX_HISTORICO)  # KB/s suavizado (EMA)

        # ── Parâmetros de suavização ─────────────────────────────────────────
        self._alpha_ema:    float = ALPHA_EMA_PADRAO
        self._ema_anterior: float = 0.0

        # ── Estado de navegação temporal ─────────────────────────────────────
        # "ao_vivo"   → exibe as últimas JANELA_GRAFICO amostras (padrão)
        # "navegacao" → janela congelada _nav_offset amostras antes do fim
        self._modo:       str = "ao_vivo"
        self._nav_offset: int = 0         # amostras antes do fim do buffer

        # ── Teto do eixo Y (suavizado) ────────────────────────────────────────
        # _teto_y interpola gradualmente em direção a _teto_y_alvo a cada
        # chamada de _renderizar_grafico() — elimina os saltos bruscos da v1.
        self._teto_y:      float = 10.0
        self._teto_y_alvo: float = 10.0

        # ── Objetos PyQtGraph ─────────────────────────────────────────────────
        self._plot_widget  = None
        self._curva_raw    = None   # curva bruta  (dim, fina)
        self._curva_ema    = None   # curva EMA    (brilhante, fill sutil)
        self._linha_ch_v   = None   # crosshair vertical
        self._linha_ch_h   = None   # crosshair horizontal
        self._label_valor  = None   # tooltip flutuante
        self._proxy_mouse  = None   # SignalProxy do movimento do mouse

        # Guard para evitar recursão nos sinais dos botões
        self._bloqueio_sinal: bool = False

        self._montar_layout()

    # ── Construção do layout ──────────────────────────────────────────────────

    def _montar_layout(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(4, 2, 4, 4)
        layout.setSpacing(6)

        # ── Cards de resumo ───────────────────────────────────────────────────
        row = QHBoxLayout()
        self.card_pacotes      = CardEstatistica("TOTAL DE PACOTES",    "0",      "#3498DB")
        self.card_dados        = CardEstatistica("DADOS TRANSMITIDOS",  "0 KB",   "#2ECC71")
        self.card_dispositivos = CardEstatistica("DISPOSITIVOS ATIVOS", "0",      "#E74C3C")
        self.card_velocidade   = CardEstatistica("VELOCIDADE ATUAL",    "0 KB/s", "#9B59B6")
        for c in (self.card_pacotes, self.card_dados,
                  self.card_dispositivos, self.card_velocidade):
            row.addWidget(c)
        layout.addLayout(row)

        splitter = QSplitter(Qt.Orientation.Horizontal)
        layout.addWidget(splitter)

        # ── Esquerda: gráfico + barra de controles ────────────────────────────
        w_graf = QWidget()
        l_graf = QVBoxLayout(w_graf)
        l_graf.setContentsMargins(0, 0, 4, 0)
        l_graf.setSpacing(4)

        if PYQTGRAPH_DISPONIVEL:
            self._criar_grafico(l_graf)
            self._criar_barra_controles(l_graf)
        else:
            aviso = QLabel("PyQtGraph não encontrado.\npip install pyqtgraph")
            aviso.setAlignment(Qt.AlignmentFlag.AlignCenter)
            aviso.setStyleSheet("color:#e74c3c;")
            l_graf.addWidget(aviso)

        splitter.addWidget(w_graf)

        # ── Direita: tabelas ──────────────────────────────────────────────────
        w_tab = QWidget()
        l_tab = QVBoxLayout(w_tab)
        l_tab.setContentsMargins(4, 4, 0, 0)

        fonte_label = QFont("Arial", 10)
        fonte_label.setBold(True)

        lbl_p = QLabel("Protocolos Detectados")
        lbl_p.setStyleSheet("color:#bdc3c7;")
        lbl_p.setFont(fonte_label)
        l_tab.addWidget(lbl_p)
        self.tabela_protocolos = self._criar_tabela(
            ["Protocolo", "Pacotes", "Dados (KB)"], altura=180
        )
        l_tab.addWidget(self.tabela_protocolos)

        lbl_d = QLabel("Top Dispositivos por Tráfego")
        lbl_d.setStyleSheet("color:#bdc3c7; margin-top:6px;")
        lbl_d.setFont(fonte_label)
        l_tab.addWidget(lbl_d)
        self.tabela_dispositivos = self._criar_tabela(
            ["Endereço IP", "Enviado (KB)", "Recebido (KB)", "Total (KB)"]
        )
        l_tab.addWidget(self.tabela_dispositivos)

        splitter.addWidget(w_tab)
        splitter.setSizes([640, 360])

    # ── Criação do gráfico PyQtGraph ──────────────────────────────────────────

    def _criar_grafico(self, layout_pai: QVBoxLayout):
        """
        Configura o widget PyQtGraph com:
         - fundo escuro contrastante
         - curva RAW (dim): mostra a volatilidade real
         - curva EMA (brilhante): tendência suavizada com fill
         - crosshair (linhas tracejadas verticais + horizontal)
         - SignalProxy limitado a 60 fps para o tooltip do mouse
        """
        pg.setConfigOption("background", "#080c18")
        pg.setConfigOption("foreground", "#bdc3c7")

        self._plot_widget = pg.PlotWidget()
        self._plot_widget.setMinimumHeight(200)
        self._plot_widget.disableAutoRange()
        self._plot_widget.setXRange(0, JANELA_GRAFICO, padding=0)
        self._plot_widget.setYRange(0, self._teto_y,   padding=0)

        self._plot_widget.setLabel("left",   "KB/s",      color="#8a9ab8", size="9pt")
        self._plot_widget.setLabel("bottom", "Tempo (s)", color="#8a9ab8", size="9pt")
        self._plot_widget.showGrid(x=True, y=True, alpha=0.12)

        # Desabilita zoom/pan do mouse para não confundir o aluno
        self._plot_widget.setMouseEnabled(x=False, y=False)

        eixo_x = list(range(JANELA_GRAFICO))
        zeros  = [0.0] * JANELA_GRAFICO

        # Curva bruta — sutil, fina, mostra a volatilidade real
        self._curva_raw = self._plot_widget.plot(
            x=eixo_x, y=zeros,
            pen=pg.mkPen(color=(90, 130, 180, 80), width=1.0),
        )

        # Curva EMA — principal, brilhante, fill suave
        self._curva_ema = self._plot_widget.plot(
            x=eixo_x, y=zeros,
            pen=pg.mkPen(color="#4dabf7", width=2.2),
            fillLevel=0,
            brush=pg.mkBrush(color=(52, 152, 219, 28)),
        )

        # Crosshair
        _pen_ch = pg.mkPen(
            color=(200, 220, 255, 55), width=1,
            style=Qt.PenStyle.DashLine
        )
        self._linha_ch_v = pg.InfiniteLine(angle=90,  movable=False, pen=_pen_ch)
        self._linha_ch_h = pg.InfiniteLine(angle=0,   movable=False, pen=_pen_ch)
        self._plot_widget.addItem(self._linha_ch_v, ignoreBounds=True)
        self._plot_widget.addItem(self._linha_ch_h, ignoreBounds=True)

        # Tooltip flutuante
        self._label_valor = pg.TextItem(
            text="", color="#ecf0f1",
            fill=pg.mkBrush(color=(12, 18, 36, 210)),
            anchor=(0, 1),
        )
        self._plot_widget.addItem(self._label_valor)

        # SignalProxy: dispara _ao_mover_mouse no máximo 60× por segundo
        self._proxy_mouse = pg.SignalProxy(
            self._plot_widget.scene().sigMouseMoved,
            rateLimit=60, slot=self._ao_mover_mouse
        )

        layout_pai.addWidget(self._plot_widget)

    # ── Barra de controles temporais e suavização ─────────────────────────────

    def _criar_barra_controles(self, layout_pai: QVBoxLayout):
        """
        Barra compacta (38 px) com navegação temporal e controle de EMA.

        Layout:
          [⏮][◀30s][◀10s][⏸ Pausar][10s▶][30s▶][▶▶ Ao Vivo]  |  label  |  EMA: [slider] valor
        """
        barra = QFrame()
        barra.setFixedHeight(38)
        barra.setStyleSheet("""
            QFrame {
                background: #0c1020;
                border: 1px solid #1e2d40;
                border-radius: 5px;
            }
            QPushButton {
                background: #182030;
                color: #8a9ab8;
                border: 1px solid #283850;
                border-radius: 4px;
                padding: 2px 7px;
                font-size: 11px;
            }
            QPushButton:hover    { background: #243550; color: #c8d8f0; }
            QPushButton:disabled { background: #0e1520; color: #3a4a5a;
                                   border-color: #1a2530; }
            QPushButton:checked  { background: #1e3a5f; color: #4dabf7;
                                   border-color: #4dabf7; }
            QLabel {
                color: #7f8c8d;
                font-size: 10px;
                background: transparent;
                border: none;
            }
            QSlider::groove:horizontal {
                background: #1e2d40;
                height: 4px;
                border-radius: 2px;
            }
            QSlider::handle:horizontal {
                background: #3498DB;
                width: 10px;
                height: 10px;
                margin: -3px 0;
                border-radius: 5px;
            }
            QSlider::sub-page:horizontal {
                background: #3498DB;
                border-radius: 2px;
            }
        """)

        hbox = QHBoxLayout(barra)
        hbox.setContentsMargins(8, 4, 8, 4)
        hbox.setSpacing(4)

        # Botões de navegação
        self._btn_inicio    = QPushButton("⏮")
        self._btn_recuar30  = QPushButton("◀30s")
        self._btn_recuar10  = QPushButton("◀10s")
        self._btn_pausar    = QPushButton("⏸ Pausar")
        self._btn_pausar.setCheckable(True)
        self._btn_avancar10 = QPushButton("10s▶")
        self._btn_avancar30 = QPushButton("30s▶")
        self._btn_ao_vivo   = QPushButton("▶▶ Ao Vivo")

        dicas = [
            (self._btn_inicio,    "Ir para o início do histórico"),
            (self._btn_recuar30,  "Recuar 30 segundos no histórico"),
            (self._btn_recuar10,  "Recuar 10 segundos no histórico"),
            (self._btn_pausar,    "Pausar / retomar exibição ao vivo"),
            (self._btn_avancar10, "Avançar 10 segundos"),
            (self._btn_avancar30, "Avançar 30 segundos"),
            (self._btn_ao_vivo,   "Voltar para o tempo real"),
        ]
        for btn, dica in dicas:
            btn.setFixedHeight(26)
            btn.setToolTip(dica)
            hbox.addWidget(btn)

        self._btn_inicio.clicked.connect(self._ir_para_inicio)
        self._btn_recuar30.clicked.connect(lambda: self._navegar(+30))
        self._btn_recuar10.clicked.connect(lambda: self._navegar(+10))
        self._btn_pausar.toggled.connect(self._ao_alternar_pausa)
        self._btn_avancar10.clicked.connect(lambda: self._navegar(-10))
        self._btn_avancar30.clicked.connect(lambda: self._navegar(-30))
        self._btn_ao_vivo.clicked.connect(self._ir_para_ao_vivo)

        # Separador
        sep = QFrame()
        sep.setFrameShape(QFrame.Shape.VLine)
        sep.setFixedWidth(1)
        sep.setStyleSheet("background:#283850; border:none;")
        hbox.addWidget(sep)

        # Label de posição temporal
        self._lbl_posicao = QLabel("  ● Ao vivo")
        self._lbl_posicao.setStyleSheet(
            "color:#2ECC71; font-size:10px; font-weight:bold;"
            "background:transparent; border:none;"
        )
        self._lbl_posicao.setMinimumWidth(145)
        hbox.addWidget(self._lbl_posicao)

        hbox.addStretch()

        # Separador
        sep2 = QFrame()
        sep2.setFrameShape(QFrame.Shape.VLine)
        sep2.setFixedWidth(1)
        sep2.setStyleSheet("background:#283850; border:none;")
        hbox.addWidget(sep2)

        # Controle de suavização EMA
        lbl_ema = QLabel("  EMA:")
        hbox.addWidget(lbl_ema)

        self._slider_suav = QSlider(Qt.Orientation.Horizontal)
        self._slider_suav.setRange(5, 50)                       # alpha = valor / 100
        self._slider_suav.setValue(int(self._alpha_ema * 100))
        self._slider_suav.setFixedWidth(72)
        self._slider_suav.setFixedHeight(20)
        self._slider_suav.setToolTip(
            "Fator de suavização EMA\n"
            "Esquerda → mais suave (reage mais devagar)\n"
            "Direita → menos suave (reage mais rápido)"
        )
        self._slider_suav.valueChanged.connect(self._ao_mudar_suavizacao)
        hbox.addWidget(self._slider_suav)

        self._lbl_alpha = QLabel(f"{self._alpha_ema:.2f}")
        self._lbl_alpha.setFixedWidth(34)
        self._lbl_alpha.setStyleSheet(
            "color:#4dabf7; font-size:10px; font-family:Consolas;"
            "background:transparent; border:none;"
        )
        hbox.addWidget(self._lbl_alpha)

        layout_pai.addWidget(barra)
        self._atualizar_estado_botoes()

    @staticmethod
    def _criar_tabela(cabecalhos: list, altura: int = None) -> QTableWidget:
        t = QTableWidget(0, len(cabecalhos))
        t.setHorizontalHeaderLabels(cabecalhos)
        t.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        t.verticalHeader().setVisible(False)
        t.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        t.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        t.setAlternatingRowColors(True)
        if altura:
            t.setMaximumHeight(altura)
        return t

    # ── API pública ───────────────────────────────────────────────────────────

    def adicionar_ponto_grafico(self, kb_por_segundo: float):
        """
        Chamado a cada segundo pelo timer da janela principal.

        1. Calcula a amostra EMA com o alpha atual.
        2. Adiciona ambos os valores aos buffers históricos.
        3. Se em modo ao_vivo, redesenha o gráfico imediatamente.
        """
        # EMA: ema_t = α * x_t + (1 − α) * ema_{t−1}
        if not self._buffer_ema:
            ema = kb_por_segundo
        else:
            ema = (self._alpha_ema * kb_por_segundo
                   + (1.0 - self._alpha_ema) * self._ema_anterior)
        self._ema_anterior = ema

        self._buffer_raw.append(kb_por_segundo)
        self._buffer_ema.append(ema)

        self._atualizar_label_posicao()
        self._atualizar_estado_botoes()

        if self._modo == "ao_vivo":
            self._renderizar_grafico()

    def atualizar_tabelas(self, estatisticas_protocolos: list,
                           top_dispositivos: list,
                           total_pacotes: int, total_bytes: int,
                           total_topologia: int = None,
                           total_ativos: int = None):
        """Atualiza cards e tabelas com os dados mais recentes do analisador."""

        # ── Cards ──────────────────────────────────────────────────────────────
        self.card_pacotes.definir_valor(f"{total_pacotes:,}")

        kb = total_bytes / 1024
        self.card_dados.definir_valor(
            f"{kb / 1024:.2f} MB" if kb > 1024 else f"{kb:.1f} KB"
        )

        ativos = total_ativos if total_ativos is not None else len(top_dispositivos)
        self.card_dispositivos.definir_valor(str(ativos))

        # Velocidade: sempre mostra o ponto mais recente (ao vivo), não o
        # offset de navegação — o card reflete a rede agora, não o histórico.
        vel = self._buffer_ema[-1] if self._buffer_ema else 0.0
        self.card_velocidade.definir_valor(f"{vel:.1f} KB/s")

        # ── Tabela de protocolos ───────────────────────────────────────────────
        fonte_c = QFont("Consolas", 9)
        fonte_c.setBold(True)
        self.tabela_protocolos.setRowCount(len(estatisticas_protocolos))

        for i, stat in enumerate(estatisticas_protocolos):
            proto = stat["protocolo"]
            cor   = QColor(CORES_PROTOCOLOS.get(proto, "#95a5a6"))

            item_p = QTableWidgetItem(proto)
            item_p.setForeground(cor)
            item_p.setFont(fonte_c)

            item_n = QTableWidgetItem(f"{stat['pacotes']:,}")
            item_n.setTextAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)

            item_k = QTableWidgetItem(f"{stat['bytes'] / 1024:.1f}")
            item_k.setTextAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)

            self.tabela_protocolos.setItem(i, 0, item_p)
            self.tabela_protocolos.setItem(i, 1, item_n)
            self.tabela_protocolos.setItem(i, 2, item_k)

        # ── Tabela de dispositivos ─────────────────────────────────────────────
        fonte_ip = QFont("Consolas", 9)
        self.tabela_dispositivos.setRowCount(len(top_dispositivos))

        for i, d in enumerate(top_dispositivos):
            ev = d["enviado"]  / 1024
            rv = d["recebido"] / 1024
            tv = d["total"]    / 1024

            ip_item = QTableWidgetItem(d["ip"])
            ip_item.setFont(fonte_ip)

            env_item = QTableWidgetItem(f"{ev:.1f}")
            env_item.setForeground(QColor("#E74C3C"))
            env_item.setTextAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)

            rec_item = QTableWidgetItem(f"{rv:.1f}")
            rec_item.setForeground(QColor("#2ECC71"))
            rec_item.setTextAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)

            tot_item = QTableWidgetItem(f"{tv:.1f}")
            tot_item.setTextAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)

            self.tabela_dispositivos.setItem(i, 0, ip_item)
            self.tabela_dispositivos.setItem(i, 1, env_item)
            self.tabela_dispositivos.setItem(i, 2, rec_item)
            self.tabela_dispositivos.setItem(i, 3, tot_item)

    def limpar(self):
        """
        Reinicia completamente o painel (nova sessão explícita).
        Chamado por _nova_sessao() em janela_principal.py.
        NÃO é chamado ao pausar/retomar a captura — o histórico persiste.
        """
        self._buffer_raw.clear()
        self._buffer_ema.clear()
        self._ema_anterior = 0.0
        self._modo         = "ao_vivo"
        self._nav_offset   = 0
        self._teto_y       = 10.0
        self._teto_y_alvo  = 10.0

        if self._curva_raw:
            self._curva_raw.setData(
                x=list(range(JANELA_GRAFICO)), y=[0.0] * JANELA_GRAFICO
            )
        if self._curva_ema:
            self._curva_ema.setData(
                x=list(range(JANELA_GRAFICO)), y=[0.0] * JANELA_GRAFICO
            )
        if self._plot_widget:
            self._plot_widget.setYRange(0, 10, padding=0)
        if self._label_valor:
            self._label_valor.setText("")

        self.tabela_protocolos.setRowCount(0)
        self.tabela_dispositivos.setRowCount(0)

        for c in (self.card_pacotes, self.card_dados,
                  self.card_dispositivos, self.card_velocidade):
            c.definir_valor("0")
        self.card_dados.definir_valor("0 KB")
        self.card_velocidade.definir_valor("0 KB/s")

        if hasattr(self, "_lbl_posicao"):
            self._lbl_posicao.setText("  ● Ao vivo")
            self._lbl_posicao.setStyleSheet(
                "color:#2ECC71; font-size:10px; font-weight:bold;"
                "background:transparent; border:none;"
            )
        if hasattr(self, "_btn_pausar"):
            self._bloqueio_sinal = True
            self._btn_pausar.setChecked(False)
            self._bloqueio_sinal = False
        self._atualizar_estado_botoes()

    # ── Renderização do gráfico ───────────────────────────────────────────────

    def _obter_janela(self) -> tuple:
        """
        Retorna (raw[60], ema[60]) para a janela de exibição atual.

        _nav_offset = 0  → últimas 60 amostras (ao vivo)
        _nav_offset = N  → janela que termina N amostras antes do fim

        Preenche com zeros à esquerda quando ainda não há 60 amostras.
        """
        n = len(self._buffer_raw)
        if n == 0:
            zeros = [0.0] * JANELA_GRAFICO
            return zeros, zeros

        fim    = n - self._nav_offset
        fim    = max(1, min(fim, n))
        inicio = fim - JANELA_GRAFICO

        buf_raw = list(self._buffer_raw)
        buf_ema = list(self._buffer_ema)

        if inicio >= 0:
            raw = buf_raw[inicio:fim]
            ema = buf_ema[inicio:fim]
        else:
            # Ainda não há amostras suficientes — pad com zeros à esquerda
            pad = -inicio
            raw = [0.0] * pad + buf_raw[:fim]
            ema = [0.0] * pad + buf_ema[:fim]

        return raw, ema

    def _renderizar_grafico(self):
        """Atualiza as duas curvas e reajusta suavemente o teto do eixo Y."""
        if not (self._curva_raw and self._curva_ema):
            return

        raw, ema = self._obter_janela()
        x = list(range(JANELA_GRAFICO))

        self._curva_raw.setData(x=x, y=raw)
        self._curva_ema.setData(x=x, y=ema)

        # ── Transição suave do teto Y ─────────────────────────────────────────
        # Calcula o novo alvo com margem de 35%.
        maximo = max(max(ema, default=0.0), max(raw, default=0.0))
        alvo   = max(maximo * 1.35, 10.0)

        # Eleva rápido (sem cortar picos), abaixa devagar (sem tremer).
        if alvo > self._teto_y_alvo:
            self._teto_y_alvo = alvo
        elif alvo < self._teto_y_alvo * 0.60:
            # Relaxa o teto suavemente — nunca mais que 8% por frame
            self._teto_y_alvo = self._teto_y_alvo * 0.92 + alvo * 0.08

        # Interpola o teto atual em direção ao alvo (25% por frame)
        self._teto_y += (self._teto_y_alvo - self._teto_y) * 0.25
        self._teto_y  = max(self._teto_y, 10.0)

        self._plot_widget.setYRange(0, self._teto_y,           padding=0)
        self._plot_widget.setXRange(0, JANELA_GRAFICO - 1,     padding=0)

    # ── Navegação temporal ────────────────────────────────────────────────────

    def _navegar(self, delta: int):
        """
        Ajusta o offset de navegação por `delta` amostras.

          delta > 0  →  recua no tempo  (janela se move para o passado)
          delta < 0  →  avança no tempo (janela se move em direção ao presente)

        Clamp automático: [0, n − JANELA_GRAFICO].
        offset == 0  →  volta ao modo ao_vivo automaticamente.
        """
        n          = len(self._buffer_raw)
        max_offset = max(0, n - JANELA_GRAFICO)
        novo       = max(0, min(self._nav_offset + delta, max_offset))

        # Se está ao vivo e está recuando, entra em modo navegação
        if delta > 0 and self._modo == "ao_vivo":
            self._modo = "navegacao"

        self._nav_offset = novo

        if self._nav_offset == 0:
            self._modo = "ao_vivo"

        # Sincroniza o botão sem disparar o slot novamente
        self._bloqueio_sinal = True
        if hasattr(self, "_btn_pausar"):
            self._btn_pausar.setChecked(self._modo == "navegacao")
        self._bloqueio_sinal = False

        self._renderizar_grafico()
        self._atualizar_label_posicao()
        self._atualizar_estado_botoes()

    def _ir_para_inicio(self):
        """Salta para o ponto mais antigo do histórico disponível."""
        n          = len(self._buffer_raw)
        max_offset = max(0, n - JANELA_GRAFICO)
        delta      = max_offset - self._nav_offset
        if delta > 0:
            self._navegar(delta)

    def _ir_para_ao_vivo(self):
        """Volta imediatamente para o tempo real (offset = 0)."""
        if self._nav_offset > 0:
            self._navegar(-self._nav_offset)

    def _ao_alternar_pausa(self, pausado: bool):
        """Slot do botão ⏸ Pausar — chamado pelo toggled(bool)."""
        if self._bloqueio_sinal:
            return
        if pausado:
            # Congela no ponto atual sem mover o offset
            self._modo = "navegacao"
        else:
            self._ir_para_ao_vivo()
        self._atualizar_label_posicao()
        self._atualizar_estado_botoes()

    def _atualizar_label_posicao(self):
        """Atualiza o label de posição temporal (cor verde = ao vivo, laranja = histórico)."""
        if not hasattr(self, "_lbl_posicao"):
            return

        n       = len(self._buffer_raw)
        buf_min = n // 60
        buf_seg = n % 60

        if self._modo == "ao_vivo" or self._nav_offset == 0:
            texto = f"  ● Ao vivo  ({buf_min:02d}m{buf_seg:02d}s de hist.)"
            cor   = "#2ECC71"
        else:
            atras_min = self._nav_offset // 60
            atras_seg = self._nav_offset % 60
            texto = (
                f"  -{atras_min:02d}m{atras_seg:02d}s  "
                f"({buf_min:02d}m{buf_seg:02d}s de hist.)"
            )
            cor = "#E67E22"

        self._lbl_posicao.setText(texto)
        self._lbl_posicao.setStyleSheet(
            f"color:{cor}; font-size:10px; font-weight:bold;"
            "background:transparent; border:none;"
        )

    def _atualizar_estado_botoes(self):
        """Habilita/desabilita botões de navegação conforme o contexto atual."""
        if not hasattr(self, "_btn_pausar"):
            return

        n         = len(self._buffer_raw)
        tem_hist  = n > JANELA_GRAFICO
        pode_rec  = tem_hist                        # pode recuar se há histórico além da janela
        pode_ava  = self._nav_offset > 0            # pode avançar se não está ao vivo

        self._btn_inicio.setEnabled(pode_rec and self._nav_offset < n - JANELA_GRAFICO)
        self._btn_recuar30.setEnabled(pode_rec)
        self._btn_recuar10.setEnabled(pode_rec)
        self._btn_avancar10.setEnabled(pode_ava)
        self._btn_avancar30.setEnabled(pode_ava)
        self._btn_ao_vivo.setEnabled(pode_ava)

    # ── Suavização EMA ────────────────────────────────────────────────────────

    def _ao_mudar_suavizacao(self, valor: int):
        """
        Atualiza alpha e recomputa todo o buffer EMA histórico.

        Recomputar o histórico garante que a curva exibida seja sempre
        consistente com o alpha atual — independente de quando o slider
        foi movido durante a sessão.
        Complexidade: O(n) onde n ≤ MAX_HISTORICO (7200 iterações ≈ < 1 ms).
        """
        self._alpha_ema = valor / 100.0

        if hasattr(self, "_lbl_alpha"):
            self._lbl_alpha.setText(f"{self._alpha_ema:.2f}")

        # Recomputa histórico EMA
        self._recomputar_ema()

        # Redesenha na posição atual
        self._renderizar_grafico()

    def _recomputar_ema(self):
        """
        Reconstrói _buffer_ema inteiramente a partir de _buffer_raw
        usando o alpha atual.  Mantém o maxlen original.
        """
        if not self._buffer_raw:
            return

        raw_list  = list(self._buffer_raw)
        ema_val   = raw_list[0]
        ema_list  = []

        for x in raw_list:
            ema_val = self._alpha_ema * x + (1.0 - self._alpha_ema) * ema_val
            ema_list.append(ema_val)

        self._buffer_ema   = deque(ema_list, maxlen=MAX_HISTORICO)
        self._ema_anterior = ema_list[-1] if ema_list else 0.0

    # ── Crosshair e tooltip ───────────────────────────────────────────────────

    def _ao_mover_mouse(self, evento):
        """
        Atualiza crosshair e label ao mover o mouse sobre o gráfico.
        Disparado pelo SignalProxy (máx. 60 Hz) para não sobrecarregar a UI.
        """
        if not (self._plot_widget and self._linha_ch_v and self._label_valor):
            return

        pos = evento[0]
        if not self._plot_widget.sceneBoundingRect().contains(pos):
            self._label_valor.setText("")
            return

        pt = self._plot_widget.plotItem.vb.mapSceneToView(pos)
        x  = pt.x()
        y  = pt.y()

        self._linha_ch_v.setPos(x)
        self._linha_ch_h.setPos(y)

        # Valor EMA no índice mais próximo
        idx = int(round(x))
        if 0 <= idx < JANELA_GRAFICO:
            _, ema = self._obter_janela()
            if idx < len(ema):
                val = ema[idx]
                # Posiciona o label ligeiramente acima e à direita do cursor
                self._label_valor.setPos(x + 0.8, val + self._teto_y * 0.03)
                self._label_valor.setText(f"  {val:.2f} KB/s  ")