# interface/painel_trafego.py
# Painel de tráfego em tempo real com gráfico corrigido.
# O gráfico usa uma janela deslizante de 60 segundos com eixos fixos.

from collections import deque

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel,
    QTableWidget, QTableWidgetItem, QHeaderView,
    QFrame, QSplitter
)
from PyQt6.QtCore import Qt
from PyQt6.QtGui import QFont, QColor
from utils.constantes import CORES_PROTOCOLO
from utils.rede import formatar_bytes

try:
    import pyqtgraph as pg
    PYQTGRAPH_DISPONIVEL = True
except ImportError:
    PYQTGRAPH_DISPONIVEL = False

JANELA_GRAFICO = 60   # segundos exibidos no gráfico


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


class PainelTrafego(QWidget):

    def __init__(self, parent=None):
        super().__init__(parent)
        # Histórico para o gráfico — mantido aqui para ter controle total
        self._historico_kb: deque = deque([0.0] * JANELA_GRAFICO, maxlen=JANELA_GRAFICO)
        self._plot_widget  = None
        self._curva        = None
        self._teto_y       = 10.0
        self._montar_layout()

    def _montar_layout(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(4, 2, 4, 4)
        layout.setSpacing(6)

        # Cards
        row = QHBoxLayout()
        self.card_pacotes      = CardEstatistica("TOTAL DE PACOTES",    "0",      "#3498DB")
        self.card_dados        = CardEstatistica("DADOS TRANSMITIDOS",  "0 KB",   "#2ECC71")
        self.card_dispositivos = CardEstatistica("DISPOSITIVOS ATIVOS", "0",      "#E74C3C")
        self.card_velocidade   = CardEstatistica("VELOCIDADE ATUAL",    "0 KB/s", "#9B59B6")
        for c in (self.card_pacotes, self.card_dados, self.card_dispositivos, self.card_velocidade):
            row.addWidget(c)
        layout.addLayout(row)

        splitter = QSplitter(Qt.Orientation.Horizontal)
        layout.addWidget(splitter)

        # ── Lado esquerdo: gráfico ──────────────
        w_graf = QWidget()
        l_graf = QVBoxLayout(w_graf)
        l_graf.setContentsMargins(0, 0, 4, 0)

        if PYQTGRAPH_DISPONIVEL:
            self._criar_grafico(l_graf)
        else:
            aviso = QLabel("PyQtGraph não encontrado.\npip install pyqtgraph")
            aviso.setAlignment(Qt.AlignmentFlag.AlignCenter)
            aviso.setStyleSheet("color:#e74c3c;")
            l_graf.addWidget(aviso)

        splitter.addWidget(w_graf)

        # ── Lado direito: tabelas ───────────────
        w_tab = QWidget()
        l_tab = QVBoxLayout(w_tab)
        l_tab.setContentsMargins(4, 4, 0, 0)

        fonte_label2 = QFont("Arial", 10)
        fonte_label2.setBold(True)

        lbl_p = QLabel("Protocolos Detectados")
        lbl_p.setStyleSheet("color:#bdc3c7;")
        lbl_p.setFont(fonte_label2)
        l_tab.addWidget(lbl_p)
        self.tabela_protocolos = self._criar_tabela(
            ["Protocolo", "Pacotes", "Dados (KB)"], altura=180
        )
        l_tab.addWidget(self.tabela_protocolos)

        lbl_d = QLabel("Top Dispositivos por Tráfego")
        lbl_d.setStyleSheet("color:#bdc3c7; margin-top:6px;")
        lbl_d.setFont(fonte_label2)
        l_tab.addWidget(lbl_d)
        self.tabela_dispositivos = self._criar_tabela(
            ["Endereço IP", "Enviado (KB)", "Recebido (KB)", "Total (KB)"]
        )
        l_tab.addWidget(self.tabela_dispositivos)

        splitter.addWidget(w_tab)
        splitter.setSizes([640, 360])

    def _criar_grafico(self, layout_pai: QVBoxLayout):
        """
        Cria o gráfico PyQtGraph com eixos completamente fixos na inicialização.
        Isso evita o bug de escala x1e+09 causado pelo auto-range em dados vazios.
        """
        pg.setConfigOption("background", "#0f1423")
        pg.setConfigOption("foreground", "#bdc3c7")

        self._plot_widget = pg.PlotWidget()
        self._plot_widget.setMinimumHeight(200)

        # Desabilitar TODO o auto-range desde o início
        self._plot_widget.disableAutoRange()

        # Definir eixos fixos iniciais
        self._plot_widget.setXRange(0, JANELA_GRAFICO, padding=0)
        self._plot_widget.setYRange(0, 10, padding=0)

        self._plot_widget.setLabel("left",   "KB/s",      color="#bdc3c7", size="9pt")
        self._plot_widget.setLabel("bottom", "Tempo (s)", color="#bdc3c7", size="9pt")
        self._plot_widget.showGrid(x=True, y=True, alpha=0.2)

        # Desabilitar interação de zoom do mouse para não confundir o aluno
        self._plot_widget.setMouseEnabled(x=False, y=False)

        self._curva = self._plot_widget.plot(
            x=list(range(JANELA_GRAFICO)),
            y=[0.0] * JANELA_GRAFICO,
            pen=pg.mkPen(color="#3498DB", width=2),
            fillLevel=0,
            brush=pg.mkBrush(color=(52, 152, 219, 40)),
        )
        layout_pai.addWidget(self._plot_widget)

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

    # ── Atualização pública ───────────────────

    def adicionar_ponto_grafico(self, kb_por_segundo: float):
        """
        Chamado a cada segundo pelo timer da janela principal.
        Adiciona um ponto à janela deslizante e redesenha a curva.
        """
        self._historico_kb.append(kb_por_segundo)
        valores = list(self._historico_kb)
        eixo_x  = list(range(len(valores)))

        if self._curva:
            self._curva.setData(x=eixo_x, y=valores)

            maximo = max(valores) if valores else 0
            # Ajusta teto Y apenas quando necessário para evitar "pulos"
            if maximo > self._teto_y * 0.8 or maximo < self._teto_y * 0.3:
                self._teto_y = max(maximo * 1.3, 10.0)
            self._plot_widget.setYRange(0, self._teto_y, padding=0)
            self._plot_widget.setXRange(0, JANELA_GRAFICO - 1, padding=0)

    def atualizar_tabelas(self, estatisticas_protocolos: list,
                           top_dispositivos: list,
                           total_pacotes: int, total_bytes: int,
                           total_topologia: int = None,
                           total_ativos: int = None):
        """Atualiza cards e tabelas com os dados mais recentes do analisador."""

        # Cards
        self.card_pacotes.definir_valor(f"{total_pacotes:,}")
        self.card_dados.definir_valor(formatar_bytes(total_bytes))

        ativos = total_ativos if total_ativos is not None else len(top_dispositivos)
        self.card_dispositivos.definir_valor(str(ativos))

        # Velocidade atual = último ponto do histórico
        vel = list(self._historico_kb)[-1] if self._historico_kb else 0.0
        self.card_velocidade.definir_valor(f"{vel:.1f} KB/s")

        # Tabela de protocolos
        fonte_c = QFont("Consolas", 9)
        fonte_c.setBold(True)
        self.tabela_protocolos.setRowCount(len(estatisticas_protocolos))
        for i, stat in enumerate(estatisticas_protocolos):
            proto = stat["protocolo"]
            cor   = QColor(CORES_PROTOCOLO.get(proto, "#95a5a6"))

            item_p = QTableWidgetItem(proto)
            item_p.setForeground(cor)
            item_p.setFont(fonte_c)

            item_n = QTableWidgetItem(f"{stat['pacotes']:,}")
            item_n.setTextAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)

            item_k = QTableWidgetItem(f"{stat['bytes']/1024:.1f}")
            item_k.setTextAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)

            self.tabela_protocolos.setItem(i, 0, item_p)
            self.tabela_protocolos.setItem(i, 1, item_n)
            self.tabela_protocolos.setItem(i, 2, item_k)

        # Tabela de dispositivos
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
        self._historico_kb = deque([0.0] * JANELA_GRAFICO, maxlen=JANELA_GRAFICO)
        self._teto_y = 10.0
        if self._curva:
            self._curva.setData(x=list(range(JANELA_GRAFICO)), y=[0.0] * JANELA_GRAFICO)
            self._plot_widget.setYRange(0, self._teto_y, padding=0)
        self.tabela_protocolos.setRowCount(0)
        self.tabela_dispositivos.setRowCount(0)
        for c in (self.card_pacotes, self.card_dados, self.card_dispositivos, self.card_velocidade):
            c.definir_valor("0")
        self.card_dados.definir_valor("0 KB")
        self.card_velocidade.definir_valor("0 KB/s")
