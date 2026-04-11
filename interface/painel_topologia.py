# interface/painel_topologia.py
# Visualizador de topologia avançado.
# Funcionalidades:
#   - Zoom (scroll) e pan (arrastar) da visualização
#   - Auto-zoom ao redimensionar para usar toda a área disponível
#   - Hover: tooltip com IP do dispositivo
#   - Clique: painel lateral com detalhes completos do dispositivo
#   - Tamanho dos nós dinâmico por volume de tráfego
#   - Destaque de conexões ao selecionar um nó
#   - Múltiplos anéis concêntricos para evitar sobreposição

import math
import socket
from typing import Dict, Optional, Tuple
from collections import defaultdict

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel,
    QFrame, QPushButton
)
from PyQt6.QtCore import Qt, QPointF, QTimer, QRectF, QPoint
from PyQt6.QtGui import (
    QPainter, QPen, QBrush, QColor, QFont,
    QRadialGradient, QCursor, QPainterPath, QFontMetrics
)


# ── Helpers de endereço ───────────────────────────────────────────────────────

def _eh_ip_local(ip: str) -> bool:
    try:
        p = [int(x) for x in ip.split(".")]
        if len(p) != 4:
            return False
        if p[0] == 10:
            return True
        if p[0] == 172 and 16 <= p[1] <= 31:
            return True
        if p[0] == 192 and p[1] == 168:
            return True
    except Exception:
        pass
    return False


def _eh_endereco_valido(ip: str) -> bool:
    if not ip:
        return False
    try:
        p = [int(x) for x in ip.split(".")]
        if len(p) != 4:
            return False
        if p[3] == 255:
            return False
        if ip == "255.255.255.255":
            return False
        if p[0] == 127:
            return False
        if 224 <= p[0] <= 239:
            return False
        if p[0] == 169 and p[1] == 254:
            return False
        if p[0] == 0:
            return False
    except Exception:
        return False
    return True


# ── Painel de detalhes do dispositivo ────────────────────────────────────────

class PainelDetalhes(QFrame):
    """Painel flutuante exibido ao clicar em um no."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName("PainelDetalhes")
        self.setStyleSheet("""
            QFrame#PainelDetalhes {
                background-color: rgba(18, 26, 48, 240);
                border: 1px solid rgba(52, 152, 219, 180);
                border-radius: 10px;
            }
            QLabel { color: #ecf0f1; background: transparent; }
        """)
        self.setFixedWidth(260)
        self._montar_ui()
        self.hide()

    def _montar_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(14, 12, 14, 14)
        layout.setSpacing(4)

        # Cabecalho
        cabecalho = QHBoxLayout()
        self._lbl_tipo_icone = QLabel("●")
        self._lbl_tipo_icone.setFont(QFont("Arial", 16))
        self._lbl_titulo = QLabel("Dispositivo")
        self._lbl_titulo.setFont(QFont("Arial", 11, QFont.Weight.Bold))
        self._lbl_titulo.setStyleSheet("color: #3498db;")
        btn_fechar = QPushButton("x")
        btn_fechar.setFixedSize(20, 20)
        btn_fechar.setStyleSheet(
            "QPushButton { color:#7f8c8d; background:transparent; border:none; font-size:12px; }"
            "QPushButton:hover { color:#e74c3c; }"
        )
        btn_fechar.clicked.connect(self.hide)
        cabecalho.addWidget(self._lbl_tipo_icone)
        cabecalho.addWidget(self._lbl_titulo)
        cabecalho.addStretch()
        cabecalho.addWidget(btn_fechar)
        layout.addLayout(cabecalho)

        sep = QFrame()
        sep.setFrameShape(QFrame.Shape.HLine)
        sep.setStyleSheet("color: rgba(52,152,219,80);")
        layout.addWidget(sep)
        layout.addSpacing(2)

        # Campos de informacao
        self._campos: Dict[str, QLabel] = {}
        campos_def = [
            ("ip",       "IP"),
            ("mac",      "MAC"),
            ("hostname", "Hostname"),
            ("tipo",     "Tipo"),
            ("pacotes",  "Trafego"),
            ("portas",   "Portas"),
            ("status",   "Status"),
        ]
        for chave, rotulo in campos_def:
            linha = QHBoxLayout()
            lbl_r = QLabel(f"{rotulo}:")
            lbl_r.setFixedWidth(72)
            lbl_r.setStyleSheet("color: #7f8c8d; font-size: 10px;")
            lbl_v = QLabel("---")
            lbl_v.setStyleSheet("color: #ecf0f1; font-size: 10px;")
            lbl_v.setWordWrap(True)
            linha.addWidget(lbl_r)
            linha.addWidget(lbl_v, 1)
            layout.addLayout(linha)
            self._campos[chave] = lbl_v

        layout.addStretch()

    def exibir(self, ip: str, dados: dict, tipo: str, cor: QColor):
        self._lbl_tipo_icone.setText("●")
        self._lbl_tipo_icone.setStyleSheet(f"color: {cor.name()};")
        nome = dados.get("hostname") or ip
        titulo = nome[:22] + "..." if len(nome) > 22 else nome
        self._lbl_titulo.setText(titulo)

        self._campos["ip"].setText(ip if ip != "internet" else "Externo (agrupado)")
        self._campos["mac"].setText(dados.get("mac") or "---")
        self._campos["hostname"].setText(dados.get("hostname") or "---")
        self._campos["tipo"].setText(tipo)

        pacotes = dados.get("pacotes", 0)
        bytes_est = pacotes * 512
        if bytes_est >= 1_048_576:
            vol = f"{bytes_est/1_048_576:.1f} MB  ({pacotes} pcts)"
        elif bytes_est >= 1024:
            vol = f"{bytes_est/1024:.1f} KB  ({pacotes} pcts)"
        else:
            vol = f"{bytes_est} B  ({pacotes} pcts)"
        self._campos["pacotes"].setText(vol)

        portas = dados.get("portas", set())
        if portas:
            lista = sorted(portas)[:8]
            txt = ", ".join(str(p) for p in lista)
            if len(portas) > 8:
                txt += f"  (+{len(portas)-8})"
        else:
            txt = "---"
        self._campos["portas"].setText(txt)

        self._campos["status"].setText("Ativo" if pacotes > 0 else "Inativo")
        self._campos["status"].setStyleSheet(
            "color: #2ecc71; font-size:10px;" if pacotes > 0
            else "color: #95a5a6; font-size:10px;"
        )
        self.adjustSize()
        self.show()


# ── Visualizador principal ────────────────────────────────────────────────────

class VisualizadorTopologia(QWidget):
    """
    Canvas interativo da topologia.
    Suporta zoom (scroll), pan (drag), hover tooltip e selecao de no.
    """

    COR_FUNDO       = QColor(15, 20, 35)
    COR_NO_LOCAL    = QColor(46,  204, 113)
    COR_NO_GATEWAY  = QColor(231,  76,  60)
    COR_NO_NORMAL   = QColor(52,  152, 219)
    COR_NO_INTERNET = QColor(155,  89, 182)
    COR_TEXTO       = QColor(236, 240, 241)
    COR_LEGENDA     = QColor(120, 140, 160)
    MAX_CONEXOES    = 20
    RAIO_BASE       = 16
    RAIO_MIN        = 7
    RAIO_MAX        = 30

    def __init__(self, parent=None):
        super().__init__(parent)

        self.dispositivos: Dict[str, dict]        = {}
        self.contagem_conexoes: Dict[Tuple, int]  = defaultdict(int)
        self._posicoes_mundo: Dict[str, QPointF]  = {}
        self._ip_local = self._obter_ip_local()
        self._rede_local = None  # ipaddress.ip_network

        self._zoom       = 1.0
        self._offset     = QPointF(0, 0)
        self._drag_inicio: Optional[QPoint] = None
        self._offset_drag_inicio = QPointF(0, 0)
        self._no_hover: Optional[str]      = None
        self._no_selecionado: Optional[str] = None

        # callback externo chamado ao clicar em um no
        self.on_no_clicado = None

        self._fase_animacao = 0
        timer = QTimer(self)
        timer.timeout.connect(self._passo_animacao)
        # 33ms ≈ 30fps — animação fluida, ainda leve para a CPU.
        timer.start(33)

        # Debounce do recalculo de layout — chama no máximo 1x a cada 800ms,
        # independentemente de quantos novos IPs chegarem nesse intervalo.
        self._timer_layout = QTimer(self)
        self._timer_layout.setSingleShot(True)
        self._timer_layout.setInterval(800)
        self._timer_layout.timeout.connect(self._recalcular_layout)

        self.setMouseTracking(True)
        self.setCursor(QCursor(Qt.CursorShape.ArrowCursor))
        self.setMinimumSize(500, 350)
        # Evita repintura do fundo pelo Qt antes do nosso draw → menos overdraw.
        self.setAttribute(Qt.WidgetAttribute.WA_OpaquePaintEvent, True)

    # ── Interface publica ──────────────────────────────────────────────────

    def registrar_origem(self, ip: str, mac: str = "", hostname: str = ""):
        if not _eh_endereco_valido(ip):
            return
        chave = ip if self._pertence_rede(ip) else "internet"

        if chave not in self.dispositivos:
            self.dispositivos[chave] = {
                "ip":       chave,
                "mac":      mac,
                "hostname": hostname if chave != "internet" else "Internet",
                "pacotes":  0,
                "portas":   set(),
            }
            # Agenda recalculo de layout com debounce — evita chamar
            # _recalcular_layout centenas de vezes por segundo em capturas pesadas.
            if not self._timer_layout.isActive():
                self._timer_layout.start()
        else:
            if mac and chave != "internet":
                self.dispositivos[chave]["mac"] = mac
            if hostname and chave != "internet":
                self.dispositivos[chave]["hostname"] = hostname

        self.dispositivos[chave]["pacotes"] += 1

    def registrar_conexao(self, ip_origem: str, ip_destino: str,
                          porta_origem: int = 0, porta_destino: int = 0):
        if not _eh_endereco_valido(ip_origem) or not _eh_endereco_valido(ip_destino):
            return
        no_a = ip_origem  if self._pertence_rede(ip_origem)  else "internet"
        no_b = ip_destino if self._pertence_rede(ip_destino) else "internet"
        if no_a == no_b:
            return
        if no_a not in self.dispositivos and no_b not in self.dispositivos:
            return

        chave = tuple(sorted([no_a, no_b]))
        self.contagem_conexoes[chave] += 1

        if porta_destino and no_b in self.dispositivos:
            self.dispositivos[no_b].setdefault("portas", set()).add(porta_destino)
        if porta_origem and no_a in self.dispositivos:
            self.dispositivos[no_a].setdefault("portas", set()).add(porta_origem)

    def adicionar_dispositivo_manual(self, ip: str, mac: str = "", hostname: str = ""):
        self.registrar_origem(ip, mac, hostname)

    def limpar(self):
        self.dispositivos.clear()
        self.contagem_conexoes.clear()
        self._posicoes_mundo.clear()
        self._no_selecionado = None
        self._no_hover = None
        self.update()

    # ── Zoom / Pan ─────────────────────────────────────────────────────────

    def wheelEvent(self, evento):
        fator = 1.12 if evento.angleDelta().y() > 0 else 1 / 1.12
        pos_cursor = QPointF(evento.position())
        self._offset = pos_cursor + (self._offset - pos_cursor) * fator
        self._zoom  *= fator
        self._zoom   = max(0.2, min(self._zoom, 6.0))
        self.update()

    def mousePressEvent(self, evento):
        pos = evento.position()
        if evento.button() == Qt.MouseButton.LeftButton:
            ip = self._no_em(pos)
            if ip:
                self._no_selecionado = ip if ip != self._no_selecionado else None
                if self.on_no_clicado:
                    self.on_no_clicado(self._no_selecionado)
            else:
                self._drag_inicio = evento.pos()
                self._offset_drag_inicio = QPointF(self._offset)
                self._no_selecionado = None
                if self.on_no_clicado:
                    self.on_no_clicado(None)
            self.update()
        elif evento.button() == Qt.MouseButton.RightButton:
            self._resetar_vista()

    def mouseMoveEvent(self, evento):
        pos = evento.position()
        if self._drag_inicio is not None:
            delta = evento.pos() - self._drag_inicio
            self._offset = self._offset_drag_inicio + QPointF(delta)
            self.update()
        else:
            ip = self._no_em(pos)
            if ip != self._no_hover:
                self._no_hover = ip
                self.setCursor(
                    QCursor(Qt.CursorShape.PointingHandCursor)
                    if ip else QCursor(Qt.CursorShape.ArrowCursor)
                )
                self.update()

    def mouseReleaseEvent(self, evento):
        self._drag_inicio = None

    def _resetar_vista(self):
        self._zoom   = 1.0
        self._offset = QPointF(0, 0)
        self._auto_zoom()
        self.update()

    def definir_rede_local(self, cidr: str):
        """Define a rede local (CIDR) para filtrar nós fora da LAN."""
        try:
            import ipaddress
            self._rede_local = ipaddress.ip_network(cidr, strict=False) if cidr else None
        except Exception:
            self._rede_local = None

    def _pertence_rede(self, ip: str) -> bool:
        if not ip or not _eh_endereco_valido(ip):
            return False
        if self._rede_local is None:
            return _eh_ip_local(ip)
        try:
            import ipaddress
            return ipaddress.ip_address(ip) in self._rede_local
        except Exception:
            return _eh_ip_local(ip)

    # ── Desenho ────────────────────────────────────────────────────────────

    def paintEvent(self, _):
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        p.fillRect(self.rect(), self.COR_FUNDO)

        if not self.dispositivos:
            self._pintar_vazio(p)
            return

        p.save()
        p.translate(self._offset)
        p.scale(self._zoom, self._zoom)
        self._pintar_conexoes(p)
        self._pintar_nos(p)
        p.restore()

        self._pintar_legenda(p)
        self._pintar_info(p)
        self._pintar_tooltip(p)
        self._pintar_dica(p)

    def _pintar_vazio(self, p: QPainter):
        p.setPen(QPen(QColor(80, 100, 130)))
        p.setFont(QFont("Arial", 13))
        p.drawText(
            self.rect(), Qt.AlignmentFlag.AlignCenter,
            "Nenhum dispositivo detectado.\n"
            "Inicie a captura ou clique em 'Descobrir Rede'."
        )

    def _pintar_conexoes(self, p: QPainter):
        if not self.contagem_conexoes:
            return

        top = sorted(
            self.contagem_conexoes.items(),
            key=lambda x: x[1], reverse=True
        )[:self.MAX_CONEXOES]
        maximo = top[0][1] if top else 1

        for (no_a, no_b), contagem in top:
            if no_a not in self._posicoes_mundo or no_b not in self._posicoes_mundo:
                continue

            proporcao = contagem / maximo
            espessura = 0.8 + proporcao * 3.0

            if self._no_selecionado:
                if self._no_selecionado in (no_a, no_b):
                    alpha = int(160 + proporcao * 95)
                    cor   = QColor(243, 156, 18, alpha)
                    espessura *= 1.8
                else:
                    cor = QColor(52, 152, 219, 20)
                    espessura *= 0.4
            else:
                alpha = int(45 + proporcao * 150)
                cor   = QColor(52, 152, 219, alpha)

            p.setPen(QPen(cor, espessura))
            p.drawLine(self._posicoes_mundo[no_a], self._posicoes_mundo[no_b])

    def _pintar_nos(self, p: QPainter):
        ordem = list(self.dispositivos.keys())
        if self._no_selecionado and self._no_selecionado in ordem:
            ordem.remove(self._no_selecionado)
            ordem.append(self._no_selecionado)

        for ip in ordem:
            if ip not in self._posicoes_mundo:
                continue
            dados = self.dispositivos[ip]
            pos   = self._posicoes_mundo[ip]
            cor   = self._cor_do_no(ip)
            raio  = self._raio_do_no(ip)

            desfocado = (
                self._no_selecionado is not None
                and ip != self._no_selecionado
            )

            # Sombra
            p.setPen(Qt.PenStyle.NoPen)
            p.setBrush(QBrush(QColor(0, 0, 0, 55)))
            p.drawEllipse(QPointF(pos.x() + 2, pos.y() + 3), raio, raio)

            # Pulso no IP local
            if ip == self._ip_local and not desfocado:
                raio_p = raio + 6 + 3 * math.sin(self._fase_animacao * 0.12)
                pen_p  = QPen(cor.lighter(170), 1.2)
                pen_p.setStyle(Qt.PenStyle.DotLine)
                p.setPen(pen_p)
                p.setBrush(Qt.BrushStyle.NoBrush)
                p.drawEllipse(pos, raio_p, raio_p)

            # Borda de selecao / hover
            if ip == self._no_selecionado:
                p.setPen(QPen(QColor(243, 156, 18), 2.5))
                p.setBrush(Qt.BrushStyle.NoBrush)
                p.drawEllipse(pos, raio + 5, raio + 5)
            elif ip == self._no_hover and not desfocado:
                p.setPen(QPen(cor.lighter(200), 1.8))
                p.setBrush(Qt.BrushStyle.NoBrush)
                p.drawEllipse(pos, raio + 4, raio + 4)

            # Corpo do no com gradiente
            grad = QRadialGradient(
                pos.x() - raio * 0.3,
                pos.y() - raio * 0.3,
                raio * 1.4
            )
            if desfocado:
                grad.setColorAt(0, QColor(cor.red(), cor.green(), cor.blue(), 70))
                grad.setColorAt(1, QColor(cor.red(), cor.green(), cor.blue(), 25))
                p.setPen(QPen(QColor(cor.red(), cor.green(), cor.blue(), 45), 1))
            else:
                grad.setColorAt(0, cor.lighter(155))
                grad.setColorAt(1, cor.darker(155))
                p.setPen(QPen(cor.lighter(190), 1.5))
            p.setBrush(QBrush(grad))
            p.drawEllipse(pos, raio, raio)

            # Label dentro do no
            if raio >= 11 and not desfocado:
                if ip == "internet":
                    label = "WEB"
                else:
                    partes = ip.split(".")
                    label  = f".{partes[-1]}" if len(partes) == 4 else ip
                font_sz = max(5, min(9, int(raio * 0.55)))
                p.setPen(QPen(self.COR_TEXTO))
                p.setFont(QFont("Consolas", font_sz, QFont.Weight.Bold))
                p.drawText(
                    QRectF(pos.x() - raio, pos.y() - raio * 0.6,
                           raio * 2, raio * 1.2),
                    Qt.AlignmentFlag.AlignCenter, label
                )

            # Nome abaixo do no
            if raio >= 16 and not desfocado:
                nome = "Internet" if ip == "internet" else (dados.get("hostname") or ip)
                if len(nome) > 18:
                    nome = nome[:16] + "..."
                p.setPen(QPen(self.COR_LEGENDA))
                p.setFont(QFont("Arial", 7))
                p.drawText(
                    QRectF(pos.x() - 50, pos.y() + raio + 3, 100, 13),
                    Qt.AlignmentFlag.AlignCenter, nome
                )

    def _pintar_legenda(self, p: QPainter):
        itens = [
            (self.COR_NO_LOCAL,    "Este computador"),
            (self.COR_NO_NORMAL,   "Dispositivo local"),
            (self.COR_NO_GATEWAY,  "Gateway"),
            (self.COR_NO_INTERNET, "Internet"),
        ]
        x, y = 12, self.height() - 96
        p.setFont(QFont("Arial", 8))
        for cor, rotulo in itens:
            p.setPen(Qt.PenStyle.NoPen)
            p.setBrush(QBrush(cor))
            p.drawEllipse(x, y, 10, 10)
            p.setPen(QPen(self.COR_LEGENDA))
            p.drawText(x + 15, y + 9, rotulo)
            y += 18

    def _pintar_info(self, p: QPainter):
        locais   = sum(1 for ip in self.dispositivos if ip != "internet")
        conexoes = len(self.contagem_conexoes)
        zoom_pct = int(self._zoom * 100)
        texto    = (
            f"Dispositivos: {locais}   "
            f"Conexoes: {conexoes}   "
            f"Zoom: {zoom_pct}%"
        )
        p.setPen(QPen(QColor(70, 90, 120)))
        p.setFont(QFont("Arial", 8))
        p.drawText(
            QRectF(self.width() - 360, 8, 350, 16),
            Qt.AlignmentFlag.AlignRight, texto
        )

    def _pintar_tooltip(self, p: QPainter):
        if not self._no_hover or self._no_hover == self._no_selecionado:
            return

        ip    = self._no_hover
        dados = self.dispositivos.get(ip, {})
        nome  = dados.get("hostname") or ""
        if ip == "internet":
            txt = "Internet (IPs externos)"
        elif nome and nome != ip:
            txt = f"{ip}  -  {nome}"
        else:
            txt = ip

        pos_mundo = self._posicoes_mundo.get(ip)
        if not pos_mundo:
            return
        pos_tela  = self._mundo_para_tela(pos_mundo)
        raio_tela = self._raio_do_no(ip) * self._zoom

        tx = pos_tela.x() + raio_tela + 8
        ty = pos_tela.y() - 14

        fm   = QFontMetrics(QFont("Arial", 9))
        larg = fm.horizontalAdvance(txt) + 16
        alt  = 22

        if tx + larg > self.width() - 4:
            tx = pos_tela.x() - raio_tela - larg - 8
        ty = max(4, min(ty, self.height() - alt - 4))

        p.setPen(Qt.PenStyle.NoPen)
        p.setBrush(QBrush(QColor(18, 28, 50, 230)))
        path = QPainterPath()
        path.addRoundedRect(QRectF(tx, ty, larg, alt), 5, 5)
        p.drawPath(path)
        p.setPen(QPen(QColor(52, 152, 219, 120), 1))
        p.drawPath(path)

        p.setPen(QPen(QColor(220, 230, 245)))
        p.setFont(QFont("Arial", 9))
        p.drawText(
            QRectF(tx + 8, ty, larg - 8, alt),
            Qt.AlignmentFlag.AlignVCenter, txt
        )

    def _pintar_dica(self, p: QPainter):
        p.setPen(QPen(QColor(55, 70, 100)))
        p.setFont(QFont("Arial", 7))
        p.drawText(
            QRectF(8, self.height() - 16, 350, 13),
            Qt.AlignmentFlag.AlignLeft,
            "Scroll: zoom  |  Arrastar: mover  |  Clicar no: detalhes  |  Botao dir.: resetar"
        )

    # ── Utilitarios internos ───────────────────────────────────────────────

    def _cor_do_no(self, ip: str) -> QColor:
        if ip == "internet":
            return self.COR_NO_INTERNET
        if ip == self._ip_local:
            return self.COR_NO_LOCAL
        if ip.endswith(".1") or ip.endswith(".254"):
            return self.COR_NO_GATEWAY
        return self.COR_NO_NORMAL

    def _tipo_do_no(self, ip: str) -> str:
        if ip == "internet":
            return "Externo / Internet"
        if ip == self._ip_local:
            return "Este computador"
        if ip.endswith(".1") or ip.endswith(".254"):
            return "Gateway / Roteador"
        return "Dispositivo local"

    def _raio_do_no(self, ip: str) -> float:
        """Raio cresce logaritmicamente com o volume de trafego."""
        pacotes = self.dispositivos.get(ip, {}).get("pacotes", 0)
        if pacotes <= 0:
            return float(self.RAIO_BASE)
        bonus = math.log1p(pacotes) * 1.8
        return min(float(self.RAIO_MAX), max(float(self.RAIO_MIN), self.RAIO_BASE + bonus))

    def _mundo_para_tela(self, pt: QPointF) -> QPointF:
        return QPointF(
            pt.x() * self._zoom + self._offset.x(),
            pt.y() * self._zoom + self._offset.y(),
        )

    def _tela_para_mundo(self, pt: QPointF) -> QPointF:
        return QPointF(
            (pt.x() - self._offset.x()) / self._zoom,
            (pt.y() - self._offset.y()) / self._zoom,
        )

    def _no_em(self, pos_tela: QPointF) -> Optional[str]:
        pt_mundo = self._tela_para_mundo(pos_tela)
        for ip, pos_mundo in self._posicoes_mundo.items():
            raio = self._raio_do_no(ip) + 4
            dx   = pt_mundo.x() - pos_mundo.x()
            dy   = pt_mundo.y() - pos_mundo.y()
            if dx * dx + dy * dy <= raio * raio:
                return ip
        return None

    def _recalcular_layout(self):
        """
        Distribui nos em multiplos aneis concentricos no espaco-mundo,
        depois aplica auto-zoom para preencher a area visivel.
        """
        locais   = [ip for ip in self.dispositivos if ip != "internet"]
        tem_inet = "internet" in self.dispositivos
        n        = len(locais)

        raio_no_layout    = self.RAIO_BASE + 4
        margem            = raio_no_layout * 2.8
        raio_anel_inicial = max(margem * 2.2, 60.0)
        incremento_anel   = margem * 2.4

        aneis = []
        restantes = list(locais)
        idx_anel  = 0
        while restantes:
            r   = raio_anel_inicial + idx_anel * incremento_anel
            cap = max(1, int(2 * math.pi * r / margem))
            aneis.append(restantes[:cap])
            restantes = restantes[cap:]
            idx_anel += 1

        for idx_anel, ips_anel in enumerate(aneis):
            r = raio_anel_inicial + idx_anel * incremento_anel
            m = len(ips_anel)
            for i, ip in enumerate(ips_anel):
                ang = (2 * math.pi * i / max(m, 1)) - math.pi / 2
                self._posicoes_mundo[ip] = QPointF(
                    r * math.cos(ang),
                    r * math.sin(ang),
                )

        if tem_inet:
            raio_ext = raio_anel_inicial + max(len(aneis) - 1, 0) * incremento_anel
            self._posicoes_mundo["internet"] = QPointF(raio_ext * 1.55, 0)

        self._auto_zoom()

    def _auto_zoom(self):
        """Calcula zoom e offset para que todos os nos preencham a area."""
        if not self._posicoes_mundo:
            return

        xs = [p.x() for p in self._posicoes_mundo.values()]
        ys = [p.y() for p in self._posicoes_mundo.values()]

        margem_extra = self.RAIO_MAX + 50
        xmin, xmax = min(xs) - margem_extra, max(xs) + margem_extra
        ymin, ymax = min(ys) - margem_extra, max(ys) + margem_extra

        larg_mundo = xmax - xmin
        alt_mundo  = ymax - ymin
        if larg_mundo <= 0 or alt_mundo <= 0:
            return

        zoom_x = self.width()  / larg_mundo
        zoom_y = self.height() / alt_mundo
        self._zoom = max(0.2, min(zoom_x, zoom_y, 3.5))

        cx_mundo = (xmin + xmax) / 2
        cy_mundo = (ymin + ymax) / 2
        self._offset = QPointF(
            self.width()  / 2 - cx_mundo * self._zoom,
            self.height() / 2 - cy_mundo * self._zoom,
        )

    def _passo_animacao(self):
        self._fase_animacao += 1
        # Redesenha apenas quando necessário:
        #   • Sempre que o nó local existir (pulso animado precisa de update contínuo)
        #   • A cada 4 ticks (~400ms) para manter hover/tooltip responsivos
        #     sem redesenhar a cada 100ms quando não há animação ativa.
        if self._ip_local and self._ip_local in self._posicoes_mundo:
            self.update()
        elif self._fase_animacao % 4 == 0:
            self.update()

    def resizeEvent(self, evento):
        self._auto_zoom()
        super().resizeEvent(evento)

    @staticmethod
    def _obter_ip_local() -> str:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.connect(("8.8.8.8", 80))
                return s.getsockname()[0]
        except Exception:
            return ""


# ── Painel contentor ──────────────────────────────────────────────────────────

class PainelTopologia(QWidget):

    def __init__(self, parent=None):
        super().__init__(parent)
        self._montar_layout()

    def _montar_layout(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        # Wrapper para sobrepor o painel de detalhes ao canvas
        self._area = QWidget()
        self._area.setMinimumSize(500, 350)

        self.visualizador = VisualizadorTopologia(self._area)
        self.visualizador.setGeometry(0, 0,
                                      self._area.width(),
                                      self._area.height())

        self._painel_detalhes = PainelDetalhes(self._area)
        self._painel_detalhes.raise_()

        self.visualizador.on_no_clicado = self._on_no_clicado

        layout.addWidget(self._area, 1)

        rodape = QLabel(
            "Apenas dispositivos que originaram pacotes sao exibidos.  "
            "IPs externos sao agrupados em 'Internet'.  "
            "Nos maiores = maior volume de trafego.  "
            "Clique num no para detalhes."
        )
        rodape.setStyleSheet(
            "color: #566573; font-size: 9px; padding: 3px 6px;"
            "background: rgba(10,14,24,180);"
        )
        layout.addWidget(rodape)

    def resizeEvent(self, evento):
        super().resizeEvent(evento)
        # Fazer o visualizador preencher toda a area
        self.visualizador.setGeometry(0, 0,
                                      self._area.width(),
                                      self._area.height())
        self._reposicionar_painel()

    def _reposicionar_painel(self):
        w  = self._area.width()
        pw = self._painel_detalhes.width()
        self._painel_detalhes.move(w - pw - 10, 10)

    def _on_no_clicado(self, ip: Optional[str]):
        if not ip or ip not in self.visualizador.dispositivos:
            self._painel_detalhes.hide()
            return
        dados = self.visualizador.dispositivos[ip]
        tipo  = self.visualizador._tipo_do_no(ip)
        cor   = self.visualizador._cor_do_no(ip)
        self._painel_detalhes.exibir(ip, dados, tipo, cor)
        self._reposicionar_painel()
        self._painel_detalhes.raise_()

    # ── Metodos publicos usados pela janela principal ──────────────────────

    def adicionar_dispositivo(self, ip: str, mac: str = "", hostname: str = ""):
        """Chamado durante a captura - registra apenas IPs de origem."""
        self.visualizador.registrar_origem(ip, mac, hostname)

    def adicionar_conexao(self, ip_origem: str, ip_destino: str,
                          porta_origem: int = 0, porta_destino: int = 0):
        self.visualizador.registrar_conexao(
            ip_origem, ip_destino, porta_origem, porta_destino
        )

    def adicionar_dispositivo_manual(self, ip: str, mac: str = "", hostname: str = ""):
        """Chamado pela varredura ARP - aceita qualquer IP local valido."""
        self.visualizador.adicionar_dispositivo_manual(ip, mac, hostname)

    def atualizar(self):
        self.visualizador.update()

    def definir_rede_local(self, cidr: str):
        """Define rede local para filtrar o que é exibido na topologia."""
        self.visualizador.definir_rede_local(cidr)

    def limpar(self):
        self._painel_detalhes.hide()
        self.visualizador.limpar()

    def total_dispositivos(self) -> int:
        """Retorna total de nÃ³s renderizados (ativos + descobertos)."""
        return len([ip for ip in self.visualizador.dispositivos if ip != "internet"])

    def total_dispositivos_ativos(self) -> int:
        """Conta apenas nÃ³s que jÃ¡ trafegaram pacotes."""
        return sum(
            1
            for ip, d in self.visualizador.dispositivos.items()
            if ip != "internet" and d.get("pacotes", 0) > 0
        )
