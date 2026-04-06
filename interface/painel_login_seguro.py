# interface/painel_login_seguro.py
# Painel didático: compara login vulnerável x login protegido,
# simula brute force e exibe métricas e gráficos para o TCC.

import math
import secrets
import hashlib
import time
from collections import defaultdict
from dataclasses import dataclass
from typing import Dict, List, Tuple

from PyQt6.QtCore import Qt, QThread, pyqtSignal
from PyQt6.QtGui import QFont
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QFrame,
    QGroupBox, QGridLayout, QLineEdit, QPushButton,
    QTextEdit, QProgressBar, QTableWidget, QTableWidgetItem,
    QHeaderView
)

try:
    import pyqtgraph as pg
    PYQTGRAPH_DISPONIVEL = True
except Exception:
    PYQTGRAPH_DISPONIVEL = False


# ──────────────────────────────────────────────────────────────────────
# Modelo simples de autenticação
# ──────────────────────────────────────────────────────────────────────

def _hash_senha(senha: str, salt: bytes) -> bytes:
    # PBKDF2 aproxima o custo de bcrypt sem exigir dependências extras
    return hashlib.pbkdf2_hmac("sha256", senha.encode("utf-8"), salt, 120_000)


class SistemaLogin:
    """Dois comportamentos: vulnerável (texto puro) e seguro (hash + limites)."""

    def __init__(self, seguro: bool):
        self.seguro = seguro
        self._senhas: Dict[str, str | bytes] = {}
        self._salts: Dict[str, bytes] = {}
        self._tentativas_por_ip: Dict[str, List[float]] = defaultdict(list)
        self._bloqueado_ate: Dict[str, float] = {}
        self._captcha_por_ip: Dict[str, str] = {}

        # Políticas do modo seguro
        self.limite_tentativas = 6        # por janela
        self.janela_segundos = 30
        self.tempo_bloqueio = 45          # segundos

    def registrar_usuario(self, usuario: str, senha: str):
        if not self.seguro:
            self._senhas[usuario] = senha
            return
        salt = secrets.token_bytes(16)
        self._salts[usuario] = salt
        self._senhas[usuario] = _hash_senha(senha, salt)

    # Dados para exibição didática
    def dado_armazenado(self, usuario: str) -> str:
        if usuario not in self._senhas:
            return "—"
        if not self.seguro:
            return f"Texto puro: {self._senhas[usuario]}"
        salt = self._salts[usuario].hex()[:12] + "..."
        hash_hex = self._senhas[usuario].hex()[:32] + "..."
        return f"Hash PBKDF2: {hash_hex}\nSalt: {salt}"

    def gerar_captcha(self) -> str:
        letras = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
        return "".join(secrets.choice(letras) for _ in range(5))

    def autenticar(self, usuario: str, senha: str,
                   ip: str = "127.0.0.1", captcha: str | None = None) -> Tuple[bool, str]:
        agora = time.time()

        # Bloqueio temporário
        if self.seguro and ip in self._bloqueado_ate and agora < self._bloqueado_ate[ip]:
            restante = int(self._bloqueado_ate[ip] - agora)
            return False, f"IP bloqueado por {restante}s"

        # Rate limiting
        if self.seguro:
            janela = [
                t for t in self._tentativas_por_ip[ip]
                if agora - t < self.janela_segundos
            ]
            self._tentativas_por_ip[ip] = janela
            if len(janela) >= self.limite_tentativas:
                self._bloqueado_ate[ip] = agora + self.tempo_bloqueio
                return False, "Limite excedido — IP bloqueado 45s"

            # CAPTCHA após 3 falhas
            if len(janela) >= 3:
                codigo = self._captcha_por_ip.setdefault(ip, self.gerar_captcha())
                if captcha is None or captcha.strip().upper() != codigo:
                    return False, f"CAPTCHA obrigatório ({codigo})"

        # Verificação de senha
        senha_registrada = self._senhas.get(usuario)
        if senha_registrada is None:
            return False, "Usuário não encontrado"

        if not self.seguro:
            ok = senha == senha_registrada
        else:
            hash_tentativa = _hash_senha(senha, self._salts[usuario])
            ok = secrets.compare_digest(hash_tentativa, senha_registrada)

        # Atualiza contadores
        if ok:
            self._tentativas_por_ip[ip] = []
            if ip in self._captcha_por_ip:
                del self._captcha_por_ip[ip]
            return True, "Login permitido"

        # falha
        if self.seguro:
            self._tentativas_por_ip[ip].append(agora)
        return False, "Senha incorreta"


# ──────────────────────────────────────────────────────────────────────
# Estruturas do simulador
# ──────────────────────────────────────────────────────────────────────

@dataclass
class ResultadoAtaque:
    senha_alvo: str
    espaco_busca: str
    tentativas_inseguro: int
    tempo_inseguro: float  # segundos
    tentativas_seguro: int
    tempo_seguro: float    # segundos
    bloqueios: int


class SimuladorAtaque(QThread):
    progresso = pyqtSignal(int)
    resultado = pyqtSignal(ResultadoAtaque)
    log = pyqtSignal(str)

    def __init__(self):
        super().__init__()
        self.cenarios = [
            ("1234", "10^4 (apenas números)"),
            ("12345678", "10^8 (números)"),
            ("SenhaF0rte!", "62^10 (mistos)")
        ]

    def _estimar(self, senha: str, espaco: int,
                 taxa_basica: int = 1200,
                 taxa_segura: int = 6,
                 limite: int = 6,
                 tempo_bloqueio: int = 45) -> ResultadoAtaque:
        tentativas_medias = espaco // 2
        tempo_inseguro = tentativas_medias / taxa_basica

        blocos = math.ceil(tentativas_medias / limite)
        tempo_seguro = (tentativas_medias / taxa_segura) + ((blocos - 1) * tempo_bloqueio)

        # Corta valores muito grandes para a UI
        if tempo_seguro > 60 * 60 * 24 * 365:
            tempo_seguro = float("inf")
        return ResultadoAtaque(
            senha_alvo=senha,
            espaco_busca=f"{espaco:,}".replace(",", "."),
            tentativas_inseguro=tentativas_medias,
            tempo_inseguro=tempo_inseguro,
            tentativas_seguro=tentativas_medias,
            tempo_seguro=tempo_seguro,
            bloqueios=max(0, blocos - 1),
        )

    def run(self):
        total = len(self.cenarios)
        for idx, (senha, espaco_label) in enumerate(self.cenarios, start=1):
            if len(senha) == 4:
                espaco = 10_000
            elif len(senha) == 8:
                espaco = 100_000_000
            else:
                espaco = 62 ** len(senha)

            self.log.emit(f"Calculando brute force para {senha} (espaço {espaco_label})")
            res = self._estimar(senha, espaco)
            self.resultado.emit(res)
            self.progresso.emit(int(idx / total * 100))
            time.sleep(0.2)


# ──────────────────────────────────────────────────────────────────────
# Componentes visuais
# ──────────────────────────────────────────────────────────────────────

class CardInfo(QFrame):
    def __init__(self, titulo: str, descricao: str, cor: str):
        super().__init__()
        self.setFrameShape(QFrame.Shape.Box)
        self.setStyleSheet(f"""
            QFrame {{
                background-color: #0f1423;
                border: 1px solid {cor};
                border-radius: 8px;
            }}
            QLabel {{
                color: #ecf0f1;
                border: none;
            }}
        """)
        layout = QVBoxLayout(self)
        t = QLabel(titulo)
        t.setStyleSheet(f"color:{cor}; font-weight:bold; font-size:12px;")
        d = QLabel(descricao)
        d.setWordWrap(True)
        d.setStyleSheet("color:#bfc7d5; font-size:11px;")
        layout.addWidget(t)
        layout.addWidget(d)


class PainelLoginSeguro(QWidget):
    """Painel didático completo."""

    def __init__(self):
        super().__init__()
        self.sistema_inseguro = SistemaLogin(seguro=False)
        self.sistema_seguro = SistemaLogin(seguro=True)
        self.sistema_inseguro.registrar_usuario("admin", "123456")
        self.sistema_seguro.registrar_usuario("admin", "SenhaF0rte!")

        self.simulador = SimuladorAtaque()
        self.simulador.progresso.connect(self._atualizar_progresso)
        self.simulador.resultado.connect(self._receber_resultado)
        self.simulador.log.connect(self._log)

        self.resultados: List[ResultadoAtaque] = []

        self._montar_ui()

    # ── UI ────────────────────────────────────────────────────────────
    def _montar_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(10, 10, 10, 10)

        titulo = QLabel("🔐 Laboratório de Login — vulnerável x protegido")
        f = QFont("Arial", 14)
        f.setBold(True)
        titulo.setFont(f)
        titulo.setStyleSheet("color:#ecf0f1;")
        layout.addWidget(titulo)

        cards = QHBoxLayout()
        cards.addWidget(CardInfo("Versão insegura",
                                 "Senha em texto puro, sem limite de tentativas, nenhum bloqueio ou CAPTCHA.",
                                 "#e74c3c"))
        cards.addWidget(CardInfo("Versão segura",
                                 "Hash PBKDF2 (equivalente a bcrypt), rate limiting, bloqueio temporário e CAPTCHA simples.",
                                 "#2ecc71"))
        cards.addWidget(CardInfo("Objetivo",
                                 "Mostrar ao vivo a diferença de resiliência e medir tempo/tentativas em cada cenário.",
                                 "#3498db"))
        layout.addLayout(cards)

        # Seção de login manual
        box_login = QHBoxLayout()
        box_login.addWidget(self._painel_login_unico("Versão vulnerável", False))
        box_login.addWidget(self._painel_login_unico("Versão segura", True))
        layout.addLayout(box_login)

        # Tabela + gráfico + logs
        seção_resultados = QHBoxLayout()
        seção_resultados.addWidget(self._painel_tabela())
        seção_resultados.addWidget(self._painel_grafico())
        layout.addLayout(seção_resultados)

        # Barra inferior
        barra = QHBoxLayout()
        self.btn_simular = QPushButton("Rodar ataque didático")
        self.btn_simular.clicked.connect(self._rodar_simulador)
        self.progresso = QProgressBar()
        self.progresso.setMaximum(100)
        barra.addWidget(self.btn_simular, 2)
        barra.addWidget(self.progresso, 3)
        layout.addLayout(barra)

        self.log = QTextEdit()
        self.log.setReadOnly(True)
        self.log.setMinimumHeight(100)
        self.log.setStyleSheet("background:#0f1423; color:#d0d6e4;")
        layout.addWidget(self.log)

    def _painel_login_unico(self, titulo: str, seguro: bool) -> QGroupBox:
        box = QGroupBox(titulo)
        box.setStyleSheet("""
            QGroupBox { color:#ecf0f1; font-weight:bold; }
            QLabel { color:#bfc7d5; }
        """)
        grid = QGridLayout(box)

        grid.addWidget(QLabel("Usuário"), 0, 0)
        usuario = QLineEdit("admin")
        grid.addWidget(usuario, 0, 1)

        grid.addWidget(QLabel("Senha"), 1, 0)
        senha = QLineEdit("123456" if not seguro else "SenhaF0rte!")
        senha.setEchoMode(QLineEdit.EchoMode.Password)
        grid.addWidget(senha, 1, 1)

        grid.addWidget(QLabel("IP"), 2, 0)
        ip = QLineEdit("192.168.0.50")
        grid.addWidget(ip, 2, 1)

        captcha = None
        if seguro:
            grid.addWidget(QLabel("CAPTCHA (após falhas)"), 3, 0)
            captcha = QLineEdit()
            grid.addWidget(captcha, 3, 1)

        saida = QLabel("Aguardando tentativa...")
        grid.addWidget(saida, 4, 0, 1, 2)

        def tentar():
            alvo = self.sistema_seguro if seguro else self.sistema_inseguro
            ok, msg = alvo.autenticar(
                usuario.text().strip(),
                senha.text(),
                ip.text().strip() or "127.0.0.1",
                captcha.text().strip() if seguro else None
            )
            cor = "#2ecc71" if ok else "#e74c3c"
            saida.setStyleSheet(f"color:{cor}; font-weight:bold;")
            saida.setText(msg)

        btn = QPushButton("Tentar login")
        btn.clicked.connect(tentar)
        grid.addWidget(btn, 5, 0, 1, 2)

        # Exibe armazenamento
        lbl_store = QLabel("Como a senha está guardada:")
        lbl_store.setStyleSheet("color:#95a5a6;")
        grid.addWidget(lbl_store, 6, 0, 1, 2)
        armazenado = QTextEdit()
        armazenado.setReadOnly(True)
        armazenado.setMaximumHeight(70)
        armazenado.setStyleSheet("background:#0f1423; color:#d0d6e4;")
        armazenado.setText(
            self.sistema_seguro.dado_armazenado("admin") if seguro
            else self.sistema_inseguro.dado_armazenado("admin")
        )
        grid.addWidget(armazenado, 7, 0, 1, 2)

        return box

    def _painel_tabela(self) -> QGroupBox:
        box = QGroupBox("Painel de análise")
        box.setStyleSheet("QGroupBox { color:#ecf0f1; font-weight:bold; }")
        layout = QVBoxLayout(box)
        self.tabela = QTableWidget(0, 6)
        self.tabela.setHorizontalHeaderLabels([
            "Senha alvo",
            "Espaço de busca",
            "Tentativas (Vuln.)",
            "Tempo (Vuln.)",
            "Tentativas (Seguro)",
            "Tempo (Seguro)"
        ])
        self.tabela.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        layout.addWidget(self.tabela)
        return box

    def _painel_grafico(self) -> QGroupBox:
        box = QGroupBox("Gráfico: tentativas vs tempo")
        box.setStyleSheet("QGroupBox { color:#ecf0f1; font-weight:bold; }")
        layout = QVBoxLayout(box)
        if PYQTGRAPH_DISPONIVEL:
            pg.setConfigOption("background", "#0f1423")
            pg.setConfigOption("foreground", "#e0e6f3")
            self.plot = pg.PlotWidget()
            self.plot.addLegend()
            self.curva_vuln = self.plot.plot(pen=pg.mkPen("#e74c3c", width=2),
                                             symbol="o", symbolBrush="#e74c3c",
                                             name="Vulnerável")
            self.curva_seg = self.plot.plot(pen=pg.mkPen("#2ecc71", width=2),
                                            symbol="s", symbolBrush="#2ecc71",
                                            name="Seguro")
            self.plot.setLabel("bottom", "Tentativas médias")
            self.plot.setLabel("left", "Tempo (s)")
            layout.addWidget(self.plot)
        else:
            aviso = QLabel("pyqtgraph não encontrado. pip install pyqtgraph")
            aviso.setStyleSheet("color:#e74c3c;")
            layout.addWidget(aviso)
        return box

    # ── Ações ─────────────────────────────────────────────────────────
    def _rodar_simulador(self):
        if self.simulador.isRunning():
            return
        self.resultados.clear()
        self.tabela.setRowCount(0)
        self.log.clear()
        self.progresso.setValue(0)
        self.simulador.start()

    def _atualizar_progresso(self, valor: int):
        self.progresso.setValue(valor)

    def _receber_resultado(self, res: ResultadoAtaque):
        self.resultados.append(res)
        row = self.tabela.rowCount()
        self.tabela.insertRow(row)
        self.tabela.setItem(row, 0, QTableWidgetItem(res.senha_alvo))
        self.tabela.setItem(row, 1, QTableWidgetItem(res.espaco_busca))
        self.tabela.setItem(row, 2, QTableWidgetItem(f"{res.tentativas_inseguro:,}".replace(",", ".")))
        self.tabela.setItem(row, 3, QTableWidgetItem(self._formatar_tempo(res.tempo_inseguro)))
        self.tabela.setItem(row, 4, QTableWidgetItem(f"{res.tentativas_seguro:,}".replace(",", ".")))
        self.tabela.setItem(row, 5, QTableWidgetItem(self._formatar_tempo(res.tempo_seguro, res.bloqueios)))
        self._atualizar_grafico()

    def _atualizar_grafico(self):
        if not PYQTGRAPH_DISPONIVEL or not self.resultados:
            return
        x = [r.tentativas_inseguro for r in self.resultados]
        y_v = [r.tempo_inseguro for r in self.resultados]
        y_s = [r.tempo_seguro if math.isfinite(r.tempo_seguro) else 0 for r in self.resultados]
        self.curva_vuln.setData(x, y_v)
        self.curva_seg.setData(x, y_s)
        if any(not math.isfinite(r.tempo_seguro) for r in self.resultados):
            self.plot.setTitle("Tempo (seguro) marcado como inviável → bloqueios/captcha")

    def _formatar_tempo(self, segundos: float, bloqueios: int = 0) -> str:
        if not math.isfinite(segundos):
            return "inviável"
        if segundos < 1:
            return f"{segundos*1000:.0f} ms"
        if segundos < 60:
            return f"{segundos:.1f} s"
        minutos = segundos / 60
        if minutos < 60:
            return f"{minutos:.1f} min"
        horas = minutos / 60
        if horas < 24:
            return f"{horas:.1f} h"
        dias = horas / 24
        return f"{dias:.1f} dias" + (f" (+{bloqueios} bloqueios)" if bloqueios else "")

    def _log(self, texto: str):
        self.log.append(texto)



