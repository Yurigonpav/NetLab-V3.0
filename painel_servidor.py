# painel_servidor.py
# Versão corrigida - controles proporcionais e layout estável

import threading
import time
import secrets
import hashlib
import re
from collections import defaultdict
from datetime import datetime
from http.server import HTTPServer, BaseHTTPRequestHandler
from socketserver import ThreadingMixIn
from typing import Optional, Callable
from urllib.parse import parse_qs

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel,
    QPushButton, QFrame, QTableWidget,
    QTableWidgetItem, QHeaderView, QSplitter,
    QTextEdit, QCheckBox, QGroupBox, QGridLayout,
    QProgressBar, QRadioButton, QButtonGroup
)
from PyQt6.QtCore import Qt, QTimer, pyqtSignal, QObject
from PyQt6.QtGui import QFont, QColor
from utils.rede import obter_ip_local, formatar_bytes


#  Sinais para comunicação thread-safe 

class SinaisServidor(QObject):
    """Sinais emitidos pelo servidor HTTP para atualizar a UI."""
    requisicao_recebida = pyqtSignal(dict)   # dados de cada requisição
    status_alterado     = pyqtSignal(str)    # mensagem de status
    alerta_emitido      = pyqtSignal(str)    # alerta didático


sinais_servidor = SinaisServidor()


#  Handler HTTP personalizado 

class HandlerLabEducacional(BaseHTTPRequestHandler):
    """
    Handler HTTP que registra todas as requisições recebidas,
    detecta padrões de sobrecarga e serve páginas didáticas.
    """

    # Controle de rate limiting por IP (compartilhado entre todas as instâncias)
    _contagem_por_ip:     dict = defaultdict(int)
    _timestamps_por_ip:   dict = defaultdict(list)
    _ips_bloqueados:      set  = set()
    _ip_bloqueado_ate:    dict = {}          # IP -> timestamp de expiração
    _limite_req_por_seg:  int  = 10           # 0 = sem limite
    _tempo_bloqueio:      int  = 30           # segundos
    _protecao_ativa:      bool = False
    _callback_requisicao: Optional[Callable] = None
    _lock                = threading.Lock()

    # Controle do cenário de login (vulnerável x seguro)
    _modo_login: str = "vulneravel"
    _salt_seguro: bytes = secrets.token_bytes(16)
    _hash_seguro: bytes = hashlib.pbkdf2_hmac(
        "sha256", "SenhaF0rte!".encode("utf-8"), _salt_seguro, 120_000
    )
    _usuarios_vuln: dict = {"admin": "123456"}
    _usuarios_seguro: dict = {"admin": (_salt_seguro, _hash_seguro)}
    _tentativas_login_ip: dict = defaultdict(list)   # ip -> timestamps
    _bloqueio_login_ip: dict = {}
    _captcha_por_ip: dict = {}
    _limite_login: int = 5
    _janela_login: int = 30       # segundos
    _tempo_bloqueio_login: int = 60

    @classmethod
    def configurar_modo(cls, modo: str, ativar_protecao: bool,
                        limite_req: int, tempo_bloqueio: int):
        """Ajusta o modo de login e os limites globais."""
        cls._modo_login = modo
        cls._protecao_ativa = ativar_protecao
        cls._limite_req_por_seg = limite_req
        cls._tempo_bloqueio = tempo_bloqueio
        # reset de estado de segurança
        cls._contagem_por_ip.clear()
        cls._timestamps_por_ip.clear()
        cls._ips_bloqueados.clear()
        cls._ip_bloqueado_ate.clear()
        cls._tentativas_login_ip.clear()
        cls._bloqueio_login_ip.clear()
        cls._captcha_por_ip.clear()

    #  Páginas HTML servidas pelo servidor 

    PAGINA_INICIAL = """<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>NetLab — Servidor de Laboratório</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        body {
            font-family: 'Segoe UI', Roboto, system-ui, sans-serif;
            background: linear-gradient(145deg, #0a0f1e 0%, #0f1423 100%);
            color: #e0e4f0;
            min-height: 100vh;
            display: flex;
            flex-direction: column;
            align-items: center;
            padding: 1.5rem;
        }
        h1 {
            font-size: clamp(1.8rem, 6vw, 2.5rem);
            color: #5a9eff;
            margin-bottom: 0.25rem;
            letter-spacing: -0.02em;
            font-weight: 600;
        }
        .subtitle {
            color: #7f8fa3;
            font-size: clamp(0.9rem, 4vw, 1rem);
            margin-bottom: 2rem;
            text-align: center;
        }
        .nav {
            display: flex;
            flex-wrap: wrap;
            justify-content: center;
            gap: 0.75rem;
            margin-bottom: 2.5rem;
            width: 100%;
            max-width: 600px;
        }
        .nav a {
            color: #cbd5e6;
            text-decoration: none;
            padding: 0.6rem 1.2rem;
            background: rgba(18, 26, 40, 0.8);
            backdrop-filter: blur(4px);
            border: 1px solid #1e3a5f;
            border-radius: 40px;
            font-size: 0.95rem;
            font-weight: 500;
            transition: all 0.2s ease;
            box-shadow: 0 4px 8px rgba(0, 0, 0, 0.3);
            flex: 0 1 auto;
        }
        .nav a:hover {
            background: #1e3a5f;
            color: white;
            border-color: #3b6ea0;
            transform: translateY(-2px);
        }
        .card {
            background: rgba(18, 26, 40, 0.9);
            backdrop-filter: blur(8px);
            border: 1px solid #2a4a70;
            border-radius: 28px;
            padding: 2rem 1.8rem;
            width: 100%;
            max-width: 600px;
            box-shadow: 0 20px 40px -10px rgba(0, 0, 0, 0.7);
            transition: transform 0.2s;
        }
        .card h2 {
            font-size: 1.8rem;
            color: #3fe0a0;
            margin-bottom: 1rem;
            font-weight: 500;
            display: flex;
            align-items: center;
            gap: 0.5rem;
        }
        .card p {
            line-height: 1.6;
            margin-bottom: 1.2rem;
            color: #b0c2d9;
        }
        .aviso {
            background: #2c1a1a;
            border-left: 6px solid #e55;
            border-radius: 16px;
            padding: 1.2rem;
            margin: 1.5rem 0 1rem;
            color: #ffb8b8;
            font-size: 0.95rem;
            box-shadow: inset 0 0 10px rgba(200, 50, 50, 0.3);
        }
        .aviso strong {
            color: #ff7b7b;
            font-weight: 600;
        }
        .info-footer {
            color: #6f7e95;
            font-size: 0.85rem;
            text-align: center;
            margin-top: 1rem;
            border-top: 1px solid #1e3a5f;
            padding-top: 1.2rem;
        }
        /* Para telas pequenas */
        @media (max-width: 480px) {
            body { padding: 1rem; }
            .card { padding: 1.5rem; }
            .nav a { padding: 0.5rem 1rem; font-size: 0.85rem; }
        }
    </style>
</head>
<body>
    <h1> NetLab</h1>
    <div class="subtitle">Servidor educacional HTTP</div>

    <div class="nav">
        <a href="/">Início</a>
        <a href="/login">Login</a>
        <a href="/formulario">Formulário</a>
    </div>

    <div class="card">
        <h2> Servidor ativo</h2>
        <p>Este ambiente simula um servidor web real para fins didáticos. Todas as requisições são monitoradas em tempo real no painel do NetLab.</p>
        <p>Utilize os links acima para gerar tráfego HTTP e visualize os dados sendo capturados.</p>
        <div class="info-footer">
            Acesse de outros dispositivos usando o IP exibido no painel do NetLab.
        </div>
    </div>
</body>
</html>"""

    PAGINA_FORMULARIO = """<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Formulário — NetLab</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        body {
            font-family: 'Segoe UI', Roboto, sans-serif;
            background: linear-gradient(145deg, #0a0f1e 0%, #0f1423 100%);
            color: #e0e4f0;
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 1.5rem;
        }
        .card {
            background: rgba(18, 26, 40, 0.95);
            backdrop-filter: blur(8px);
            border: 1px solid #3b6ea0;
            border-radius: 36px;
            padding: 2.5rem 2rem;
            width: 100%;
            max-width: 520px;
            box-shadow: 0 30px 50px -15px #0a1a2a;
        }
        h2 {
            color: #6ab0ff;
            font-size: 2rem;
            font-weight: 500;
            margin-bottom: 1.5rem;
            text-align: center;
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 0.5rem;
        }
        .aviso {
            background: #1a2a3a;
            border: 1px solid #e77;
            border-radius: 40px;
            padding: 1rem;
            color: #ffbcbc;
            font-size: 0.9rem;
            text-align: center;
            margin-bottom: 2rem;
        }
        form {
            display: flex;
            flex-direction: column;
            gap: 1.2rem;
        }
        label {
            color: #a0b8d0;
            font-size: 0.85rem;
            font-weight: 600;
            margin-left: 0.5rem;
            margin-bottom: -0.5rem;
        }
        input {
            width: 100%;
            padding: 1rem 1.2rem;
            background: #0d1a2a;
            border: 1px solid #2a4a70;
            border-radius: 40px;
            color: #ecf0f1;
            font-size: 1rem;
            outline: none;
            transition: border 0.2s;
        }
        input:focus {
            border-color: #6ab0ff;
        }
        button {
            background: #2563EB;
            color: white;
            border: none;
            border-radius: 40px;
            padding: 1rem;
            font-size: 1.2rem;
            font-weight: 600;
            cursor: pointer;
            transition: background 0.2s, transform 0.1s;
            margin-top: 0.8rem;
        }
        button:hover {
            background: #3b82f6;
            transform: scale(1.02);
        }
        .voltar {
            display: block;
            text-align: center;
            margin-top: 1.8rem;
            color: #7f9fcf;
            text-decoration: none;
            font-size: 0.95rem;
        }
        .voltar:hover {
            color: #9bc0ff;
            text-decoration: underline;
        }
    </style>
</head>
<body>
    <div class="card">
        <h2> Formulário</h2>
        <form method="POST" action="/formulario">
            <label>Nome completo</label>
            <input type="text"     name="nome"     placeholder="Nome">
            <label>Telefone</label>
            <input type="text"     name="telefone" placeholder="(00) 00000-0000">
            <label>Senha</label>
            <input type="password" name="senha"    placeholder="Sua senha">
            <button type="submit">Enviar</button>
        </form>
        <a class="voltar" href="/">← Voltar ao início</a>
    </div>
</body>
</html>"""

    #  Métodos do handler 

    def do_GET(self):
        """Serve páginas GET e registra a requisição."""
        ts_inicio = time.time()
        ip_cliente = self.client_address[0]

        permitido, ttl, reqs_atual = self._verificar_limite(ip_cliente)
        if not permitido:
            self._servir_bloqueado(ttl)
            self._registrar(ip_cliente, "GET", self.path, 0, ts_inicio,
                            bloqueado=True, reqs_por_seg=reqs_atual)
            return

        if self.path == "/":
            corpo = self.PAGINA_INICIAL.encode("utf-8")
        elif self.path.startswith("/login"):
            seguro = (self.__class__._modo_login == "seguro")
            captcha = ""
            if seguro:
                captcha = self._gerar_captcha(ip_cliente)
            corpo = self._html_login(seguro, captcha, ip_cliente).encode("utf-8")
        elif self.path.startswith("/signup"):
            seguro = (self.__class__._modo_login == "seguro")
            corpo = self._html_signup(seguro).encode("utf-8")
        elif self.path == "/formulario":
            corpo = self.PAGINA_FORMULARIO.encode("utf-8")
        else:
            corpo = b"<h1>404 - Pagina nao encontrada</h1>"
            self.send_response(404)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(corpo)))
            self.end_headers()
            self.wfile.write(corpo)
            self._registrar(ip_cliente, "GET", self.path, len(corpo), ts_inicio)
            return

        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(corpo)))
        self.end_headers()
        self.wfile.write(corpo)
        self._registrar(ip_cliente, "GET", self.path, len(corpo), ts_inicio)

    def do_POST(self):
        """Processa POST, registra os dados enviados."""
        ts_inicio   = time.time()
        ip_cliente  = self.client_address[0]
        permitido, ttl, reqs_atual = self._verificar_limite(ip_cliente)
        if not permitido:
            self._servir_bloqueado(ttl)
            self._registrar(ip_cliente, "POST", self.path, 0, ts_inicio,
                            bloqueado=True, reqs_por_seg=reqs_atual)
            return

        tamanho     = int(self.headers.get("Content-Length", 0))
        corpo_bytes = self.rfile.read(tamanho)

        if self.path.startswith("/login"):
            status, corpo_resposta, bloqueado = self._processar_login(
                corpo_bytes, ip_cliente
            )
            self.send_response(status)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(corpo_resposta)))
            self.end_headers()
            self.wfile.write(corpo_resposta)
            self._registrar(
                ip_cliente, "POST", self.path, tamanho, ts_inicio,
                corpo=corpo_bytes.decode("utf-8", errors="replace"),
                bloqueado=bloqueado
            )
            return
        if self.path.startswith("/signup"):
            status, corpo_resposta, bloqueado = self._processar_signup(
                corpo_bytes, ip_cliente
            )
            self.send_response(status)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(corpo_resposta)))
            self.end_headers()
            self.wfile.write(corpo_resposta)
            self._registrar(
                ip_cliente, "POST", self.path, tamanho, ts_inicio,
                corpo=corpo_bytes.decode("utf-8", errors="replace"),
                bloqueado=bloqueado
            )
            return
        if self.path == "/formulario":
            resposta = (
                f"<html><body style='background:#0f1423;color:#ecf0f1;"
                f"font-family:Arial;padding:40px;'>"
                f"<h2 style='color:#2ECC71;'>Dados recebidos pelo servidor!</h2>"
                f"<p>O NetLab capturou este envio em tempo real.</p>"
                f"<p style='color:#E74C3C;'>⚠️ Estes dados foram transmitidos "
                f"via HTTP — visíveis para qualquer capturador na rede.</p>"
                f"<a href='/' style='color:#3498DB;'>← Voltar</a>"
                f"</body></html>"
            ).encode("utf-8")

            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(resposta)))
            self.end_headers()
            self.wfile.write(resposta)
            self._registrar(
                ip_cliente, "POST", self.path, tamanho, ts_inicio,
                corpo=corpo_bytes.decode("utf-8", errors="replace")
            )
            return

        corpo = b"<h1>404 - Pagina nao encontrada</h1>"
        self.send_response(404)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(corpo)))
        self.end_headers()
        self.wfile.write(corpo)
        self._registrar(
            ip_cliente, "POST", self.path, len(corpo), ts_inicio,
            corpo=corpo_bytes.decode("utf-8", errors="replace")
        )

    #  Login helpers 
    def _gerar_captcha(self, ip: str) -> str:
        codigo = "".join(secrets.choice("ABCDEFGHJKLMNPQRSTUVWXYZ23456789") for _ in range(4))
        self.__class__._captcha_por_ip[ip] = codigo
        return codigo

    def _html_login(self, seguro: bool, captcha: str, ip: str) -> str:
        badge = " Versão vulnerável — sem limites" if not seguro else " Versão segura — hash + rate limit + CAPTCHA"
        extra = ""
        captcha_input = ""
        if seguro:
            extra = (
                "<li>Hash PBKDF2 + salt</li>"
                "<li>Rate limit 5 tentativas a cada 30s</li>"
                "<li>Bloqueio de 60s após estouro</li>"
                "<li>CAPTCHA obrigatório após 3 falhas</li>"
            )
            captcha_input = (
                f"<label>CAPTCHA (código {captcha})</label>"
                f"<input type='text' name='captcha' placeholder='Digite {captcha}' required>"
            )
        else:
            extra = "<li>Senha em texto puro, sem bloqueio</li>"

        return f"""
<!DOCTYPE html>
<html lang="pt-BR">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Login — NetLab</title>
  <style>
    body {{
      font-family: 'Segoe UI', Roboto, system-ui, sans-serif;
      background: linear-gradient(145deg, #0a0f1e 0%, #0f1423 100%);
      color: #e0e4f0; display:flex; justify-content:center; align-items:center;
      min-height: 100vh; padding: 16px;
    }}
    .card {{
      background: rgba(18,26,40,0.95); border:1px solid #1e3a5f; border-radius: 28px;
      padding: 28px 24px; max-width: 440px; width: 100%; box-shadow:0 20px 40px -10px rgba(0,0,0,.7);
    }}
    h1 {{ margin:0 0 8px; color:#5a9eff; font-size:24px; }}
    .badge {{ margin-bottom:12px; color:{'#e74c3c' if not seguro else '#2ecc71'}; font-weight:600; }}
    form {{ display:flex; flex-direction:column; gap:10px; margin-top:12px; }}
    input {{ padding:10px 12px; border-radius:10px; border:1px solid #2a4a70; background:#0f1423; color:#e0e4f0; }}
    button {{ padding:12px; border:none; border-radius:12px; background:{'#e74c3c' if not seguro else '#2ecc71'}; color:#0f1423; font-weight:700; cursor:pointer; }}
    ul {{ color:#9fb2c8; font-size:13px; line-height:1.5; margin:8px 0 0 16px; }}
    .ip {{ color:#7f8fa3; font-size:12px; margin-top:8px; }}
  </style>
</head>
<body>
  <div class="card">
    <h1>Login educacional</h1>
    <div class="badge">{badge}</div>
    <ul>{extra}</ul>
    <form method="POST" action="/login">
      <input type="text" name="usuario" placeholder="Usuário" required>
      <input type="password" name="senha" placeholder="Senha (numérica)">
      {captcha_input}
      <button type="submit">Entrar</button>
    </form>
    <div class="ip">Seu IP visto pelo servidor: {ip}</div>
    <div style="margin-top:12px;"><a style="color:#3498DB;" href="/signup">Criar conta</a></div>
  </div>
</body>
</html>
"""

    def _processar_login(self, corpo_bytes: bytes, ip: str):
        dados = parse_qs(corpo_bytes.decode("utf-8", errors="ignore"))
        usuario = dados.get("usuario", [""])[0]
        senha = dados.get("senha", [""])[0]
        captcha = dados.get("captcha", [""])[0]

        cls = self.__class__
        modo = cls._modo_login

        # Cenário vulnerável: sem limites
        if modo == "vulneravel":
            senha_salva = cls._usuarios_vuln.get(usuario, "")
            ok = senha.isdigit() and senha == senha_salva
            corpo = self._html_resposta_login(ok, vulneravel=True)
            return (200 if ok else 401, corpo, False)

        # Cenário seguro
        agora = time.time()
        # Bloqueio ativo?
        if ip in cls._bloqueio_login_ip and agora < cls._bloqueio_login_ip[ip]:
            restante = int(cls._bloqueio_login_ip[ip] - agora)
            corpo = self._html_resposta_login(False, mensagem=f"IP bloqueado por {restante}s")
            return 429, corpo, True

        # Janela de tentativas
        janela = [t for t in cls._tentativas_login_ip[ip] if agora - t < cls._janela_login]
        cls._tentativas_login_ip[ip] = janela
        if len(janela) >= cls._limite_login:
            cls._bloqueio_login_ip[ip] = agora + cls._tempo_bloqueio_login
            corpo = self._html_resposta_login(False, mensagem="Limite excedido — bloqueio temporário")
            return 429, corpo, True

        # CAPTCHA após 3 falhas
        if len(janela) >= 3:
            esperado = cls._captcha_por_ip.get(ip, "")
            if not captcha or captcha.strip().upper() != esperado:
                corpo = self._html_resposta_login(False, mensagem="CAPTCHA inválido ou ausente")
                cls._tentativas_login_ip[ip].append(agora)
                return 401, corpo, False

        # Validação de senha
        info = cls._usuarios_seguro.get(usuario)
        ok = False
        if info and senha.isdigit():
            salt, hash_salvo = info
            hash_tentativa = hashlib.pbkdf2_hmac("sha256", senha.encode("utf-8"), salt, 120_000)
            ok = secrets.compare_digest(hash_tentativa, hash_salvo)

        if ok:
            cls._tentativas_login_ip[ip] = []
            cls._captcha_por_ip.pop(ip, None)
            corpo = self._html_resposta_login(True, mensagem="Login permitido (modo seguro)")
            return 200, corpo, False

        # Falha
        cls._tentativas_login_ip[ip].append(agora)
        corpo = self._html_resposta_login(False, mensagem="Credenciais inválidas")
        return 401, corpo, False

    def _processar_signup(self, corpo_bytes: bytes, ip: str):
        cls = self.__class__
        dados = parse_qs(corpo_bytes.decode("utf-8", errors="ignore"))
        nome = dados.get("usuario", [""])[0].strip()
        senha = dados.get("senha", [""])[0].strip()

        if not re.fullmatch(r"[A-Za-zÀ-ÿ ]+", nome):
            corpo = self._html_resposta_login(False, mensagem="Nome deve conter apenas letras e espaços.")
            return 400, corpo, False
        if not senha.isdigit():
            corpo = self._html_resposta_login(False, mensagem="Senha deve conter apenas números.")
            return 400, corpo, False

        if cls._modo_login == "vulneravel":
            if nome in cls._usuarios_vuln:
                corpo = self._html_resposta_login(False, vulneravel=True, mensagem="Usuário já existe.")
                return 409, corpo, False
            cls._usuarios_vuln[nome] = senha
        else:
            if nome in cls._usuarios_seguro:
                corpo = self._html_resposta_login(False, mensagem="Usuário já existe.")
                return 409, corpo, False
            salt = secrets.token_bytes(16)
            hash_ = hashlib.pbkdf2_hmac("sha256", senha.encode("utf-8"), salt, 120_000)
            cls._usuarios_seguro[nome] = (salt, hash_)

        corpo = self._html_resposta_login(True, mensagem=f"Conta '{nome}' criada. Faça login em /login.")
        return 201, corpo, False

    def _html_resposta_login(self, sucesso: bool, vulneravel: bool = False, mensagem: str = "") -> bytes:
        cor = "#2ecc71" if sucesso else "#e74c3c"
        titulo = "Login permitido" if sucesso else "Acesso negado"
        detalhe = mensagem or ("Sem proteção — ataque deve passar facilmente" if vulneravel else "Proteções ativas — tente novamente com cautela")
        html = f"""
        <html><body style='background:#0f1423;color:#ecf0f1;font-family:Arial;padding:32px;'>
        <h2 style='color:{cor};'>{titulo}</h2>
        <p>{detalhe}</p>
        <a href='/login' style='color:#3498DB;'>← Voltar</a> · <a href='/signup' style='color:#3498DB;'>Criar conta</a>
        </body></html>
        """
        return html.encode("utf-8")

    def _html_signup(self, seguro: bool) -> str:
        badge = " Cadastro vulnerável — senha em texto" if not seguro else " Cadastro seguro — hash + salt"
        return f"""
<!DOCTYPE html>
<html lang="pt-BR">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Criar conta — NetLab</title>
  <style>
    body {{
      font-family: 'Segoe UI', Roboto, system-ui, sans-serif;
      background: linear-gradient(145deg, #0a0f1e 0%, #0f1423 100%);
      color: #e0e4f0; display:flex; justify-content:center; align-items:center;
      min-height: 100vh; padding: 16px;
    }}
    .card {{
      background: rgba(18,26,40,0.95); border:1px solid #1e3a5f; border-radius: 28px;
      padding: 28px 24px; max-width: 440px; width: 100%; box-shadow:0 20px 40px -10px rgba(0,0,0,.7);
    }}
    h1 {{ margin:0 0 8px; color:#5a9eff; font-size:24px; }}
    .badge {{ margin-bottom:12px; color:{'#e74c3c' if not seguro else '#2ecc71'}; font-weight:600; }}
    form {{ display:flex; flex-direction:column; gap:10px; margin-top:12px; }}
    input {{ padding:10px 12px; border-radius:10px; border:1px solid #2a4a70; background:#0f1423; color:#e0e4f0; }}
    button {{ padding:12px; border:none; border-radius:12px; background:{'#e74c3c' if not seguro else '#2ecc71'}; color:#0f1423; font-weight:700; cursor:pointer; }}
    .tip {{ color:#9fb2c8; font-size:12px; margin-top:4px; }}
  </style>
</head>
<body>
  <div class="card">
    <h1>Criar conta</h1>
    <div class="badge">{badge}</div>
    <form method="POST" action="/signup">
      <input type="text" name="usuario" placeholder="Nome (letras e espaço)" pattern="[A-Za-zÀ-ÿ ]+" required>
      <input type="password" name="senha" placeholder="Senha numérica" pattern="\\d+" required>
      <div class="tip">Nome: apenas letras e espaço. Senha: apenas números.</div>
      <button type="submit">Criar</button>
    </form>
    <div style="margin-top:12px;"><a style="color:#3498DB;" href="/login">Voltar ao login</a></div>
  </div>
</body>
</html>
"""

    def _servir_bloqueado(self, ttl_bloqueio: Optional[int] = None):
        if ttl_bloqueio is None or ttl_bloqueio <= 0:
            ttl_bloqueio = self.__class__._tempo_bloqueio
        corpo = (
            b"<html><body style='background:#0f1423;color:#E74C3C;"
            b"font-family:Arial;padding:40px;text-align:center;'>"
            b"<h2> Acesso Bloqueado</h2>"
            b"<p>Seu IP foi temporariamente bloqueado por excesso de requisicoes.</p>"
            b"<p style='color:#7f8c8d;'>Esta e uma demonstracao educacional de "
            b"protecao contra DoS.</p>"
            b"</body></html>"
        )
        self.send_response(429)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(corpo)))
        self.send_header("Retry-After", str(ttl_bloqueio))
        self.end_headers()
        self.wfile.write(corpo)

    def _registrar(self, ip: str, metodo: str, path: str,
                   tamanho: int, ts_inicio: float,
                   corpo: str = "", bloqueado: bool = False,
                   reqs_por_seg: Optional[int] = None):
        """Registra a requisição."""
        tempo_resposta_ms = int((time.time() - ts_inicio) * 1000)
        agora = time.time()

        cls = self.__class__
        if reqs_por_seg is None:
            reqs_por_seg = len([
                t for t in cls._timestamps_por_ip[ip]
                if agora - t < 1.0
            ])

        # Detectar padrão de sobrecarga
        cls._contagem_por_ip[ip] += 1
        if reqs_por_seg >= 10:
            sinais_servidor.alerta_emitido.emit(
                f"️ ALERTA: {ip} enviou {reqs_por_seg} requisições/segundo! "
                f"Possível teste de carga ou ataque DoS."
            )

        dados = {
            "timestamp":        datetime.now().strftime("%H:%M:%S"),
            "ip_cliente":       ip,
            "metodo":           metodo,
            "endpoint":         path,
            "tamanho":          tamanho,
            "user_agent":       self.headers.get("User-Agent", "—")[:50],
            "tempo_ms":         tempo_resposta_ms,
            "reqs_por_seg":     reqs_por_seg,
            "bloqueado":        bloqueado,
            "corpo":            corpo[:500] if corpo else "",
        }
        sinais_servidor.requisicao_recebida.emit(dados)

    def log_message(self, formato, *args):
        """Suprimir saída padrão do HTTPServer no console."""
        pass

    def _verificar_limite(self, ip: str):
        """
        Aplica rate limit e bloqueio antes de processar a requisição.
        Retorna (permitido, ttl_bloqueio, reqs_atual).
        """
        cls = self.__class__
        if not cls._protecao_ativa or cls._limite_req_por_seg <= 0:
            return True, 0, 0

        agora = time.time()
        with cls._lock:
            # Bloqueio ativo?
            expira = cls._ip_bloqueado_ate.get(ip, 0)
            if expira and expira > agora:
                return False, int(expira - agora), len(cls._timestamps_por_ip[ip])
            if expira and expira <= agora:
                cls._ips_bloqueados.discard(ip)
                cls._ip_bloqueado_ate.pop(ip, None)

            # Janela deslizante de 1s
            cls._timestamps_por_ip[ip] = [
                t for t in cls._timestamps_por_ip[ip]
                if agora - t < 1.0
            ]
            cls._timestamps_por_ip[ip].append(agora)
            reqs_por_seg = len(cls._timestamps_por_ip[ip])

            if reqs_por_seg > cls._limite_req_por_seg:
                cls._ips_bloqueados.add(ip)
                cls._ip_bloqueado_ate[ip] = agora + cls._tempo_bloqueio
                sinais_servidor.alerta_emitido.emit(
                    f" IP {ip} bloqueado por {cls._tempo_bloqueio}s após "
                    f"{reqs_por_seg} req/s (limite: {cls._limite_req_por_seg} req/s)"
                )
                return False, cls._tempo_bloqueio, reqs_por_seg

        return True, 0, reqs_por_seg


#  Thread do servidor HTTP 

class ThreadingHTTPServer(ThreadingMixIn, HTTPServer):
    daemon_threads = True
    # reduz a fila de conexões pendentes; evita enfileirar ataques longos
    request_queue_size = 64

    def handle_error(self, request, client_address):
        """
        Silencia erros esperados quando o cliente fecha a conexão abruptamente
        (BrokenPipe/ConnectionReset/ConnectionAborted), comuns em testes de carga.
        Outros erros continuam sendo tratados pelo comportamento padrão.
        """
        import sys
        exc_type, _, _ = sys.exc_info()
        if exc_type and issubclass(exc_type, (BrokenPipeError, ConnectionResetError, ConnectionAbortedError)):
            return
        return super().handle_error(request, client_address)


class ThreadServidor(threading.Thread):
    """Thread dedicada ao servidor HTTP — não bloqueia a UI Qt."""

    def __init__(self, porta: int):
        super().__init__(daemon=True)
        self.porta   = porta
        self._server: Optional[HTTPServer] = None

    def run(self):
        try:
            self._server = ThreadingHTTPServer(("0.0.0.0", self.porta), HandlerLabEducacional)
            sinais_servidor.status_alterado.emit(f" Servidor iniciado na porta {self.porta}")
            self._server.serve_forever()
        except Exception as e:
            sinais_servidor.status_alterado.emit(f" Erro ao iniciar servidor: {e}")

    def parar(self):
        if self._server:
            # Chama shutdown em uma thread separada para não bloquear a UI
            threading.Thread(target=self._server.shutdown, daemon=True).start()


#  Painel principal da aba 

class PainelServidor(QWidget):
    """
    Aba 'Servidor de Laboratório' do NetLab Educacional.

    Permite ao professor:
    - Iniciar e parar um servidor HTTP de teste
    - Monitorar requisições em tempo real
    - Ativar proteção contra DoS para demonstração didática
    - Visualizar alertas de comportamento anômalo
    """

    # Sinal emitido para a janela principal quando um cliente acessa o servidor
    cliente_detectado = pyqtSignal(str)   # IP do cliente

    def __init__(self, parent=None):
        super().__init__(parent)
        self._thread_servidor: Optional[ThreadServidor] = None
        self._servidor_ativo  = False
        self._total_requisicoes = 0
        self._total_bytes       = 0
        self._reqs_por_segundo  = 0
        self._contador_segundo  = 0
        self._clientes_unicos   = set()

        # Valores atuais dos controles
        self._porta_atual = 8080  # 80 requer privilégio elevado no Windows (WinError 10013)
        self._limite_atual = 10
        self._tempo_atual = 30
        self._modo_login = "vulneravel"

        # Timer para atualizar métricas por segundo
        self._timer_metricas = QTimer()
        self._timer_metricas.timeout.connect(self._atualizar_metricas_por_segundo)

        # Conectar sinais do servidor
        sinais_servidor.requisicao_recebida.connect(self._ao_receber_requisicao)
        sinais_servidor.status_alterado.connect(self._ao_mudar_status)
        sinais_servidor.alerta_emitido.connect(self._ao_emitir_alerta)

        self._montar_layout()

    #  Construção da interface 

    def _montar_layout(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(4, 2, 4, 4)
        layout.setSpacing(4)

        # Splitter: controles (esquerda) | log (direita)
        splitter = QSplitter(Qt.Orientation.Horizontal)
        layout.addWidget(splitter)

        splitter.addWidget(self._criar_painel_controles())
        splitter.addWidget(self._criar_painel_requisicoes())
        splitter.setSizes([380, 700])

        # Sincroniza o modo inicial
        self._ao_mudar_modo_login(self._modo_login)

    def _criar_painel_controles(self) -> QWidget:
        """Painel esquerdo: controles, status, métricas e proteção."""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(0, 0, 8, 0)
        layout.setSpacing(8)

        #  Grupo: Configuração do Servidor 
        grp_config = self._criar_grupo_configuracao()
        layout.addWidget(grp_config)

        #  Grupo: Status e Endereço 
        grp_status = self._criar_grupo_status()
        layout.addWidget(grp_status)

        #  Grupo: Modo de Login 
        grp_modo = self._criar_grupo_modo_login()
        layout.addWidget(grp_modo)

        #  Grupo: Métricas em Tempo Real 
        grp_metricas = self._criar_grupo_metricas()
        layout.addWidget(grp_metricas)

        layout.addStretch()

        return widget

    def _criar_grupo_configuracao(self) -> QGroupBox:
        """Cria o grupo de configuração do servidor."""
        grp = QGroupBox("️ Configuração")
        grp.setStyleSheet(
            "QGroupBox { border: 1px solid #1e3a5f; border-radius: 6px; "
            "margin-top: 8px; font-weight: bold; color: #bdc3c7; }"
            "QGroupBox::title { subcontrol-origin: margin; padding: 0 6px; }"
        )
        layout = QGridLayout(grp)

        # Label da porta
        lbl_porta = QLabel("Porta:")
        lbl_porta.setStyleSheet("color: #ecf0f1; font-size: 11px;")
        layout.addWidget(lbl_porta, 0, 0)

        # Container do controle de porta (horizontal compacto)
        container = QWidget()
        container.setFixedHeight(30)
        hbox = QHBoxLayout(container)
        hbox.setContentsMargins(0, 0, 0, 0)
        hbox.setSpacing(2)

        # Botão diminuir
        btn_menos = self._criar_botao_controle("−", "#3498db", 18, 18)
        btn_menos.clicked.connect(lambda: self._ajustar_valor('porta', -1))
        hbox.addWidget(btn_menos)

        # Label do valor
        self.lbl_porta = QLabel(str(self._porta_atual))
        self.lbl_porta.setFixedSize(50, 25)
        self.lbl_porta.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.lbl_porta.setStyleSheet("""
            QLabel {
                background: #0d1a2a;
                color: #ecf0f1;
                border: 1px solid #3498db;
                border-radius: 4px;
                font-size: 12px;
                font-weight: bold;
            }
        """)
        hbox.addWidget(self.lbl_porta)

        # Botão aumentar
        btn_mais = self._criar_botao_controle("+", "#3498db", 18, 18)
        btn_mais.clicked.connect(lambda: self._ajustar_valor('porta', 1))
        hbox.addWidget(btn_mais)

        layout.addWidget(container, 0, 1)

        # Botão iniciar/parar
        self.btn_iniciar = QPushButton("  Iniciar Servidor")
        self.btn_iniciar.setObjectName("botao_captura")
        self.btn_iniciar.setMinimumHeight(32)
        self.btn_iniciar.clicked.connect(self._alternar_servidor)
        layout.addWidget(self.btn_iniciar, 1, 0, 1, 2)

        return grp

    def _criar_grupo_status(self) -> QGroupBox:
        """Cria o grupo de status do servidor."""
        grp = QGroupBox(" Status do Servidor")
        grp.setStyleSheet(
            "QGroupBox { border: 1px solid #1e3a5f; border-radius: 6px; "
            "margin-top: 2px; font-weight: bold; color: #bdc3c7; }"
            "QGroupBox::title { subcontrol-origin: margin; padding: 0 3px; }"
        )
        layout = QVBoxLayout(grp)

        self.lbl_status = QLabel("️  Servidor parado")
        self.lbl_status.setStyleSheet("color: #E74C3C; font-weight: bold; font-size: 11px;")
        layout.addWidget(self.lbl_status)

        # Usar QTextEdit com altura fixa para evitar expansão
        self.lbl_endereco = QTextEdit()
        self.lbl_endereco.setReadOnly(True)
        self.lbl_endereco.setMaximumHeight(50)
        self.lbl_endereco.setStyleSheet(
            "color: #3498DB; font-family: Consolas; font-size: 11px; "
            "background: #0d1a2a; border: 1px solid #1e3a5f; border-radius: 4px; "
            "padding: 6px;"
        )
        self.lbl_endereco.setText("—")
        layout.addWidget(self.lbl_endereco)

        self.lbl_instrucao = QLabel(
            "Após iniciar, acesse o endereço acima\n"
            "de qualquer dispositivo na mesma rede Wi-Fi."
        )
        self.lbl_instrucao.setStyleSheet("color: #7f8c8d; font-size: 10px;")
        self.lbl_instrucao.setWordWrap(True)
        layout.addWidget(self.lbl_instrucao)

        return grp

    def _criar_grupo_modo_login(self) -> QGroupBox:
        grp = QGroupBox(" Cenário de Login para Pentest Externo")
        grp.setStyleSheet(
            "QGroupBox { border: 1px solid #1e3a5f; border-radius: 6px; "
            "margin-top: 2px; font-weight: bold; color: #bdc3c7; }"
            "QGroupBox::title { subcontrol-origin: margin; padding: 0 3px; }"
        )
        layout = QVBoxLayout(grp)
        layout.setSpacing(6)

        self.grp_radios = QButtonGroup(grp)
        self.rad_vuln = QRadioButton(" Versão vulnerável — senha em texto, sem limites")
        self.rad_seg = QRadioButton(" Versão segura — hash + rate limit + bloqueio + CAPTCHA")
        self.rad_vuln.setChecked(True)
        self.grp_radios.addButton(self.rad_vuln)
        self.grp_radios.addButton(self.rad_seg)
        self.rad_vuln.toggled.connect(lambda checked: checked and self._ao_mudar_modo_login("vulneravel"))
        self.rad_seg.toggled.connect(lambda checked: checked and self._ao_mudar_modo_login("seguro"))

        desc = QLabel("Use este endereço no Hydra ou outra ferramenta: http://<IP>:<porta>/login")
        desc.setStyleSheet("color:#7f8c8d; font-size:10px;")

        layout.addWidget(self.rad_vuln)
        layout.addWidget(self.rad_seg)
        layout.addWidget(desc)
        return grp

    def _criar_grupo_metricas(self) -> QGroupBox:
        """Cria o grupo de métricas em tempo real."""
        grp = QGroupBox(" Métricas em Tempo Real")
        grp.setStyleSheet(
            "QGroupBox { border: 1px solid #1e3a5f; border-radius: 6px; "
            "margin-top: 8px; font-weight: bold; color: #bdc3c7; }"
            "QGroupBox::title { subcontrol-origin: margin; padding: 0 6px; }"
        )
        layout = QGridLayout(grp)

        def _card_metrica(rotulo: str, valor: str, cor: str) -> tuple:
            lbl_r = QLabel(rotulo)
            lbl_r.setStyleSheet(f"color: {cor}; font-size: 9px; font-weight: bold;")
            lbl_v = QLabel(valor)
            lbl_v.setStyleSheet(f"color: #ecf0f1; font-size: 16px; font-weight: bold;")
            lbl_v.setAlignment(Qt.AlignmentFlag.AlignCenter)
            lbl_r.setAlignment(Qt.AlignmentFlag.AlignCenter)
            return lbl_r, lbl_v

        lbl_r1, self.lbl_total_reqs = _card_metrica("TOTAL REQS", "0", "#3498DB")
        lbl_r2, self.lbl_reqs_seg = _card_metrica("REQS/SEG", "0", "#E74C3C")
        lbl_r3, self.lbl_total_bytes = _card_metrica("DADOS", "0 B", "#2ECC71")
        lbl_r4, self.lbl_clientes = _card_metrica("CLIENTES", "0", "#9B59B6")

        for col, (lr, lv) in enumerate([
            (lbl_r1, self.lbl_total_reqs),
            (lbl_r2, self.lbl_reqs_seg),
            (lbl_r3, self.lbl_total_bytes),
            (lbl_r4, self.lbl_clientes)
        ]):
            frame = QFrame()
            frame.setStyleSheet(
                "QFrame { background: #0d1a2a; border: 1px solid #1e3a5f; "
                "border-radius: 6px; }"
            )
            fl = QVBoxLayout(frame)
            fl.setContentsMargins(4, 4, 4, 4)
            fl.addWidget(lr)
            fl.addWidget(lv)
            layout.addWidget(frame, 0, col)

        # Barra de carga
        self.barra_carga = QProgressBar()
        self.barra_carga.setRange(0, 50)
        self.barra_carga.setValue(0)
        self.barra_carga.setTextVisible(False)
        self.barra_carga.setStyleSheet("""
            QProgressBar {
                background: #0d1a2a; border: 1px solid #1e3a5f;
                border-radius: 4px; height: 12px;
            }
            QProgressBar::chunk { background: #3498DB; border-radius: 3px; }
        """)
        layout.addWidget(QLabel("Carga do servidor:"), 1, 0, 1, 2)
        layout.addWidget(self.barra_carga, 1, 2, 1, 2)

        return grp

    def _criar_grupo_protecao(self) -> QGroupBox:
        """Cria o grupo de proteção didática com layout estável."""
        grp = QGroupBox("️ Proteção Didática (Demo DoS)")
        grp.setStyleSheet(
            "QGroupBox { border: 1px solid #E67E22; border-radius: 6px; "
            "margin-top: 3px; font-weight: bold; color: #E67E22; }"
            "QGroupBox::title { subcontrol-origin: margin; padding: 0 3px; }"
        )
        layout = QVBoxLayout(grp)
        layout.setSpacing(8)

        # Checkbox
        self.chk_protecao = QCheckBox("Ativar proteção rate limiting")
        self.chk_protecao.setStyleSheet("color: #ecf0f1; font-size: 11px;")
        self.chk_protecao.stateChanged.connect(self._ao_mudar_protecao)
        layout.addWidget(self.chk_protecao)

        # Container para os controles (usando grid para alinhamento)
        container_controles = QWidget()
        grid = QGridLayout(container_controles)
        grid.setContentsMargins(0, 0, 0, 0)
        grid.setVerticalSpacing(6)
        grid.setHorizontalSpacing(8)

        # Linha 1: Limite req/s
        lbl_limite = QLabel("Limite req/s por IP:")
        lbl_limite.setStyleSheet("color: #ecf0f1; font-size: 11px;")
        grid.addWidget(lbl_limite, 0, 0, Qt.AlignmentFlag.AlignVCenter)

        # Controle de limite
        container_limite = QWidget()
        hbox_limite = QHBoxLayout(container_limite)
        hbox_limite.setContentsMargins(0, 0, 0, 0)
        hbox_limite.setSpacing(2)

        self.btn_limite_menos = self._criar_botao_controle("−", "#E67E22", 16, 16)
        self.btn_limite_menos.setEnabled(False)
        self.btn_limite_menos.clicked.connect(lambda: self._ajustar_valor('limite', -1))
        hbox_limite.addWidget(self.btn_limite_menos)

        self.lbl_limite = QLabel(str(self._limite_atual))
        self.lbl_limite.setFixedSize(35, 18)
        self.lbl_limite.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.lbl_limite.setStyleSheet("""
            QLabel {
                background: #0d1a2a;
                color: #ecf0f1;
                border: 1px solid #E67E22;
                border-radius: 4px;
                font-size: 11px;
                font-weight: bold;
                padding: 3px;
            }
        """)
        hbox_limite.addWidget(self.lbl_limite)

        self.btn_limite_mais = self._criar_botao_controle("+", "#E67E22", 16, 16)
        self.btn_limite_mais.setEnabled(False)
        self.btn_limite_mais.clicked.connect(lambda: self._ajustar_valor('limite', 1))
        hbox_limite.addWidget(self.btn_limite_mais)

        grid.addWidget(container_limite, 0, 1, Qt.AlignmentFlag.AlignLeft)

        # Linha 2: Tempo de bloqueio
        lbl_tempo = QLabel("Tempo de bloqueio (s):")
        lbl_tempo.setStyleSheet("color: #ecf0f1; font-size: 11px;")
        grid.addWidget(lbl_tempo, 1, 0, Qt.AlignmentFlag.AlignVCenter)

        # Controle de tempo
        container_tempo = QWidget()
        hbox_tempo = QHBoxLayout(container_tempo)
        hbox_tempo.setContentsMargins(0, 0, 0, 0)
        hbox_tempo.setSpacing(2)

        self.btn_tempo_menos = self._criar_botao_controle("−", "#E67E22", 16, 16)
        self.btn_tempo_menos.setEnabled(False)
        self.btn_tempo_menos.clicked.connect(lambda: self._ajustar_valor('tempo', -1))
        hbox_tempo.addWidget(self.btn_tempo_menos)

        self.lbl_tempo = QLabel(str(self._tempo_atual))
        self.lbl_tempo.setFixedSize(35, 18)
        self.lbl_tempo.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.lbl_tempo.setStyleSheet("""
            QLabel {
                background: #0d1a2a;
                color: #ecf0f1;
                border: 1px solid #E67E22;
                border-radius: 4px;
                font-size: 11px;
                font-weight: bold;
                padding: 3px;

            }
        """)
        hbox_tempo.addWidget(self.lbl_tempo)

        self.btn_tempo_mais = self._criar_botao_controle("+", "#E67E22", 16, 16)
        self.btn_tempo_mais.setEnabled(False)
        self.btn_tempo_mais.clicked.connect(lambda: self._ajustar_valor('tempo', 1))
        hbox_tempo.addWidget(self.btn_tempo_mais)

        grid.addWidget(container_tempo, 1, 1, Qt.AlignmentFlag.AlignLeft)

        # Adicionar o container de controles ao layout principal
        layout.addWidget(container_controles)

        # Botão desbloquear (em linha separada)
        self.btn_desbloquear = QPushButton(" Desbloquear todos os IPs")
        self.btn_desbloquear.setFixedHeight(20)
        self.btn_desbloquear.setStyleSheet("""
            QPushButton {
                background: #1e3a5f;
                color: #ecf0f1;
                border: none;
                border-radius: 4px;
                padding: 0px;
                font-size: 11px;
            }
            QPushButton:hover {
                background: #2a5080;
            }
            QPushButton:pressed {
                background: #15304f;
            }
        """)
        self.btn_desbloquear.clicked.connect(self._desbloquear_ips)
        layout.addWidget(self.btn_desbloquear)

        # Texto explicativo
        lbl_explicacao = QLabel(
        )
        lbl_explicacao.setStyleSheet("color: #7f8c8d; font-size: 2px;")
        lbl_explicacao.setWordWrap(True)
        layout.addWidget(lbl_explicacao)

        return grp

    def _criar_botao_controle(self, texto: str, cor: str, largura: int, altura: int) -> QPushButton:
        """Cria um botão de controle padronizado."""
        btn = QPushButton(texto)
        btn.setFixedSize(largura, altura)
        btn.setStyleSheet(f"""
            QPushButton {{
                background: #2c3e50;
                color: white;
                border: 1px solid {cor};
                border-radius: 4px;
                font-size: 14px;
                font-weight: bold;
                padding: 0px;
            }}
            QPushButton:hover {{
                background: #34495e;
                border: 2px solid {cor};
            }}
            QPushButton:pressed {{
                background: #1e2b3a;
            }}
            QPushButton:disabled {{
                background: #2c3e50;
                color: #7f8c8d;
                border: 1px solid #7f8c8d;
            }}
        """)
        return btn

    def _criar_painel_requisicoes(self) -> QWidget:
        """Painel direito: tabela de requisições e log de alertas."""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(8, 0, 0, 0)
        layout.setSpacing(6)

        splitter_v = QSplitter(Qt.Orientation.Vertical)
        layout.addWidget(splitter_v)

        # Tabela de requisições
        w_tabela = QWidget()
        l_tabela = QVBoxLayout(w_tabela)
        l_tabela.setContentsMargins(0, 0, 0, 0)

        cab_tabela = QHBoxLayout()
        lbl_tab = QLabel("  Requisições Recebidas em Tempo Real")
        fonte_tab = QFont("Arial", 10)
        fonte_tab.setBold(True)
        lbl_tab.setFont(fonte_tab)
        lbl_tab.setStyleSheet("color: #bdc3c7;")
        cab_tabela.addWidget(lbl_tab)
        cab_tabela.addStretch()

        btn_limpar_tab = QPushButton(" Limpar")
        btn_limpar_tab.setMaximumWidth(70)
        btn_limpar_tab.setFixedHeight(24)
        btn_limpar_tab.clicked.connect(self._limpar_tabela)
        cab_tabela.addWidget(btn_limpar_tab)
        l_tabela.addLayout(cab_tabela)

        self.tabela_reqs = QTableWidget(0, 8)
        self.tabela_reqs.setHorizontalHeaderLabels([
            "Hora", "IP", "Método", "Endpoint",
            "Tamanho", "User-Agent", "Tempo(ms)", "Req/s",
        ])
        self.tabela_reqs.horizontalHeader().setSectionResizeMode(
            QHeaderView.ResizeMode.ResizeToContents
        )
        self.tabela_reqs.horizontalHeader().setStretchLastSection(True)
        self.tabela_reqs.verticalHeader().setVisible(False)
        self.tabela_reqs.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.tabela_reqs.setAlternatingRowColors(True)
        l_tabela.addWidget(self.tabela_reqs)
        splitter_v.addWidget(w_tabela)

        # Área de alertas
        w_alertas = QWidget()
        l_alertas = QVBoxLayout(w_alertas)
        l_alertas.setContentsMargins(0, 0, 0, 0)

        lbl_alertas = QLabel("️  Alertas Didáticos")
        lbl_alertas.setStyleSheet("color: #E67E22; font-weight: bold; font-size: 10px;")
        l_alertas.addWidget(lbl_alertas)

        self.texto_alertas = QTextEdit()
        self.texto_alertas.setReadOnly(True)
        self.texto_alertas.setMaximumHeight(140)
        self.texto_alertas.setStyleSheet("""
            QTextEdit {
                background-color: #0a0f1a;
                color: #ecf0f1;
                border: 1px solid #1e3a5f;
                border-radius: 4px;
                padding: 6px;
                font-family: Consolas;
                font-size: 10px;
            }
        """)
        self.texto_alertas.setPlaceholderText(
            "Alertas sobre comportamento do tráfego aparecerão aqui…"
        )
        l_alertas.addWidget(self.texto_alertas)
        splitter_v.addWidget(w_alertas)

        splitter_v.setSizes([500, 140])
        return widget

    #  Controle do servidor 

    def _alternar_servidor(self):
        if self._servidor_ativo:
            self._parar_servidor()
        else:
            self._iniciar_servidor()

    def _iniciar_servidor(self):
        porta = self._porta_atual

        # Resetar estado do handler
        HandlerLabEducacional._contagem_por_ip.clear()
        HandlerLabEducacional._timestamps_por_ip.clear()
        HandlerLabEducacional._ips_bloqueados.clear()
        HandlerLabEducacional._ip_bloqueado_ate.clear()
        HandlerLabEducacional._limite_req_por_seg = self._limite_atual
        HandlerLabEducacional._tempo_bloqueio = self._tempo_atual

        self._total_requisicoes = 0
        self._total_bytes       = 0
        self._clientes_unicos   = set()

        self._thread_servidor = ThreadServidor(porta)
        self._thread_servidor.start()

        self._servidor_ativo = True
        self.btn_iniciar.setText("  Parar Servidor")
        self.btn_iniciar.setObjectName("botao_parar")
        self._repolir(self.btn_iniciar)

        ip_local = obter_ip_local()
        self.lbl_status.setText("  Servidor ativo")
        self.lbl_status.setStyleSheet(
            "color: #2ECC71; font-weight: bold; font-size: 11px;"
        )
        self.lbl_endereco.setText(f"http://{ip_local}:{porta}/login")

        self._timer_metricas.start(1000)
        self._adicionar_alerta(
            "INFO",
            f"Servidor iniciado em http://{ip_local}:{porta}. "
            f"Aguardando requisições..."
        )

    def _parar_servidor(self):
        self._timer_metricas.stop()

        if self._thread_servidor:
            self._thread_servidor.parar()

        self._servidor_ativo = False
        self.btn_iniciar.setText("  Iniciar Servidor")
        self.btn_iniciar.setObjectName("botao_captura")
        self._repolir(self.btn_iniciar)

        self.lbl_status.setText("️  Servidor parado")
        self.lbl_status.setStyleSheet(
            "color: #E74C3C; font-weight: bold; font-size: 11px;"
        )
        self.lbl_endereco.setText("—")
        self.barra_carga.setValue(0)
        self.lbl_reqs_seg.setText("0")

        self._adicionar_alerta("INFO", "Servidor parado.")

    #  Slots de dados 

    def _ajustar_valor(self, tipo: str, delta: int):
        """Ajusta os valores dos controles numéricos."""
        if tipo == 'porta':
            novo = self._porta_atual + delta
            if 1024 <= novo <= 65535:
                self._porta_atual = novo
                self.lbl_porta.setText(str(novo))

        elif tipo == 'limite' and self.chk_protecao.isChecked():
            novo = self._limite_atual + delta
            if 1 <= novo <= 100:
                self._limite_atual = novo
                self.lbl_limite.setText(str(novo))
                HandlerLabEducacional._limite_req_por_seg = novo

        elif tipo == 'tempo' and self.chk_protecao.isChecked():
            novo = self._tempo_atual + delta
            if 5 <= novo <= 300:
                self._tempo_atual = novo
                self.lbl_tempo.setText(str(novo))
                HandlerLabEducacional._tempo_bloqueio = novo

    def _ao_receber_requisicao(self, dados: dict):
        """Adiciona uma linha na tabela para cada requisição recebida."""
        self._total_requisicoes += 1
        self._total_bytes       += dados.get("tamanho", 0)
        self._contador_segundo  += 1

        ip = dados.get("ip_cliente", "")
        self._clientes_unicos.add(ip)

        if ip:
            self.cliente_detectado.emit(ip)

        # Inserir no topo
        self.tabela_reqs.insertRow(0)

        reqs_seg = dados.get("reqs_por_seg", 0)
        itens = [
            dados.get("timestamp", ""),
            ip,
            dados.get("metodo", ""),
            dados.get("endpoint", ""),
            f"{dados.get('tamanho', 0)} bytes",
            dados.get("user_agent", "—")[:20],
            f"{dados.get('tempo_ms', 0)}",
            str(reqs_seg),
        ]

        for col, texto in enumerate(itens):
            item = QTableWidgetItem(texto)
            if dados.get("bloqueado"):
                item.setForeground(QColor("#E74C3C"))
                item.setBackground(QColor("#1a0a00"))
            elif reqs_seg >= 10:
                item.setForeground(QColor("#E67E22"))
            self.tabela_reqs.setItem(0, col, item)

        # Limitar linhas
        while self.tabela_reqs.rowCount() > 100:
            self.tabela_reqs.removeRow(100)

        # Atualizar métricas
        self.lbl_total_reqs.setText(f"{self._total_requisicoes:,}")
        self.lbl_total_bytes.setText(formatar_bytes(self._total_bytes))
        self.lbl_clientes.setText(str(len(self._clientes_unicos)))

        # Alertas para POST
        corpo = dados.get("corpo", "")
        if corpo and dados.get("metodo") == "POST":
            self._adicionar_alerta(
                "AVISO",
                f"POST de {ip}: {corpo[:80]}"
            )

    def _ao_mudar_status(self, mensagem: str):
        self.lbl_status.setText(mensagem)

    def _ao_emitir_alerta(self, mensagem: str):
        tipo = "CRITICO" if "bloqueado" in mensagem.lower() or "ataque" in mensagem.lower() else "AVISO"
        self._adicionar_alerta(tipo, mensagem)

    def _adicionar_alerta(self, tipo: str, mensagem: str):
        cores = {"INFO": "#3498DB", "AVISO": "#E67E22", "CRITICO": "#E74C3C"}
        hora = datetime.now().strftime("%H:%M:%S")
        cor = cores.get(tipo, "#ecf0f1")
        html = f"<span style='color:{cor};font-size:10px;'>[{hora}] [{tipo}] {mensagem}</span><br>"
        self.texto_alertas.insertHtml(html)

        # Limitar linhas
        if self.texto_alertas.document().lineCount() > 50:
            cursor = self.texto_alertas.textCursor()
            cursor.movePosition(cursor.MoveOperation.Start)
            cursor.movePosition(cursor.MoveOperation.Down, cursor.MoveMode.KeepAnchor, 10)
            cursor.removeSelectedText()

    #  Métodos auxiliares 

    def _repolir(self, widget):
        widget.style().unpolish(widget)
        widget.style().polish(widget)

    def _limpar_tabela(self):
        self.tabela_reqs.setRowCount(0)

    def _atualizar_metricas_por_segundo(self):
        self.lbl_reqs_seg.setText(str(self._contador_segundo))
        self.barra_carga.setValue(min(self._contador_segundo, 50))
        self._contador_segundo = 0

    def _ao_mudar_protecao(self, estado):
        ativo = (estado == Qt.CheckState.Checked.value)
        HandlerLabEducacional._protecao_ativa = ativo

        self.btn_limite_menos.setEnabled(ativo)
        self.btn_limite_mais.setEnabled(ativo)
        self.btn_tempo_menos.setEnabled(ativo)
        self.btn_tempo_mais.setEnabled(ativo)

        if ativo:
            HandlerLabEducacional._limite_req_por_seg = self._limite_atual
            HandlerLabEducacional._tempo_bloqueio = self._tempo_atual
        else:
            self._desbloquear_ips()

    def _desbloquear_ips(self):
        HandlerLabEducacional._ips_bloqueados.clear()
        HandlerLabEducacional._ip_bloqueado_ate.clear()
        self._adicionar_alerta("INFO", "Todos os IPs foram desbloqueados.")

    def _ao_mudar_modo_login(self, modo: str):
        """Alterna entre cenário vulnerável e seguro para testes externos."""
        self._modo_login = modo
        # Sincronizar com o handler
        ativar_protecao = (modo == "seguro")
        HandlerLabEducacional.configurar_modo(
            modo,
            ativar_protecao=ativar_protecao,
            limite_req=self._limite_atual if ativar_protecao else 0,
            tempo_bloqueio=self._tempo_atual,
        )
        # Atualizar check de proteção visual
        if hasattr(self, "chk_protecao"):
            self.chk_protecao.setChecked(ativar_protecao)
        if hasattr(self, "lbl_status"):
            self.lbl_status.setText(
                " Modo seguro: proteções ligadas" if ativar_protecao else "️ Modo vulnerável: sem limites"
            )






