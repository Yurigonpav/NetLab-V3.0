# motor_pedagogico.py
# Motor pedagÃ³gico com Deep Packet Inspection para HTTP, HTTPS, DNS, ARP, TCP, ICMP, etc.
# Exibe explicaÃ§Ãµes em mÃºltiplos nÃ­veis (simples, tÃ©cnico, estruturado, pacote bruto)
# com destaque de seguranÃ§a, tabelas e dump hexadecimal.

import urllib.parse
import re
from datetime import datetime

# Palavras-chave que identificam campos sensÃ­veis em formulÃ¡rios
CAMPOS_SENSIVEIS = {
    "senha", "password", "pass", "pwd", "secret", "token",
    "auth", "key", "api_key", "apikey", "credential",
    "credit_card", "card_number", "cvv", "cpf", "rg", "pin",
    "ssn", "user", "usuario", "login", "email", "e-mail",
    "username", "nome", "name", "telefone", "phone",
}

# Mapeamento OUI rÃ¡pido para identificar fabricantes (apenas exemplos comuns)
OUI_VENDORS = {
    "00:14:22": "Dell",
    "00:1A:2B": "Intel",
    "00:1B:63": "Apple",
    "00:1E:C2": "Apple",
    "00:25:00": "Apple",
    "00:0C:29": "VMware",
    "00:50:56": "VMware",
    "00:05:69": "Cisco",
    "00:1C:42": "Cisco",
    "B8:27:EB": "Raspberry Pi Foundation",
    "DC:A6:32": "Raspberry Pi",
    "00:16:3E": "Xensource",
    "00:15:5D": "Microsoft Hyper-V",
    "08:00:27": "Oracle VirtualBox",
    "00:1D:09": "Samsung",
    "70:B3:D5": "TP-Link",
    "94:65:2D": "Intelbras",
    "00:11:22": "Generic",
}

class MotorPedagogico:
    """
    Gera explicaÃ§Ãµes didÃ¡ticas dinÃ¢micas baseadas nos dados reais
    extraÃ­dos de cada pacote capturado.

    Para cada tipo de evento, produz trÃªs nÃ­veis exibidos:
      nivel1 â€” explicaÃ§Ã£o simples (linguagem do dia a dia)
      nivel2 â€” detalhes tÃ©cnicos do protocolo
      nivel4 â€” pacote bruto exatamente como trafegou na rede (quando disponÃ­vel)
    (nivel3 permanece interno para organizaÃ§Ã£o dos metadados)
    """

    def __init__(self):
        self._contadores: dict = {}
        # Log interno de alertas educacionais HTTP — alimentado via hook
        # em gerar_explicacao(), sem alterar nenhum retorno existente.
        self._alertas_educacionais: list = []

    #  Interface pÃºblica 

    def gerar_explicacao(self, evento: dict) -> dict:
        tipo = evento.get("tipo", "")
        self._contadores[tipo] = self._contadores.get(tipo, 0) + 1

        geradores = {
            "DNS":              self._dns,
            "HTTP":             self._http,
            "HTTPS":            self._https,
            "TCP_SYN":          self._tcp_syn,
            "TCP_FIN":          self._tcp_fin,
            "TCP_RST":          self._tcp_rst,
            "ICMP":             self._icmp,
            "ARP":              self._arp,
            "DHCP":             self._dhcp,
            "SSH":              self._ssh,
            "FTP":              self._ftp,
            "SMB":              self._smb,
            "RDP":              self._rdp,
            "NOVO_DISPOSITIVO": self._novo_dispositivo,
            "HTTP_CREDENTIALS": self._http_credenciais,
            "HTTP_REQUEST":     self._http_request,
        }
        resultado = geradores.get(tipo, self._generico)(evento)

        # Hook educacional HTTP — fail-safe, não altera resultado
        try:
            self._hook_analise_educacional_http(evento, resultado)
        except Exception:
            pass

        return resultado

    #  UtilitÃ¡rios internos 

    def _base(self, evento: dict, icone: str, titulo: str, nivel: str,
              n1: str, n2: str, n3: str, n4: str = "",
              fluxo: str = "", alerta: str = "") -> dict:
        def _fix_mojibake(txt: str) -> str:
            if not isinstance(txt, str):
                return txt
            for enc in ("cp1252", "latin1"):
                try:
                    return txt.encode(enc, errors="ignore").decode("utf-8")
                except Exception:
                    continue
            return txt

        tipo = evento.get("tipo", "")
        resultado = {
            "timestamp":        datetime.now().strftime("%H:%M:%S"),
            "tipo":             tipo,
            "icone":            icone,
            "titulo":           titulo,
            "nivel":            nivel,
            "fluxo_visual":     fluxo,
            "nivel1":           n1,
            "nivel2":           n2,
            "nivel3":           n3,
            "nivel4":           n4,
            "alerta_seguranca": alerta,
            "payload_visivel":  "",
            "ip_envolvido":     evento.get("ip_origem", ""),
            "ip_destino":       evento.get("ip_destino", ""),
            "contador":         self._contadores.get(tipo, 1),
        }
        # Corrige eventuais mojibakes antes de devolver
        for k, v in list(resultado.items()):
            if isinstance(v, str):
                resultado[k] = _fix_mojibake(v)
        return resultado

    # ── Hook educacional HTTP (camada adicional, fail-safe) ──

    _KEYWORDS_SENSIVEIS = (
        b"user", b"login", b"username", b"password", b"senha",
        b"email", b"token", b"auth", b"cpf", b"credential",
        b"passwd", b"pass", b"pwd", b"secret",
    )

    def _hook_analise_educacional_http(self, evento: dict, resultado: dict):
        """
        Análise educacional adicional para eventos HTTP.
        Padrão fail-safe: nunca altera `resultado`, nunca lança exceção.
        Alimenta self._alertas_educacionais para uso externo (ex.: Insights).
        """
        if evento.get("tipo") != "HTTP":
            return

        # Analisa payload bruto quando disponível
        payload_raw = (
            evento.get("payload_bruto") or
            evento.get("payload_resumo") or
            resultado.get("nivel4", "") or ""
        )
        payload_bytes = (
            payload_raw.encode("utf-8", errors="ignore")
            if isinstance(payload_raw, str) else payload_raw
        )

        findings = self._extrair_campos_sensiveis(payload_bytes)

        # Também verifica pelo alerta gerado pelo motor
        alerta_gerado = resultado.get("alerta_seguranca", "").lower()
        if "credencial" in alerta_gerado or "exposta" in alerta_gerado:
            if not findings:
                findings = ["dados sensíveis (via alerta)"]

        if findings:
            self._emitir_alerta_educacional_http(evento, resultado, findings)

    def _extrair_campos_sensiveis(self, payload_bytes: bytes) -> list:
        """Extrai nomes de campos sensíveis presentes no payload HTTP."""
        if not payload_bytes:
            return []
        payload_lower = payload_bytes.lower()
        return [
            kw.decode() for kw in self._KEYWORDS_SENSIVEIS
            if kw in payload_lower
        ]

    def _emitir_alerta_educacional_http(self, evento: dict, resultado: dict,
                                         findings: list):
        """
        Registra alerta educacional no log interno.
        Mensagem formatada para uso didático em sala de aula.
        """
        if len(self._alertas_educacionais) >= 200:
            self._alertas_educacionais.pop(0)

        ip_origem = evento.get("ip_origem", "?")
        ip_destino= evento.get("ip_destino", "?")
        ts        = resultado.get("timestamp", "")
        campos    = ", ".join(sorted(set(findings)))
        mensagem  = (
            f"[HTTP ALERT] {ts} · {ip_origem} → {ip_destino} "
            f"| Dados sensíveis detectados: {campos} "
            f"| ⚠ Um atacante pode interceptar essas informações (MITM)."
        )
        self._alertas_educacionais.append({
            "timestamp":  ts,
            "ip_origem":  ip_origem,
            "ip_destino": ip_destino,
            "campos":     campos,
            "mensagem":   mensagem,
            "nivel":      "CRÍTICO",
        })

    def obter_alertas_educacionais(self, ultimo_n: int = 20) -> list:
        """
        Retorna os últimos N alertas educacionais HTTP registrados.
        API pública para uso por componentes externos (ex.: PainelEventos).
        """
        return list(self._alertas_educacionais[-ultimo_n:])

    def resetar_alertas_educacionais(self):
        """Limpa o log de alertas — chamar em nova sessão."""
        self._alertas_educacionais.clear()

    @staticmethod
    def _fluxo(origem: str, protocolo: str, destino: str) -> str:
        return f"{origem}  --[{protocolo}]-->  {destino}"

    @staticmethod
    def _tabela_campos(campos: list) -> str:
        """Gera tabela HTML com os campos reais do pacote."""
        linhas = "".join(
            f"<tr>"
            f"<td style='padding:3px 12px 3px 0;color:#7f8c8d;"
            f"white-space:nowrap;font-size:10px;'>{nome}</td>"
            f"<td style='padding:3px 0;color:#ecf0f1;"
            f"font-family:Consolas;font-size:10px;'>{valor}</td>"
            f"</tr>"
            for nome, valor in campos
            if valor not in (None, "", "None", {})
        )
        if not linhas:
            return "<i style='color:#7f8c8d;'>Campos nÃ£o disponÃ­veis.</i>"
        return (
            "<table style='border-collapse:collapse;width:100%;'>"
            + linhas + "</table>"
        )

    @staticmethod
    def _eh_sensivel(nome_campo: str) -> bool:
        return any(s in nome_campo.lower() for s in CAMPOS_SENSIVEIS)

    @staticmethod
    def _indicadores_maliciosos(texto: str) -> list:
        suspeitos = [
            r"union\s+select",
            r"or\s+1=1",
            r"sleep\s*\(",
            r"<script",
            r"\.\./",
            r"xp_cmdshell",
            r"load_file\s*\(",
        ]
        encontrados = []
        for pad in suspeitos:
            if re.search(pad, texto or "", flags=re.IGNORECASE):
                encontrados.append(pad)
        return encontrados

    @staticmethod
    def _escape_html(texto: str) -> str:
        return (
            (texto or "")
            .replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
        )

    @staticmethod
    def _hexdump_text(texto: str, limite: int = 2048) -> str:
        dados = (texto or "").encode("latin-1", "replace")[:limite]
        linhas = []
        for i in range(0, len(dados), 16):
            chunk = dados[i:i + 16]
            hexes = " ".join(f"{b:02x}" for b in chunk)
            hexes = hexes.ljust(16 * 3 - 1)
            ascii_ = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
            linhas.append(f"{i:04x}  {hexes}  {ascii_}")
        return "\n".join(linhas)

    @staticmethod
    def _headers_inseguros(headers: dict) -> list:
        falta = []
        if not headers:
            return ["Nenhum header HTTP disponÃ­vel."]
        checks = [
            ("Strict-Transport-Security", "HSTS ausente (HTTPS deveria enviÃ¡-lo)"),
            ("Content-Security-Policy",   "CSP ausente â€” risco de XSS"),
            ("X-Frame-Options",           "X-Frame-Options ausente â€” clickjacking"),
            ("X-Content-Type-Options",    "X-Content-Type-Options ausente â€” MIME sniffing"),
            ("Referrer-Policy",           "Referrer-Policy ausente â€” vazamento de URL"),
        ]
        for chave, msg in checks:
            if chave not in headers:
                falta.append(msg)
        return falta

    @staticmethod
    def _estimar_os(ttl) -> str:
        if ttl is None:
            return ""
        try:
            t = int(ttl)
            if t >= 120:
                return "Windows (TTL padrÃ£o 128)"
            if t >= 55:
                return "Linux / macOS (TTL padrÃ£o 64)"
            return "Dispositivo embarcado (TTL padrÃ£o 32)"
        except Exception:
            return ""

    @staticmethod
    def _obter_fabricante(mac: str) -> str:
        if not mac or len(mac) < 8:
            return ""
        oui = mac[:8].upper()
        return OUI_VENDORS.get(oui, "Fabricante desconhecido")

    #  Gerador HTTP â€” DPI completo
    def _http(self, e: dict) -> dict:
        origem       = e.get("ip_origem", "?")
        destino      = e.get("ip_destino", "?")
        porta        = e.get("porta_destino") or 80
        porta_origem = e.get("porta_origem", "")
        tamanho      = e.get("tamanho", 0)
        ttl          = e.get("ttl")
        linha_req    = e.get("http_linha_req", "")
        # Aceita tanto os campos do analisador_pacotes (metodo, recurso,
        # payload_bruto) quanto os campos estendidos do DPI (http_metodo,
        # http_caminho, payload_resumo) — compatibilidade total com ambos.
        metodo       = e.get("http_metodo") or e.get("metodo", "") or "GET"
        caminho      = e.get("http_caminho") or e.get("recurso", "") or "/"
        versao       = e.get("http_versao", "") or "HTTP/1.1"
        host         = e.get("http_host", "")
        headers      = e.get("http_headers", {}) or {}
        headers_raw  = e.get("http_headers_raw", "") or ""
        corpo        = e.get("http_corpo", "") or e.get("corpo", "") or e.get("payload_resumo", "") or ""
        if isinstance(corpo, bytes):
            corpo = corpo.decode('utf-8', errors='ignore')
        cookie       = e.get("http_cookie", "")
        content_type = e.get("http_content_type", "") or ""
        payload_raw  = e.get("payload_resumo") or e.get("payload_bruto", "") or ""

        # Se o analisador enviou credenciais como lista de (chave, valor),
        # reconstrói o corpo para que os campos sensíveis sejam detectados.
        creds_raw = e.get("credenciais", [])
        if creds_raw and not corpo:
            corpo = "&".join(f"{k}={v}" for k, v in creds_raw)
            content_type = content_type or "application/x-www-form-urlencoded"
        metodo_up    = metodo.upper()
        alvo   = host or destino
        titulo = f"HTTP sem criptografia â€” {metodo} {alvo}{caminho}"
        fluxo  = self._fluxo(origem, "HTTP", f"{alvo}:{porta}")
        query_suspeita = self._indicadores_maliciosos(caminho)
        headers_inseguros = self._headers_inseguros(headers)
        metodos_arriscados = {"TRACE", "OPTIONS", "PUT", "DELETE"}
        metodo_alerta = metodo_up in metodos_arriscados

        # Parsear campos do formulÃ¡rio
        campos_formulario: dict = {}
        if corpo:
            try:
                if "urlencoded" in content_type.lower() or re.search(r'\w+=', corpo):
                    campos_formulario = {
                        k: v[0] if v else ""
                        for k, v in urllib.parse.parse_qs(
                            corpo, keep_blank_values=True
                        ).items()
                    }
            except Exception:
                pass

        campos_sensiveis_encontrados = [
            k for k in campos_formulario if self._eh_sensivel(k)
        ]
        tem_dados_sensiveis = bool(campos_sensiveis_encontrados)

        # NÃVEL 1
        if tem_dados_sensiveis:
            exemplos = " Â· ".join(
                f"{k} = <b style='color:#E74C3C;'>{campos_formulario[k]}</b>"
                for k in campos_sensiveis_encontrados[:3]
            )
            bloco_dados = (
                f"<br><br>Os dados enviados incluem campos sensÃ­veis "
                f"completamente visÃ­veis na rede:<br>"
                f"<div style='background:#1a0000;border-left:4px solid #E74C3C;"
                f"padding:8px 12px;margin:8px 0;border-radius:4px;"
                f"font-family:Consolas;font-size:11px;color:#ecf0f1;'>"
                f"{exemplos}</div>"
            )
        else:
            bloco_dados = ""

        bloco_injecao = ""
        if query_suspeita:
            blocos = ", ".join(query_suspeita)
            bloco_injecao = (
                f"<br><br><div style='background:#2a0a00;border-left:4px solid #E74C3C;"
                f"padding:8px 12px;margin:8px 0;border-radius:4px;'>"
                f"<b style='color:#E74C3C;'>PossÃ­vel injeÃ§Ã£o / payload suspeito:</b> "
                f"{blocos} encontrado na URL ou corpo.</div>"
            )

        bloco_metodo = ""
        if metodo_alerta:
            bloco_metodo = (
                f"<br><div style='background:#2a0a00;border:1px solid #E67E22;"
                f"border-radius:4px;padding:8px 12px;margin-top:8px;'>"
                f"<b style='color:#E67E22;'>MÃ©todo incomum:</b> {metodo_up}. "
                f"Use apenas quando estritamente necessÃ¡rio e protegido por autenticaÃ§Ã£o.</div>"
            )

        n1 = (
            f"O computador <b>{origem}</b> enviou uma requisição HTTP para "
            f"<b style='color:#E74C3C;'>{alvo}</b>.<br><br>"
            f"HTTP não possui nenhuma criptografia: qualquer pessoa na mesma "
            f"rede Wi-Fi consegue ver exatamente o que foi enviado, como se "
            f"estivesse lendo uma carta sem envelope."
            + bloco_dados +
            bloco_injecao +
            bloco_metodo +
            f"<br><br><b style='color:#E74C3C;'>HTTP não protege confidencialidade nem integridade; use sempre HTTPS para dados sensíveis.</b>"
            f"<br><br>Isso demonstra por que o HTTPS é indispensável para "
            f"proteger qualquer informação transmitida pela web."
        )

        # NÃVEL 2
        content_length = headers.get("Content-Length", "")
        user_agent     = headers.get("User-Agent", "")[:70] if headers.get("User-Agent") else ""

        aviso_cookie = (
            f"<br><br><div style='background:#2a1500;border:1px solid #E67E22;"
            f"border-radius:4px;padding:8px 12px;'>"
            f"<b style='color:#E67E22;'>Cookie de sessÃ£o detectado!</b><br>"
            f"<span style='color:#ecf0f1;font-size:10px;'>"
            f"Cookies via HTTP permitem sequestrar a conta da vÃ­tima sem "
            f"precisar da senha â€” tÃ©cnica chamada Session Hijacking.</span></div>"
        ) if cookie else ""

        aviso_injecao = ""
        if query_suspeita:
            aviso_injecao = (
                f"<br><div style='background:#2a0a00;border:1px solid #E74C3C;"
                f"border-radius:4px;padding:8px 12px;margin-top:8px;'>"
                f"<b style='color:#E74C3C;'>Indicador de ataque:</b> "
                f"padrÃµes de injeÃ§Ã£o detectados ({', '.join(query_suspeita)}). "
                f"Verifique parÃ¢metros e sanitize entradas.</div>"
            )

        aviso_headers = ""
        if headers_inseguros:
            aviso_headers = (
                f"<br><div style='background:#1a2430;border:1px solid #3498DB;"
                f"border-radius:4px;padding:8px 12px;margin-top:8px;'>"
                f"<b style='color:#3498DB;'>Headers de seguranÃ§a ausentes:</b><br>"
                + "<br>".join(f"â€¢ {h}" for h in headers_inseguros)
                + "</div>"
            )

        aviso_metodo = ""
        if metodo_alerta:
            aviso_metodo = (
                f"<br><div style='background:#2a0a00;border:1px solid #E67E22;"
                f"border-radius:4px;padding:6px 10px;margin-top:6px;'>"
                f"<b style='color:#E67E22;'>MÃ©todo {metodo_up} expÃµe risco</b> â€” "
                f"confirme autenticaÃ§Ã£o e autorizaÃ§Ã£o.</div>"
            )

        n2 = (
            f"<b>RequisiÃ§Ã£o:</b> <code style='color:#3498DB;'>"
            f"{linha_req or metodo + ' ' + caminho + ' ' + versao}</code>"
            f"<br><b>Destino:</b> {alvo}:{porta} â€” transmissÃ£o em "
            f"<b style='color:#E74C3C;'>texto puro</b>"
            f"<br><b>Tamanho total:</b> {tamanho} bytes"
            + (f"<br><b>Corpo:</b> {content_length} bytes" if content_length else "")
            + (f"<br><b>Navegador:</b> {user_agent}" if user_agent else "")
            + aviso_cookie +
            aviso_injecao +
            aviso_headers +
            aviso_metodo +
            f"<br><br><b>O que qualquer capturador na mesma rede consegue ver:</b>"
            f"<table style='border-collapse:collapse;margin-top:8px;width:100%;'>"
            f"<tr><td style='padding:3px 10px;color:#E74C3C;'></td>"
            f"<td style='color:#E74C3C;'>URL completa acessada</td></tr>"
            f"<tr><td style='padding:3px 10px;color:#E74C3C;'></td>"
            f"<td style='color:#E74C3C;'>Todos os headers da requisiÃ§Ã£o</td></tr>"
            f"<tr><td style='padding:3px 10px;color:#E74C3C;'></td>"
            f"<td style='color:#E74C3C;'>Corpo completo: senhas, formulÃ¡rios, dados pessoais</td></tr>"
            f"<tr><td style='padding:3px 10px;color:#E74C3C;'></td>"
            f"<td style='color:#E74C3C;'>ConteÃºdo completo da resposta do servidor</td></tr>"
            f"<tr><td style='padding:3px 10px;color:#2ECC71;'></td>"
            f"<td style='color:#2ECC71;'>Com HTTPS: tudo isso seria completamente ilegÃ­vel</td></tr>"
            f"</table>"
        )

        # NÃVEL 3
        meta = [
            ("IP Origem",       origem),
            ("IP Destino",      destino),
            ("Porta origem",    str(porta_origem) if porta_origem else "â€”"),
            ("Porta destino",   str(porta)),
            ("Protocolo",       "HTTP / TCP"),
            ("Tamanho",         f"{tamanho} bytes"),
            ("TTL",             f"{ttl} â€” {self._estimar_os(ttl)}" if ttl else "â€”"),
            ("Timestamp",       datetime.now().strftime("%Y-%m-%d %H:%M:%S")),
            ("Criptografado",   " NÃ£o â€” dados em texto puro"),
        ]
        bloco_meta = (
            "<b style='color:#3498DB;font-size:11px;'>1. Metadados do Pacote IP/TCP</b><br>"
            + self._tabela_campos(meta)
        )

        bloco_headers = ""
        if headers:
            linhas_h = "".join(
                f"<tr>"
                f"<td style='padding:4px 14px 4px 0;color:#7f8c8d;"
                f"white-space:nowrap;font-size:10px;'>{k}</td>"
                f"<td style='padding:4px 0;color:#ecf0f1;"
                f"font-family:Consolas;font-size:10px;"
                f"word-break:break-all;'>{v}</td>"
                f"</tr>"
                for k, v in headers.items()
            )
            bloco_headers = (
                f"<br><b style='color:#3498DB;font-size:11px;'>"
                f"2. Headers HTTP Capturados</b>"
                f"<br><span style='color:#7f8c8d;font-size:10px;'>"
                f"Todos os cabeÃ§alhos transmitidos em texto puro:</span>"
                f"<div style='background:#0a0f1a;border:1px solid #1e2d40;"
                f"border-radius:4px;padding:10px;margin-top:6px;'>"
                f"<table style='border-collapse:collapse;width:100%;'>"
                f"{linhas_h}</table></div>"
            )
        elif headers_raw:
            bloco_headers = (
                f"<br><b style='color:#3498DB;font-size:11px;'>"
                f"2. Headers HTTP Capturados</b><br>"
                f"<code style='font-size:10px;color:#ecf0f1;"
                f"white-space:pre-wrap;'>{headers_raw}</code>"
            )

        bloco_corpo = ""
        if campos_formulario:
            linhas_form = []
            for campo, valor in campos_formulario.items():
                eh_s    = self._eh_sensivel(campo)
                cor_c   = "#F39C12" if eh_s else "#3498DB"
                cor_v   = "#E74C3C" if eh_s else "#2ECC71"
                badge   = (
                    " <span style='background:#5a0000;color:#ff6b6b;"
                    "font-size:9px;padding:1px 6px;border-radius:3px;"
                    "font-weight:bold;'>SENSÃVEL</span>"
                ) if eh_s else ""
                icone_c = "" if eh_s else ""

                linhas_form.append(
                    f"<tr>"
                    f"<td style='padding:6px 16px 6px 4px;white-space:nowrap;"
                    f"font-size:11px;'>{icone_c} "
                    f"<span style='color:{cor_c};font-family:Consolas;'>"
                    f"{campo}</span>{badge}</td>"
                    f"<td style='padding:6px 0;font-family:Consolas;"
                    f"font-size:12px;font-weight:bold;color:{cor_v};'>"
                    f"{valor}</td>"
                    f"</tr>"
                )

            bloco_corpo = (
                f"<br><b style='color:#E74C3C;font-size:11px;'>"
                f"3. Campos do FormulÃ¡rio Capturados em Texto Puro</b>"
                f"<div style='background:#1a0a00;border:1px solid #E74C3C;"
                f"border-radius:6px;padding:12px 16px;margin-top:8px;'>"
                f"<table style='border-collapse:collapse;width:100%;'>"
                + "".join(linhas_form) +
                f"</table>"
                f"<br><span style='color:#7f8c8d;font-size:10px;'>"
                f"Estes dados foram transmitidos sem qualquer proteÃ§Ã£o. "
                f"Qualquer dispositivo na mesma rede Wi-Fi teria acesso "
                f"imediato a estas informaÃ§Ãµes ao executar uma captura "
                f"de pacotes como a realizada por este software.</span>"
                f"</div>"
            )
        elif corpo:
            preview = corpo[:400].replace("<", "&lt;").replace(">", "&gt;")
            bloco_corpo = (
                f"<br><b style='color:#E74C3C;font-size:11px;'>"
                f"3. Corpo da RequisiÃ§Ã£o</b><br>"
                f"<div style='background:#0a0f1a;border:1px solid #E74C3C;"
                f"border-radius:4px;padding:10px;margin-top:6px;'>"
                f"<code style='font-size:10px;color:#ecf0f1;"
                f"white-space:pre-wrap;'>{preview}</code></div>"
            )

        n3 = bloco_meta + bloco_headers + bloco_corpo

        # NÃVEL 4
        if payload_raw:
            if linha_req and headers:
                pacote_reconstruido = linha_req + "\r\n"
                for k, v in headers.items():
                    pacote_reconstruido += f"{k}: {v}\r\n"
                pacote_reconstruido += "\r\n"
                if corpo:
                    pacote_reconstruido += corpo
                conteudo_bruto = pacote_reconstruido
            else:
                conteudo_bruto = payload_raw

            metodo_cor   = "#E74C3C" if metodo_alerta else "#2ECC71"
            req_line = (
                f"<span style='color:{metodo_cor};font-weight:bold'>"
                f"{self._escape_html(metodo_up)}</span> "
                f"{self._escape_html(caminho)} "
                f"<span style='color:#7f8c8d'>{self._escape_html(versao)}</span>"
            )

            headers_destacados = []
            for k, v in headers.items():
                k_lower = k.lower()
                cor_val = "#ecf0f1"
                if k_lower.startswith("authorization") or k_lower == "cookie":
                    cor_val = "#E67E22"
                headers_destacados.append(
                    f"<div><span style='color:#9b59b6'>{self._escape_html(k)}</span>: "
                    f"<span style='color:{cor_val}'>{self._escape_html(str(v))}</span></div>"
                )
            bloco_headers_bruto = "".join(headers_destacados) or (
                "<i style='color:#7f8c8d;'>Sem headers.</i>"
            )

            corpo_preview = (
                f"<pre style='white-space:pre-wrap;margin:6px 0 0 0;"
                f"color:#ecf0f1;font-size:10px;'>{self._escape_html(corpo[:800])}</pre>"
                if corpo else "<i style='color:#7f8c8d;'>Corpo vazio.</i>"
            )

            alertas_brutos = []
            if tem_dados_sensiveis:
                alertas_brutos.append(
                    "Campos sensÃ­veis visÃ­veis (ex.: senha, token, user)."
                )
            if query_suspeita:
                alertas_brutos.append(
                    f"PossÃ­vel injeÃ§Ã£o/payload suspeito: {', '.join(query_suspeita)}."
                )
            if metodo_alerta:
                alertas_brutos.append(f"MÃ©todo incomum: {metodo_up}.")
            if headers_inseguros:
                alertas_brutos.append(
                    "Headers de seguranÃ§a ausentes: "
                    + ", ".join(headers_inseguros[:4])
                )
            if cookie:
                alertas_brutos.append("Cookie de sessÃ£o enviado em HTTP em texto puro.")
            if not alertas_brutos:
                alertas_brutos.append("Nenhum risco crÃ­tico detectado neste pacote.")

            hexdump = self._hexdump_text(conteudo_bruto, limite=2048)

            n4 = (
                f"<div style='font-family:Consolas;font-size:10px;line-height:1.6;'>"
                f"<div style='background:#0a0505;border:1px solid #E74C3C;"
                f"border-radius:6px;padding:12px 14px;margin-bottom:10px;'>"
                f"<b style='color:#E74C3C;font-size:11px;'>VisÃ£o rÃ¡pida do pacote HTTP</b><br>"
                f"<div style='margin:6px 0 10px 0;color:#ecf0f1;'>{req_line}</div>"
                f"<div style='color:#bdc3c7;font-size:10px;'>Headers</div>"
                f"{bloco_headers_bruto}"
                f"<div style='color:#bdc3c7;font-size:10px;margin-top:8px;'>Corpo (preview)</div>"
                f"{corpo_preview}"
                f"</div>"
                f"<div style='background:#0d1a2a;border:1px solid #1e3a5f;"
                f"border-radius:6px;padding:12px 14px;margin-bottom:10px;'>"
                f"<b style='color:#3498DB;font-size:11px;'>Riscos detectados</b>"
                f"<ul style='margin:6px 0 0 16px;color:#ecf0f1;font-family:Arial;'>"
                f"{''.join(f'<li>{self._escape_html(a)}</li>' for a in alertas_brutos)}</ul>"
                f"</div>"
                f"<div style='background:#000;border:1px solid #222;"
                f"border-radius:6px;padding:12px 14px;'>"
                f"<b style='color:#2ECC71;font-size:11px;'>Dump hexadecimal + ASCII "
                f"(primeiros 2048 bytes)</b><br><br>"
                f"<pre style='color:#ecf0f1;white-space:pre;font-size:10px;"
                f"margin:0;'>{self._escape_html(hexdump)}</pre>"
                f"</div>"
                f"</div>"
            )
        else:
            n4 = (
                "<i style='color:#7f8c8d;'>"
                "Payload bruto nÃ£o disponÃ­vel para este pacote.</i>"
            )

        if campos_sensiveis_encontrados:
            alerta = (
                f"Credenciais capturadas em texto puro: "
                f"{', '.join(campos_sensiveis_encontrados)}. "
                f"Este ataque Ã© trivial em qualquer rede Wi-Fi nÃ£o protegida."
            )
        elif corpo:
            alerta = (
                "Dados de formulÃ¡rio transmitidos sem criptografia via HTTP. "
                "Todo o conteÃºdo Ã© visÃ­vel para qualquer capturador na rede."
            )
        elif cookie:
            alerta = (
                "Cookie de sessÃ£o exposto. Permite sequestrar a conta "
                "sem precisar da senha (Session Hijacking)."
            )
        else:
            alerta = (
                "TrÃ¡fego HTTP sem criptografia. "
                "Todo o conteÃºdo Ã© visÃ­vel para qualquer capturador na rede."
            )

        return self._base(
            e, "", titulo, "AVISO",
            n1, n2, n3, n4, fluxo, alerta
        )

    #  Gerador HTTP_CREDENTIALS (vulnerabilidade crÃ­tica)
    def _http_credenciais(self, e: dict) -> dict:
        origem = e.get("ip_origem", "?")
        destino = e.get("ip_destino", "?")
        creds = e.get("credenciais", [])
        payload = e.get("payload_resumo", "") or e.get("http_corpo", "")

        linhas_creds = "\n".join([f"  â€¢ {k} = {v}" for k, v in creds])
        n1 = (
            f"ðŸš¨ **VULNERABILIDADE CRÃTICA** â€“ Credenciais enviadas em texto puro!\n\n"
            f"O dispositivo **{origem}** enviou dados de login/senha para **{destino}** "
            f"usando HTTP (sem criptografia).\n\n"
            f"Qualquer pessoa na mesma rede Wi-Fi pode capturar estas informaÃ§Ãµes:\n"
            f"{linhas_creds}\n\n"
            f"Isso permite sequestro de conta, acesso nÃ£o autorizado e roubo de identidade."
        )
        n2 = (
            f"RequisiÃ§Ã£o HTTP contendo parÃ¢metros sensÃ­veis.\n"
            f"Origem: {origem} â†’ Destino: {destino}\n"
            f"Payload capturado (primeiros 500 caracteres):\n```\n{payload[:500]}\n```\n\n"
            f"âŒ O uso de HTTP para envio de credenciais Ã© uma falha grave de seguranÃ§a. "
            f"A soluÃ§Ã£o Ã© usar HTTPS (TLS), que cifra toda a comunicaÃ§Ã£o."
        )
        n3 = f"Detalhes tÃ©cnicos:\n- Credenciais: {creds}\n- Payload bruto: {payload[:200]}"
        alerta = f"Credenciais expostas: {', '.join([f'{k}={v}' for k,v in creds])}. Risco imediato de invasÃ£o."
        return self._base(e, "ðŸš¨", "Credenciais em texto puro (HTTP)", "CRÃTICO",
                          n1, n2, n3, "", f"{origem} --[HTTP]--> {destino}", alerta)

    #  Gerador HTTP_REQUEST (requisiÃ§Ã£o comum)
    def _http_request(self, e: dict) -> dict:
        origem = e.get("ip_origem", "?")
        destino = e.get("ip_destino", "?")
        metodo = e.get("http_metodo", "GET")
        payload = e.get("payload_resumo", "") or e.get("http_corpo", "")
        n1 = f"ðŸŒ RequisiÃ§Ã£o HTTP {metodo} de **{origem}** para **{destino}** (navegaÃ§Ã£o web sem proteÃ§Ã£o)."
        n2 = f"O dispositivo acessou um site via HTTP. Todo o conteÃºdo da requisiÃ§Ã£o Ã© visÃ­vel na rede.\nPayload: {payload[:100]}"
        n3 = f"Metadados: Origem {origem}, Destino {destino}, MÃ©todo {metodo}"
        alerta = "TrÃ¡fego HTTP nÃ£o criptografado â€“ qualquer dado enviado pode ser interceptado."
        return self._base(e, "ðŸŒ", f"RequisiÃ§Ã£o HTTP {metodo}", "AVISO",
                          n1, n2, n3, "", f"{origem} --[HTTP]--> {destino}", alerta)

    #  DNS
    def _dns(self, e: dict) -> dict:
        origem  = e.get("ip_origem", "?")
        destino = e.get("ip_destino", "?")
        dominio = e.get("dominio", "")
        porta   = e.get("porta_destino") or 53
        tamanho = e.get("tamanho", 0)
        titulo  = f"Consulta DNS â€” {dominio}" if dominio else "Consulta DNS"
        fluxo   = self._fluxo(origem, "DNS/UDP", destino)
        n1 = (
            f"O computador <b>{origem}</b> estÃ¡ perguntando ao servidor DNS "
            f"qual Ã© o IP de <b style='color:#3498DB;'>{dominio or 'um domÃ­nio'}</b>.<br><br>"
            f"O DNS funciona como a lista telefÃ´nica da internet: vocÃª sabe "
            f"o nome do site, mas precisa do nÃºmero (IP) para se conectar."
        )
        n2 = (
            f"Consulta DNS de <b>{origem}</b> para <b>{destino}:{porta}</b> "
            f"via UDP â€” transmitida sem criptografia."
            + (f"<br>DomÃ­nio: <code style='color:#3498DB;'>{dominio}</code>" if dominio else "") +
            f"<br><br><b>Alerta Privacidade:</b> consultas DNS padrÃ£o sÃ£o "
            f"visÃ­veis para todos na rede. SoluÃ§Ã£o: DNS over HTTPS (DoH) "
            f"ou DNS over TLS (DoT)."
        )
        campos = [
            ("IP Origem",        origem),
            ("Servidor DNS",     destino),
            ("DomÃ­nio",          dominio or "â€”"),
            ("Porta",            f"UDP/{porta}"),
            ("Tamanho",          f"{tamanho} bytes"),
            ("Criptografado",    " NÃ£o"),
        ]
        n3 = self._tabela_campos(campos)
        alerta = "Consulta DNS sem criptografia â€“ qualquer um na rede vÃª os sites que vocÃª acessa."
        return self._base(e, "", titulo, "INFO", n1, n2, n3, "", fluxo, alerta)

    #  HTTPS
    def _https(self, e: dict) -> dict:
        origem  = e.get("ip_origem", "?")
        destino = e.get("ip_destino", "?")
        sni     = e.get("tls_sni", "")
        porta   = e.get("porta_destino") or 443
        tamanho = e.get("tamanho", 0)
        flags   = e.get("flags_tcp", "")
        alvo    = sni or destino
        titulo  = f"HTTPS protegido â€” {alvo}"
        fluxo   = self._fluxo(origem, "HTTPS ", f"{alvo}:{porta}")

        fase = ""
        if flags and "S" in flags and "A" not in flags:
            fase = "InÃ­cio do handshake TCP (SYN) â€” precede o TLS"
        elif sni:
            fase = "TLS ClientHello â€” SNI extraÃ­do com sucesso"

        n1 = (
            f"O computador <b>{origem}</b> estÃ¡ acessando "
            f"<b style='color:#2ECC71;'>{alvo}</b> com HTTPS.<br><br>"
            f"Mesmo capturando todos os pacotes, o conteÃºdo Ã© ilegÃ­vel â€” "
            f"cifrado com TLS. Senhas e dados pessoais estÃ£o protegidos. "
            f"O sniffer sÃ³ enxerga IPs, porta e o SNI (nome do host no certificado)."
        )
        n2 = (
            f"ConexÃ£o HTTPS de <b>{origem}</b> para <b>{alvo}:{porta}</b>."
            + (f"<br>Fase detectada: {fase}" if fase else "")
            + (f"<br>SNI: <code style='color:#2ECC71;'>{sni}</code>" if sni else "") +
            f"<br><br>O TLS Handshake negocia uma chave de sessÃ£o Ãºnica que "
            f"cifra todo o trÃ¡fego. Perfect Forward Secrecy garante que sessÃµes "
            f"passadas nÃ£o possam ser decifradas mesmo com vazamento futuro da chave. "
            f"Se o SNI revelar serviÃ§os sensÃ­veis (ex.: admin), considere ESNI/HTTP/3 para "
            f"ocultar o host."
        )
        campos = [
            ("IP Origem",       origem),
            ("DomÃ­nio (SNI)",   sni or "nÃ£o extraÃ­do neste pacote"),
            ("IP Destino",      destino),
            ("Porta",           str(porta)),
            ("Flags TCP",       flags or "â€”"),
            ("Tamanho",         f"{tamanho} bytes"),
            ("Criptografado",   " Sim â€” AES-256 via TLS"),
        ]
        n3 = self._tabela_campos(campos)
        return self._base(e, "", titulo, "INFO", n1, n2, n3, "", fluxo)

    #  TCP SYN
    def _tcp_syn(self, e: dict) -> dict:
        origem  = e.get("ip_origem", "?")
        destino = e.get("ip_destino", "?")
        porta   = e.get("porta_destino", "?")
        ttl     = e.get("ttl")
        tamanho = e.get("tamanho", 0)
        os_info = self._estimar_os(ttl)
        titulo  = f"InÃ­cio de conexÃ£o TCP â†’ {destino}:{porta}"
        fluxo   = self._fluxo(origem, "TCP SYN", f"{destino}:{porta}")

        n1 = (
            f"<b>{origem}</b> estÃ¡ iniciando uma conexÃ£o com "
            f"<b>{destino}:{porta}</b>.<br><br>"
            f"O TCP realiza um 'aperto de mÃ£o' em 3 etapas antes de transmitir "
            f"dados, garantindo que ambos os lados estÃ£o prontos."
        )
        n2 = (
            f"<b>Passo 1/3 â€” SYN</b> de <b>{origem}</b> para "
            f"<b>{destino}:{porta}</b>."
            + (f"<br>OS estimado pelo TTL: <b>{os_info}</b>" if os_info else "") +
            f"<br><br>PrÃ³ximas etapas: SYN-ACK (servidor) â†’ ACK (cliente) "
            f"â†’ conexÃ£o estabelecida e pronta para transmitir dados."
        )
        campos = [
            ("IP Origem",          origem),
            ("IP Destino",         f"{destino}:{porta}"),
            ("Flags TCP",          "SYN"),
            ("TTL",                f"{ttl} â€” {os_info}" if ttl and os_info else str(ttl) if ttl else "â€”"),
            ("Tamanho",            f"{tamanho} bytes"),
            ("Fase do handshake",  "1/3 â€” SYN enviado"),
        ]
        n3 = self._tabela_campos(campos)
        return self._base(e, "", titulo, "INFO", n1, n2, n3, "", fluxo)

    #  TCP FIN
    def _tcp_fin(self, e: dict) -> dict:
        origem  = e.get("ip_origem", "?")
        destino = e.get("ip_destino", "?")
        tamanho = e.get("tamanho", 0)
        titulo  = f"Encerramento TCP â€” {origem} â†’ {destino}"
        fluxo   = self._fluxo(origem, "TCP FIN", destino)
        n1 = (
            f"<b>{origem}</b> estÃ¡ encerrando a conexÃ£o com <b>{destino}</b>.<br><br>"
            f"A flag FIN encerra a conexÃ£o educadamente, garantindo entrega "
            f"de todos os dados pendentes antes do fechamento."
        )
        n2 = (
            "Encerramento TCP em 4 etapas: FIN â†’ ACK â†’ FIN â†’ ACK. "
            "ApÃ³s o fechamento, o estado TIME_WAIT persiste ~60s para "
            "absorver pacotes atrasados da sessÃ£o."
        )
        n3 = self._tabela_campos([
            ("IP Origem",  origem),
            ("IP Destino", destino),
            ("Tamanho",    f"{tamanho} bytes"),
        ])
        return self._base(e, "", titulo, "INFO", n1, n2, n3, "", fluxo)

    #  TCP RST
    def _tcp_rst(self, e: dict) -> dict:
        origem  = e.get("ip_origem", "?")
        destino = e.get("ip_destino", "?")
        porta   = e.get("porta_destino", "?")
        titulo  = f"ConexÃ£o recusada (RST) â€” {destino}:{porta}"
        fluxo   = self._fluxo(origem, "TCP RST Alerta", destino)
        n1 = (
            f"A conexÃ£o com <b>{destino}:{porta}</b> foi recusada abruptamente.<br><br>"
            f"Indica porta fechada, firewall bloqueando ou serviÃ§o indisponÃ­vel."
        )
        n2 = (
            "Flag RST encerra a conexÃ£o imediatamente sem negociaÃ§Ã£o. "
            "Diferente do FIN, nenhum dado pendente Ã© entregue. "
            "RSTs frequentes podem indicar port scanning."
        )
        n3 = self._tabela_campos([
            ("IP Origem",   origem),
            ("IP Destino",  f"{destino}:{porta}"),
            ("Flags TCP",   "RST â€” reset abrupto"),
        ])
        alerta = f"ConexÃ£o recusada na porta {porta} â€“ pode ser firewall ou serviÃ§o inexistente."
        return self._base(e, "", titulo, "AVISO", n1, n2, n3, "", fluxo, alerta)

    #  ICMP
    def _icmp(self, e: dict) -> dict:
        origem  = e.get("ip_origem", "?")
        destino = e.get("ip_destino", "?")
        ttl     = e.get("ttl")
        tamanho = e.get("tamanho", 0)
        payload = e.get("payload_resumo", "")
        os_info = self._estimar_os(ttl)
        titulo  = f"Ping ICMP â€” {origem} â†’ {destino}"
        fluxo   = self._fluxo(origem, "ICMP", destino)

        saltos = None
        if ttl:
            try:
                t = int(ttl)
                saltos = (128 - t if t >= 120 else 64 - t if t >= 55 else 32 - t)
            except Exception:
                pass

        n1 = (
            f"<b>{origem}</b> estÃ¡ verificando se <b>{destino}</b> estÃ¡ "
            f"acessÃ­vel e medindo a latÃªncia da conexÃ£o."
        )
        n2 = (
            f"ICMP Echo Request de <b>{origem}</b> para <b>{destino}</b>."
            + (f"<br>TTL={ttl} â†’ aprox. <b>{saltos} salto(s)</b> ({os_info})."
               if ttl and saltos is not None else "")
        )
        campos = [
            ("IP Origem",       origem),
            ("IP Destino",      destino),
            ("TTL",             str(ttl) if ttl else "â€”"),
            ("OS estimado",     os_info),
            ("Saltos",          str(saltos) if saltos is not None else "â€”"),
            ("Tamanho",         f"{tamanho} bytes"),
            ("Detalhe ICMP",    payload or "â€”"),
        ]
        n3 = self._tabela_campos(campos)
        return self._base(e, "", titulo, "INFO", n1, n2, n3, "", fluxo)

    #  ARP
    def _arp(self, e: dict) -> dict:
        origem  = e.get("ip_origem", "?")
        destino = e.get("ip_destino", "?")
        mac_src = e.get("mac_origem", "")
        titulo  = f"ARP â€” {origem} busca MAC de {destino}"
        fluxo   = self._fluxo(origem, "ARP broadcast", "FF:FF:FF:FF:FF:FF")
        n1 = (
            f"<b>{origem}</b> pergunta para a rede: "
            f"'Quem tem o IP <b>{destino}</b>? Me diga seu MAC.'"
        )
        fabricante = self._obter_fabricante(mac_src)
        n2 = (
            f"Broadcast ARP de <b>{origem}</b> (MAC {mac_src} - {fabricante}) "
            f"buscando o MAC de <b>{destino}</b>. "
            f"Sem autenticaÃ§Ã£o â€” vulnerÃ¡vel a ARP Spoofing (Man-in-the-Middle). "
            f"Verifique a tabela ARP: arp -a"
        )
        campos = [
            ("IP que pergunta",  origem),
            ("MAC que pergunta", f"{mac_src} ({fabricante})" if mac_src else "â€”"),
            ("IP sendo buscado", destino),
            ("Broadcast",        "FF:FF:FF:FF:FF:FF"),
        ]
        n3 = self._tabela_campos(campos)
        alerta = "ARP sem criptografia â€“ permite ataques de interceptaÃ§Ã£o (ARP spoofing)."
        return self._base(e, "", titulo, "INFO", n1, n2, n3, "", fluxo, alerta)

    #  DHCP
    def _dhcp(self, e: dict) -> dict:
        origem  = e.get("ip_origem", "?")
        destino = e.get("ip_destino", "?")
        tipo    = e.get("dhcp_tipo", "")
        titulo  = f"DHCP {tipo} â€” {origem}" if tipo else f"DHCP â€” {origem}"
        fluxo   = self._fluxo(origem, f"DHCP {tipo}", destino)
        descs = {
            "DISCOVER": "procurando servidor DHCP (broadcast)",
            "OFFER":    "recebeu oferta de IP do servidor DHCP",
            "REQUEST":  "solicitando formalmente o IP oferecido",
            "ACK":      "IP concedido com sucesso!",
            "NAK":      "IP recusado pelo servidor DHCP",
            "RELEASE":  "liberando o IP de volta ao servidor",
        }
        n1 = (
            f"<b>{origem}</b> {descs.get(tipo, 'trocou mensagem DHCP')}.<br><br>"
            f"O DHCP distribui IPs automaticamente via processo DORA: "
            f"Discover â†’ Offer â†’ Request â†’ Ack."
        )
        n2 = (
            f"Mensagem DHCP {tipo}. AlÃ©m do IP, o DHCP entrega: "
            f"mÃ¡scara de sub-rede, gateway padrÃ£o e servidores DNS."
        )
        campos = [
            ("IP Origem",  origem),
            ("IP Destino", destino),
            ("Tipo DHCP",  tipo or "â€”"),
        ]
        n3 = self._tabela_campos(campos)
        alerta = "DHCP sem autenticaÃ§Ã£o â€“ pode haver servidor DHCP falso (ataque de rogue DHCP)."
        return self._base(e, "", titulo, "INFO", n1, n2, n3, "", fluxo, alerta)

    #  SSH
    def _ssh(self, e: dict) -> dict:
        origem  = e.get("ip_origem", "?")
        destino = e.get("ip_destino", "?")
        porta   = e.get("porta_destino") or 22
        titulo  = f"SSH â€” Acesso remoto a {destino}"
        fluxo   = self._fluxo(origem, "SSH ", f"{destino}:{porta}")
        n1 = (
            f"<b>{origem}</b> estÃ¡ acessando o terminal de <b>{destino}</b> "
            f"via SSH â€” protocolo completamente criptografado."
        )
        n2 = (
            f"SessÃ£o SSH porta {porta}. Todo trÃ¡fego cifrado. "
            f"AutenticaÃ§Ã£o por senha ou chave pÃºblica/privada."
        )
        campos = [
            ("IP Origem",    origem),
            ("IP Destino",   f"{destino}:{porta}"),
            ("Criptografado"," Sim"),
        ]
        n3 = self._tabela_campos(campos)
        return self._base(e, "ï¸", titulo, "INFO", n1, n2, n3, "", fluxo)

    #  FTP
    def _ftp(self, e: dict) -> dict:
        origem  = e.get("ip_origem", "?")
        destino = e.get("ip_destino", "?")
        porta   = e.get("porta_destino") or 21
        titulo  = f"FTP sem criptografia â€” {destino}"
        fluxo   = self._fluxo(origem, "FTP Alerta", destino)
        n1 = (
            f"<b>{origem}</b> estÃ¡ transferindo arquivos via FTP para "
            f"<b>{destino}</b> â€” sem criptografia. "
            f"UsuÃ¡rio e senha trafegam em texto puro."
        )
        n2 = (
            f"FTP porta {porta} â€” credenciais visÃ­veis na rede. "
            f"Use SFTP (porta 22) ou FTPS como alternativa segura."
        )
        campos = [
            ("IP Origem",    origem),
            ("IP Destino",   f"{destino}:{porta}"),
            ("Criptografado"," NÃ£o â€” texto puro"),
        ]
        n3 = self._tabela_campos(campos)
        alerta = "FTP transmite credenciais em texto puro â€“ risco alto de captura de senha."
        return self._base(e, "", titulo, "AVISO", n1, n2, n3, "", fluxo, alerta)

    #  SMB
    def _smb(self, e: dict) -> dict:
        origem  = e.get("ip_origem", "?")
        destino = e.get("ip_destino", "?")
        titulo  = f"SMB â€” Compartilhamento {destino}"
        fluxo   = self._fluxo(origem, "SMB", destino)
        n1 = (
            f"<b>{origem}</b> estÃ¡ acessando arquivos compartilhados em "
            f"<b>{destino}</b> via SMB (porta 445)."
        )
        n2 = (
            "Vulnerabilidade histÃ³rica: EternalBlue (MS17-010) no SMBv1 "
            "foi explorado pelo WannaCry em 2017. "
            "Verifique: Get-SmbServerConfiguration | Select EnableSMB1Protocol"
        )
        campos = [
            ("IP Origem",  origem),
            ("IP Destino", destino),
            ("Porta",      "445"),
        ]
        n3 = self._tabela_campos(campos)
        alerta = "TrÃ¡fego SMB â€“ verifique permissÃµes de compartilhamento."
        return self._base(e, "", titulo, "AVISO", n1, n2, n3, "", fluxo, alerta)

    #  RDP
    def _rdp(self, e: dict) -> dict:
        origem  = e.get("ip_origem", "?")
        destino = e.get("ip_destino", "?")
        titulo  = f"RDP â€” Ãrea de Trabalho Remota {destino}"
        fluxo   = self._fluxo(origem, "RDP Alerta", destino)
        n1 = (
            f"<b>{origem}</b> estÃ¡ controlando remotamente a tela de "
            f"<b>{destino}</b> via RDP (porta 3389)."
        )
        n2 = (
            "RDP exposto Ã  internet Ã© vetor crÃ­tico. Bots varrem a porta 3389 "
            "continuamente. Use NLA, VPN e monitore eventos 4625."
        )
        campos = [
            ("IP Origem",  origem),
            ("IP Destino", destino),
            ("Porta",      "3389"),
        ]
        n3 = self._tabela_campos(campos)
        alerta = "RDP exposto â€“ risco de ataque de forÃ§a bruta e BlueKeep."
        return self._base(e, "ï¸", titulo, "AVISO", n1, n2, n3, "", fluxo, alerta)

    #  NOVO_DISPOSITIVO
    def _novo_dispositivo(self, e: dict) -> dict:
        ip  = e.get("ip_origem", "?")
        mac = e.get("mac_origem", "")
        fabricante = self._obter_fabricante(mac) if mac else ""
        titulo = f"Novo dispositivo - {ip}"
        fluxo  = self._fluxo("Novo dispositivo", "DHCP/ARP", ip)
        n1 = (
            f"Novo dispositivo detectado na rede: IP <b>{ip}</b>.<br><br>"
            f"O DHCP distribuiu o endereco automaticamente via processo "
            f"DORA: Discover -> Offer -> Request -> Ack."
        )
        n2 = (
            f"IP: <b>{ip}</b>"
            + (f" | MAC: <code>{mac}</code> ({fabricante})" if mac else "") +
            f"<br>Os primeiros 3 bytes do MAC identificam o fabricante (OUI). "
            f"Consulte: macvendors.com"
        )
        campos = [
            ("IP detectado", ip),
            ("MAC",          f"{mac} ({fabricante})" if mac else "nao identificado"),
        ]
        n3 = self._tabela_campos(campos)
        alerta = f"Novo dispositivo conectado - verifique se é autorizado (MAC {mac})."
        return self._base(e, "", titulo, "INFO", n1, n2, n3, "", fluxo, alerta)

    #  GenÃ©rico
    def _generico(self, e: dict) -> dict:
        protocolo = e.get("protocolo", "Desconhecido")
        origem    = e.get("ip_origem", "?")
        destino   = e.get("ip_destino", "?")
        tamanho   = e.get("tamanho", 0)
        titulo    = f"{protocolo} â€” {origem} â†’ {destino}"
        fluxo     = self._fluxo(origem, protocolo, destino)
        n1 = f"Atividade de rede: <b>{protocolo}</b> de <b>{origem}</b> para <b>{destino}</b>."
        n2 = f"Protocolo <b>{protocolo}</b> capturado. Tamanho: {tamanho} bytes."
        n3 = self._tabela_campos([
            ("Protocolo",  protocolo),
            ("IP Origem",  origem),
            ("IP Destino", destino),
            ("Tamanho",    f"{tamanho} bytes"),
        ])
        return self._base(e, "", titulo, "INFO", n1, n2, n3, "", fluxo)

    def gerar_resumo_sessao(self, total_pacotes: int, total_bytes: int,
                             protocolos: list, total_dispositivos: int) -> str:
        mb    = total_bytes / (1024 * 1024)
        linhas = [
            " RESUMO DA SESSÃƒO", "-" * 36,
            f"Pacotes capturados:  {total_pacotes:>10,}",
            f"Volume transmitido:  {mb:>9.2f} MB",
            f"Dispositivos ativos: {total_dispositivos:>10}", "",
            "TOP PROTOCOLOS:",
        ]
        for item in protocolos[:6]:
            kb = item["bytes"] / 1024
            linhas.append(
                f"  {item['protocolo']:<12} {item['pacotes']:>6} pcts "
                f"({kb:.1f} KB)"
            )
        return "\n".join(linhas)
