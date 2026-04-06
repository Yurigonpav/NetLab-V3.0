# banco_dados.py
# Gerencia toda a persistência de dados usando SQLite.
# Armazena dispositivos, pacotes, eventos pedagógicos e sessões de monitoramento.

import sqlite3
import os
from typing import List, Optional


class BancoDados:
    """Interface com o banco de dados SQLite do NetLab Educacional."""

    def __init__(self, caminho_banco: Optional[str] = None):
        if caminho_banco is None:
            diretorio_dados = os.path.join(
                os.path.dirname(os.path.abspath(__file__)), "dados"
            )
            os.makedirs(diretorio_dados, exist_ok=True)
            caminho_banco = os.path.join(diretorio_dados, "historico.db")

        self.caminho_banco = caminho_banco
        self.conexao: Optional[sqlite3.Connection] = None

    def inicializar(self):
        """Abre a conexão e cria todas as tabelas necessárias."""
        self.conexao = sqlite3.connect(self.caminho_banco, check_same_thread=False)
        self.conexao.row_factory = sqlite3.Row
        cursor = self.conexao.cursor()

        # Tabela de dispositivos detectados na rede
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS dispositivos (
                id                INTEGER PRIMARY KEY AUTOINCREMENT,
                endereco_ip       TEXT NOT NULL,
                endereco_mac      TEXT,
                nome_host         TEXT,
                primeira_deteccao TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                ultima_deteccao   TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(endereco_ip)
            )
        """)

        # Tabela de pacotes capturados
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS pacotes (
                id             INTEGER PRIMARY KEY AUTOINCREMENT,
                registrado_em  TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                ip_origem      TEXT,
                ip_destino     TEXT,
                mac_origem     TEXT,
                mac_destino    TEXT,
                protocolo      TEXT,
                tamanho_bytes  INTEGER,
                porta_origem   INTEGER,
                porta_destino  INTEGER,
                sessao_id      INTEGER
            )
        """)

        # Tabela de eventos pedagógicos detectados
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS eventos (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                registrado_em TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                tipo_evento   TEXT,
                descricao     TEXT,
                ip_envolvido  TEXT,
                sessao_id     INTEGER
            )
        """)

        # Tabela de sessões de monitoramento
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS sessoes (
                id             INTEGER PRIMARY KEY AUTOINCREMENT,
                iniciada_em    TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                encerrada_em   TIMESTAMP,
                total_pacotes  INTEGER DEFAULT 0,
                total_bytes    INTEGER DEFAULT 0
            )
        """)

        self.conexao.commit()

    # ──────────────────────────────────────────────
    # Sessões
    # ──────────────────────────────────────────────

    def iniciar_sessao(self) -> int:
        """Registra o início de uma nova sessão e retorna seu ID."""
        cursor = self.conexao.cursor()
        cursor.execute("INSERT INTO sessoes (iniciada_em) VALUES (CURRENT_TIMESTAMP)")
        self.conexao.commit()
        return cursor.lastrowid

    def finalizar_sessao(self, sessao_id: int, total_pacotes: int, total_bytes: int):
        """Atualiza os totais e registra o fim da sessão."""
        cursor = self.conexao.cursor()
        cursor.execute("""
            UPDATE sessoes
            SET encerrada_em = CURRENT_TIMESTAMP,
                total_pacotes = ?,
                total_bytes   = ?
            WHERE id = ?
        """, (total_pacotes, total_bytes, sessao_id))
        self.conexao.commit()

    # ──────────────────────────────────────────────
    # Dispositivos
    # ──────────────────────────────────────────────

    def salvar_dispositivo(self, ip: str, mac: str = None, nome_host: str = None):
        """Insere um novo dispositivo ou atualiza dados de um existente."""
        cursor = self.conexao.cursor()
        cursor.execute("""
            INSERT INTO dispositivos (endereco_ip, endereco_mac, nome_host)
            VALUES (?, ?, ?)
            ON CONFLICT(endereco_ip) DO UPDATE SET
                endereco_mac    = COALESCE(excluded.endereco_mac, endereco_mac),
                nome_host       = COALESCE(excluded.nome_host, nome_host),
                ultima_deteccao = CURRENT_TIMESTAMP
        """, (ip, mac, nome_host))
        self.conexao.commit()

    def buscar_dispositivos(self) -> List[dict]:
        """Retorna todos os dispositivos registrados."""
        cursor = self.conexao.cursor()
        cursor.execute("SELECT * FROM dispositivos ORDER BY ultima_deteccao DESC")
        return [dict(linha) for linha in cursor.fetchall()]

    # ──────────────────────────────────────────────
    # Pacotes
    # ──────────────────────────────────────────────

    def salvar_pacote(self, ip_origem: str, ip_destino: str, mac_origem: str,
                      mac_destino: str, protocolo: str, tamanho_bytes: int,
                      porta_origem: int = None, porta_destino: int = None,
                      sessao_id: int = None):
        """Registra um pacote capturado no banco."""
        cursor = self.conexao.cursor()
        cursor.execute("""
            INSERT INTO pacotes
                (ip_origem, ip_destino, mac_origem, mac_destino,
                 protocolo, tamanho_bytes, porta_origem, porta_destino, sessao_id)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (ip_origem, ip_destino, mac_origem, mac_destino,
              protocolo, tamanho_bytes, porta_origem, porta_destino, sessao_id))
        self.conexao.commit()

    # ──────────────────────────────────────────────
    # Eventos
    # ──────────────────────────────────────────────

    def salvar_evento(self, tipo_evento: str, descricao: str,
                      ip_envolvido: str = None, sessao_id: int = None) -> int:
        """Persiste um evento pedagógico detectado."""
        cursor = self.conexao.cursor()
        cursor.execute("""
            INSERT INTO eventos (tipo_evento, descricao, ip_envolvido, sessao_id)
            VALUES (?, ?, ?, ?)
        """, (tipo_evento, descricao, ip_envolvido, sessao_id))
        self.conexao.commit()
        return cursor.lastrowid

    def buscar_eventos_recentes(self, limite: int = 100) -> List[dict]:
        """Retorna os eventos mais recentes, do mais novo ao mais antigo."""
        cursor = self.conexao.cursor()
        cursor.execute(
            "SELECT * FROM eventos ORDER BY registrado_em DESC LIMIT ?", (limite,)
        )
        return [dict(linha) for linha in cursor.fetchall()]

    # ──────────────────────────────────────────────
    # Estatísticas
    # ──────────────────────────────────────────────

    def buscar_estatisticas_protocolo(self, sessao_id: int = None) -> List[dict]:
        """Retorna contagem e volume de dados por protocolo."""
        cursor = self.conexao.cursor()
        if sessao_id:
            cursor.execute("""
                SELECT protocolo,
                       COUNT(*)          AS quantidade,
                       SUM(tamanho_bytes) AS total_bytes
                FROM pacotes
                WHERE sessao_id = ?
                GROUP BY protocolo
                ORDER BY quantidade DESC
            """, (sessao_id,))
        else:
            cursor.execute("""
                SELECT protocolo,
                       COUNT(*)          AS quantidade,
                       SUM(tamanho_bytes) AS total_bytes
                FROM pacotes
                GROUP BY protocolo
                ORDER BY quantidade DESC
            """)
        return [dict(linha) for linha in cursor.fetchall()]

    def fechar(self):
        """Encerra a conexão com o banco de dados."""
        if self.conexao:
            self.conexao.close()