# main.py
# Ponto de entrada do NetLab Educacional.
# Inicializa a aplicação Qt, aplica o tema visual e abre a janela principal.

import sys
import os

from PyQt6.QtWidgets import QApplication, QStyleFactory
from PyQt6.QtCore import Qt
from PyQt6.QtGui import QPalette, QColor

from interface.janela_principal import JanelaPrincipal
from banco_dados import BancoDados


def resource_path(relative_path):
    """Retorna o caminho absoluto para um recurso, compatível com PyInstaller."""
    try:
        base_path = sys._MEIPASS
    except Exception:
        base_path = os.path.abspath(".")
    return os.path.join(base_path, relative_path)


def iniciar_aplicacao():
    """Configura e inicializa toda a aplicação."""

    # Necessário antes de criar QApplication no Windows com HiDPI
    os.environ.setdefault("QT_AUTO_SCREEN_SCALE_FACTOR", "1")

    app = QApplication(sys.argv)

    # Forçar estilo Fusion para consistência entre ambientes
    app.setStyle(QStyleFactory.create("Fusion"))

    # Metadados da aplicação
    app.setApplicationName("NetLab Educacional")
    app.setApplicationVersion("2.1")
    app.setOrganizationName("TCC - Técnico em Informática - Yuri Gonçalves Pavão")

    # Carregar folha de estilos personalizada (tema escuro) usando resource_path
    caminho_estilo = resource_path(os.path.join("recursos", "estilos", "tema_escuro.qss"))

    if os.path.exists(caminho_estilo):
        with open(caminho_estilo, "r", encoding="utf-8") as arquivo:
            app.setStyleSheet(arquivo.read())
        print(f"Estilo carregado de: {caminho_estilo}")
    else:
        print(f"ERRO: Arquivo de estilo não encontrado em {caminho_estilo}")
        print("   Verifique se o arquivo foi incluído no build com --add-data")

    # Inicializar banco de dados
    banco = BancoDados()
    banco.inicializar()

    # Criar e exibir a janela principal
    janela = JanelaPrincipal(banco)
    janela.show()

    sys.exit(app.exec())


if __name__ == "__main__":
    iniciar_aplicacao()


