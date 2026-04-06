<div align="center">

<img src="https://img.shields.io/badge/Python-3.11-3776AB?style=for-the-badge&logo=python&logoColor=white"/>
<img src="https://img.shields.io/badge/PyQt6-6.x-41CD52?style=for-the-badge&logo=qt&logoColor=white"/>
<img src="https://img.shields.io/badge/Scapy-2.x-E34F26?style=for-the-badge"/>
<img src="https://img.shields.io/badge/SQLite-3-003B57?style=for-the-badge&logo=sqlite&logoColor=white"/>
<img src="https://img.shields.io/badge/Windows-10%2F11-0078D4?style=for-the-badge&logo=windows&logoColor=white"/>
<img src="https://img.shields.io/badge/Npcap-1.87-222222?style=for-the-badge"/>

<br/><br/>

# 🔬 NetLab Educacional

**Software desktop de monitoramento e análise de redes com foco pedagógico.**  
Captura pacotes em tempo real, visualiza a topologia da rede local e explica cada evento  
de rede em três níveis de profundidade — do iniciante ao técnico.

<br/>

> 📌 **Trabalho de Conclusão de Curso — Curso Técnico em Informática**  
> Instituto Federal Farroupilha (IFFar) — Campus Uruguaiana  
> Autor: **Yuri Gonçalves Pavão**

<br/>

[Funcionalidades](#-funcionalidades) •
[Demonstração](#-demonstração) •
[Requisitos](#-requisitos) •
[Instalação](#-instalação) •
[Arquitetura](#-arquitetura) •
[Como Usar](#-como-usar) •
[Tecnologias](#-tecnologias)

</div>

---

## 📖 Sobre o Projeto

O **NetLab Educacional** foi desenvolvido como ferramenta de apoio ao ensino de redes de computadores em ambiente escolar. O objetivo é transformar dados técnicos brutos de pacotes de rede — como flags TCP, queries DNS e payloads HTTP — em explicações didáticas automáticas, acessíveis a alunos em diferentes níveis de conhecimento.

O software funciona como um **Wireshark didático**: captura o tráfego real da rede, mas em vez de exibir campos hexadecimais crípticos, gera explicações em linguagem natural com analogias do cotidiano, análise técnica dos protocolos e visualização do pacote bruto.

### Diferenciais pedagógicos

- **Três níveis de explicação** para cada evento capturado: *Simples*, *Técnico* e *Pacote Bruto*
- **Alertas de segurança automáticos** — identifica credenciais expostas em HTTP, ARP spoofing, port scanning e sessões FTP/RDP sem criptografia
- **Servidor HTTP embutido** para demonstrações ao vivo de ataques e defesas (modo vulnerável × modo seguro com PBKDF2 + rate limiting + CAPTCHA)
- **Laboratório de autenticação** (`painel_login_seguro.py`) — simula ataques de força bruta e compara métricas entre sistemas vulneráveis e protegidos

---

## ✨ Funcionalidades

| Módulo | Descrição |
|--------|-----------|
| 🔴 **Captura em Tempo Real** | Captura pacotes IP via Scapy/Npcap com suporte a TCP, UDP, DNS, ARP, ICMP e HTTP (DPI) |
| 🗺️ **Topologia Interativa** | Mapa visual com zoom, pan, hover e detalhes de cada nó (IP, MAC, fabricante, portas) |
| 📊 **Painel de Tráfego** | Gráfico KB/s com janela deslizante de 60s, ranking de protocolos e top dispositivos |
| 🎓 **Motor Pedagógico** | Explicações automáticas em 3 níveis com análise de segurança, hexdump e headers HTTP |
| 🌐 **Servidor HTTP** | Servidor educacional com páginas de login/formulário e proteção anti-DoS configurável |
| 🔐 **Lab de Segurança** | Comparação interativa de sistemas de login com brute force simulado e métricas reais |
| 🗄️ **Persistência SQLite** | Histórico completo de sessões, pacotes e eventos com escrita assíncrona |
| 🔍 **Descoberta ARP + ICMP** | Varredura automática da rede local em duas fases com suporte a redes com client isolation |

---

## 🎬 Demonstração

```
┌─────────────────────────────────────────────────────────────────┐
│  NetLab Educacional v2.1          Interface: Intel Wi-Fi 6 AX   │
│  [Iniciar Captura]    Meu IP: 192.168.1.10                      │
├──────────────────┬──────────────────────────────────────────────┤
│  Topologia       │  Tráfego em Tempo Real                       │
│  da Rede         │                                              │
│                  │  TOTAL PACOTES    VELOCIDADE    DADOS        │
│   .10 ●──────● .1│    12.847          84.3 KB/s   6.2 MB       │
│        \      /  │                                              │
│    .15 ● ● .20   │  ████████████████░░░░  Gráfico KB/s [60s]   │
│                  │                                              │
├──────────────────┴──────────────────────────────────────────────┤
│  Modo Análise — Evento Selecionado                              │
│                                                                 │
│  ⚠ HTTP sem criptografia — POST 192.168.1.15 → 203.0.113.10    │
│                                                                 │
│  [Simples ✓] [Técnico] [Pacote Bruto]                          │
│                                                                 │
│  O computador 192.168.1.15 enviou um formulário de login via   │
│  HTTP. Qualquer pessoa na mesma rede Wi-Fi pode ler os dados   │
│  exatamente como foram enviados — incluindo a senha.           │
│                                                                 │
│  ⚠ ALERTA: usuario=admin  senha=123456  [EXPOSTO EM TEXTO PURO]│
└─────────────────────────────────────────────────────────────────┘
```

---

## 📋 Requisitos

### Sistema

| Componente | Mínimo | Recomendado |
|------------|--------|-------------|
| Sistema Operacional | Windows 10 64-bit | Windows 11 64-bit |
| Processador | Intel Core i3 / 1.5 GHz | Intel Core i5 ou superior |
| Memória RAM | 4 GB | 8 GB |
| Espaço em disco | 500 MB | 1 GB |

### Dependências obrigatórias

- **[Npcap 1.87+](https://npcap.com/)** — driver de captura de pacotes (com *WinPcap API-compatible mode* ativado)
- **Python 3.11+** — incluído no instalador
- **Execução como Administrador** — obrigatória para captura de pacotes

### Dependências Python

```
PyQt6
scapy
pyqtgraph
cryptography
reportlab
```

> **Nota:** Todas as dependências Python são instaladas automaticamente pelo instalador ou pelo `pip install -r requirements.txt`.

---

## 🚀 Instalação

### Opção 1 — Instalador (recomendado para usuários finais)

1. Baixe o `NetLab_Setup.exe` na seção [Releases](../../releases)
2. Execute como Administrador
3. Na instalação do Npcap, marque ✅ **WinPcap API-compatible mode**
4. Conclua a instalação — um atalho será criado na Área de Trabalho

### Opção 2 — Execução via código-fonte

```bash
# 1. Clone o repositório
git clone https://github.com/seu-usuario/netlab-educacional.git
cd netlab-educacional

# 2. Crie e ative o ambiente virtual
python -m venv .venv
.venv\Scripts\activate

# 3. Instale as dependências
pip install -r requirements.txt

# 4. (Opcional) Compile o parser HTTP em C para máxima performance
python compilar_http_parser.py

# 5. Execute como Administrador
python main.py
```

> ⚠️ **Importante:** o Npcap deve estar instalado antes de executar o software. Baixe em [npcap.com](https://npcap.com) e instale com a opção *WinPcap API-compatible mode* marcada.

### Opção 3 — Build do executável

```bash
# Gera o executável em dist/NetLab/
build_exe.bat

# Ou diretamente com PyInstaller usando o spec incluído
pyinstaller NetLab.spec
```

### Diagnóstico de interface

Se nenhum pacote for capturado, execute o diagnóstico para identificar a interface correta:

```bash
# Execute como Administrador e acesse sites durante o teste
python diagnostico.py
```

---

## 🏗️ Arquitetura

```
netlab-educacional/
│
├── main.py                      # Ponto de entrada — inicializa Qt e banco de dados
│
├── analisador_pacotes.py        # Motor de análise (3 camadas: C parser + thread + filas)
├── motor_pedagogico.py          # Gerador de explicações didáticas por tipo de evento
├── banco_dados.py               # Persistência SQLite com escrita assíncrona
│
├── interface/
│   ├── janela_principal.py      # Janela principal — coordena todos os módulos
│   ├── painel_topologia.py      # Visualizador interativo de topologia (canvas Qt)
│   ├── painel_trafego.py        # Gráfico KB/s + tabelas de protocolos/dispositivos
│   ├── painel_eventos.py        # Modo Análise — eventos + insights + filtros
│   └── painel_login_seguro.py   # Lab de segurança — brute force + comparação
│
├── painel_servidor.py           # Servidor HTTP educacional com proteção anti-DoS
│
├── http_parser.c                # Parser HTTP em C (ctypes) — hot-path de DPI
├── compilar_http_parser.py      # Compila http_parser.c → .dll/.so
│
├── recursos/estilos/
│   └── tema_escuro.qss          # Folha de estilos Qt (tema escuro)
│
├── diagnostico.py               # Ferramenta de diagnóstico de interfaces
├── requirements.txt
├── NetLab.spec                  # Configuração PyInstaller
├── build_exe.bat                # Script de build automatizado
└── setup_script.iss             # Script Inno Setup (instalador Windows)
```

### Fluxo de dados

```
Scapy/Npcap                    ThreadAnalisador              UI Thread (Qt)
────────────                   ────────────────              ─────────────
Captura pacote  →  fila_global  →  analisa lote  →  fila_saída  →  timer 250ms
                   (maxlen=5000)   (100 pcts)       (maxlen=2000)    coleta eventos
                                                                       │
                                                               _WorkerRunnable
                                                               (QThreadPool, 4 workers)
                                                                       │
                                                               MotorPedagogico
                                                               gera explicação
                                                                       │
                                                               PainelEventos
                                                               exibe cartão
                                                                       │
                                                               _EscritorBanco
                                                               commit assíncrono
```

### Decisões de design notáveis

- **Zero travamento de UI:** commits SQLite delegados a `_EscritorBanco` (thread daemon); análise de pacotes na `ThreadAnalisador`; explicações pedagógicas no `QThreadPool` (máx. 4 workers)
- **Parser HTTP em C:** `http_parser.c` compilado via `ctypes` para o hot-path de DPI — até 10× mais rápido que `re.match()` em Python; fallback automático para Python se a DLL não for encontrada
- **Filas circulares com descarte automático:** `deque(maxlen=N)` em todas as filas — nunca trava por OOM em capturas de alto volume
- **EMA para suavização de KB/s:** média móvel exponencial (α=0,3) elimina spikes no gráfico sem introduzir atraso perceptível

---

## 📖 Como Usar

### Monitoramento básico

1. Abra o NetLab **como Administrador**
2. Selecione a interface de rede no campo `Interface:` da barra de ferramentas
3. Clique em **Iniciar Captura**
4. Acesse sites no navegador — eventos aparecerão automaticamente no **Modo Análise**
5. Clique em qualquer evento para ver a explicação nos três níveis

### Demonstração de segurança em sala de aula

```
Professor:
  1. Aba "Servidor" → Iniciar Servidor (porta 8080)
  2. Selecionar "Versão vulnerável"
  3. Compartilhar o endereço http://<IP>:8080/login com os alunos

Alunos (em seus dispositivos):
  → Acessam o endereço e preenchem o formulário de login

Professor (no NetLab):
  → Aba "Modo Análise" → filtro HTTP
  → Mostra as credenciais capturadas em texto puro em tempo real
  → Alterna para "Versão segura" e demonstra a diferença
```

### Filtros de eventos

| Filtro | Como usar |
|--------|-----------|
| Por protocolo | Combo `Filtrar:` → selecione DNS, HTTP, HTTPS, ARP... |
| Por IP/domínio | Campo de busca → digite o IP ou nome de domínio |
| Nível de detalhe | Botões `Simples` / `Técnico` / `Pacote Bruto` |

---

## 🛠️ Tecnologias

| Tecnologia | Versão | Uso |
|-----------|--------|-----|
| **Python** | 3.11 | Linguagem principal |
| **PyQt6** | 6.x | Interface gráfica |
| **Scapy** | 2.x | Captura e análise de pacotes |
| **PyQtGraph** | 0.13+ | Gráfico de tráfego em tempo real |
| **SQLite** | 3 | Persistência de dados (via `sqlite3` stdlib) |
| **ReportLab** | 4.x | Geração de relatórios PDF |
| **Cryptography** | 41+ | SSL/TLS para o servidor HTTPS embutido |
| **Npcap** | 1.87 | Driver de captura (Windows) |
| **PyInstaller** | 6.x | Geração do executável |
| **Inno Setup** | 6.x | Instalador Windows |
| **C (gcc/MSVC)** | — | Parser HTTP de alta performance (ctypes) |

---

## 🔒 Segurança e Privacidade

> **O NetLab Educacional é uma ferramenta pedagógica** destinada ao uso em ambientes controlados (sala de aula, laboratório de informática) com autorização explícita dos participantes.

- A captura de pacotes é **passiva** — não injeta tráfego nem modifica dados
- O software captura apenas o tráfego que passa pela interface selecionada
- Todos os dados capturados ficam **armazenados localmente** no dispositivo
- O uso em redes sem autorização dos proprietários e usuários pode violar leis de privacidade

---

## 🐛 Problemas Conhecidos

| Problema | Causa | Solução |
|---------|-------|---------|
| Nenhum pacote capturado | Npcap sem WinPcap mode ou sem admin | Reinstale o Npcap; execute como Administrador |
| `WinError 10013` no servidor | Porta 80/443 reservada pelo Windows | Use porta ≥ 1024 (padrão: 8080) |
| Poucos dispositivos no mapa | Client isolation ativo no Wi-Fi | Use cabo Ethernet ou rede sem isolamento |
| Alto uso de CPU | Rede de alto volume | Normal em redes movimentadas; o descarte automático de filas protege a memória |
| Interface não reconhecida | Npcap desatualizado | Atualize o Npcap para 1.87+ |

---

## 📄 Licença

Este projeto foi desenvolvido exclusivamente para fins acadêmicos como parte do **Trabalho de Conclusão de Curso** do Curso Técnico em Informática do Instituto Federal Farroupilha — Campus Uruguaiana.

---

<div align="center">

Desenvolvido por **Yuri Gonçalves Pavão**  
Instituto Federal Farroupilha — Campus Uruguaiana  
Curso Técnico em Informática — 2026

</div>
