<div align="center">

# 🌐 NetLab 

### Monitor de Redes com Motor
*Transformando pacotes de rede em conhecimento didático em tempo real*

---

![Python](https://img.shields.io/badge/Python-3.11-3776AB?style=for-the-badge&logo=python&logoColor=white)
![PyQt6](https://img.shields.io/badge/PyQt6-6.x-41CD52?style=for-the-badge&logo=qt&logoColor=white)
![Scapy](https://img.shields.io/badge/Scapy-2.x-FF6B35?style=for-the-badge)
![SQLite](https://img.shields.io/badge/SQLite-3-003B57?style=for-the-badge&logo=sqlite&logoColor=white)
![Windows](https://img.shields.io/badge/Windows-10%2F11-0078D4?style=for-the-badge&logo=windows&logoColor=white)
![License](https://img.shields.io/badge/Licença-Acadêmica%20%2F%20Educacional-green?style=for-the-badge)

**TCC — Curso Técnico em Informática**  
**Instituto Federal Farroupilha — Campus Uruguaiana**  
**Autor: Yuri Gonçalves Pavão · Versão 3.0 · abril de 2026**

</div>

---

## 📋 Índice

- [Sobre o Projeto](#-sobre-o-projeto)
- [Funcionalidades](#-funcionalidades)
- [Arquitetura do Sistema](#-arquitetura-do-sistema)
- [Tecnologias Utilizadas](#-tecnologias-utilizadas)
- [Requisitos do Sistema](#-requisitos-do-sistema)
- [Instalação](#-instalação)
- [Como Usar](#-como-usar)
- [Estrutura do Projeto](#-estrutura-do-projeto)
- [Detalhes Técnicos](#-detalhes-técnicos)
- [Contexto Acadêmico](#-contexto-acadêmico)
- [Limitações Conhecidas](#-limitações-conhecidas)
- [Licença](#-licença)

---

## Sobre o Projeto

O **NetLab Educacional** é um software desktop de análise de redes concebido como ferramenta pedagógica para o ensino de redes de computadores em ambiente escolar. Funciona de forma conceitual similar a um Wireshark didático: captura tráfego real da rede e, em vez de exibir apenas dados brutos, traduz cada evento automaticamente em **explicações acessíveis em três níveis de profundidade**.

O projeto foi desenvolvido como **Trabalho de Conclusão de Curso (TCC)** do Curso Técnico em Informática do **Instituto Federal Farroupilha (IFFar) — Campus Uruguaiana**, com foco em tornar conceitos complexos de redes — como pacotes IP, handshakes TCP, consultas DNS e vulnerabilidades HTTP — compreensíveis para estudantes de qualquer nível.

### Por que o NetLab existe?

O ensino de redes frequentemente esbarra em uma barreira: ferramentas profissionais como Wireshark são poderosas, mas mostram dados técnicos crus que intimidam iniciantes. O NetLab preenche essa lacuna ao:

- **Capturar tráfego real** da rede local sem intermediários
- **Explicar automaticamente** cada evento em linguagem simples, técnica ou como dump bruto
- **Visualizar a topologia** da rede de forma interativa e intuitiva
- **Demonstrar vulnerabilidades** de segurança de forma controlada e didática (HTTP vs HTTPS, brute force, DoS)

---

## Funcionalidades

### Captura e Análise de Pacotes
- Captura em tempo real via **Scapy + Npcap** com suporte a TCP, UDP, DNS, ARP, ICMP, HTTP, HTTPS, DHCP, SSH, FTP, SMB e RDP
- **Deep Packet Inspection (DPI)** para HTTP: extrai método, caminho, headers, corpo do formulário e credenciais em texto puro
- Parser HTTP em **C nativo (ctypes)** para hot-path de alta performance, com fallback Python transparente
- Detecção automática de **campos sensíveis** (senhas, tokens, e-mails) e alertas de segurança
- Identificação de OS por TTL e fabricante por OUI (MAC address)

### Motor Pedagógico com 3 Níveis de Explicação
- **Nível Simples** — linguagem do dia a dia, sem jargão técnico, acessível a qualquer estudante
- **Nível Técnico** — detalhes de protocolo, portas, flags, vulnerabilidades e boas práticas
- **Pacote Bruto** — conteúdo exato como trafegou na rede, com hexdump + ASCII e visualização de headers HTTP destacados
- Análise automática de **indicadores de ataque**: injeção SQL, XSS, métodos HTTP incomuns, cookies expostos, headers de segurança ausentes
- Cooldown inteligente por evento para evitar flood na interface em redes movimentadas

### Visualizador de Topologia Interativo
- Mapa gráfico da rede local com zoom (scroll), pan (arrastar) e seleção de nós
- Tamanho dos nós proporcional ao volume de tráfego (escala logarítmica)
- Tooltip com hostname e IP ao passar o mouse; painel de detalhes ao clicar
- Destaque de conexões ao selecionar um dispositivo
- **ARP sweep automático** com múltiplas rodadas e retry para descoberta de hosts em redes com switches gerenciados
- Agrupamento de IPs externos em nó "Internet"

### Painel de Tráfego em Tempo Real
- Gráfico de KB/s com janela deslizante de 60 segundos (PyQtGraph, eixos fixos sem bug de escala)
- Cards com total de pacotes, dados transmitidos, dispositivos ativos e velocidade atual
- Tabela de protocolos detectados com contagem e volume de dados
- Top dispositivos por tráfego (enviado, recebido e total)

### Aba Insights
- **Sites mais acessados** baseado em consultas DNS reais capturadas
- **Classificação de uso da rede** por categoria (Navegação, Conexão Segura, Novo Dispositivo, etc.)
- Diff incremental para evitar recriação desnecessária de widgets

### Servidor HTTP Embutido para Demonstrações
- Servidor multi-threaded com páginas de login, formulário e API JSON
- **Modo Vulnerável**: senha em texto puro, sem limites — demonstra como credenciais aparecem capturadas
- **Modo Seguro**: hash PBKDF2 + salt, rate limiting, bloqueio temporário de IP e CAPTCHA após falhas
- Proteção contra DoS com controle de req/s por IP e desbloqueio manual
- Monitoramento de requisições em tempo real com tabela e log de alertas

### Laboratório de Login (HTTP vs HTTPS)
- Simulação interativa comparando autenticação vulnerável × protegida
- Demonstração visual de como senhas aparecem em texto puro no HTTP
- Como dados armazenados diferem entre texto puro e hash PBKDF2
- Simulação de força bruta com métricas de tempo e número de tentativas

### 🗄️ Persistência com SQLite
- Banco de dados local com tabelas para sessões, pacotes, dispositivos e eventos pedagógicos
- Escrita assíncrona via thread dedicada (`_EscritorBanco`) — nenhum commit bloqueia a UI
- Amostragem de 1 em cada 5 pacotes para controle de memória e performance

---

## Arquitetura do Sistema

O NetLab é organizado em **três camadas de performance** para garantir que a interface gráfica jamais trave, mesmo em redes com alto volume de tráfego:

```
┌─────────────────────────────────────────────────────────────────────┐
│                        INTERFACE (UI Thread)                        │
│  QTimer 250ms → _consumir_fila() → enfileirar() + coletar()        │
│  QTimer 1500ms → _atualizar_ui_por_segundo() → painéis visuais     │
│  QThreadPool (max 4) → Motor Pedagógico → pyqtSignal → UI          │
└───────────────────────────┬─────────────────────────────────────────┘
                            │ deque(maxlen=5.000)  ← sem bloqueio
┌───────────────────────────▼─────────────────────────────────────────┐
│                   CAMADA 2 — ThreadAnalisador                       │
│  Thread daemon · lotes de 100 pacotes · SLEEP_VAZIO = 5ms           │
│  _parsear_pacote() → classificação + DPI HTTP + estatísticas        │
│  Resultados → fila_saida deque(maxlen=2.000)                        │
└───────────────────────────┬─────────────────────────────────────────┘
                            │ deque(maxlen=8.000)
┌───────────────────────────▼─────────────────────────────────────────┐
│               CAMADA 1 — _CapturadorPacotesThread                   │
│  AsyncSniffer (Scapy) · filtro "ip" · TCPSession · daemon           │
│  Decodifica Ether / IP / TCP / UDP / DNS / ARP / Raw               │
└─────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────┐
│                    _EscritorBanco (thread daemon)                   │
│  Fila de operações SQLite · commit nunca ocorre na UI thread        │
│  Amostragem 1:5 pacotes · salvar_dispositivo / salvar_evento       │
└─────────────────────────────────────────────────────────────────────┘

┌──────────────────────┐    ┌──────────────────────────────────────────┐
│  netlab_core_lib.c   │    │  http_parser.c                           │
│  Buffer circular C   │    │  Parser HTTP minimalista (ctypes)        │
│  Métricas de KB/s    │    │  Hot-path 10× mais rápido que Python     │
│  Fallback Python puro│    │  Fallback Python transparente            │
└──────────────────────┘    └──────────────────────────────────────────┘
```

### Decisões de Design

| Decisão | Motivo |
|---|---|
| `deque(maxlen=N)` em todas as filas | Zero OOM mesmo em picos — descarte automático do mais antigo |
| `_EscritorBanco` thread separada | Commits SQLite levam 5–50ms; executar na UI thread congela o gráfico |
| `QThreadPool` (máx 4) para DPI | Substitui criação de 1 `QThread` por evento — elimina vazamento de threads |
| Parser HTTP em C (ctypes) | Parsing de regex em Python é gargalo em capturas de alto volume |
| EMA α=0,3 no gráfico KB/s | Suaviza spikes sem atrasar a leitura visual da velocidade real |
| Cooldown por evento (5s DNS, 3s outros) | Evita flood de eventos redundantes na UI em redes ativas |
| Debounce 800ms no layout de topologia | `_recalcular_layout()` é O(n²); não executar a cada pacote |

---

## 🛠️ Tecnologias Utilizadas

| Tecnologia | Versão | Função |
|---|---|---|
| **Python** | 3.11 | Linguagem principal |
| **PyQt6** | 6.x | Interface gráfica (janelas, painéis, widgets) |
| **Scapy** | 2.x | Captura e decodificação de pacotes de rede |
| **PyQtGraph** | latest | Gráfico de tráfego em tempo real (alto desempenho) |
| **SQLite** | 3 | Persistência local de sessões e eventos |
| **ReportLab** | latest | Geração de relatórios PDF |
| **Npcap** | 1.87+ | Driver de captura de pacotes para Windows |
| **GCC / MSVC** | — | Compilação dos módulos C nativos |
| **PyInstaller** | latest | Empacotamento do executável `.exe` |
| **Inno Setup** | — | Criação do instalador `NetLab_Setup.exe` |

---

## 💻 Requisitos do Sistema

### Hardware (Mínimo)
| Componente | Especificação |
|---|---|
| Processador | Intel Core i3 ou equivalente (≥ 1,5 GHz) |
| Memória RAM | 4 GB (recomendado: 8 GB) |
| Espaço em Disco | 500 MB disponíveis |
| Resolução | 1280 × 720 pixels |

### Software
- **Windows 10 (64 bits)** ou superior
- **Npcap 1.87+** com *WinPcap API-compatible mode* ativado
- **Microsoft Visual C++ Redistributable x64**

> ⚠️ **Obrigatório:** O NetLab deve ser executado com **privilégios de Administrador**. Sem isso, o driver Npcap não consegue capturar pacotes no nível de hardware.

---

## Instalação

### Opção 1 — Instalador Automático (Recomendado)

1. Baixe o arquivo `NetLab_Setup.exe`
2. Clique com o **botão direito** → **Executar como administrador**
3. Siga o assistente de instalação
4. Na tela do Npcap, certifique-se de marcar **"WinPcap API-compatible mode"**
5. Ao finalizar, marque **"Executar NetLab"** e clique em **Concluir**

Um atalho será criado automaticamente na Área de Trabalho e no Menu Iniciar.

### Opção 2 — A partir do Código-Fonte

**Pré-requisitos:** Python 3.11, Git, GCC (MinGW no Windows)

```bash
# 1. Clone o repositório
git clone https://github.com/seu-usuario/netlab-educacional.git
cd netlab-educacional

# 2. Instale as dependências Python
pip install -r requirements.txt

# 3. (Opcional, mas recomendado) Compile os módulos C nativos
python compilar_http_parser.py
python setup_netlab.py build_gcc

# 4. Execute como Administrador
python main.py
```

**`requirements.txt`:**
```
PyQt6
scapy
pyqtgraph
cryptography
reportlab
```

### Opção 3 — Build do Executável

```bash
# Gera o executável na pasta dist\NetLab\
build_exe.bat
```

O script `build_exe.bat` usa PyInstaller com todas as flags necessárias (coleta completa do PyQt6 e Scapy, dados do tema, UAC admin, ícone).

### Compilação dos Módulos C Nativos (Opcional)

Os módulos C melhoram a performance em capturas de alto volume. O software funciona sem eles (fallback Python puro é ativado automaticamente).

```bash
# Windows (MinGW)
gcc -O2 -shared -o netlab_core_lib.dll netlab_core_lib.c
gcc -O2 -shared -o http_parser.dll http_parser.c

# Linux / macOS
gcc -O2 -shared -fPIC -o netlab_core_lib.so netlab_core_lib.c
gcc -O2 -shared -fPIC -o http_parser.so http_parser.c

# Ou use os scripts automatizados
python setup_netlab.py build_gcc
python compilar_http_parser.py
```

---

## Como Usar

### 1. Iniciando a Captura

1. Abra o NetLab **como Administrador**
2. Na barra de ferramentas, selecione a **interface de rede** ativa (Wi-Fi ou Ethernet)
3. Clique em **"Iniciar Captura"** (botão verde)
4. Abra qualquer site no navegador — os pacotes aparecerão imediatamente

> 💡 **Não sabe qual interface selecionar?** Execute `python diagnostico.py` em um terminal como Administrador. Ele testa cada interface por 4 segundos e indica qual está recebendo tráfego.

### 2. Explorando os Painéis

| Aba | O que mostra |
|---|---|
| **Topologia da Rede** | Mapa gráfico interativo dos dispositivos detectados. Scroll para zoom, arrastar para mover, clicar para detalhes. |
| **Tráfego em Tempo Real** | Gráfico de KB/s, protocolos detectados, top dispositivos por volume. |
| **Modo Análise** | Eventos de rede com explicações didáticas em 3 níveis. Clique em qualquer evento para expandir. |
| **Servidor** | Servidor HTTP embutido para demonstrações de segurança em sala de aula. |

### 3. Modo Análise — Os 3 Níveis de Explicação

Para cada evento capturado (DNS, HTTP, HTTPS, ARP, TCP, etc.):

- **Simples** — "O computador `192.168.0.5` está perguntando para a rede qual é o IP de `google.com`"
- **Técnico** — detalhes do protocolo, portas, flags TCP, TTL, vulnerabilidades detectadas, headers HTTP
- **Pacote Bruto** — conteúdo exato transmitido, hexdump + ASCII, campos de formulário destacados, alertas de segurança

### 4. Demonstração de Segurança com o Servidor Embutido

```
1. Vá para a aba "Servidor"
2. Clique em "Iniciar Servidor" (porta padrão: 8080)
3. Acesse http://<seu-IP>:8080/login de outro dispositivo na mesma rede
4. Mode VULNERÁVEL: faça login — observe as credenciais em texto puro no Modo Análise
5. Mode SEGURO: ative o modo seguro e refaça — as proteções entram em ação
```

**O que é demonstrado:**
- Credenciais HTTP aparecem em texto puro capturáveis por qualquer dispositivo na rede
- Hash PBKDF2 + salt como alternativa segura
- Rate limiting, bloqueio de IP e CAPTCHA como defesas contra força bruta
- Proteção contra DoS com controle de requisições por segundo

---

## 📁 Estrutura do Projeto

```
netlab-educacional/
│
├── main.py                      # Ponto de entrada — inicializa Qt, tema e janela
├── banco_dados.py               # Camada de persistência SQLite
├── analisador_pacotes.py        # Processamento de pacotes (3 camadas async)
├── motor_pedagogico.py          # Geração de explicações didáticas por protocolo
├── netlab_core.py               # Wrapper ctypes para netlab_core_lib
├── painel_servidor.py           # Servidor HTTP embutido para demonstrações
├── diagnostico.py               # Ferramenta de diagnóstico de interfaces
│
├── netlab_core_lib.c            # Buffer circular C — métricas de KB/s (O(1))
├── http_parser.c                # Parser HTTP em C — hot-path DPI
├── compilar_http_parser.py      # Script de compilação do http_parser.c
├── setup_netlab.py              # Script de compilação do netlab_core_lib.c
│
├── interface/
│   ├── __init__.py
│   ├── janela_principal.py      # Janela principal, timers, controle de captura
│   ├── painel_topologia.py      # Visualizador de topologia interativo (PyQt6)
│   ├── painel_trafego.py        # Gráfico KB/s e tabelas de tráfego
│   ├── painel_eventos.py        # Modo Análise — eventos + Insights
│   └── painel_login_seguro.py   # Laboratório de autenticação (HTTP vs HTTPS)
│
├── recursos/
│   └── estilos/
│       └── tema_escuro.qss      # Folha de estilos Qt (tema dark personalizado)
│
├── dados/
│   └── historico.db             # Banco SQLite (criado automaticamente)
│
├── requirements.txt             # Dependências Python
├── build_exe.bat                # Script de build do executável (PyInstaller)
├── setup_script.iss             # Script Inno Setup para o instalador .exe
└── .gitattributes
```

---

## Detalhes Técnicos

### netlab_core_lib.c — Buffer Circular de Alta Performance

Módulo C com buffer circular de 8.192 posições (potência de 2, mascaramento com `& (N-1)`) para cálculo eficiente de KB/s em janela deslizante. Todas as operações são O(1) amortizado, sem alocação dinâmica. Compilado como DLL/SO e carregado via ctypes; se não encontrado, o fallback Python puro (`_FallbackCore`) é ativado silenciosamente.

```c
// Índices de protocolo (sincronizados com netlab_core.py)
// 0=TCP  1=UDP  2=DNS  3=HTTP  4=HTTPS  5=ARP
// 6=ICMP 7=DHCP 8=TCP_SYN  9=OUTRO
```

### http_parser.c — Parser HTTP Minimalista

Exporta `parse_http_request()` que identifica o método HTTP, extrai o recurso (path + query) e busca credenciais no corpo POST (user, login, email, pass, password). Sem dependências externas, sem alocação dinâmica. Resultado retornado em struct `HttpResult` lida diretamente pelo ctypes Python.

### Motor Pedagógico — Deep Packet Inspection

Para cada tipo de evento, o `MotorPedagogico` gera explicações ricas usando os dados reais do pacote:

- Detecção de **indicadores de ataque** via regex: `union select`, `or 1=1`, `<script>`, `../`, `xp_cmdshell`
- Verificação de **headers de segurança ausentes**: HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy
- Estimativa de **sistema operacional** pelo TTL (Windows=128, Linux=64, Embedded=32)
- Identificação de **fabricante** pelo OUI (3 primeiros bytes do MAC)
- **Hexdump** dos primeiros 2048 bytes do payload com visualização ASCII

### Concorrência e Threading

```
UI Thread (Qt)
  ├── QTimer 250ms  → _consumir_fila()          ← coleta resultados prontos, O(n)
  ├── QTimer 1500ms → _atualizar_ui_por_segundo() ← redraw visual
  ├── QTimer 2000ms → _descarregar_eventos_ui()  ← despacha para Motor Pedagógico
  └── QTimer 30s    → _descoberta_periodica()    ← ARP sweep

Thread Pool (max 4 workers)
  └── _WorkerRunnable → motor.gerar_explicacao() → pyqtSignal → UI

ThreadAnalisador (daemon)
  └── consome deque(maxlen=8000), produz deque(maxlen=2000)

_CapturadorPacotesThread (daemon)
  └── AsyncSniffer (Scapy) → fila_pacotes_global

_EscritorBanco (daemon)
  └── fila de commits SQLite → sem bloqueio na UI

_DescobrirDispositivosThread (daemon)
  └── ARP sweep (3 rodadas, lotes de 256)
```

---

## Contexto Acadêmico

Este projeto foi desenvolvido como **Trabalho de Conclusão de Curso (TCC)** do **Curso Técnico em Informática** do **Instituto Federal Farroupilha (IFFar) — Campus Uruguaiana**.

**Objetivo acadêmico:** desenvolver uma ferramenta que torne o ensino de redes de computadores mais acessível e prático, permitindo que professores demonstrem em tempo real conceitos como protocolos de comunicação, topologia de rede, vulnerabilidades de segurança e mecanismos de proteção.

**Aluno:** Yuri Gonçalves Pavão  
**Instituição:** Instituto Federal Farroupilha — Campus Uruguaiana  
**Curso:** Técnico em Informática  
**Ano:** 2026

---

## ⚠️ Limitações Conhecidas

| Limitação | Detalhes |
|---|---|
| **Permissões obrigatórias** | Requer execução como Administrador no Windows e Npcap instalado. Em ambientes com GPO restritiva, pode ser necessária autorização do TI. |
| **HTTPS — conteúdo cifrado** | O NetLab detecta conexões HTTPS e extrai o hostname via SNI, mas **não decifra o conteúdo**. Isso é comportamento esperado e correto — o TLS garante confidencialidade. |
| **Isolamento de clientes Wi-Fi** | Redes com *client isolation* (comum em Wi-Fi escolar/corporativo) impedem descoberta ARP entre dispositivos. Apenas tráfego passando pelo computador monitorado será visível. |
| **Switches gerenciados** | Em redes com switches gerenciados sem port mirroring configurado, somente o tráfego da porta do computador é capturado. |
| **Alto volume de pacotes** | Em redes muito movimentadas (servidores, dezenas de dispositivos ativos), o volume pode causar descarte de pacotes nas filas internas (por design — proteção contra OOM). |
| **Plataforma primária** | Projetado e testado para Windows 10/11 (64 bits). Compatibilidade com Linux foi explorada mas não é o foco principal do projeto. |

---

## Licença

Este software é distribuído para **uso acadêmico e educacional**.

Desenvolvido como TCC no Instituto Federal Farroupilha — Campus Uruguaiana.  
Contribuições e sugestões de professores e alunos são bem-vindas.

---

<div align="center">

**NetLab Educacional v3.0** · Junho de 2025

*Desenvolvido por Yuri Gonçalves Pavão*  
*Este projeto contou com o apoio de diversas LLMs (Large Language Models) para auxílio no desenvolvimento, revisão de código e otimização de funcionalidades, sempre sob supervisão e validação do autor.*
*Instituto Federal Farroupilha — Campus Uruguaiana*

---

</div>
