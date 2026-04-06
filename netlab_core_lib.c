/*
 * netlab_core_lib.c
 * Módulo C de alta performance para o NetLab Educacional.
 *
 * FUNÇÕES EXPORTADAS
 * ──────────────────
 *   void     nl_inicializar(void)
 *   void     nl_resetar(void)
 *   void     nl_adicionar_pacote(uint8_t proto_idx, uint32_t tamanho_bytes)
 *   double   nl_bytes_por_segundo(uint32_t janela_ms)
 *   void     nl_obter_estatisticas(uint32_t *out_cont, uint64_t *out_bytes)
 *   uint32_t nl_total_pacotes(void)
 *   uint64_t nl_total_bytes(void)
 *
 * COMPILAÇÃO
 * ──────────
 *   Windows (MinGW/MSYS2):
 *     gcc -O2 -shared -o netlab_core_lib.dll netlab_core_lib.c
 *
 *   Windows (MSVC):
 *     cl /O2 /LD netlab_core_lib.c /Fe:netlab_core_lib.dll
 *
 *   Linux / macOS:
 *     gcc -O2 -shared -fPIC -o netlab_core_lib.so netlab_core_lib.c
 *
 * ÍNDICES DE PROTOCOLO (sincronizados com netlab_core.py)
 * ────────────────────────────────────────────────────────
 *   0=TCP  1=UDP  2=DNS  3=HTTP  4=HTTPS  5=ARP
 *   6=ICMP 7=DHCP 8=TCP_SYN  9=OUTRO
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

/* ── Plataforma ──────────────────────────────────────────────────────── */
#ifdef _WIN32
  #include <windows.h>
  static uint64_t _agora_ms(void) {
      LARGE_INTEGER freq, cnt;
      QueryPerformanceFrequency(&freq);
      QueryPerformanceCounter(&cnt);
      return (uint64_t)((double)cnt.QuadPart / freq.QuadPart * 1000.0);
  }
  #define EXPORT __declspec(dllexport)
#else
  #include <time.h>
  static uint64_t _agora_ms(void) {
      struct timespec ts;
      clock_gettime(CLOCK_MONOTONIC, &ts);
      return (uint64_t)ts.tv_sec * 1000ULL + (uint64_t)(ts.tv_nsec / 1000000);
  }
  #define EXPORT
#endif

/* ── Constantes ─────────────────────────────────────────────────────── */
#define MAX_PROTO      16
#define CBUF_CAP    8192u   /* potência de 2 → mascaramento rápido     */
#define CBUF_MASK (CBUF_CAP - 1u)

/* ── Estruturas internas ─────────────────────────────────────────────── */
typedef struct {
    uint32_t tamanho;
    uint8_t  protocolo;
    uint32_t ts_ms_rel;   /* ms desde ts_inicio */
} _Pacote;

typedef struct {
    _Pacote   buf[CBUF_CAP];
    uint32_t  head;           /* próxima posição de escrita (mod CBUF_CAP) */
    uint32_t  count;          /* itens no buffer (max CBUF_CAP)            */
    uint64_t  total_bytes;
    uint32_t  total_pacotes;
    uint32_t  cont[MAX_PROTO];
    uint64_t  bytes_proto[MAX_PROTO];
    uint64_t  ts_inicio;      /* ms absoluto no momento de nl_inicializar  */
} _Estado;

static _Estado g;

/* ── Implementação ───────────────────────────────────────────────────── */

EXPORT void nl_inicializar(void) {
    memset(&g, 0, sizeof(g));
    g.ts_inicio = _agora_ms();
}

EXPORT void nl_resetar(void) {
    nl_inicializar();
}

/*
 * nl_adicionar_pacote
 * Insere um pacote no buffer circular e actualiza contadores agregados.
 * Complexidade: O(1) — sem alocação dinâmica.
 */
EXPORT void nl_adicionar_pacote(uint8_t proto_idx, uint32_t tamanho) {
    if (g.ts_inicio == 0) nl_inicializar();
    if (proto_idx >= MAX_PROTO) proto_idx = 9; /* OUTRO */

    uint64_t agora = _agora_ms();
    _Pacote *slot  = &g.buf[g.head & CBUF_MASK];
    slot->tamanho    = tamanho;
    slot->protocolo  = proto_idx;
    slot->ts_ms_rel  = (uint32_t)(agora - g.ts_inicio);

    g.head = (g.head + 1u) & CBUF_MASK;
    if (g.count < CBUF_CAP) g.count++;

    g.total_bytes          += tamanho;
    g.total_pacotes        += 1u;
    g.cont[proto_idx]      += 1u;
    g.bytes_proto[proto_idx] += tamanho;
}

/*
 * nl_bytes_por_segundo
 * Calcula a taxa de transferência média na janela deslizante de `janela_ms`
 * milissegundos. Percorre apenas os itens do buffer circular de forma
 * eficiente — O(min(count, CBUF_CAP)).
 */
EXPORT double nl_bytes_por_segundo(uint32_t janela_ms) {
    if (g.count == 0 || janela_ms == 0) return 0.0;

    uint64_t agora     = _agora_ms();
    uint32_t agora_rel = (uint32_t)(agora - g.ts_inicio);
    uint32_t corte     = (agora_rel > janela_ms) ? agora_rel - janela_ms : 0u;

    uint64_t soma = 0;
    /* Índice do item mais antigo no buffer */
    uint32_t mais_antigo = (g.count < CBUF_CAP)
                           ? 0u
                           : g.head; /* sobrescreveu: o mais antigo é g.head */

    for (uint32_t i = 0; i < g.count; i++) {
        uint32_t idx = (mais_antigo + i) & CBUF_MASK;
        if (g.buf[idx].ts_ms_rel >= corte) {
            soma += g.buf[idx].tamanho;
        }
    }

    return (double)soma / ((double)janela_ms / 1000.0);
}

/*
 * nl_obter_estatisticas
 * Preenche dois arrays fornecidos pelo caller:
 *   out_cont[MAX_PROTO]  → contagem de pacotes por protocolo
 *   out_bytes[MAX_PROTO] → bytes por protocolo
 */
EXPORT void nl_obter_estatisticas(uint32_t *out_cont, uint64_t *out_bytes) {
    if (!out_cont || !out_bytes) return;
    memcpy(out_cont,  g.cont,        sizeof(g.cont));
    memcpy(out_bytes, g.bytes_proto, sizeof(g.bytes_proto));
}

EXPORT uint32_t nl_total_pacotes(void) { return g.total_pacotes; }
EXPORT uint64_t nl_total_bytes(void)   { return g.total_bytes;   }
