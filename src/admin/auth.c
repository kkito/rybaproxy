#include "rybaproxy/auth.h"

#include <string.h>

static int b64val(char c) {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    return -1;
}

int base64_decode(const char *in, unsigned char *out, size_t outcap) {
    if (!in || !out) return -1;
    size_t len = strlen(in);
    size_t outlen = 0;
    int val = 0, bits = -8;
    for (size_t i = 0; i < len; i++) {
        char c = in[i];
        if (c == '=') break;
        int v = b64val(c);
        if (v < 0) {
            if (c == ' ' || c == '\t' || c == '\n' || c == '\r') continue;
            return -1;
        }
        val = (val << 6) | v;
        bits += 6;
        if (bits >= 0) {
            if (outlen >= outcap) return -1;
            out[outlen++] = (unsigned char)((val >> bits) & 0xFF);
            bits -= 8;
        }
    }
    return (int)outlen;
}

static int ct_memcmp(const void *a, const void *b, size_t n) {
    const unsigned char *pa = a, *pb = b;
    unsigned char r = 0;
    for (size_t i = 0; i < n; i++) r |= pa[i] ^ pb[i];
    return r;
}

bool auth_basic_check(const char *header_value, const char *username, const char *password) {
    if (!header_value || !username || !password) return false;
    const char *prefix = "Basic ";
    size_t plen = strlen(prefix);
    if (strncmp(header_value, prefix, plen) != 0) return false;
    unsigned char dec[256];
    int n = base64_decode(header_value + plen, dec, sizeof dec - 1);
    if (n < 0) return false;
    dec[n] = '\0';
    char *colon = strchr((char*)dec, ':');
    if (!colon) return false;
    *colon = '\0';
    const char *u = (const char*)dec;
    const char *p = colon + 1;
    if (strlen(u) != strlen(username) || strlen(p) != strlen(password)) return false;
    if (ct_memcmp(u, username, strlen(username)) != 0) return false;
    if (ct_memcmp(p, password, strlen(password)) != 0) return false;
    return true;
}
