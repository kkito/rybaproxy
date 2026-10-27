#include "rybaproxy/geo.h"

#include <arpa/inet.h>
#include <ctype.h>
#include <netdb.h>
#include <pthread.h>
#include <regex.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/stat.h>
#include <time.h>

/* ---------- varint / wire ---------- */
static int read_varint(const unsigned char **pp, const unsigned char *end, uint64_t *out) {
    uint64_t v = 0;
    int shift = 0;
    const unsigned char *p = *pp;
    while (p < end && shift < 64) {
        unsigned char b = *p++;
        v |= ((uint64_t)(b & 0x7F)) << shift;
        if (!(b & 0x80)) { *pp = p; *out = v; return 0; }
        shift += 7;
    }
    return -1;
}

/* ---------- IP 表 ---------- */
typedef struct { unsigned char addr[16]; int bits; int is6; } cidr_t;
static cidr_t *g_cidrs = NULL;
static size_t g_cidr_n = 0, g_cidr_cap = 0;
static void geo_tables_clear(void);
static pthread_mutex_t g_lock = PTHREAD_MUTEX_INITIALIZER;

static void cidr_push(const unsigned char *ip, size_t iplen, int prefix) {
    if (g_cidr_n == g_cidr_cap) {
        size_t ncap = g_cidr_cap ? g_cidr_cap * 2 : 256;
        cidr_t *nr = realloc(g_cidrs, ncap * sizeof *nr);
        if (!nr) return;
        g_cidrs = nr; g_cidr_cap = ncap;
    }
    cidr_t *c = &g_cidrs[g_cidr_n++];
    memset(c->addr, 0, 16);
    if (iplen == 4) { c->is6 = 0; memcpy(c->addr, ip, 4); c->bits = prefix > 32 ? 32 : prefix; }
    else if (iplen == 16) { c->is6 = 1; memcpy(c->addr, ip, 16); c->bits = prefix > 128 ? 128 : prefix; }
    else g_cidr_n--;
}

static int cidr_cmp(const void *a, const void *b) {
    const cidr_t *x = a, *y = b;
    if (x->is6 != y->is6) return x->is6 - y->is6;
    int r = memcmp(x->addr, x->is6 ? x->addr : x->addr, x->is6 ? 16 : 4);
    (void)y;
    return r;
}

/* v6 统一比较：v4 视为 ::ffff:a.b.c.d */
static void norm_key(const unsigned char *raw, int is6, unsigned char out[16]) {
    if (is6) memcpy(out, raw, 16);
    else { memset(out, 0, 16); out[10] = 0xFF; out[11] = 0xFF; memcpy(out + 12, raw, 4); }
}

static int match_cidr6(const unsigned char key[16], const cidr_t *c) {
    unsigned char net[16];
    norm_key(c->addr, c->is6, net);
    int bits = c->bits + (c->is6 ? 0 : 96);
    for (int i = 0; i < bits; i++)
        if (((key[i / 8] >> (7 - i % 8)) & 1) != ((net[i / 8] >> (7 - i % 8)) & 1)) return 0;
    return 1;
}

/* ---------- 域名表 ---------- */
typedef struct { char *rev; } suffix_t; /* 反转小写后缀 */
static suffix_t *g_suffix = NULL;
static size_t g_suffix_n = 0, g_suffix_cap = 0;
static char **g_exact = NULL;
static size_t g_exact_n = 0, g_exact_cap = 0;
static regex_t *g_res = NULL;
static size_t g_re_n = 0, g_re_cap = 0;

static char *strlowdup(const char *s, size_t n) {
    char *o = malloc(n + 1);
    if (!o) return NULL;
    for (size_t i = 0; i < n; i++) o[i] = (char)tolower((unsigned char)s[i]);
    o[n] = '\0';
    return o;
}

static void suffix_push(const char *s, size_t n) {
    char *low = strlowdup(s, n);
    if (!low) return;
    size_t L = strlen(low);
    char *rev = malloc(L + 1);
    if (!rev) { free(low); return; }
    for (size_t i = 0; i < L; i++) rev[i] = low[L - 1 - i];
    rev[L] = '\0';
    free(low);
    if (g_suffix_n == g_suffix_cap) {
        size_t ncap = g_suffix_cap ? g_suffix_cap * 2 : 256;
        suffix_t *nr = realloc(g_suffix, ncap * sizeof *nr);
        if (!nr) { free(rev); return; }
        g_suffix = nr; g_suffix_cap = ncap;
    }
    g_suffix[g_suffix_n++].rev = rev;
}

static void exact_push(const char *s, size_t n) {
    char *low = strlowdup(s, n);
    if (!low) return;
    if (g_exact_n == g_exact_cap) {
        size_t ncap = g_exact_cap ? g_exact_cap * 2 : 256;
        char **nr = realloc(g_exact, ncap * sizeof *nr);
        if (!nr) { free(low); return; }
        g_exact = nr; g_exact_cap = ncap;
    }
    g_exact[g_exact_n++] = low;
}

static void regex_push(const char *s, size_t n) {
    char *pat = malloc(n + 1);
    if (!pat) return;
    memcpy(pat, s, n); pat[n] = '\0';
    if (g_re_n == g_re_cap) {
        size_t ncap = g_re_cap ? g_re_cap * 2 : 16;
        regex_t *nr = realloc(g_res, ncap * sizeof *nr);
        if (!nr) { free(pat); return; }
        g_res = nr; g_re_cap = ncap;
    }
    if (regcomp(&g_res[g_re_n], pat, REG_EXTENDED | REG_NOSUB | REG_ICASE) == 0) g_re_n++;
    free(pat);
}

/* ---------- wire 跳读 ---------- */
static int skip_field(const unsigned char **pp, const unsigned char *end, unsigned tag) {
    int wire = tag & 7;
    if (wire == 0) { uint64_t v; return read_varint(pp, end, &v); }
    if (wire == 5) { if (*pp + 4 > end) return -1; *pp += 4; return 0; }
    if (wire == 1) { if (*pp + 8 > end) return -1; *pp += 8; return 0; }
    if (wire == 2) {
        uint64_t L; if (read_varint(pp, end, &L) != 0) return -1;
        if (*pp + L > end) return -1; *pp += L; return 0;
    }
    return -1;
}

/* 从 GeoSite entry payload 提取 domain 条目 */
static void parse_geosite_entry(const unsigned char *p, const unsigned char *end) {
    while (p < end) {
        const unsigned char *fp = p;
        uint64_t tag;
        if (read_varint(&p, end, &tag) != 0) return;
        int field = (int)(tag >> 3), wire = (int)(tag & 7);
        if (field == 2 && wire == 2) { /* domain */
            uint64_t L; if (read_varint(&p, end, &L) != 0) return;
            if (p + L > end) return;
            const unsigned char *dp = p, *dend = p + L;
            int dtype = -1; const unsigned char *dval = NULL; uint64_t dlen = 0;
            while (dp < dend) {
                uint64_t dtag; if (read_varint(&dp, dend, &dtag) != 0) return;
                int df = (int)(dtag >> 3), dw = (int)(dtag & 7);
                if (df == 1 && dw == 0) { uint64_t v; if (read_varint(&dp, dend, &v) != 0) return; dtype = (int)v; }
                else if (df == 2 && dw == 2) {
                    uint64_t vl; if (read_varint(&dp, dend, &vl) != 0) return;
                    if (dp + vl > dend) return; dval = dp; dlen = vl; dp += vl;
                } else if (skip_field(&dp, dend, (unsigned)dtag) != 0) return;
            }
            if (dtype >= 0 && dval) {
                if (dtype == 0) exact_push((const char *)dval, (size_t)dlen);
                else if (dtype == 1 || dtype == 2) suffix_push((const char *)dval, (size_t)dlen);
                else if (dtype == 3) regex_push((const char *)dval, (size_t)dlen);
                /* dtype 2=DomainSuffix 等价 suffix；未知类型忽略 */
            }
            p = dend; /* 消费整个 domain 子消息 */
        } else if (skip_field(&p, end, (unsigned)tag) != 0) return;
        (void)fp;
    }
}

/* 从 GeoIP entry payload 提取 cidr 条目 */
static void parse_geoip_entry(const unsigned char *p, const unsigned char *end) {
    while (p < end) {
        uint64_t tag; if (read_varint(&p, end, &tag) != 0) return;
        int field = (int)(tag >> 3), wire = (int)(tag & 7);
        if (field == 2 && wire == 2) { /* cidr */
            uint64_t L; if (read_varint(&p, end, &L) != 0) return;
            if (p + L > end) return;
            const unsigned char *cp = p, *cend = p + L;
            const unsigned char *ipb = NULL; uint64_t iplen = 0; int prefix = -1;
            while (cp < cend) {
                uint64_t ctag; if (read_varint(&cp, cend, &ctag) != 0) return;
                int cf = (int)(ctag >> 3), cw = (int)(ctag & 7);
                if (cf == 1 && cw == 2) {
                    uint64_t vl; if (read_varint(&cp, cend, &vl) != 0) return;
                    if (cp + vl > cend) return; ipb = cp; iplen = vl; cp += vl;
                } else if (cf == 2 && cw == 0) { uint64_t v; if (read_varint(&cp, cend, &v) != 0) return; prefix = (int)v; }
                else if (skip_field(&cp, cend, (unsigned)ctag) != 0) return;
            }
            if (ipb && (iplen == 4 || iplen == 16) && prefix >= 0) cidr_push(ipb, (size_t)iplen, prefix);
            p += L;
        } else if (skip_field(&p, end, (unsigned)tag) != 0) return;
    }
}

/* 顶层：GeoIPList{entry=1}/GeoSiteList{entry=1}，只收 country_code=="CN"(大小写不敏感) 的 entry */
static int parse_dat(const unsigned char *buf, size_t len, int is_ip) {
    const unsigned char *p = buf, *end = buf + len;
    while (p < end) {
        uint64_t tag; if (read_varint(&p, end, &tag) != 0) return -1;
        int field = (int)(tag >> 3), wire = (int)(tag & 7);
        if (field != 1 || wire != 2) { if (skip_field(&p, end, (unsigned)tag) != 0) return -1; continue; }
        uint64_t L; if (read_varint(&p, end, &L) != 0) return -1;
        if (p + L > end) return -1;
        const unsigned char *ep = p, *eend = p + L;
        /* 先找 country_code */
        const unsigned char *q = ep;
        char cc[8] = ""; size_t ccl = 0;
        while (q < eend) {
            uint64_t et; if (read_varint(&q, eend, &et) != 0) break;
            int ef = (int)(et >> 3), ew = (int)(et & 7);
            if (ef == 1 && ew == 2) {
                uint64_t vl; if (read_varint(&q, eend, &vl) != 0) break;
                if (q + vl > eend) break;
                ccl = vl > sizeof cc - 1 ? sizeof cc - 1 : (size_t)vl;
                memcpy(cc, q, ccl); cc[ccl] = '\0'; q += vl;
            } else if (skip_field(&q, eend, (unsigned)et) != 0) break;
        }
        /* geosite 的 CN 语义：纯 CN 分类 + 名字含 -CN 后缀且不以 !CN 结尾的分类；geosite:cn 的反选逻辑在查询侧用本表 */
    int want = 0;
    if (is_ip) want = (strcasecmp(cc, "CN") == 0);
    else {
        if (strcasecmp(cc, "CN") == 0) want = 1;
        else {
            size_t cl = strlen(cc);
            if (cl > 3 && strcasecmp(cc + cl - 3, "-CN") == 0) want = 1;
        }
    }
    if (want) {
            if (is_ip) parse_geoip_entry(ep, eend);
            else parse_geosite_entry(ep, eend);
        }
        p += L;
    }
    /* 排序供二分/前缀比较 */
    if (is_ip && g_cidr_n) qsort(g_cidrs, g_cidr_n, sizeof *g_cidrs, cidr_cmp);
    return 0;
}

/* 数据源：开源社区维护的 GeoIP / Geosite 数据文件（换源只改这两行）
 * 默认走直连（DIRECT），避免代理污染下载。环境变量可覆盖：
 *   RYBA_GEOIP_URL / RYBA_GEOSITE_URL
 *   RYBA_GEO_PROXY  （例如 http://127.0.0.1:18081，经本地链路下载）
 */
static const char *kGeoIpURL = "https://cdn.jsdelivr.net/gh/Loyalsoldier/v2ray-rules-dat@release/geoip.dat";
static const char *kGeoSiteURL = "https://cdn.jsdelivr.net/gh/Loyalsoldier/v2ray-rules-dat@release/geosite.dat";

static const char *geo_env_or(const char *name, const char *fallback) {
    const char *v = getenv(name);
    return (v && *v) ? v : fallback;
}

/* 目录不存在则递归创建（dat 落盘用），失败返回 -1 */
#include <errno.h>
static int geo_ensure_dir(const char *dir) {
    struct stat st;
    if (stat(dir, &st) == 0) return S_ISDIR(st.st_mode) ? 0 : -1;
    char tmp[1024];
    snprintf(tmp, sizeof tmp, "%s", dir);
    for (char *p = tmp + 1; *p; p++) {
        if (*p == '/') {
            *p = '\0';
            if (mkdir(tmp, 0755) != 0 && errno != EEXIST) return -1;
            *p = '/';
        }
    }
    if (mkdir(tmp, 0755) != 0 && errno != EEXIST) return -1;
    return 0;
}

int geo_download(const char *dir, char *err, size_t errsz) {
    if (err && errsz) err[0] = '\0';
    if (!dir || !*dir) { if (err && errsz) snprintf(err, errsz, "empty dir"); return -1; }
    if (geo_ensure_dir(dir) != 0) {
        if (err && errsz) snprintf(err, errsz, "cannot create dir %s: %s", dir, strerror(errno));
        return -1;
    }
    const char *urls[2] = { geo_env_or("RYBA_GEOIP_URL", kGeoIpURL),
                            geo_env_or("RYBA_GEOSITE_URL", kGeoSiteURL) };
    const char *proxy = getenv("RYBA_GEO_PROXY");
    char proxy_opt[512] = "";
    if (proxy && *proxy) snprintf(proxy_opt, sizeof proxy_opt, " -x '%s'", proxy);
    const char *names[2] = { "geoip.dat", "geosite.dat" };
    for (int i = 0; i < 2; i++) {
        char tmp[1024], dst[1024];
        snprintf(tmp, sizeof tmp, "%s/%s.tmp", dir, names[i]);
        snprintf(dst, sizeof dst, "%s/%s", dir, names[i]);
        char cmd[2560];
        /* --noproxy '*'：curl 默认读 http_proxy 环境变量会把流量发往代理；
         * 加 --noproxy '*' 强制直连（除非 RYBA_GEO_PROXY 显式指定走代理）。
         * 超时分开设：连接 15s + 总 300s（小水管也能下完 28MB）。 */
        snprintf(cmd, sizeof cmd, "curl -fsSL --connect-timeout 15 --max-time 300 --retry 2 --noproxy '*'%s -o '%s' '%s' 2>&1", proxy_opt, tmp, urls[i]);
        FILE *p = popen(cmd, "r");
        if (!p) { if (err && errsz) snprintf(err, errsz, "popen failed: %s", names[i]); return -1; }
        char msg[512] = "";
        size_t ml = fread(msg, 1, sizeof msg - 1, p);
        msg[ml] = '\0';
        int rc = pclose(p);
        if (rc != 0) {
            remove(tmp);
            if (err && errsz) snprintf(err, errsz, "download %s failed: %s", names[i], msg);
            return -1;
        }
        struct stat st;
        if (stat(tmp, &st) != 0 || st.st_size < 1024) {
            remove(tmp);
            if (err && errsz) snprintf(err, errsz, "%s too small, aborted", names[i]);
            return -1;
        }
        if (rename(tmp, dst) != 0) {
            remove(tmp);
            if (err && errsz) snprintf(err, errsz, "rename %s failed", names[i]);
            return -1;
        }
    }
    if (geo_load(dir) != 0) { if (err && errsz) snprintf(err, errsz, "parse failed"); return -1; }
    return 0;
}

static unsigned char *read_file(const char *path, size_t *out_len) {
    FILE *f = fopen(path, "rb");
    if (!f) return NULL;
    struct stat st;
    if (fstat(fileno(f), &st) != 0 || st.st_size <= 0 || st.st_size > (off_t)(64 << 20)) { fclose(f); return NULL; }
    unsigned char *b = malloc((size_t)st.st_size);
    if (!b) { fclose(f); return NULL; }
    size_t n = fread(b, 1, (size_t)st.st_size, f);
    fclose(f);
    if (n != (size_t)st.st_size) { free(b); return NULL; }
    *out_len = n;
    return b;
}

static int g_loaded = 0;

/* DNS 缓存前向声明（定义在文件后部，free/reset 需先用） */
static void dns_cache_clear(void);

int geo_init(void) { return 0; }

void geo_free(void) {
    pthread_mutex_lock(&g_lock);
    geo_tables_clear();
    dns_cache_clear();
    g_loaded = 0;
    pthread_mutex_unlock(&g_lock);
}

static void geo_tables_clear(void) {
    free(g_cidrs); g_cidrs = NULL; g_cidr_n = g_cidr_cap = 0;
    for (size_t i = 0; i < g_suffix_n; i++) free(g_suffix[i].rev);
    free(g_suffix); g_suffix = NULL; g_suffix_n = g_suffix_cap = 0;
    for (size_t i = 0; i < g_exact_n; i++) free(g_exact[i]);
    free(g_exact); g_exact = NULL; g_exact_n = g_exact_cap = 0;
    for (size_t i = 0; i < g_re_n; i++) regfree(&g_res[i]);
    free(g_res); g_res = NULL; g_re_n = g_re_cap = 0;
}

int geo_db_loaded(void) { return g_loaded; }

const char *geo_ip_url(void) { return geo_env_or("RYBA_GEOIP_URL", kGeoIpURL); }
const char *geo_site_url(void) { return geo_env_or("RYBA_GEOSITE_URL", kGeoSiteURL); }
const char *geo_proxy(void) { const char *p = getenv("RYBA_GEO_PROXY"); return (p && *p) ? p : NULL; }
/* 测试钩子：清表 + 清 DNS 缓存 + loaded=0（空库语义回归用） */
void geo_test_reset(void) {
    pthread_mutex_lock(&g_lock);
    geo_tables_clear();
    dns_cache_clear();
    g_loaded = 0;
    pthread_mutex_unlock(&g_lock);
}
size_t geo_ip_count(void) { return g_cidr_n; }
size_t geo_site_count(void) { return g_suffix_n + g_exact_n + g_re_n; }

int geo_load(const char *dir) {
    if (!dir || !*dir) return -1;
    char p1[1024], p2[1024];
    snprintf(p1, sizeof p1, "%s/geoip.dat", dir);
    snprintf(p2, sizeof p2, "%s/geosite.dat", dir);
    int ok = 0;
    pthread_mutex_lock(&g_lock);
    geo_tables_clear();
    size_t n = 0;
    unsigned char *b = read_file(p1, &n);
    if (b) { if (parse_dat(b, n, 1) == 0) ok |= 1; free(b); }
    b = read_file(p2, &n);
    if (b) { if (parse_dat(b, n, 0) == 0) ok |= 2; free(b); }
    if (ok) g_loaded = 1;
    pthread_mutex_unlock(&g_lock);
    return ok ? 0 : -1;
}

/* 私网视同 CN */
static int is_private_ip(const unsigned char key[16], int is6) {
    if (!is6) {
        unsigned int h;
        memcpy(&h, key, 4); h = ntohl(h);
        if ((h >> 24) == 10) return 1;
        if ((h & 0xFFF00000u) == 0xAC100000u) return 1;
        if ((h & 0xFFFF0000u) == 0xC0A80000u) return 1;
        if ((h >> 24) == 127) return 1;
        return 0;
    }
    static const unsigned char loop[16] = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1};
    if (memcmp(key, loop, 16) == 0) return 1;
    if (key[0] == 0xFC || key[0] == 0xFD) return 1;
    if (key[0] == 0xFE && (key[1] & 0xC0) == 0x80) return 1;
    return 0;
}

/* ---------- 查表（纯匹配，要求调用方已持 g_lock；无锁/无IO，可单测） ---------- */
static int cidr_table_hit(const unsigned char key[16]) {
    for (size_t i = 0; i < g_cidr_n; i++)
        if (match_cidr6(key, &g_cidrs[i])) return 1;
    return 0;
}

static int site_table_hit(const char *low) {
    size_t L = strlen(low);
    for (size_t i = 0; i < g_exact_n; i++)
        if (strcmp(low, g_exact[i]) == 0) return 1;
    char rev[256];
    for (size_t i = 0; i < L; i++) rev[i] = low[L - 1 - i];
    rev[L] = '\0';
    for (size_t i = 0; i < g_suffix_n; i++) {
        size_t sl = strlen(g_suffix[i].rev);
        if (L >= sl && memcmp(rev, g_suffix[i].rev, sl) == 0) {
            /* 须是完整 label 边界：example.cn 命中 a.example.cn；不命中 notexample.cn */
            if (L == sl || rev[sl] == '.') return 1;
        }
    }
    for (size_t i = 0; i < g_re_n; i++)
        if (regexec(&g_res[i], low, 0, NULL, 0) == 0) return 1;
    return 0;
}

int geo_ip_is_cn(const char *ip) {
    if (!ip || !*ip) return -1;
    unsigned char raw[16]; int is6 = 0;
    struct in_addr a4; struct in6_addr a6;
    if (inet_pton(AF_INET, ip, &a4) == 1) { memcpy(raw, &a4.s_addr, 4); is6 = 0; }
    else if (inet_pton(AF_INET6, ip, &a6) == 1) { memcpy(raw, &a6, 16); is6 = 1; }
    else return -1;
    unsigned char key[16];
    norm_key(raw, is6, key);
    if (is_private_ip(raw, is6)) return 1; /* 私网不依赖 dat */
    pthread_mutex_lock(&g_lock);
    int hit = 0;
    if (!g_loaded) hit = -1; /* 空库报未知，不许报非CN */
    else hit = cidr_table_hit(key);
    pthread_mutex_unlock(&g_lock);
    return hit < 0 ? -1 : (hit ? 1 : 0);
}

int geo_site_is_cn(const char *host) {
    if (!host || !*host) return -1;
    /* 先做纯归一化（无锁）：IP 字面量 / 大小写 / 尾点 */
    struct in_addr a4; struct in6_addr a6;
    int is_lit = (inet_pton(AF_INET, host, &a4) == 1 || inet_pton(AF_INET6, host, &a6) == 1);
    char low[256];
    size_t L = strlen(host);
    if (is_lit) low[0] = '\0';
    else {
        if (L >= sizeof low) return -1;
        for (size_t i = 0; i <= L; i++) low[i] = (char)tolower((unsigned char)host[i]);
        while (L && low[L - 1] == '.') low[--L] = '\0';
        if (!L) return -1;
    }
    pthread_mutex_lock(&g_lock);
    int r;
    if (!g_loaded) r = -1; /* 空库报未知，不许报非CN */
    else if (is_lit) r = 0; /* IP 字面量无域名可查 */
    else r = site_table_hit(low) ? 1 : 0;
    pthread_mutex_unlock(&g_lock);
    return r;
}

/* ---------- DNS + 缓存 ---------- */
#define GEO_DNS_CAP 256
typedef struct { char host[128]; char ip[64]; int cn; time_t ts; } dns_ent_t;
static dns_ent_t g_dns[GEO_DNS_CAP];
static int g_dns_pos = 0;

static void dns_cache_clear(void) {
    memset(g_dns, 0, sizeof g_dns);
    g_dns_pos = 0;
}

int geo_host_is_cn(const char *host) {
    if (!host || !*host) return -1;
    struct in_addr a4; struct in6_addr a6;
    if (inet_pton(AF_INET, host, &a4) == 1 || inet_pton(AF_INET6, host, &a6) == 1)
        return geo_ip_is_cn(host);
    time_t now = time(NULL);
    pthread_mutex_lock(&g_lock);
    for (int i = 0; i < GEO_DNS_CAP; i++) {
        if (g_dns[i].host[0] && strcmp(g_dns[i].host, host) == 0 && now - g_dns[i].ts < 300) {
            int c = g_dns[i].cn;
            pthread_mutex_unlock(&g_lock);
            return c;
        }
    }
    pthread_mutex_unlock(&g_lock);
    struct addrinfo hints, *res = NULL;
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC; hints.ai_socktype = SOCK_STREAM;
    char ipstr[64] = "";
    int cn = -1;
    if (getaddrinfo(host, "80", &hints, &res) == 0 && res) {
        void *ap = NULL;
        if (res->ai_family == AF_INET) ap = &((struct sockaddr_in *)res->ai_addr)->sin_addr;
        else if (res->ai_family == AF_INET6) ap = &((struct sockaddr_in6 *)res->ai_addr)->sin6_addr;
        if (ap) {
            inet_ntop(res->ai_family, ap, ipstr, sizeof ipstr);
            cn = geo_ip_is_cn(ipstr);
            if (cn < 0) cn = -1;
        }
        freeaddrinfo(res);
    }
    if (cn >= 0 && ipstr[0]) {
        pthread_mutex_lock(&g_lock);
        dns_ent_t *e = &g_dns[g_dns_pos++ % GEO_DNS_CAP];
        snprintf(e->host, sizeof e->host, "%s", host);
        snprintf(e->ip, sizeof e->ip, "%s", ipstr);
        e->cn = cn; e->ts = now;
        pthread_mutex_unlock(&g_lock);
    }
    return cn;
}
