#include "rybaproxy/geo.h"
#include "rybaproxy/db.h"
#include "rybaproxy/paths.h"

#include <arpa/inet.h>
#include <ctype.h>
#include <netdb.h>
#include <pthread.h>
#include <regex.h>
#include <sqlite3.h>
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
/* sqlite 落盘查询（调用方已持 g_lock）。v4: start/end 存 uint32；v6: 128 位拆四列。 */
static void geo_tables_clear(void);
static pthread_mutex_t g_lock = PTHREAD_MUTEX_INITIALIZER;

static int sql_hit_ip4(uint32_t addr) {
    sqlite3 *h = db_handle();
    if (!h) return -1;
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(h, "SELECT 1 FROM geo_ip WHERE start<=?1 AND ?1<=end LIMIT 1",
                           -1, &st, NULL) != SQLITE_OK) return -1;
    sqlite3_bind_int64(st, 1, (sqlite3_int64)addr);
    int hit = (sqlite3_step(st) == SQLITE_ROW) ? 1 : 0;
    sqlite3_finalize(st);
    return hit;
}

static int sql_hit_ip6(const unsigned char key[16]) {
    sqlite3 *h = db_handle();
    if (!h) return -1;
    uint64_t s_hi = 0, s_lo = 0;
    for (int i = 0; i < 8; i++) { s_hi = (s_hi << 8) | key[i]; s_lo = (s_lo << 8) | key[8 + i]; }
    sqlite3_stmt *st = NULL;
    const char *sql = "SELECT 1 FROM geo_ip6 WHERE (s_hi< ?1 OR (s_hi==?1 AND s_lo<=?2))"
                      " AND (e_hi> ?1 OR (e_hi==?1 AND e_lo>=?2)) LIMIT 1";
    if (sqlite3_prepare_v2(h, sql, -1, &st, NULL) != SQLITE_OK) return -1;
    sqlite3_bind_int64(st, 1, (sqlite3_int64)s_hi);
    sqlite3_bind_int64(st, 2, (sqlite3_int64)s_lo);
    int hit = (sqlite3_step(st) == SQLITE_ROW) ? 1 : 0;
    sqlite3_finalize(st);
    return hit;
}

static int sql_hit_exact(const char *low) {
    sqlite3 *h = db_handle();
    if (!h) return -1;
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(h, "SELECT 1 FROM geo_site_exact WHERE host=?1 LIMIT 1",
                           -1, &st, NULL) != SQLITE_OK) return -1;
    sqlite3_bind_text(st, 1, low, -1, SQLITE_STATIC);
    int hit = (sqlite3_step(st) == SQLITE_ROW) ? 1 : 0;
    sqlite3_finalize(st);
    return hit;
}

/* suffix 前缀查：rev<=low 倒序取 8 条候选，逐个做 label 边界校验 */
static int sql_hit_suffix(const char *low) {
    sqlite3 *h = db_handle();
    if (!h) return -1;
    size_t L = strlen(low);
    char rev[256];
    if (L >= sizeof rev) return -1;
    for (size_t i = 0; i < L; i++) rev[i] = low[L - 1 - i];
    rev[L] = '\0';
    sqlite3_stmt *st = NULL;
    const char *sql = "SELECT rev FROM geo_site_suffix WHERE rev<=?1 ORDER BY rev DESC LIMIT 8";
    if (sqlite3_prepare_v2(h, sql, -1, &st, NULL) != SQLITE_OK) return -1;
    sqlite3_bind_text(st, 1, rev, -1, SQLITE_STATIC);
    int hit = 0;
    while (sqlite3_step(st) == SQLITE_ROW) {
        const unsigned char *r = sqlite3_column_text(st, 0);
        if (!r) continue;
        size_t sl = strlen((const char *)r);
        if (L >= sl && memcmp(rev, r, sl) == 0 && (L == sl || rev[sl] == '.')) { hit = 1; break; }
    }
    sqlite3_finalize(st);
    return hit;
}

/* ---------- 域名表：regex 留内存（几十条），exact/suffix 进 sqlite ---------- */
static regex_t *g_res = NULL;
static size_t g_re_n = 0, g_re_cap = 0;

/* 导入回调上下文：批量 INSERT 的 prepared statement */
typedef struct {
    sqlite3_stmt *ip4;
    sqlite3_stmt *ip6;
    sqlite3_stmt *exact;
    sqlite3_stmt *suffix;
    long n_since_commit;
} import_ctx_t;

static char *strlowdup(const char *s, size_t n) {
    char *o = malloc(n + 1);
    if (!o) return NULL;
    for (size_t i = 0; i < n; i++) o[i] = (char)tolower((unsigned char)s[i]);
    o[n] = '\0';
    return o;
}

/* 每 500 条 COMMIT 一次防 WAL 膨胀 */
static void import_maybe_commit(sqlite3 *h, import_ctx_t *cx) {
    if (++cx->n_since_commit < 500) return;
    cx->n_since_commit = 0;
    sqlite3_exec(h, "COMMIT;BEGIN IMMEDIATE;", NULL, NULL, NULL);
}

static void suffix_insert(sqlite3 *h, import_ctx_t *cx, const char *s, size_t n) {
    char *low = strlowdup(s, n);
    if (!low) return;
    size_t L = strlen(low);
    char rev[256];
    if (L >= sizeof rev) { free(low); return; }
    for (size_t i = 0; i < L; i++) rev[i] = low[L - 1 - i];
    rev[L] = '\0';
    free(low);
    sqlite3_bind_text(cx->suffix, 1, rev, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(cx->suffix, 2, "CN", -1, SQLITE_STATIC);
    if (sqlite3_step(cx->suffix) == SQLITE_DONE) import_maybe_commit(h, cx);
    sqlite3_reset(cx->suffix);
}

static void exact_insert(import_ctx_t *cx, const char *s, size_t n) {
    char *low = strlowdup(s, n);
    if (!low) return;
    sqlite3_bind_text(cx->exact, 1, low, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(cx->exact, 2, "CN", -1, SQLITE_STATIC);
    sqlite3_step(cx->exact);
    sqlite3_reset(cx->exact);
    free(low);
}

/* cidr 转区间存 sqlite：v4→uint32 start/end；v6→128 位拆四列 */
static void cidr_insert(sqlite3 *h, import_ctx_t *cx,
                        const unsigned char *ip, size_t iplen, int prefix) {
    if (iplen == 4) {
        if (prefix < 0 || prefix > 32) return;
        uint32_t a;
        memcpy(&a, ip, 4); a = ntohl(a);
        uint32_t mask = prefix == 0 ? 0 : (~0u << (32 - prefix));
        uint32_t s = a & mask, e = s | ~mask;
        sqlite3_bind_int64(cx->ip4, 1, (sqlite3_int64)s);
        sqlite3_bind_int64(cx->ip4, 2, (sqlite3_int64)e);
        sqlite3_bind_text(cx->ip4, 3, "CN", -1, SQLITE_STATIC);
        if (sqlite3_step(cx->ip4) == SQLITE_DONE) import_maybe_commit(h, cx);
        sqlite3_reset(cx->ip4);
    } else if (iplen == 16) {
        if (prefix < 0 || prefix > 128) return;
        uint64_t hi = 0, lo = 0;
        for (int i = 0; i < 8; i++) { hi = (hi << 8) | ip[i]; lo = (lo << 8) | ip[8 + i]; }
        unsigned __int128 full = ((unsigned __int128)hi << 64) | lo;
        unsigned __int128 mask = prefix == 0 ? 0 : (~(unsigned __int128)0 << (128 - prefix));
        unsigned __int128 s = full & mask, e = s | ~mask;
        sqlite3_bind_int64(cx->ip6, 1, (sqlite3_int64)(uint64_t)(s >> 64));
        sqlite3_bind_int64(cx->ip6, 2, (sqlite3_int64)(uint64_t)s);
        sqlite3_bind_int64(cx->ip6, 3, (sqlite3_int64)(uint64_t)(e >> 64));
        sqlite3_bind_int64(cx->ip6, 4, (sqlite3_int64)(uint64_t)e);
        sqlite3_bind_text(cx->ip6, 5, "CN", -1, SQLITE_STATIC);
        if (sqlite3_step(cx->ip6) == SQLITE_DONE) import_maybe_commit(h, cx);
        sqlite3_reset(cx->ip6);
    }
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

/* 从 GeoSite entry payload 按 domain 条目回调（type,val,len） */
static void parse_geosite_entry(const unsigned char *p, const unsigned char *end,
                                void (*emit)(int type, const char *val, size_t len, void *ud),
                                void *ud) {
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
                emit(dtype, (const char *)dval, (size_t)dlen, ud);
            }
            p = dend; /* 消费整个 domain 子消息 */
        } else if (skip_field(&p, end, (unsigned)tag) != 0) return;
        (void)fp;
    }
}

/* 从 GeoIP entry payload 按 cidr 条目回调（ip,len,prefix） */
static void parse_geoip_entry(const unsigned char *p, const unsigned char *end,
                              void (*emit)(const unsigned char *ip, size_t len, int prefix, void *ud),
                              void *ud) {
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
            if (ipb && (iplen == 4 || iplen == 16) && prefix >= 0) emit(ipb, (size_t)iplen, prefix, ud);
            p += L;
        } else if (skip_field(&p, end, (unsigned)tag) != 0) return;
    }
}

/* 顶层：GeoIPList{entry=1}/GeoSiteList{entry=1}，只收 country_code=="CN"(大小写不敏感) 的 entry */
static int parse_dat(const unsigned char *buf, size_t len, int is_ip,
                     void (*emit_ip)(const unsigned char *, size_t, int, void *),
                     void (*emit_site)(int, const char *, size_t, void *),
                     void *ud) {
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
            if (is_ip) parse_geoip_entry(ep, eend, emit_ip, ud);
            else parse_geosite_entry(ep, eend, emit_site, ud);
        }
        p += L;
    }
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

/* 目录解析：纯函数，优先级 cfg > env(RYBA_GEO_DIR) > $HOME/.local/rybaproxy > "." */
int geo_resolve_dir(const char *cfg_dir, const char *env_dir, const char *home,
                    char *out, size_t outsz) {
    if (!out || outsz == 0) return -1;
    if (cfg_dir && *cfg_dir) { snprintf(out, outsz, "%s", cfg_dir); return 0; }
    if (env_dir && *env_dir) { snprintf(out, outsz, "%s", env_dir); return 0; }
    char dflt[512];
    ryba_data_dir(home, dflt, sizeof dflt);
    snprintf(out, outsz, "%s", dflt);
    return 0;
}

/* 生效目录：薄胶水，只读环境 + 委托纯函数 */
int geo_active_dir(const char *cfg_dir, char *out, size_t outsz) {
    return geo_resolve_dir(cfg_dir, getenv("RYBA_GEO_DIR"), getenv("HOME"), out, outsz);
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
/* 可注入 DNS 解析器（定义在后部 DNS 节；free/reset 需先用） */
static geo_resolver_fn g_resolver;

int geo_init(void) { return 0; }

void geo_free(void) {
    pthread_mutex_lock(&g_lock);
    geo_tables_clear();
    dns_cache_clear();
    g_loaded = 0;
    g_resolver = NULL;
    pthread_mutex_unlock(&g_lock);
}

static void geo_tables_clear(void) {
    for (size_t i = 0; i < g_re_n; i++) regfree(&g_res[i]);
    free(g_res); g_res = NULL; g_re_n = g_re_cap = 0;
}

static int sql_count(const char *sql) {
    sqlite3 *h = db_handle();
    if (!h) return -1;
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(h, sql, -1, &st, NULL) != SQLITE_OK) return -1;
    int n = -1;
    if (sqlite3_step(st) == SQLITE_ROW) n = sqlite3_column_int(st, 0);
    sqlite3_finalize(st);
    return n;
}

int geo_db_loaded(void) { return g_loaded; }

const char *geo_ip_url(void) { return geo_env_or("RYBA_GEOIP_URL", kGeoIpURL); }
const char *geo_site_url(void) { return geo_env_or("RYBA_GEOSITE_URL", kGeoSiteURL); }
const char *geo_proxy(void) { const char *p = getenv("RYBA_GEO_PROXY"); return (p && *p) ? p : NULL; }
/* 测试钩子：清表 + 清 DNS 缓存 + loaded=0 + resolver=NULL（空库语义回归用） */
void geo_test_reset(void) {
    pthread_mutex_lock(&g_lock);
    geo_tables_clear();
    dns_cache_clear();
    g_loaded = 0;
    g_resolver = NULL;
    pthread_mutex_unlock(&g_lock);
}

void *geo_test_get_resolver(void) {
    pthread_mutex_lock(&g_lock);
    void *r = (void *)g_resolver;
    pthread_mutex_unlock(&g_lock);
    return r;
}
size_t geo_ip_count(void) { int n = sql_count("SELECT COUNT(*) FROM geo_ip")
    + sql_count("SELECT COUNT(*) FROM geo_ip6"); return n < 0 ? 0 : (size_t)n; }
size_t geo_site_count(void) { int n = sql_count("SELECT COUNT(*) FROM geo_site_exact")
    + sql_count("SELECT COUNT(*) FROM geo_site_suffix") + (int)g_re_n; return n < 0 ? 0 : (size_t)n; }

static void emit_site_sql(int type, const char *val, size_t len, void *ud) {
    import_ctx_t *cx = ud;
    if (type == 0) exact_insert(cx, val, len);
    else if (type == 1 || type == 2) suffix_insert(db_handle(), cx, val, len);
    else if (type == 3) regex_push(val, len);
}

static void emit_ip_sql(const unsigned char *ip, size_t len, int prefix, void *ud) {
    import_ctx_t *cx = ud;
    cidr_insert(db_handle(), cx, ip, len, prefix);
}

int geo_load(const char *dir) {
    if (!dir || !*dir) return -1;
    char p1[1024], p2[1024];
    snprintf(p1, sizeof p1, "%s/geoip.dat", dir);
    snprintf(p2, sizeof p2, "%s/geosite.dat", dir);
    size_t n = 0;
    unsigned char *b1 = read_file(p1, &n);
    size_t n1 = b1 ? n : 0;
    unsigned char *b2 = read_file(p2, &n);
    size_t n2 = b2 ? n : 0;
    if (!b1 && !b2) return -1;
    sqlite3 *h = db_handle();
    if (!h) { free(b1); free(b2); return -1; }
    int rc = -1;
    pthread_mutex_lock(&g_lock);
    geo_tables_clear();
    if (sqlite3_exec(h, "BEGIN IMMEDIATE;", NULL, NULL, NULL) != SQLITE_OK) goto out;
    sqlite3_exec(h, "DELETE FROM geo_ip;", NULL, NULL, NULL);
    sqlite3_exec(h, "DELETE FROM geo_ip6;", NULL, NULL, NULL);
    sqlite3_exec(h, "DELETE FROM geo_site_exact;", NULL, NULL, NULL);
    sqlite3_exec(h, "DELETE FROM geo_site_suffix;", NULL, NULL, NULL);
    import_ctx_t cx;
    memset(&cx, 0, sizeof cx);
    sqlite3_prepare_v2(h, "INSERT INTO geo_ip(start,end,cc) VALUES(?1,?2,?3)", -1, &cx.ip4, NULL);
    sqlite3_prepare_v2(h, "INSERT INTO geo_ip6(s_hi,s_lo,e_hi,e_lo,cc) VALUES(?1,?2,?3,?4,?5)", -1, &cx.ip6, NULL);
    sqlite3_prepare_v2(h, "INSERT OR IGNORE INTO geo_site_exact(host,cc) VALUES(?1,?2)", -1, &cx.exact, NULL);
    sqlite3_prepare_v2(h, "INSERT OR IGNORE INTO geo_site_suffix(rev,cc) VALUES(?1,?2)", -1, &cx.suffix, NULL);
    if (b1) { if (parse_dat(b1, n1, 1, emit_ip_sql, emit_site_sql, &cx) != 0) goto fin; }
    if (b2) { if (parse_dat(b2, n2, 0, emit_ip_sql, emit_site_sql, &cx) != 0) goto fin; }
    sqlite3_finalize(cx.ip4); sqlite3_finalize(cx.ip6);
    sqlite3_finalize(cx.exact); sqlite3_finalize(cx.suffix);
    cx.ip4 = cx.ip6 = cx.exact = cx.suffix = NULL;
    if (sqlite3_exec(h, "COMMIT;", NULL, NULL, NULL) != SQLITE_OK) { sqlite3_exec(h, "ROLLBACK;", NULL, NULL, NULL); goto out; }
    g_loaded = 1;
    rc = 0;
fin:
    if (cx.ip4) sqlite3_finalize(cx.ip4);
    if (cx.ip6) sqlite3_finalize(cx.ip6);
    if (cx.exact) sqlite3_finalize(cx.exact);
    if (cx.suffix) sqlite3_finalize(cx.suffix);
    if (rc != 0) sqlite3_exec(h, "ROLLBACK;", NULL, NULL, NULL);
out:
    pthread_mutex_unlock(&g_lock);
    free(b1); free(b2);
    return rc;
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

/* v4 映射：::ffff:a.b.c.d；v6 原样 */
static void norm_key(const unsigned char *raw, int is6, unsigned char out[16]) {
    if (is6) memcpy(out, raw, 16);
    else { memset(out, 0, 16); out[10] = 0xFF; out[11] = 0xFF; memcpy(out + 12, raw, 4); }
}

/* ---------- 查表（调用方已持 g_lock；无锁/无IO，可单测） ---------- */
static int site_table_hit(const char *low) {
    int e = sql_hit_exact(low);
    if (e != 0) return e; /* 1 命中，-1 降级走 regex */
    int s = sql_hit_suffix(low);
    if (s == 1) return 1;
    for (size_t i = 0; i < g_re_n; i++)
        if (regexec(&g_res[i], low, 0, NULL, 0) == 0) return 1;
    return s < 0 ? s : 0;
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
    else if (is6) hit = sql_hit_ip6(key);
    else { uint32_t a; memcpy(&a, raw, 4); hit = sql_hit_ip4(ntohl(a)); }
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

/* 可注入的 DNS 解析器：默认 NULL=走系统 getaddrinfo；测试注入 fake */
/* （定义已前移到文件顶部，供 geo_free/reset 使用） */

void geo_set_resolver(geo_resolver_fn fn) {
    pthread_mutex_lock(&g_lock);
    g_resolver = fn;
    pthread_mutex_unlock(&g_lock);
}

/* 系统 DNS（唯一碰网络的地方；单测用注入绕过） */
static int sys_resolve(const char *host, char *ip_out, size_t ipsz) {
    struct addrinfo hints, *res = NULL;
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC; hints.ai_socktype = SOCK_STREAM;
    int rc = -1;
    if (getaddrinfo(host, "80", &hints, &res) == 0 && res) {
        void *ap = NULL;
        if (res->ai_family == AF_INET) ap = &((struct sockaddr_in *)res->ai_addr)->sin_addr;
        else if (res->ai_family == AF_INET6) ap = &((struct sockaddr_in6 *)res->ai_addr)->sin6_addr;
        if (ap && inet_ntop(res->ai_family, ap, ip_out, (socklen_t)ipsz)) rc = 0;
        freeaddrinfo(res);
    }
    return rc;
}

int geo_host_is_cn(const char *host) {
    if (!host || !*host) return -1;
    struct in_addr a4; struct in6_addr a6;
    if (inet_pton(AF_INET, host, &a4) == 1 || inet_pton(AF_INET6, host, &a6) == 1)
        return geo_ip_is_cn(host);
    pthread_mutex_lock(&g_lock);
    int loaded = g_loaded;
    geo_resolver_fn resolver = g_resolver;
    pthread_mutex_unlock(&g_lock);
    if (!loaded) return -1; /* 空库未知：不许发起 DNS，直接返回 */
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
    char ipstr[64] = "";
    int cn = -1;
    if ((resolver ? resolver(host, ipstr, sizeof ipstr)
                  : sys_resolve(host, ipstr, sizeof ipstr)) == 0 && ipstr[0]) {
        cn = geo_ip_is_cn(ipstr);
        if (cn < 0) cn = -1;
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
