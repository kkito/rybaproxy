#ifndef RYBAPROXY_GEO_H
#define RYBAPROXY_GEO_H

#include <stddef.h>

/* Geo 分流：IP 段查询 + 域名清单查询。数据来自开源社区 geoip.dat/geosite.dat。
 * 三值语义：1=命中CN 0=未命中/-1=输入无效或未知 */
int geo_init(void);
void geo_free(void);
/* 1=至少一个 dat 已加载 */
int geo_db_loaded(void);
/* 返回 1=CN(含私网) 0=非CN(未知按非CN) -1=输入无效 */
int geo_ip_is_cn(const char *ip);
/* 内网/私网判定：1=内网, 0=公网, -1=非法（不查库不解析） */
int geo_ip_is_lan(const char *ip);
int geo_site_is_cn(const char *host);
/* 域名→DNS解析→查段：1=CN 0=非CN -1=未知/DNS失败；5分钟缓存 */
int geo_host_is_cn(const char *host);
int geo_host_is_lan(const char *host);
/* DNS 解析器注入（测试用 mock；NULL=用系统 getaddrinfo）。返回 0 成功并写 ip_out */
typedef int (*geo_resolver_fn)(const char *host, char *ip_out, size_t ipsz);
void geo_set_resolver(geo_resolver_fn fn);
/* 从目录加载 geoip.dat + geosite.dat；缺文件返回-1（旧数据保留） */
int geo_load(const char *dir);
/* 当前数据源 URL（环境变量覆盖后生效）；调用方不要 free */
const char *geo_ip_url(void);
const char *geo_site_url(void);
const char *geo_proxy(void);
size_t geo_ip_count(void);
size_t geo_site_count(void);
/* 下载 dat 到 dir（tmp+rename 原子落盘，成功后 geo_load）；失败 err 写原因 */
int geo_download(const char *dir, char *err, size_t errsz);
/* 目录解析（纯函数）：cfg > env > $HOME/.local/rybaproxy > "." */
int geo_resolve_dir(const char *cfg_dir, const char *env_dir, const char *home,
                    char *out, size_t outsz);
/* 生效目录（薄胶水）：读 RYBA_GEO_DIR/HOME 环境 */
int geo_active_dir(const char *cfg_dir, char *out, size_t outsz);
/* LRU 大小：默认 512，0=关闭，直查 sqlite；上限 4096，返回生效值 */
int geo_set_cache_size(int n);
int geo_cache_size(void);
/* 测试钩子：清表+清DNS缓存+loaded=0+resolver=NULL */
void geo_test_reset(void);
/* 测试断言：当前注入的 resolver（NULL=系统 DNS）；供单测验证零网络 */
void *geo_test_get_resolver(void);

#endif
