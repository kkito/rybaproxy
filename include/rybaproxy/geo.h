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
int geo_site_is_cn(const char *host);
/* 域名→DNS解析→查段：1=CN 0=非CN -1=未知/DNS失败；5分钟缓存 */
int geo_host_is_cn(const char *host);
/* 从目录加载 geoip.dat + geosite.dat；缺文件返回-1（旧数据保留） */
int geo_load(const char *dir);
size_t geo_ip_count(void);
size_t geo_site_count(void);
/* 下载 dat 到 dir（tmp+rename 原子落盘，成功后 geo_load）；失败 err 写原因 */
int geo_download(const char *dir, char *err, size_t errsz);

#endif
