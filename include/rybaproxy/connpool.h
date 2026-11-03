#ifndef RYBAPROXY_CONNPOOL_H
#define RYBAPROXY_CONNPOOL_H

#include "rybaproxy/common.h"
#include <event2/event.h>

/* 异步连接池。
 *
 * 为什么需要它：上游连接（DNS + connect + CONNECT/SOCKS5 握手）全是阻塞调用，
 * 直接跑在 libevent 的单线程事件循环里时，一个慢连接会把所有并发请求一起卡住
 * （实测 10 个 3s 的坏连接能让其它请求排队 15s）。把这段阻塞工作丢进工作线程，
 * 事件循环只负责收结果。
 *
 * 完成回调在事件循环线程里执行：
 *   fd >= 0 表示连上了，调用方负责 set_nonblock / 建 bufferevent / 最终 close；
 *   fd < 0  表示失败。
 * 任务在飞期间调用方必须保持 ctx 有效；销毁前记得 connpool_cancel(ctx)，
 * 池子会把已经连上的 fd 关掉并且不再回调。
 */

typedef void (*connpool_done_fn)(void *ctx, int fd, int upstream_id, void *ud);
typedef int (*connpool_connect_fn)(const upstream_profile_t *up, const char *host,
                                   uint16_t port, int *out_fd);

int connpool_init(struct event_base *base, int workers);
void connpool_shutdown(void);

/* 注入连接实现（默认走 upstream_connect_profile）。单测用假实现，零网络。 */
void connpool_set_connect_fn(connpool_connect_fn fn);

int connpool_submit(void *ctx, const upstream_profile_t *up, const char *host,
                    uint16_t port, connpool_done_fn done, void *ud);
void connpool_cancel(void *ctx);

#endif
