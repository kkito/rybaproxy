#ifndef RYBAPROXY_CONNPOOL_H
#define RYBAPROXY_CONNPOOL_H

#include <event2/event.h>

/* 异步任务池（连接池）。
 *
 * 为什么需要它：DNS 解析（含 geo 判定里的解析）、TCP connect、上游 CONNECT/SOCKS5
 * 握手全是阻塞调用。它们一旦跑在 libevent 的单线程事件循环里，一个慢目标就能让所有
 * 并发请求串行排队（实测 10 个 3s 的坏目标把无关请求拖到 15s），DNS 卡顿同理。
 *
 * 任务在工作线程执行，完成回调在事件循环线程执行：
 *   fd >= 0 表示成功，调用方负责抓走 fd（set_nonblock / 建 bufferevent / 关闭）；
 *   fd < 0  表示失败。
 * 任务在飞期间调用方必须保持 ctx 与 task_ctx 有效；销毁前调 connpool_cancel(ctx)，
 * 池子会把任务产出的 fd 关掉并且不再回调。
 */

/* 跑在工作线程里的阻塞任务：把 fd 塞进 out_fd，返回 0 表示成功。 */
typedef int (*connpool_task_fn)(void *task_ctx, int *out_fd);
/* 在事件循环线程里回调。 */
typedef void (*connpool_done_fn)(void *ctx, int fd, void *ud);

int connpool_init(struct event_base *base, int workers);
void connpool_shutdown(void);

int connpool_submit(void *ctx, connpool_task_fn task, void *task_ctx,
                    connpool_done_fn done, void *ud);
void connpool_cancel(void *ctx);

#endif
