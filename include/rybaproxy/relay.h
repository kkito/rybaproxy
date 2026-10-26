#ifndef RYBAPROXY_RELAY_H
#define RYBAPROXY_RELAY_H

#include "rybaproxy/session.h"
#include <event2/bufferevent.h>

void relay_start(session_t *s, struct bufferevent *client, struct bufferevent *upstream);

#endif
