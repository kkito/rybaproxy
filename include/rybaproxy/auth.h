#ifndef RYBAPROXY_AUTH_H
#define RYBAPROXY_AUTH_H

#include <stdbool.h>
#include <stddef.h>

bool auth_basic_check(const char *header_value, const char *username, const char *password);
/* base64 decode; returns decoded length or -1 */
int base64_decode(const char *in, unsigned char *out, size_t outcap);

#endif
