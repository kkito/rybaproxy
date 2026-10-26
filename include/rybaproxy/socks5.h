#ifndef RYBAPROXY_SOCKS5_H
#define RYBAPROXY_SOCKS5_H

#include <stddef.h>
#include <stdint.h>

#define SOCKS5_VERSION 0x05

/* reply codes */
#define SOCKS5_REP_SUCCESS 0x00
#define SOCKS5_REP_FAILURE 0x01
#define SOCKS5_REP_CMD_NOT_SUPPORTED 0x07
#define SOCKS5_REP_ATYP_NOT_SUPPORTED 0x08

/* atyp */
#define SOCKS5_ATYP_IPV4 0x01
#define SOCKS5_ATYP_DOMAIN 0x03
#define SOCKS5_ATYP_IPV6 0x04

/* parse a SOCKS5 CONNECT request from buf (after handshake/auth).
   Returns number of bytes consumed, or -1 on error/incomplete.
   On success fills host (string) and port. */
int socks5_parse_request(const unsigned char *buf, size_t len, char *host, size_t hostcap, uint16_t *port);

/* Build a success reply with bind addr 0.0.0.0:0 into out (must have >=10 bytes). Returns 10. */
int socks5_build_reply(unsigned char *out, unsigned char rep);

#endif
