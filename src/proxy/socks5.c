#include "rybaproxy/socks5.h"

#include <arpa/inet.h>
#include <stdio.h>
#include <string.h>

int socks5_parse_request(const unsigned char *buf, size_t len, char *host, size_t hostcap, uint16_t *port) {
    if (!buf || len < 4) return -1;
    if (buf[0] != SOCKS5_VERSION) return -1;
    unsigned char cmd = buf[1];
    if (cmd != 0x01) return -2; /* unsupported command */
    unsigned char atyp = buf[3];
    size_t pos = 4;
    if (atyp == SOCKS5_ATYP_IPV4) {
        if (len < pos + 4 + 2) return -1;
        snprintf(host, hostcap, "%u.%u.%u.%u", buf[pos], buf[pos+1], buf[pos+2], buf[pos+3]);
        pos += 4;
    } else if (atyp == SOCKS5_ATYP_DOMAIN) {
        if (len < pos + 1) return -1;
        unsigned char dlen = buf[pos++];
        if (len < pos + dlen + 2) return -1;
        if (dlen >= hostcap) return -2;
        memcpy(host, buf + pos, dlen);
        host[dlen] = '\0';
        pos += dlen;
    } else if (atyp == SOCKS5_ATYP_IPV6) {
        if (len < pos + 16 + 2) return -1;
        char tmp[64];
        /* format IPv6 */
        snprintf(tmp, sizeof tmp, "%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x",
            buf[pos],buf[pos+1],buf[pos+2],buf[pos+3],buf[pos+4],buf[pos+5],buf[pos+6],buf[pos+7],
            buf[pos+8],buf[pos+9],buf[pos+10],buf[pos+11],buf[pos+12],buf[pos+13],buf[pos+14],buf[pos+15]);
        snprintf(host, hostcap, "%s", tmp);
        pos += 16;
    } else {
        return -2;
    }
    *port = ((uint16_t)buf[pos] << 8) | buf[pos+1];
    pos += 2;
    return (int)pos;
}

int socks5_build_reply(unsigned char *out, unsigned char rep) {
    out[0] = 0x05; out[1] = rep; out[2] = 0x00; out[3] = 0x01;
    out[4]=out[5]=out[6]=out[7]=0; out[8]=0; out[9]=0;
    return 10;
}
