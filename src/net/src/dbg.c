#include "dbg.h"
#include "sys.h"
#include <stdarg.h>


void dbg_print(int m_level, int s_level, const char * file, const char * func, int line,const char * fmt, ...) {
    static const char * title[] = {
        [DBG_LEVEL_ERROR] = DBG_STYLE_ERROR"error",
        [DBG_LEVEL_WARNING] = DBG_STYLE_WARNING"warning",
        [DBG_LEVEL_INFO] = "info",
        [DBG_LEVEL_NONE] = "none"
    };

    if (m_level >= s_level) {

        const char * end = file + plat_strlen(file);
        while (end >= file ) {
            if (*end == '/') {
                break;
            }
            end --;
        }
        end ++;
        plat_printf("%s(%s--%s--%d) : ",title[s_level], end, func, line);

        char str_buf[128];
        va_list args;

        va_start(args, fmt);
        plat_vsprintf(str_buf, fmt, args);
        plat_printf("%s"DBG_STYLE_RESET"\n", str_buf);
        va_end(args);
    }
}

void dump_mac(const char * msg, const uint8_t * mac) {
    if (msg) {
        plat_printf("%s", msg);
    }

    plat_printf("%02x-%02x-%02x-%02x-%02x-%02x\n", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

/**
 * 打印IP地址
 * @param ip ip地址
 */
void dump_ip_buf(const char* msg, const uint8_t* ip) {
    if (msg) {
        plat_printf("%s", msg);
    }

    if (ip) {
        plat_printf("%d.%d.%d.%d\n", ip[0], ip[1], ip[2], ip[3]);
    } else {
        plat_printf("0.0.0.0\n");
    }
}


