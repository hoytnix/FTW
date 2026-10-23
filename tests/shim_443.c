/* Transparent port-443 remap for the prefer-HTTPS happy-path test.
 *
 * Unprivileged users cannot bind port 443 (`ip_unprivileged_port_start`
 * is 1024 here), so the happy-path test preloads this library into both
 * the TLS fixture server and the `ftw` binary under test: any `bind` or
 * `connect` asking for port 443 is redirected to the shadow high port in
 * `FTW_SHADOW_PORT` (default 14443). The pipeline under test is completely
 * unmodified — it still asks for literal port 443 over HTTPS; only the
 * kernel-level destination changes, so a recorded `scheme: https` +
 * `status: 200` row proves the real HTTPS code path ran.
 *
 * Built at test time, never shipped:
 *   cc -shared -fPIC -O2 -o shim.so tests/shim_443.c -ldl
 */

#define _GNU_SOURCE

#include <dlfcn.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

static int shadow_port(void) {
    const char *env = getenv("FTW_SHADOW_PORT");
    if (env != NULL && *env != '\0') {
        long value = strtol(env, NULL, 10);
        if (value > 0 && value < 65536) {
            return (int)value;
        }
    }
    return 14443;
}

static void remap(const struct sockaddr *addr) {
    if (addr->sa_family == AF_INET) {
        struct sockaddr_in *in = (struct sockaddr_in *)addr;
        if (in->sin_port == htons(443)) {
            in->sin_port = htons((uint16_t)shadow_port());
        }
    } else if (addr->sa_family == AF_INET6) {
        struct sockaddr_in6 *in6 = (struct sockaddr_in6 *)addr;
        if (in6->sin6_port == htons(443)) {
            in6->sin6_port = htons((uint16_t)shadow_port());
        }
    }
}

int bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen) {
    static int (*real_bind)(int, const struct sockaddr *, socklen_t) = NULL;
    if (real_bind == NULL) {
        real_bind = dlsym(RTLD_NEXT, "bind");
    }
    remap(addr);
    return real_bind(sockfd, addr, addrlen);
}

int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen) {
    static int (*real_connect)(int, const struct sockaddr *, socklen_t) = NULL;
    if (real_connect == NULL) {
        real_connect = dlsym(RTLD_NEXT, "connect");
    }
    remap(addr);
    return real_connect(sockfd, addr, addrlen);
}
