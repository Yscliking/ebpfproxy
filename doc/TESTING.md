# Testing

The tests are black-box and use small helper programs that set their own
process name and generate traffic. They are self-contained below so they can be
recreated anywhere.

Build the tool first:

```sh
make build          # produces ./ebpfproxy
```

All tests must run as root. The examples assume the SOCKS5 proxy is on
`127.0.0.1:1080`.

## Test client (`probenet.c`)

Sets its own `comm`, then either connects TCP or sends a DNS query over UDP
(connected or unconnected).

```c
#define _GNU_SOURCE
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>

static void setname(const char *n) { prctl(PR_SET_NAME, n, 0, 0, 0); }

static int tcp_test(const char *host, const char *port) {
    struct addrinfo hints = {0}, *res = NULL;
    hints.ai_family = AF_INET; hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo(host, port, &hints, &res) != 0) {
        printf("TCP %s:%s RESOLVEFAIL\n", host, port); return 1;
    }
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    int flags = fcntl(fd, F_GETFL, 0); fcntl(fd, F_SETFL, flags | O_NONBLOCK);
    int r = connect(fd, res->ai_addr, res->ai_addrlen);
    if (r == 0) { printf("TCP %s:%s OK\n", host, port); close(fd); return 0; }
    if (errno != EINPROGRESS) {
        printf("TCP %s:%s FAIL errno=%d(%s)\n", host, port, errno, strerror(errno));
        close(fd); return 1;
    }
    fd_set w; FD_ZERO(&w); FD_SET(fd, &w); struct timeval tv = {6, 0};
    r = select(fd + 1, NULL, &w, NULL, &tv);
    if (r <= 0) { printf("TCP %s:%s TIMEOUT\n", host, port); close(fd); return 1; }
    int err = 0; socklen_t el = sizeof(err);
    getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &el);
    if (err) { printf("TCP %s:%s FAIL errno=%d(%s)\n", host, port, err, strerror(err)); close(fd); return 1; }
    printf("TCP %s:%s OK\n", host, port); close(fd); return 0;
}

static unsigned char dnsq[] = {
    0x12,0x34,0x01,0x00,0x00,0x01,0x00,0x00,0x00,0x00,0x00,0x00,
    0x07,'e','x','a','m','p','l','e',0x03,'c','o','m',0x00, 0x00,0x01,0x00,0x01
};

static int dns_test(const char *ip, const char *port, int connected) {
    struct sockaddr_in dst = {0};
    dst.sin_family = AF_INET; dst.sin_port = htons(atoi(port));
    inet_pton(AF_INET, ip, &dst.sin_addr);
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (connected) {
        if (connect(fd, (void *)&dst, sizeof(dst)) != 0) {
            printf("UDP %s:%s CONNECTFAIL %s\n", ip, port, strerror(errno)); return 1;
        }
        send(fd, dnsq, sizeof(dnsq), 0);
    } else {
        sendto(fd, dnsq, sizeof(dnsq), 0, (void *)&dst, sizeof(dst));
    }
    fd_set r; FD_ZERO(&r); FD_SET(fd, &r); struct timeval tv = {6, 0};
    int n = select(fd + 1, &r, NULL, NULL, &tv);
    if (n <= 0) { printf("UDP %s:%s TIMEOUT\n", ip, port); close(fd); return 1; }
    unsigned char buf[512]; struct sockaddr_in from; socklen_t fl = sizeof(from);
    ssize_t got = recvfrom(fd, buf, sizeof(buf), 0, (void *)&from, &fl);
    int ancount = (buf[6] << 8) | buf[7];
    char froms[32]; inet_ntop(AF_INET, &from.sin_addr, froms, sizeof(froms));
    printf("UDP %s:%s OK from=%s:%d answers=%d\n", ip, port, froms, ntohs(from.sin_port), ancount);
    close(fd); return 0;
}

int main(int argc, char **argv) {
    if (argc < 3) return 2;
    setname(argv[1]);
    if (!strcmp(argv[2], "tcp")  && argc >= 5) return tcp_test(argv[3], argv[4]);
    if (!strcmp(argv[2], "udpc") && argc >= 5) return dns_test(argv[3], argv[4], 1);
    if (!strcmp(argv[2], "udpu") && argc >= 5) return dns_test(argv[3], argv[4], 0);
    return 2;
}
```

Build: `gcc -O2 -o probenet probenet.c`

## Firefox simulation (`firefox.c`)

Build it **as `firefox`** so the executable basename matches. It forks a child
that renames its `comm` to `Web Content`; both connect to `1.1.1.1:443` (a
destination that is blocked directly but reachable through the proxy here).

```c
#define _GNU_SOURCE
#include <sys/prctl.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>

static const char *conn_dst(void) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in a = {.sin_family = AF_INET, .sin_port = htons(443)};
    inet_pton(AF_INET, "1.1.1.1", &a.sin_addr);
    int fl = fcntl(fd, F_GETFL, 0); fcntl(fd, F_SETFL, fl | O_NONBLOCK);
    int r = connect(fd, (void *)&a, sizeof(a));
    if (r == 0) { close(fd); return "OK"; }
    if (errno != EINPROGRESS) { close(fd); return strerror(errno); }
    fd_set w; FD_ZERO(&w); FD_SET(fd, &w); struct timeval tv = {5, 0};
    r = select(fd + 1, NULL, &w, NULL, &tv);
    if (r <= 0) { close(fd); return "TIMEOUT"; }
    int err = 0; socklen_t el = sizeof(err);
    getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &el); close(fd);
    return err ? strerror(err) : "OK";
}

int main(void) {
    prctl(PR_SET_NAME, "firefox", 0, 0, 0);
    pid_t p = fork();
    if (p == 0) {
        prctl(PR_SET_NAME, "Web Content", 0, 0, 0);
        printf("child  (comm=Web Content): %s\n", conn_dst()); _exit(0);
    }
    printf("parent (comm=firefox):     %s\n", conn_dst());
    waitpid(p, 0, 0); return 0;
}
```

Build: `gcc -O2 -o firefox firefox.c`

## Scenarios

Run each block in its own shell; the examples background the engine and clean it
up.

### 1. BLOCK with an explicit DIRECT exception

There are no hardcoded process rules, so add a `DIRECT` rule yourself for the
processes that must stay up. Rules are top-to-bottom, first match wins.

```sh
./ebpfproxy --headless \
    --rule 'opencode:*:*:BOTH:DIRECT' \
    --rule '*:*:*:BOTH:BLOCK' & PID=$!; sleep 1.5
./probenet opencode tcp 172.66.147.243 443    # expect OK (rule #1 DIRECT)
./probenet victim   tcp 172.66.147.243 443    # expect FAIL errno=1 (rule #2 BLOCK)
./probenet victim   udpc 8.8.8.8 53           # expect CONNECTFAIL EPERM
kill $PID
```

### 2. TCP PROXY

Use a destination that is blocked directly but works through the proxy
(`1.1.1.1:443` here).

```sh
./ebpfproxy --headless --proxy 127.0.0.1:1080 --rule 'victim:*:*:TCP:PROXY' & PID=$!; sleep 1.5
./probenet victim tcp 1.1.1.1 443    # expect OK   (proxied)
./probenet normal tcp 1.1.1.1 443    # expect TIMEOUT (direct)
kill $PID
```

### 3. UDP PROXY

```sh
./ebpfproxy --headless --proxy 127.0.0.1:1080 --rule 'victim:*:53:UDP:PROXY' & PID=$!; sleep 1.5
./probenet victim udpu 8.8.8.8 53    # expect OK from=8.8.8.8:53 (spoofed source)
./probenet victim udpc 8.8.8.8 53    # expect OK from=127.0.0.1:15002 (relay source)
./probenet normal udpc 8.8.8.8 53    # expect OK from=8.8.8.8:53 (direct)
kill $PID
```

### 4. Firefox (executable-basename matching)

```sh
./ebpfproxy --headless --proxy 127.0.0.1:1080 --rule 'firefox:*:*:TCP:PROXY' & PID=$!; sleep 1.5
./firefox     # parent OK, child OK  (both proxied)
kill $PID

./ebpfproxy --headless --rule 'firefox:*:*:TCP:BLOCK' & PID=$!; sleep 1.5
./firefox     # parent EPERM, child EPERM
kill $PID
```

### 5. Crash cleanup

```sh
./ebpfproxy --headless --rule '*:*:*:BOTH:BLOCK' & PID=$!; sleep 1.5
./probenet victim tcp 172.66.147.243 443   # FAIL (blocked)
kill -9 $PID; sleep 1
./probenet victim tcp 172.66.147.243 443   # OK (hooks detached)
```

## Expected engine log

```
[23:00:36] TCP PROXY rule #1 pid=14211  firefox          -> 1.1.1.1:443
[23:00:36] TCP PROXY rule #1 pid=14212  Web Content      -> 1.1.1.1:443
```

## Notes

- `1.1.1.1:443` and `172.66.147.243:443` were chosen because direct access is
  blocked in the development environment while the proxy reaches them; substitute
  any destination that behaves the same way on your network.
- UDP through a proxy is subject to upstream reliability; occasionally the first
  datagram after the association is established is lost.
