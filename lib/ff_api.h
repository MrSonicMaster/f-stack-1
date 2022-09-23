/*
 * Copyright (C) 2017-2021 THL A29 Limited, a Tencent company.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice, this
 *   list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *   this list of conditions and the following disclaimer in the documentation
 *   and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR
 * ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#ifndef _FSTACK_API_H
#define _FSTACK_API_H

#ifdef __cplusplus
extern "C" {
#endif
#include <sys/socket.h>
#include <sys/select.h>
#include <sys/poll.h>
#include <netinet/in.h>
#include <sys/time.h>

#include "ff_event.h"
#include "ff_errno.h"

struct linux_sockaddr {
    short sa_family;
    char sa_data[14];
};

#define AF_INET6_LINUX    10
#define PF_INET6_LINUX    AF_INET6_LINUX
#define AF_INET6_FREEBSD    28
#define PF_INET6_FREEBSD    AF_INET6_FREEBSD

typedef void (*loop_func_t)(void *arg, uint64_t tsc);

int ff_init(int argc, char * const argv[]);

void ff_run(loop_func_t loop, void *arg);

/* POSIX-LIKE api begin */

int ff_fcntl(int fd, int cmd, ...);

int ff_sysctl(const int *name, u_int namelen, void *oldp, size_t *oldlenp,
    const void *newp, size_t newlen);

int ff_ioctl(int fd, unsigned long request, ...);

int ff_socket(int domain, int type, int protocol);

int ff_setsockopt(int s, int level, int optname, const void *optval,
    socklen_t optlen);

int ff_getsockopt(int s, int level, int optname, void *optval,
    socklen_t *optlen);

int ff_listen(int s, int backlog);
int ff_bind(int s, const struct linux_sockaddr *addr, socklen_t addrlen);
int ff_accept(int s, struct linux_sockaddr *addr, socklen_t *addrlen);
int ff_connect(int s, const struct linux_sockaddr *name, socklen_t namelen);
int ff_close(int fd);
int ff_shutdown(int s, int how);

int ff_getpeername(int s, struct linux_sockaddr *name,
    socklen_t *namelen);
int ff_getsockname(int s, struct linux_sockaddr *name,
    socklen_t *namelen);

ssize_t ff_read(int d, void *buf, size_t nbytes);
ssize_t ff_readv(int fd, const struct iovec *iov, int iovcnt);

ssize_t ff_write(int fd, const void *buf, size_t nbytes);
ssize_t ff_writev(int fd, const struct iovec *iov, int iovcnt);

ssize_t ff_send(int s, const void *buf, size_t len, int flags);
ssize_t ff_sendto(int s, const void *buf, size_t len, int flags,
    const struct linux_sockaddr *to, socklen_t tolen);
ssize_t ff_sendmsg(int s, const struct msghdr *msg, int flags);

ssize_t ff_recv(int s, void *buf, size_t len, int flags);
ssize_t ff_recvfrom(int s, void *buf, size_t len, int flags,
    struct linux_sockaddr *from, socklen_t *fromlen);
ssize_t ff_recvmsg(int s, struct msghdr *msg, int flags);

int ff_select(int nfds, fd_set *readfds, fd_set *writefds, fd_set *exceptfds,
    struct timeval *timeout);

int ff_poll(struct pollfd fds[], nfds_t nfds, int timeout);

int ff_kqueue(void);
int ff_kevent(int kq, const struct kevent *changelist, int nchanges,
    struct kevent *eventlist, int nevents, const struct timespec *timeout);
int ff_kevent_do_each(int kq, const struct kevent *changelist, int nchanges,
    void *eventlist, int nevents, const struct timespec *timeout,
    void (*do_each)(void **, struct kevent *));

int ff_gettimeofday(struct timeval *tv, struct timezone *tz);

int ff_dup(int oldfd);
int ff_dup2(int oldfd, int newfd);

/* POSIX-LIKE api end */


/* Tests if fd is used by F-Stack */
extern int ff_fdisused(int fd);

extern int ff_getmaxfd(void);

/* route api begin */
enum FF_ROUTE_CTL {
    FF_ROUTE_ADD,
    FF_ROUTE_DEL,
    FF_ROUTE_CHANGE,
};

enum FF_ROUTE_FLAG {
    FF_RTF_HOST,
    FF_RTF_GATEWAY,
};

/*
 * On success, 0 is returned.
 * On error, -1 is returned, and errno is set appropriately.
 */
int ff_route_ctl(enum FF_ROUTE_CTL req, enum FF_ROUTE_FLAG flag,
    struct linux_sockaddr *dst, struct linux_sockaddr *gw,
    struct linux_sockaddr *netmask);

/* route api end */


/* dispatch api begin */
#define FF_DISPATCH_ERROR (-1)
#define FF_DISPATCH_RESPONSE (-2)

/*
 * Packet dispatch callback function.
 * Implemented by user.
 *
 * @param data
 *   The data pointer of this packet.
 * @param len
 *   The length of this packet.
 * @param queue_id
 *   Current queue of this packet.
 * @param nb_queues
 *   Number of queues to be dispatched.
 *
 * @return 0 to (nb_queues - 1)
 *   The queue id that the packet will be dispatched to.
 * @return FF_DISPATCH_ERROR (-1)
 *   Error occurs or packet is handled by user, packet will be freed.
* @return FF_DISPATCH_RESPONSE (-2)
 *   Packet is handled by user, packet will be responsed.
 *
 */
typedef int (*dispatch_func_t)(void *data, uint16_t *len,
    uint16_t queue_id, uint16_t nb_queues);

/* regist a packet dispath function */
void ff_regist_packet_dispatcher(dispatch_func_t func);

/* dispatch api end */

/* pcb lddr api begin */
/*
 * pcb lddr callback function.
 * Implemented by user.
 *
 * @param family
 *   The remote server addr, should be AF_INET or AF_INET6.
 * @param dst_addr
 *   The remote server addr, should be (in_addr *) or (in6_addr *).
 * @param dst_port
 *   The remote server port.
 * @param src_addr
 *   Return parameter.
 *   The local addr, should be (in_addr *) or (in6_addr *).
 *   If set (INADDR_ANY) or (in6addr_any), the app then will
 *   call `in_pcbladdr()` to get laddr.
 *
 * @return error_no
 *   0 means success.
 *
 */
typedef int (*pcblddr_func_t)(uint16_t family, void *dst_addr,
    uint16_t dst_port, void *src_addr);

/* regist a pcb lddr function */
void ff_regist_pcblddr_fun(pcblddr_func_t func);

/* pcb lddr api end */

/* internal api begin */

/* FreeBSD style calls. Used for tools. */
int ff_ioctl_freebsd(int fd, unsigned long request, ...);
int ff_setsockopt_freebsd(int s, int level, int optname,
    const void *optval, socklen_t optlen);
int ff_getsockopt_freebsd(int s, int level, int optname,
    void *optval, socklen_t *optlen);

/*
 * Handle rtctl.
 * The data is a pointer to struct rt_msghdr.
 */
int ff_rtioctl(int fib, void *data, unsigned *plen, unsigned maxlen);

/*
 * Handle ngctl.
 */
enum FF_NGCTL_CMD {
    NGCTL_SOCKET,
    NGCTL_BIND,
    NGCTL_CONNECT,
    NGCTL_SEND,
    NGCTL_RECV,
    NGCTL_CLOSE,
};

int ff_ngctl(int cmd, void *data);

/* internal api end */

/* zero ccopy API begin */
struct ff_zc_mbuf {
    void *bsd_mbuf;         /* point to the head mbuf */
    void *bsd_mbuf_off;     /* ponit to the current mbuf in the mbuf chain with offset */
    int off;                /* the offset of total mbuf, APP shouldn't modify it */
    int len;                /* the total len of the mbuf chain */
};

/*
 * Get the ff zero copy mbuf.
 *
 * @param m
 *   The ponitor of 'struct ff_zc_mbuf', and can't be NULL.
 *   Can used by 'ff_zc_mbuf_write' and 'ff_zc_mbuf_read'.
 * @param len
 *   The total buf len of mbuf chain that you want to alloc.
 *
 * @return error_no
 *   0 means success.
 *  -1 means error.
 */
int ff_zc_mbuf_get(struct ff_zc_mbuf *m, int len);

/* used to expand a ff_zc_mbuf previously given by ff_zc_mbuf_get */
int ff_zc_mbuf_expand(struct ff_zc_mbuf *m, int len);

/* drop n bytes from head of zc mbuf */
int ff_zc_mbuf_drop_st(struct ff_zc_mbuf *m, int len);

/*
 * Write data to the mbuf chain in 'struct ff_zc_mbuf'.
 * APP can call this function multiple times, need pay attion to the offset of data.
 * but the total len can't be larger than m->len.
 * After this fuction return success,
 *
 * the struct 'ff_zc_mbuf *m' can be reused in `ff_zc_mbuf_get` and then Use normally.
 * Nerver directly reused in `ff_zc_mbuf_write` before recall `ff_zc_mbuf_get`.
 *
 * APP nedd call 'ff_write' to send data actually after finish write data to mbuf,
 * And use 'bsd_mbuf' of 'struct ff_zc_mbuf' as the 'buf' argument.
 *
 * See 'example/main_zc.c'
 *
 * @param m
 *   The ponitor of 'struct ff_zc_mbuf', must be call 'ff_zc_mbuf_get' first.
 * @param data
 *   The pointer of data that want to write to socket, need pay attion to the offset.
 * @param len
 *   The len that APP want to write to mbuf chain this time.
 *
 * @return error_no
 *   0 means success.
 *  -1 means error.
 */
int ff_zc_mbuf_write(struct ff_zc_mbuf *m, const char *data, int len);


/* F-STACK ZC READ API: is not really zero-copy yet, harder to 
 * pull that off because bsd stores data of each IP packet
 * in a separate mbuf and chains them. Currently only useful to decrease
 * overhead of kernel when reading data - now reading/consuming 
 * is separated and user-controlled so framed streams can be
 * cheaper to process. */

/*
 * Read data to the mbuf chain in 'struct ff_zc_mbuf'. Must call
 * ff_get_sock_rcvbuf to the ff_zc_mbuf first. 
 * Can be called multiple times, each call will consume 'len' bytes from
 * the ff_zc_mbuf or return with error if not enough length left. Can check m->len.
 */
int ff_zc_mbuf_read(struct ff_zc_mbuf *m, char *data, int len);

/* Call to get head of BSD socket rcv buffer mbuf chain (encapsulated in struct
 * ff_zc_mbuf), can read from it with ff_zc_mbuf_read. */
ssize_t ff_get_sock_rcvbuf(int s, struct ff_zc_mbuf *zm);

/* Call to consume `n` bytes of data from BSD rcvbuf of socket `s` */
ssize_t ff_sock_rcvbuf_consume_nbytes(int s, int n);

/* bind dgram socket to local port */
ssize_t ff_bind_fast(int s, uint32_t addr, uint16_t port);

/* ZERO COPY API end */

/* EXPOSE API begin */

/* can be useful if application creates its own shared memory,
 * to have a good per-proc index already provided.*/
int ff_get_rx_queue(int port_id);

/* if app needs master process to create the memory, it must
 * know how many to prepare for */
int ff_num_rx_queues(int port_id);

/* can repeat prev 2 for every port */
int ff_num_ports(void);

/* EXPOSE API end*/

#ifdef __cplusplus
}
#endif
#endif

