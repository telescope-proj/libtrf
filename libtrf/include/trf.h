/*
    SPDX-License-Identifier: LGPL-2.1-only

    Telescope Project
    Remote Framebuffer Library

    Copyright (c) 2022 Tim Dettmar

    This library is free software; you can redistribute it and/or modify it
    under the terms of the GNU Lesser General Public License as published by the
    Free Software Foundation; version 2.1. 

    This library is distributed in the hope that it will be useful, but WITHOUT
    ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
    FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License
    for more details.

    You should have received a copy of the GNU Lesser General Public License
    along with this library; if not, write to the Free Software Foundation,
    Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
*/

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

#include <rdma/fabric.h>
#include <rdma/fi_errno.h>
#include <rdma/fi_domain.h>
#include <rdma/fi_endpoint.h>
#include <rdma/fi_rma.h>
#include <rdma/fi_collective.h>

#ifdef _WIN32
#include <windows.h>
#endif

#if defined (__unix__) || (defined (__APPLE__) && defined (__MACH__))
#include <unistd.h>
#include <time.h>
#endif

#define trf_error(...) fprintf(stderr, "[error] " __VA_ARGS__)
#define trf_fi_error(call, err) fprintf(stderr, "[fabric] %s failed (%d): %s\n", call, (int) -err, fi_strerror((int) -err))
#define trf_log(...) printf("[general] " __VA_ARGS__)
#define trf_debug(...) fprintf(stderr, "[debug] " __VA_ARGS__)

/*  Simple strdup for standard C */
static inline char * trfStrdup(char * str)
{
    size_t len = strlen(str) + 1;
    char * out = malloc(len);
    memcpy(out, str, len);
    return out;
}

/*  Sleep for a given number of milliseconds */
static inline void trfSleep(int ms) {
    trf_debug("sleeping...\n");
#ifdef _WIN32
    Sleep(ms);
#else
    struct timespec t;
    t.tv_sec    = ms / 1000;
    t.tv_nsec   = (ms % 1000) * 1000000;
    nanosleep(&t, NULL);
#endif
    trf_debug("hello\n");
}

struct TRFContext {
    struct fid_fabric   * fabric;   // Fabric interface
    struct fid_domain   * domain;   // Protection domain
    struct fid_eq       * eq;       // Event queue
    struct fid_cq       * cq;       // Completion queue
    void                * addr;     // Source or destination address depending on EP type
    union {
        struct fid_pep  * pep;      // Passive endpoint (server)
        struct fid_ep   * ep;       // Active endpoint (client)
    };
    struct fid_mr       * msg_mr;   // Memory region for messages
    struct fid_mr       * fb_mr;    // Framebuffer
};

enum TRFEPType {
    TRF_EP_CLIENT,
    TRF_EP_SERVER
};

struct TRFBufferData {
    struct fid_mr * mr;
    void * addr;
    size_t len;
};

#define PTRFContext struct TRFContext *
#define TRF_MR_SIZE 64 * 1024 * 1024

/*  Allocate an active (client) endpoint 
    ctx: Allocated context to store endpoint
    fi: Endpoint selection information
    Returns 0 on success, negative error code on failure.
*/
int trfAllocActiveEP(PTRFContext ctx, struct fi_info * fi);

/*  Destroy resources associated with a context in the correct order.
    ctx: The context to destroy.
    Returns 0 on success, negative error code on failure.
*/
int trfDestroyContext(PTRFContext ctx);

/*  Create an endpoint.
    host: Hostname or IP address (server: bind address, client: connect address)
    port: Port number (server: bind port, client: connect port)
    req_type: Requested EP type to create (server or client)
    ctx: Allocated context to store endpoint
    Returns 0 on success, negative error code on failure.
*/
int trfCreateEP(const char * host, const char * port, enum TRFEPType req_type, PTRFContext ctx);

/*  Accept an incoming connection from a client.
    ctx: The created server context.
    client: Pointer to allocated context, where the resources for the new
    connection will be stored.
    Returns 0 on success, negative error code on failure.
*/
int trfAccept(PTRFContext ctx, PTRFContext client);

/*  Get the last event from the event queue.
    eq: The event queue
    buf: The buffer to store the event
    len: The length of the buffer
    nb: Non-blocking flag
    consume: Whether to consume the event from the queue or peek only
*/
int trfPopEQ(struct fid_eq * eq, void * buf, size_t len, int nb, int consume);

/*  Print the last error from the event queue.
    eq: Event queue to check
    out: Pointer to char * to be set as the error string, DO NOT MODIFY
    Returns: 0 on success, -ret on error
*/
int trfEQLastErrorDesc(struct fid_eq * eq, char ** out);

/*  Initialize a sink (client) context.
    node: Client hostname or address
    service: Client port or service name
    ctx: Allocated context to store endpoint
    Returns: 0 on success, negative error code on failure.
*/
int trfSinkInit(char * node, char * service, PTRFContext ctx);

/*  Initialize a source (server) context.
    node: Server hostname or address
    service: Server port or service name
    ctx: Allocated context to store endpoint
    Returns: 0 on success, negative error code on failure.
*/
int trfSourceInit(char * node, char * service, PTRFContext ctx);

/*  Detect an incoming connection from a client, but do not accept it.
    ctx: Server context
    nb: Non-blocking flag
    Returns: number of clients waiting, negative error code on failure.
    Currently this function only returns a max of 1 client waiting.
*/
int trfSourceCheckReq(PTRFContext ctx, int nb);

/*  Allocate a context for library use.
    This does not allocate any resources and is a simple wrapper around
    calloc.
    Returns: Allocated context pointer, NULL on failure.
*/
PTRFContext trfAllocContext();

/*  Allocate a local buffer.
    ctx: Allocate context containing domain to bind to
    size: Size of buffer to allocate
    mr: Pointer to allocated memory region to be set. The actual address of
    the allocated memory region is stored in mr->fid.context.
    It is recommended the size be a multiple of the system page size.
*/
int trfAllocLocalBuffer(PTRFContext ctx, size_t size, struct fid_mr ** mr);


int trfGetCQEvent(PTRFContext ctx);

/*  Print allocated pointers in a context.
    ctx: Context to print
*/
inline void trfDebugContextPointers(PTRFContext ctx)
{
    printf("----------------------------\n");
    printf("ctx->fabric: %p\n", ctx->fabric);
    printf("ctx->domain: %p\n", ctx->domain);
    printf("ctx->eq: %p\n", ctx->eq);
    printf("ctx->cq: %p\n", ctx->cq);
    printf("ctx->addr: %p\n", ctx->addr);
    printf("ctx->pep: %p\n", ctx->pep);
    printf("ctx->ep: %p\n", ctx->ep);
}