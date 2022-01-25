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

#pragma once

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

struct TRFOOBContext {
    int client_fd;
    int listen_fd;
};

struct TRFContext {
    enum TRFEPType      type;       // Endpoint type
    struct TRFOOBContext * oob;     // Management channel
    struct fid_fabric   * fabric;   // Fabric interface
    struct fid_domain   * domain;   // Protection domain
    struct fid_eq       * eq;       // Event queue
    struct fid_cq       * cq;       // TX completion queue
    struct fid_av       * av;       // Address vector
    union {
        fi_addr_t       src_addr;   // Local address
        fi_addr_t       dst_addr;   // Peer address
    };
    union {
        struct fid_pep  * pep;      // Passive endpoint (server)
        struct fid_ep   * ep;       // Active endpoint (client)
    };
    struct fid_mr       * msg_mr;   // Memory region for messages
    struct fid_mr       * fb_mr;    // Framebuffer
    uint32_t            intrv;      // Interrupt vector
};

enum TRFEPType {
    TRF_EP_SINK,
    TRF_EP_SOURCE
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

/*  Warm up the endpoint by sending several messages until the underlying
    connection has been established. This is primarily useful for ofi_rxm
    endpoints, where the connection is established on-demand. 
    ctx: Allocated context
    session_id: Session identifier from OOB channel
    Returns 0 on success, negative error code on failure.
*/
int trfWarmupEP(PTRFContext ctx, uint32_t session_id);

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
    Returns: Session ID of the waiting client, negative error code on failure.
*/
uint64_t trfSourceCheckReq(PTRFContext ctx, int nb);

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

/*  Retrieve an event from the completion queue inside the context ctx.
    ctx: Context to retrieve event from
    cq_entry: Pointer to the entry to be filled with the event
    nb: Non-blocking flag
    Returns: Number of events retrieved, negative error code on failure.
*/
int trfGetCQEvent(PTRFContext ctx, struct fi_cq_entry * cq_entry, int nb);