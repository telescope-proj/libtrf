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

/**
 * @file trf.h
 * @brief Telescope Remote Framebuffer Library
 */

#ifndef _TRF_H_
#define _TRF_H_

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <inttypes.h>

#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netdb.h>

#include "trf_fabric.h"
#include "trf_ncp.h"
#include "trf_def.h"
#include "trf_protobuf.h"
#include "trf_msg.pb-c.h"
#include "internal/trfi.h"

#include <rdma/fabric.h>
#include <rdma/fi_cm.h>
#include <rdma/fi_errno.h>
#include <rdma/fi_domain.h>
#include <rdma/fi_endpoint.h>
#include <rdma/fi_rma.h>

#include <trf_def.h>

#define TRF_RECV_CQ 0
#define TRF_SEND_CQ 1

// By default, libtrf will choose the highest Libfabric API version it supports.
// Should the machines you would like to use differ in API versions, a specific
// version number may be defined here. To do so, uncomment the following line
// and change the version number to the desired version.

// #define TRF_FABRIC_VERSION FI_VERSION(1, 0)

#ifndef TRF_FABRIC_VERSION
    #define TRF_FI_MIN_VER FI_VERSION(1, 10)
    #define TRF_FI_MAX_VER FI_VERSION(1, 14)
    #define TRF_FI_CUR_VER FI_VERSION(FI_MAJOR_VERSION, FI_MINOR_VERSION)

    #if (TRF_FI_CUR_VER <= TRF_FI_MIN_VER)
        #error "Libfabric version too old"
    #elif (TRF_FI_CUR_VER >= TRF_FI_MAX_VER)
        #define TRF_FABRIC_VERSION TRF_FI_MAX_VER
    #else
        #define TRF_FABRIC_VERSION TRF_FI_CUR_VER
    #endif
#endif

#ifdef _WIN32
#include <windows.h>
#endif

#include <assert.h>

#if defined (__unix__) || (defined (__APPLE__) && defined (__MACH__))
#include <unistd.h>
#include <time.h>
#include <ifaddrs.h>
#endif

#if defined (__linux__)
#include <linux/if.h>
#include <linux/ethtool.h>
#include <linux/sockios.h>
#endif

#include "trf_msg.h"
#include "trf_log.h"
#include "trf_inet.h"

/**
 * @brief               Get a timespec corresponding to a deadline in the future
 * 
 * @param out           Pointer to timespec to be filled in
 * @param delay_ms      Delay in milliseconds
 * @return              0 on success, negative error code on failure.
 */
static inline int trfGetDeadline(struct timespec * out, int delay_ms)
{
    // this is unnecessary but GCC won't shut up if I don't include it
    out->tv_sec = 0;
    out->tv_nsec = 0;

    struct timespec now;
    int ret = clock_gettime(CLOCK_MONOTONIC, &now);
    if (ret != 0)
        return -errno;

    trf__GetDelay(&now, out, delay_ms);
    return ret;
}

/**
 * @brief           Create a subchannel.
 * 
 * @param ctx       Allocated context containing the main channel.
 * 
 * @param ctx_out   Subchannel output.
 * 
 * @param id        Subchannel ID. Must be unique to the main context.
 * 
 * @return          0 on success, negative error code on failure.
 */
int trfCreateSubchannel(PTRFContext ctx, PTRFContext * ctx_out, uint32_t id);

/**
 * @brief           Process a subchannel creation request from the peer.
 *
 * @param ctx       Allocated context containing the main channel.
 *
 * @param ctx_out   Subchannel output.
 *
 * @param req       TRF control message containing the subchannel creation
 *                  request.
 * 
 * @return          0 on success, negative error code on failure.
 */
int trfProcessSubchannelReq(PTRFContext ctx, PTRFContext * ctx_out,
                            TrfMsg__MessageWrapper * req);

/**
 * @brief           Bind the subchannel to the main context. This ensures that
 *                  the subchannel is closed when the main context is destroyed.
 *
 * @param main      Main channel.
 *
 * @param sub       Subchannel.
 *
 * @return          0 on success, negative error code on failure.
 */
int trfBindSubchannel(PTRFContext main, PTRFContext sub);

/**
 * @brief           Unbind the subchannel from the main context. This is
 *                  required if the channel disconnects, to prevent invalid
 *                  memory accesses.
 *
 * @param main      Main channel
 * 
 * @param id        Subchannel ID
 * 
 * @return          0 on success, negative error code on failure.
 */
int trfUnbindSubchannel(PTRFContext main, uint32_t id);

/**
 * @brief Allocate an active endpoint.
 * 
 * @param ctx   Context in which to store the allocated endpoint.
 * 
 * @param fi    Endpoint parameters, returned by fi_getinfo()
 * 
 * @param data  If a source address was not assigned in the fi_info struct, this
 *              parameter may be used to specify the source address. The address
 *              format of this parameter must match fi->addr_format.
 *              To determine the address that was assigned, @see trfGetName()
 * 
 * @param size  Size of the data buffer
 * 
 * @return      0 on success, -errno on failure.
 */
int trfAllocActiveEP(PTRFXFabric ctx, struct fi_info * fi, void * data, 
    size_t size);

/**
 * @brief Insert a serialized address in FI_ADDR_STR or TRF format into the
 * context's address vector.
 *
 * @param ctx   Context in which to store the address.
 *
 * @param addr  Serialized address to insert.
 * 
 * @param out   If the address is successfully inserted, this parameter will
 *              be set to an address identifier.
 *
 * @return      0 on success, negative error code on failure.
 */
int trfInsertAVSerialized(PTRFXFabric ctx, char * addr, fi_addr_t * out);

/**
 * @brief           Deserialize a TRF wire protocol string into a format
 *                  understood by the fabric transport.
 * 
 * @param proto     Serialized protocol string
 * 
 * @param out       Output fabric protocol indentifier
 * 
 * @return          0 on success, negative error code on failure.
 */
int trfDeserializeWireProto(const char * proto, uint32_t * out);

/**
 * @brief           Serialize a fabric transport protocol name into a string
 *                  for transmission over the network.
 * 
 * @param proto     Protocol identifier.
 * 
 * @param out       Output string.
 * 
 * @return          0 on success, negative error code on failure.
 */
int trfSerializeWireProto(uint32_t proto, char ** out);

/**
 * @brief Allocate a TRFContext
 *
 * This does not allocate any resources within the context; you must use other
 * libtrf functions such as trfNCClientInit() to allocate resources.
 *
 * @return PTRFContext 
 */
PTRFContext trfAllocContext();

/**
 * @brief Get the list of available fabric providers which can reach the target.
 * 
 * @param host      Hostname of the target
 * 
 * @param port      Port or service name of the target
 * 
 * @param req_type  Endpoint type @see enum TRFEPType
 * 
 * @param fi_out    Output list of available fabric providers
 * 
 * @return          0 on success, negative error code on failure.
 */
int trfGetFabricProviders(const char * host, const char * port, 
    enum TRFEPType req_type, struct fi_info ** fi_out);

/**
 * @brief Free an interface list.
 *
 * This call frees a linked list of struct TRFInterface, typically allocated
 * using the trfGetInterfaceList() call.
 *
 * @param ifaces Interface list to free.
 */
void trfFreeInterfaceList(PTRFInterface ifaces);

/** 
 * @brief Allocate RD communication channel. 
 *
 * This call creates one side of a FI_EP_RDM channel from Libfabric according to
 * the supplied arguments. 
 *
 * @param ctx   Allocated context to store the channel. The context is stored
 *              within ctx->xfer.fabric. @see struct TRFXFabric
 *
 * @param fi    Fabric provider to use, returned from a fi_getinfo() or
 *              trfGetFabricProviders() call.
 *
 * @param data  If a source address was not assigned in the fi_info struct, this
 *              parameter may be used to specify the source address. The address
 *              format of this parameter must match fi->addr_format.
 * 
 * @param size  Size of the data buffer.
 *
 * @return      0 on success, negative error code on failure.
*/
int trfCreateChannel(PTRFContext ctx, struct fi_info * fi, void * data, 
    size_t size);

/**
 * @brief Determine fabrics which might reach the specified route.
 *
 * Note: This function is designed for dynamic port allocation, and as such
 * does not assign a source address to the returned fi_info list.
 *
 * @param dst   Destination address to use, in TRF Serialized format.
 *
 * @param prov  Provider name, e.g. "verbs;ofi_rxm"
 * 
 * @param proto Wire protocol e.g. FI_PROTO_RDMA_CM_IB_RC
 *
 * @param fi    Output list of available fabrics.
 *
 * @return      0 on success, negative error code on failure.
 */
int trfGetRoute(const char * dst, const char * prov, const char * proto,
    struct fi_info ** fi);

/**
 * @brief Convert internal Libfabric address format identifier into a TRF format
 * identifier to be sent over the network.
 *
 * @param fi_addr_format    Libfabric address format identifier e.g. FI_ADDR_STR
 * 
 * @return                  TRF address format identifier e.g. TRFX_SOCKADDR
 */
int trfConvertFabricAF(uint32_t fi_addr_format);

/**
 * @brief Convert TRF address format identifier into Libfabric address format.
 * 
 * @param trf_addr_format   TRF address format identifier e.g. TRFX_SOCKADDR
 * 
 * @return                  Libfabric address format identifier e.g. FI_ADDR_STR
 */
int trfConvertInternalAF(uint32_t trf_addr_format);

/**
 * @brief Serialize an address from an internal format, such as struct sockaddr,
 * into the TRF network transmission format.
 * 
 * @param data      Address to serialize, in the raw format
 * 
 * @param format    The format of the data referenced by the data pointer
 * 
 * @param out       Output buffer pointer to be allocated and set to the
 *                  serialized data, e.g. trfx_sockaddr://1.2.3.4:5678
 */
int trfSerializeAddress(void * data, enum TRFXAddr format, char ** out);

/**
 * @brief Deserialize a TRF address into an internal format, such as struct
 * sockaddr.
 * 
 * @param ser_addr  Serialized address
 * @param data_len  Length of the serialized address
 * @param data      Output buffer pointer to be allocated and set to the
 *                  deserialized data, e.g. struct sockaddr
 * @param format    Detected format of the output data
 * @return          int
 */
int trfDeserializeAddress(const char * ser_addr, int data_len, void ** data,
    int * format);

/**
 * @brief Register a memory buffer.
 *
 * @param ctx       Allocated context to store the memory region. The context
 *                  must have been initialized, with a fabric and domain.
 * 
 * @param addr      Address of the memory buffer to register.
 * 
 * @param len       Length of the memory buffer.
 * 
 * @param flags     Protection flags for the memory region.
 * 
 * @param mr_out    Output pointer to the memory region.
 * 
 * @return          0 on success, negative error code on failure.
 */
int trfRegBuf(PTRFXFabric ctx, void * addr, size_t len, uint64_t flags,
    struct fid_mr ** mr_out);

/**
 * @brief Register a memory buffer for sending and receiving messages.
 * 
 * @param ctx   Allocated context to store the memory region. The context
 *              must have been initialized, with a fabric and domain.
 * 
 * @param addr  Address of the memory buffer to register.
 * 
 * @param len   Length of the memory buffer.
 * 
 * @return      0 on success, negative error code on failure.
 */
int trfRegInternalMsgBuf(PTRFContext ctx, void * addr, size_t len);

/**
  * @brief          Get Libfabric endpoint name
  * 
  * @param ctx      Context containing initialized fabric context.
  * 
  * @param sas_buf  Pointer to a buffer to be allocated and set.
  * 
  * @return         0 on success, negative error code on failure
*/
int trfGetEndpointName(PTRFContext ctx, char ** sas_buf);

/**
  * @brief      Destroys and frees all fabric context items stored within
  *             a TRF context object.
  * 
  * @param ctx  Context containing an initialized fabric context.
*/
void trfDestroyFabricContext(PTRFContext ctx);

/**
  * @brief Sends a disconnect Message
  * @param fd   File descriptor to send disconnect message on
  * @param session_id   Session_ID
  * @return nothing is returned
*/
void trfSendDisconnectMsg(int fd, uint64_t session_id);

/**
  * @brief Destroy PTRFContext and free memory
  * @param ctx  PTRFContext to destroy
  * @return nothing is retured
*/
void trfDestroyContext(PTRFContext ctx);

/**
 * @brief Allocate an aligned block of memory.
 * 
 * @param size        Size of the memory block to allocate.
 * @param alignment   Alignment of the memory block.
 * @return            Pointer to the allocated memory block, or NULL on failure.
 */
void * trfAllocAligned(size_t size, size_t alignment);

/**
 * @brief Bind list of displays to context
 * 
 * @param ctx   Context to bind displays to
 * @param list  List of displays to bind
 * @return return 0 if successful, negative error code on failure
 */
int trfBindDisplayList(PTRFContext ctx, PTRFDisplay list);

/**
 * @brief       Update the memory address of the referenced display's
 * framebuffer, performing memory deregistration and re-registration.
 *
 * Note: This only disables RMA access to the old framebuffer, and does not free
 * the old framebuffer's memory. It is the responsibility of the caller to do so
 * after calling this function.
 *
 * @param ctx   Context the display is bound to
 * @param disp  Display to update
 * @param addr  New address
 * @return      0 on success, negative error code on failure
*/
int trfUpdateDisplayAddr(PTRFContext ctx, PTRFDisplay disp, void * addr);

/**
 * @brief Determine the number of bytes required to store a given texture.
 * 
 * @param width     Width
 * @param height    Height
 * @param fmt       Texture format.
 * @return          Number of bytes required to store the texture.
 *                  Negative error code on failure. 
 */
static inline ssize_t trfGetTextureBytes(size_t width, size_t height, 
                                         enum TRFTexFormat fmt)
{
    switch (fmt)
    {
        case TRF_TEX_BGR_888:
        case TRF_TEX_RGB_888:
            return width * height * 3;
        case TRF_TEX_RGBA_8888:
        case TRF_TEX_BGRA_8888:
        case TRF_TEX_RGBA_1010102:
            return width * height * 4;
        case TRF_TEX_RGBA_16161616:
        case TRF_TEX_RGBA_16161616F:
        case TRF_TEX_BGRA_16161616:
        case TRF_TEX_BGRA_16161616F:
            return width * height * 8;
        case TRF_TEX_ETC1:
        case TRF_TEX_DXT1:
            if (width % 4 || height % 4) { return -ENOTSUP; }
            return width * height / 2;
        case TRF_TEX_ETC2:
        case TRF_TEX_DXT5:
            if (width % 4 || height % 4) { return -ENOTSUP; }
            return width * height;
        default:
            return -EINVAL;
    }
}

/**
 * @brief Get number of bytes needed to store the contents of the display
 * 
 * @param disp  Display
 * @return      ssize_t 
 */
static inline ssize_t trfGetDisplayBytes(PTRFDisplay disp)
{
    return trfGetTextureBytes(disp->width, disp->height, disp->format);
}

static inline size_t trfGetCursorBytes(PTRFCursor cur)
{
    return trfGetTextureBytes(cur->width, cur->height, cur->format);
}

static inline uint8_t trfTextureIsCompressed(enum TRFTexFormat fmt)
{
    switch (fmt)
    {
        case TRF_TEX_ETC1:
        case TRF_TEX_ETC2:
        case TRF_TEX_DXT1:
        case TRF_TEX_DXT5:
            return 1;
        default:
            return 0;
    }
}

/**
 * @brief Free a display list.
 *
 * @param disp    Display list to free
 *
 * @param dealloc Whether to deallocate and deregister memory occupied by
 *                framebuffer data. If this display list contains shared buffer
 *                resources, it is advised to set this to 0.
 */
void trfFreeDisplayList(PTRFDisplay disp, int dealloc);

/**
 * @brief               Automatically process messages internally based on the
 *                      message type.
 *
 * @param ctx           Context to use
 *
 * @param flags         Messages to process internally
 *
 * @param processed     Message that was processed
 *
 * @param data_out      Message data. Typically this is a pointer to a
 *                      TrfMsg__MessageWrapper, but can be any data. This is set
 *                      to a non-NULL value if the message wasn't processed
 *                      internally.
 *
 * @param opaque        Opaque pointer, used internally for state tracking. Do
 *                      not modify. Before the first call, the initial value of
 *                      this variable should be set to 0.
 *
 * @return              Number of messages processed internally, negative error
 *                      code if an error occurred.
 */
int trfGetMessageAuto(PTRFContext ctx, uint64_t flags, uint64_t * processed,
    void ** data_out, int * opaque);
  
/**
 * @brief       Make the referenced display buffer available for use, as the
 * source (server) buffer.
 *
 * @param ctx   Initialized context to make the display buffer available to.
 *
 * @param disp  Display to make available. Note: if this contains multiple
 *              displays, only the first display will be made available.
 *
 * @return      0 on success, negative error code on failure.
 */
int trfRegDisplaySource(PTRFContext ctx, PTRFDisplay disp);

/**
 * @brief       Make the referenced display buffer available for use, as the
 * sink (client) buffer.
 *
 * @param ctx   Initialized context to make the display buffer available to.
 *
 * @param disp  Display to make available. Note: if this contains multiple
 *              displays, only the first display will be made available.
 *
 * @return      0 on success, negative error code on failure.
 */
int trfRegDisplaySink(PTRFContext ctx, PTRFDisplay disp);

/**
 * @brief       Custom registration routine. This is used when the framebuffer 
 *              memory region contains other data.
 * 
 * @param ctx   Initialized context to make the display buffer available to.
 * 
 * @param disp  Display to make available.
 * 
 * @param size  Size of the display buffer.
 * 
 * @param offset Offset between the start of the MR and the start of the frame data.
 */
int trfRegDisplayCustom(PTRFContext ctx, PTRFDisplay disp, size_t size, 
                        size_t offset, uint64_t flags);

/**
 * @brief       Get display by ID
 *
 * @param disp_list     Display list
 * @param id            ID
 * @return              Pointer to item in linked list with specified ID. If
 *                      NULL, the operation failed and errno will be set to
 *                      indicate the reason.
 */
PTRFDisplay trfGetDisplayByID(PTRFDisplay disp_list, int id);

/**
 * @brief           Acknowledge the client's display initialization request.
 * 
 * @param ctx           Context to use
 * @param disp_ids      Initialized display ID array
 * @param n_disp_ids    Number of display IDs in the array
 * @return              0 on success, negative error code on failure 
 */
int trfAckClientReq(PTRFContext ctx, uint32_t * disp_ids, int n_disp_ids);



/**
 * @brief Get the actual framebuffer data pointer after offsets.
 * 
 * @param disp      Display to use.
 * @return          void *
 */
static inline void * trfGetFBPtr(PTRFDisplay disp)
{
    if (disp->mem.ptr)
    {
        return (void *) ((uintptr_t) disp->mem.ptr + disp->fb_offset);
    }
    return NULL;
}

/**
 * @brief       Send a frame to the client.
 * 
 * @param ctx   Initialized context to send the frame to.
 * @param disp  Display identifier.
 * @param rbuf  Pointer to the remote frame buffer.
 * @param rkey  Remote access key.
 * @return      0 on success, negative error code on failure.
 */
static inline ssize_t trfSendFrame(PTRFContext ctx, PTRFDisplay disp, 
    uint64_t rbuf, uint64_t rkey)
{
    trf__DecrementCQ(ctx->xfer.fabric->tx_cq, 1);
    ssize_t ret;
    trf__log_trace("Sending frame update to client %lu - addr: %p, rkey: %lu",
                   ctx->xfer.fabric->peer_addr, (void *) rbuf, rkey);
    ret = fi_write(ctx->xfer.fabric->ep, 
                   trfGetFBPtr(disp), trfGetDisplayBytes(disp), 
                   trfMemFabricDesc(&disp->mem), ctx->xfer.fabric->peer_addr, 
                   rbuf, rkey, NULL);
    if (ret < 0)
    {
        trf__IncrementCQ(ctx->xfer.fabric->tx_cq, 1);
    }
    return ret;
}

/**
 * @brief       Send a partial frame update.
 *
 * Performs a fabric RMA write operation to the destination buffer. The client
 * is not informed of the operation status; once the operation completes, the
 * server should send an acknowledgement.
 * 
 * Compressed textures are not supported.
 *
 * @param ctx       Initialized context to send the frame to.
 * @param disp      Display identifier.
 * @param rbuf      Pointer to the remote frame buffer.
 * @param rkey      Remote access key.
 * @param rects     Rectangles corresponding to regions of the framebuffer to be
 * updated.
 * @param num_rects Number of rectangles in the list.
 * @return          0 on success, negative error code on failure. 
 */
ssize_t trfSendFramePart(PTRFContext ctx, PTRFDisplay disp, uint64_t rbuf,
                         uint64_t rkey, struct TRFRect * rects, 
                         size_t num_rects);

/**
 * @brief       Send a partial frame update, based on byte offsets.
 * 
 * Performs a fabric RMA write operation to the destination buffer. The client
 * is not informed of the operation status; once the operation completes, the
 * server should send an acknowledgement.
 * 
 * Compressed textures are not supported.
 * 
 * @param ctx       Initialized context to send the frame to.
 * 
 * @param disp      Display identifier.
 * 
 * @param start     Start offset in the framebuffer.
 * 
 * @param end       End offset in the framebuffer.
 * 
 * @param rbuf      Pointer to the remote frame buffer.
 * 
 * @param rkey      Remote access key.
 * 
 * @return          0 on success, negative error code on failure.
 * 
 */
ssize_t trfSendFrameChunk(PTRFContext ctx, PTRFDisplay disp, size_t start, 
                          size_t end, uint64_t rbuf, uint64_t rkey);

/**
 * @brief           Send a frame receive request. Non-blocking operation.
 *
 * @param ctx       Initialized context.
 *
 * @param disp      Display identifier, containing registered framebuffer
 *                  region.
 * 
 * @return          0 on success, negative error code on failure.
 */
ssize_t trfRecvFrame(PTRFContext ctx, PTRFDisplay disp);

/**
 * @brief Get the list of displays available to the client from the server.
 * 
 * @param ctx       Context
 * 
 * @param out       Server display list to be allocated and filled.
 * 
 * @return          0 on success, negative error code on failure.
 */
int trfGetServerDisplays(PTRFContext ctx, PTRFDisplay * out);

/**
 * @brief Send a display list to the client contained within the current
 * context.
 *
 * The client should have requested display metadata from the server.
 *
 * @param ctx   Initialized context containing display list.
 * 
 * @return      0 on success, negative error code on failure.
 */
int trfSendDisplayList(PTRFContext ctx);

/**
 * @brief       Send a display initialization request to the server.
 * 
 * @param ctx   Initialized context.
 * 
 * @param disp  Display to initialize.
 * 
 * @return      0 on success, negative error code on failure.
 */
int trfSendClientReq(PTRFContext ctx, PTRFDisplay disp);

/**
 * @brief           Send an confirmation to the client that a frame has been
 *                  updated.
 * 
 * @param ctx       Context to use.
 * 
 * @param display   Display the acknowledgement is for.
 * 
 * 
 * @return          0 on success, negative error code on failure.
 */
int trfAckFrameReq(PTRFContext ctx, PTRFDisplay display);

/**
 * @brief           Send Keep alive message
 * 
 * @param ctx       Context to use
 * @return 0 on success, negative error code
 */
int trfSendKeepAlive(PTRFContext ctx);

/**
 * @brief           Get the progress of all send operations.
 * 
 * @param ctx       Context to use.
 * 
 * @param de        Data entry containing successful completion details.
 * 
 * @param err       Data entry containing error details, if any
 * 
 * @param count     Maximum number of completions to receive.
 * 
 * @param opts      Optional options to override the default context behaviours.
 * 
 * @return          Number of completed operations.
 *                  Negative error code on failure. 
 */
ssize_t trfGetSendProgress(PTRFContext ctx, struct fi_cq_data_entry * de,
                           struct fi_cq_err_entry * err, size_t count, 
                           PTRFContextOpts opts);

/**
 * @brief           Get the progress of all receive operations.
 * 
 * @param ctx       Context to use.
 * 
 * @param de        Data entry containing successful completion details.
 * 
 * @param err       Data entry containing error details, if any
 * 
 * @param count     Maximum number of completions to receive.
 * 
 * @param opts      Optional options to override the default context behaviours.
 * 
 * @return          Number of completed operations.
 *                  Negative error code on failure. 
 */
ssize_t trfGetRecvProgress(PTRFContext ctx, struct fi_cq_data_entry * de,
                           struct fi_cq_err_entry * err, size_t count,
                           PTRFContextOpts opts);


#endif // _TRF_H_