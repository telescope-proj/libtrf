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

#include "trf_def.h"
#include "trf_protobuf.h"
#include "trf_msg.pb-c.h"

#include <rdma/fabric.h>
#include <rdma/fi_cm.h>
#include <rdma/fi_errno.h>
#include <rdma/fi_domain.h>
#include <rdma/fi_endpoint.h>
#include <rdma/fi_rma.h>


#define trf_fi_error(call, err) \
    trf__log_error("(fabric) %s failed (%d): %s", call, (int) -err, \
    fi_strerror((int) -err))

#define trf_fi_warn(call, err) \
    trf__log_warn("(fabric) %s failed (%d): %s", call, (int) -err, \
    fi_strerror((int) -err))

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
#include "trf_internal.h"

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
 * @return int 
 */
int trfInsertAVSerialized(PTRFXFabric ctx, char * addr, fi_addr_t * out);


int trfDeserializeWireProto(const char * proto, uint32_t * out);
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
 * @brief List all system interfaces.
 * 
 * @param list_out  A linked list of interfaces on the system.
 * 
 * @param length    The length of the linked list.
 * 
 * @return 0 on success, negative error code on failure.
 */
int trfGetInterfaceList(PTRFInterface * list_out, uint32_t * length);

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
 * @brief Register a memory buffer for receiving frames.
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
int trfRegInternalFrameRecvBuf(PTRFContext ctx, void * addr, size_t len);

/**
 * @brief Register a memory buffer for sending frames.
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
int trfRegInternalFrameSendBuf(PTRFContext ctx, void * addr, size_t len);

/**
  * @brief Get libfrabric Endpoint name
  * @param ctx      Context to use
  * @param sas_buf  Output buffer to store the name
  * @return 0 on success, negative error code on failure
*/
int trfGetEndpointName(PTRFContext ctx, char ** sas_buf);

/**
  * @brief Destroys everything inside the fabric context
  * @param ctx  Context containing fabric
  * @return nothing is returned
*/
void trfDestroyFabricContext(PTRFXFabric ctx);

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
 * @brief Update Display Address
 * @param ctx   Context to update
 * @param disp  Display to update
 * @param addr  Address to update
 * @return 0 on success, negative error code on failure
*/
int trfUpdateDisplayAddr(PTRFContext ctx, PTRFDisplay disp, void * addr);

/**
 * @brief Get number of bytes needed to store the contents of the display
 * 
 * @param disp      Display
 * @return ssize_t 
 */
ssize_t trfGetDisplayBytes(PTRFDisplay disp);

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
 * @brief Automatically process Messages based on incoming message types
 *
 * @param ctx           Context to use  
 * @param flags         Messages you want to be processed
 * @param processed     Message that was processed
 * @param timeout_ms    Timeout in Miliseconds
 * @param rate_limit    Set Rate limit
 * @param data_out      Message data from the client.
 *                      NULL means the message has been processed internally.
 * @return      0 on success, negative failure code on error
 */
int trfGetMessageAuto(PTRFContext ctx, uint64_t flags, uint64_t * processed,
    int timeout_ms, int rate_limit, void ** data_out);
  
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
 * @brief       Get display by ID
 *
 * @param disp_list     Display list
 * @param id            ID
 * @return              Pointer to item in linked list with specified ID. If
 *                      NULL, the operation failed and errno will be set to
 *                      indicate the reason.
 */
PTRFDisplay trfGetDisplayByID(PTRFDisplay disp_list, int id);

int trfAckClientReq(PTRFContext ctx, int disp_id);

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
    return fi_write(ctx->xfer.fabric->ep, disp->fb_addr, trfGetDisplayBytes(disp),
        fi_mr_desc(disp->fb_mr), ctx->xfer.fabric->peer_addr,
        rbuf, rkey, NULL);
}

/**
 * @brief           Get the progress of all send operations.
 *
 * @param ctx       Initialized context.
 *
 * @param de        Pointer to a data entry where completion details will be
 *                  stored.
 *
 * @param timeout   Timeout in milliseconds. If set to less than zero, the
 *                  function will be non-blocking.
 *
 * @return          Number of completed operations, negative error code on
 *                  failure.
 */
static inline ssize_t trfGetSendProgress(PTRFContext ctx, 
    struct fi_cq_data_entry * de, int timeout)
{
    if (timeout > 0)
    {
        return fi_cq_sread(ctx->xfer.fabric->tx_cq, de, 1, NULL, timeout);
    }
    else
    {
        return fi_cq_read(ctx->xfer.fabric->tx_cq, de, 1);
    }
}

/**
 * @brief Send Data to Peer over libfabric
 * 
 * @param ctx     Context containing Initialized TRFXFabric Struct
 * @param size    Size of data to be sent
 * @return 0 on success, Negative error code on error
 */
int trfFabricSend(PTRFContext ctx, TrfMsg__MessageWrapper *msg, 
    uint32_t buff_size);

/**
 * @brief Receive Message over Libfabric and Decode into MessageWrapper
 * @param ctx         Context to use
 * @param mem_size    Size of Memory Buffer
 * @param msg         Pointer to Msg to be written
 * @return 0 on success, Negative error code on error
 */
int trfFabricRecv(PTRFContext ctx, uint32_t mem_size, 
        TrfMsg__MessageWrapper ** msg);

/**
 * @brief       Send a frame receive request. 
 *              
 *              Warning: You must call trfGetRecvProgress() to ensure the frame
 *              is ready for use!
 *
 * @param ctx   Initialized context.
 * @param disp  Display identifier.
 * @return      0 on success, negative error code on failure.
 */
static inline ssize_t trfRecvFrame(PTRFContext ctx, PTRFDisplay disp)
{
    TrfMsg__MessageWrapper mw = TRF_MSG__MESSAGE_WRAPPER__INIT;
    TrfMsg__ClientFReq fr = TRF_MSG__CLIENT_FREQ__INIT;
    mw.wdata_case   = trfInternalToPB(TRFM_CLIENT_F_REQ);
    mw.client_f_req = &fr;
    fr.id           = disp->id;
    fr.addr         = (uint64_t) disp->fb_addr;
    fr.rkey         = fi_mr_key(disp->fb_mr);
    fr.frame_cntr   = disp->frame_cntr;
    ssize_t ret;
    ret = trfFabricSend(ctx, &mw, 4096);
    if (ret < 0)
    {
        trf__log_error("Unable to send frame request");
    }
    ret = fi_recv(ctx->xfer.fabric->ep, ctx->xfer.fabric->msg_ptr, 
        4096, fi_mr_desc(ctx->xfer.fabric->msg_mr), ctx->xfer.fabric->peer_addr,
        NULL);
    return ret;
}

/**
 * @brief           Get the progress of all receive operations.
 *
 * @param ctx       Initialized context.
 *
 * @param de        Pointer to a data entry where completion details will be
 *                  stored.
 *
 * @param timeout   Timeout in milliseconds. If set to less than zero, the
 *                  function will be non-blocking.
 *
 * @return          Number of completed operations, negative error code on
 *                  failure. 
 */
static inline ssize_t trfGetRecvProgress(PTRFContext ctx, 
    struct fi_cq_data_entry * de, int timeout)
{
    if (timeout > 0)
    {
        return fi_cq_sread(ctx->xfer.fabric->rx_cq, de, 1, NULL, timeout);
    }
    else
    {
        return fi_cq_read(ctx->xfer.fabric->rx_cq, de, 1);
    }
}

/**
 * @brief Get the list of displays available to the client from the server.
 * 
 * @param   ctx     Context
 * @param   out     Server display list to be allocated and filled.
 * @return          0 on success, negative error code on failure
 */
int trfGetServerDisplays(PTRFContext ctx, PTRFDisplay * out);

/**
 * @brief Send a display list to the client contained within the current
 * context.
 *
 * The client should have requested display metadata from the server.
 *
 * @param ctx 
 * @return int 
 */
int trfSendDisplayList(PTRFContext ctx);

/**
 * @brief       Send a display initialization request to the server.
 * 
 * @param ctx   Initialized context.
 * @param disp  Display to initialize.
 * @return      0 on success, negative error code on failure. 
 */
int trfSendClientReq(PTRFContext ctx, PTRFDisplay disp);

/**
 * @brief Send Acknowledgement for Client Frame
 * @param ctx       Context to use
 * @param display   Display the acknowledgement is for
 * @return 0 on success, negative error code on failure
 */
int trfAckFrameReq(PTRFContext ctx, PTRFDisplay display);

#endif // _TRF_H_