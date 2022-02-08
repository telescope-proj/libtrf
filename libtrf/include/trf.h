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

#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netdb.h>

#include <rdma/fabric.h>
#include <rdma/fi_cm.h>
#include <rdma/fi_errno.h>
#include <rdma/fi_domain.h>
#include <rdma/fi_endpoint.h>
#include <rdma/fi_rma.h>

// By default, libtrf will choose the highest Libfabric API version it supports.
// Should the machines you would like to use differ in API versions, a specific
// version number may be defined here. To do so, uncomment the following line
// and change the version number to the desired version.

// #define TRF_FABRIC_VERSION FI_VERSION(1, 0)

#ifndef TRF_FABRIC_VERSION
    #define TRF_FI_MIN_VER FI_VERSION(1, 4)
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

#include "trf_log.h"
#include "trf_inet.h"

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

#define TRF_SA_LEN(x) (((struct sockaddr *) x)->sa_family == AF_INET ? \
    sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6))

#define trf_fi_error(call, err) \
    trf__log_error("(fabric) %s failed (%d): %s", call, (int) -err, \
    fi_strerror((int) -err))

#define trf_perror(retval) trf__log_error("%s", strerror(-retval));

/**
 * @brief Simple string duplication function for standard C.
 * 
 * @param str   String to duplicate
 * @return      Pointer to the duplicated string stored in the heap.
 */
static inline char * trfStrdup(char * str)
{
    size_t len = strlen(str) + 1;
    char * out = malloc(len);
    memcpy(out, str, len);
    return out;
}

/**
 * @brief Sleep for a given number of milliseconds.
 * 
 * @param ms    Number of milliseconds to sleep.
 */
static inline void trfSleep(int ms) {
#ifdef _WIN32
    Sleep(ms);
#else
    struct timespec t;
    t.tv_sec    = ms / 1000;
    t.tv_nsec   = (ms % 1000) * 1000000;
    nanosleep(&t, NULL);
#endif
}

/**
  * @brief Struct for Storing Interface & Address Data for transmission
*/
struct TRFInterface {
    /**
      * @brief sockaddr struct containing sa_family and IP Address
    */
    struct sockaddr         * addr;     
    /**
      * @brief Netmask of address
    */
    uint8_t                 netmask;   
    /**
      * @brief Interface speed
    */
    int32_t                 speed;      
    /**
      * @brief Port
    */
    int32_t                 port;       
    /**
      * @brief Flags set if the port and ip address are valid interfaces
    */
    int32_t                 flags;      
    /**
      * @brief Next item in linked list
    */
    struct TRFInterface     * next;     
};

/**
 * @brief Address vector for storing source-destination address pairs, as well
 * as their connection speeds.
 */
struct TRFAddrV {
    /**
      * @brief struct sockaddr containing source address
    */
    struct sockaddr         * src_addr;
    /**
      * @brief struct sockaddr containing destination address
    */
    struct sockaddr         * dst_addr;
    /**
      * @brief pair speed between the interface
    */
    int32_t                 pair_speed;
    /**
      * @brief next item in linked list
    */
    struct TRFAddrV         * next;
};

#define TRFI_VALID (1)

/**
 * @brief TRF endpoint types
 *
 * This endpoint type determines the behaviour of connection functions, as well
 * as how to decode data stored within a TRFContext struct.
 */
enum TRFEPType {
    TRF_EP_INVALID,         // Invalid
    TRF_EP_FREE,            // Free node
    TRF_EP_SINK,            // Receiver
    TRF_EP_SOURCE,          // Sender
    TRF_EP_CONN_ID,         // Sender side resources for receiver
    TRF_EP_MAX              // Sentinel
};

/**
 * @brief Maximum serialized TRF address string size
 * 
 * Currently, the longest TRF address string is:
 * trfx_sockaddr_in6://[ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff]:65535
 * at 67 characters, plus the terminating null byte.
 */
#define TRFX_MAX_STR 128

/**
 * @brief Libfabric specific context objects
 * 
 */
struct TRFXFabric {
    /**
     * @brief Source address identifier
    */
    fi_addr_t           src_addr;
    /**
     * @brief Destination address identifier
    */
    fi_addr_t           peer_addr;
    /**
     * @brief Address format, from fi->addr_format
    */
    uint32_t            addr_fmt;
    /**
      * @brief Endpoint
    */
    struct fid_ep   * ep;
    /**
      * @brief Fabric interface identifier.
    */
    struct fid_fabric   * fabric;
    /**
      * @brief Domain identifier
      * 
      * A domain is the root object to which connection objects should be bound.
    */
    struct fid_domain   * domain;
    /**
      * @brief Event queue
      *
      * An event queue is a mechanism for managing asynchronous events, such as
      * address insertion. Currently, as all TRF operations are synchronous, it
      * is not used.
    */
    struct fid_eq       * eq;
    /**
      * @brief Transmission Completion queue
    */
    struct fid_cq       * tx_cq;
    /**
      * @brief Receive Completion queue
    */
    struct fid_cq       * rx_cq;
    /**
      * @brief Address Vector
      *
      * An address vector contains translations of Libfabric addresses into
      * fabric-specific addresses.
    */
    struct fid_av       * av;
    /**
      * @brief Message memory region.
      * 
      * LibTRF predefines a memory region for use in sending and receiving
      * messages. However, you can use your own memory region if you wish.
    */
    struct fid_mr       * msg_mr;   
    /**
      * @brief Framebuffer memory region.
      *
      * Stores framebuffer contents. Currently, the use of only one framebuffer
      * is supported through the TRF API.
    */
    struct fid_mr       * fb_mr;    
    /**
      * @brief Interrupt vector
      *
      * Currently unused. The interrupt vector determines the CPU thread on
      * which events are delivered. This is a "best effort" option - not all
      * fabric types support this option.
    */
    uint32_t            intrv;      
};

/**
 * @brief TRF connection types
 * 
 * May be used to determine the type of transport in use.
 * Currently, only Libfabric is supported.
 * 
 */
enum TRFXType {
    /**
      * @brief Invalid
    */
    TRFX_TYPE_INVALID,              
    /**
      * @brief Libfabric Auto-Selection
    */
    TRFX_TYPE_LIBFABRIC,            
    /**
      * @brief RDMA-CM
    */
    TRFX_TYPE_RDMACM,               
    /**
      * @brief Sentinel value
    */
    TRFX_TYPE_MAX           
};

/**
 * @brief TRF serialized address formats.
 * 
 */
enum TRFXAddr {
    /**
      * @brief Invalid
    */
    TRFX_ADDR_INVALID,             
    /**
      * @brief Libfabric FI_ADDR_STR
    */
    TRFX_ADDR_FI_STR,               
    /**
      * @brief struct sockaddr
    */
    TRFX_ADDR_SOCKADDR,             
    /**
      * @brief struct sockaddr_in
    */
    TRFX_ADDR_SOCKADDR_IN,          
    /**
      * @brief struct sockaddr_in6
    */
    TRFX_ADDR_SOCKADDR_IN6,        
    /**
      * @brief InfiniBand GID (currently unused)
    */
    TRFX_ADDR_IB_GID,               
    /**
      * @brief Sentinel value
    */
    TRFX_ADDR_MAX                  
};

enum TRFTexFormat {
    /**
      * @brief Invalid
      */
    TRF_TEX_INVALID,
    /**
      * @brief RGBA packed pixels, 8 bits per channel
      */
    TRF_TEX_RGBA_8888,
    /**
      * @brief RGB packed pixels, 8 bits per channel
      */
    TRF_TEX_RGB_888,
    /**
      * @brief BGRA packed pixels, 8 bits per channel
      */
    TRF_TEX_BGRA_8888,
    /**
      * @brief BGR packed pixels, 8 bits per channel
      */
    TRF_TEX_BGR_888,
    /**
      * @brief DXT1 compressed texture format
      */
    TRF_TEX_DXT1,
    /**
     * @brief DXT5 compressed texture format
     * 
     */
    TRF_TEX_DXT5,
    /**
     * @brief ETC1 compressed texture format
     * 
     */
    TRF_TEX_ETC1,
    /**
      * @brief ETC2 compressed texture format
      */
    TRF_TEX_ETC2,
    /**
      * @brief RGBA, 16 bits per channel HDR float
      */
    TRF_TEX_RGBA_16161616F,
    /**
      * @brief RGBA, 16 bits per channel
      */
    TRF_TEX_RGBA_16161616,
    /**
      * @brief Sentinel Value
      */
    TRF_TEX_MAX
};

struct TRFDisplay {
    /**
     * @brief Display ID
     * 
     * The display ID, unique within a context. This display is the actual value
     * used in the TRF API to identify which display should be used.
     */
    int32_t     id;
    /**
     * @brief Display name
     *
     * The display name is a user-facing string that identifies the display via
     * a human-readable name, which could be the monitor name or the name of the
     * server the display is connected to.
     */
    char        * name;
    /**
     * @brief Width
     * 
     * Display width in pixels
     * 
     */
    uint32_t     width;
    /**
     * @brief Height
     * 
     * Display height in pixels
     */
    uint32_t    height;
    /**
     * @brief Refresh rate
     * 
     * Display refresh rate, in Hz.
     */
    uint32_t    rate;
    /**`    
     * @brief Texture format
     * 
     * Currently, only one texture format is supported simultaneously.
     */
    uint32_t    format;
    /**
     * @brief Display Group
     *
     * A server acting as a multiplexer for multiple sources may set logical
     * display groups to allow users to select only sources from a particular
     * machine.
     *
     */
    uint32_t    dgid;
    /**
     * @brief X Offset
     * 
     * Horizontal offset of the display, relative to the display group only.
     */
    uint32_t    x_offset;
    /**
     * @brief Y Offset
     * 
     * Vertical offset of the display, relative to the display group only.
     */ 
    uint32_t    y_offset;
    /**
     * @brief Memory address of the display framebuffer
     * 
     */
    void        * fb_addr;
    /**
     * @brief Memory region object for the display framebuffer. Do not set manually.
     * 
     */
    struct fid_mr       * fb_mr;
    /**
     * @brief Next display in the list.
     * 
     */
    struct TRFDisplay   * next;
};

/**
 * @brief The Telescope Remote Framebuffer Library Context
 *
 * This is the main context for most TRF operations. It contains all of the
 * resources necessary to establish main and side channel communications between
 * endpoints. Additionally, the TRFContext may be chained with other related
 * contexts to allow for group operations, e.g. disconnecting all clients or
 * broadcasting frames simultaneously to all clients.
 *
 */
struct TRFContext {
    /**
     * @brief Endpoint type
     *
     * Servers and clients both use the same struct to store connection
     * information. This field determines the type of endpoint contained within
     * the context. @see enum TRFEPType
     */
    enum TRFEPType type;
    union {
        /**
         * @brief Server specific context items.
         * 
         */
        struct {
            /**
             * @brief Listen FD
             * 
             * Out of band channel FD.
             */
            int                 listen_fd;
            /**
             * @brief Client list
             * 
             * Contains a list of clients which have connected via this server.
             */
            struct TRFContext   * clients;
        } svr;
        /**
         * @brief Client specific context items.
         * 
         */
        struct {
            /**
             * @brief Session identifier
             */
            uint64_t            session_id;
            /**
             * @brief Out of band channel FD.
             */
            int                 client_fd;
        } cli;
    };
    /**
     * @brief Transfer layer type. @see enum TRFXType
     * 
    */
    enum TRFXType  xfer_type;
    /**
     * @brief Pointers to transport-specific context items
     * 
    */
    union {
        struct TRFXFabric * fabric; // Libfabric context
    } xfer;
    /**
     * @brief Display list
     * 
     * A list of displays that are available on the server.
    */
    struct TRFDisplay * displays;
    /**
     * @brief Related context pointer, next entry
     * 
    */
    struct TRFContext * next;

};

struct TRFBufferData {
    struct fid_mr * mr;
    void * addr;
    size_t len;
};

#define PTRFXFabric struct TRFXFabric *
#define PTRFAddrV struct TRFAddrV *
#define PTRFInterface struct TRFInterface *
#define PTRFSession struct TRFSession *
#define PTRFContext struct TRFContext *
#define TRF_MR_SIZE 64 * 1024 * 1024

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
 * *does not assign a source address* to the returned fi_info list.
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

#endif // _TRF_H_