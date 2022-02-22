#ifndef _TRF_DEF_H_
#define _TRF_DEF_H_

#include <string.h>
#include <stdint.h>
#include <rdma/fabric.h>

#ifdef _WIN32
    #define TRFSock SOCKET
    #define trfSockValid(sock) (sock != INVALID_SOCKET)
    #define TRFInvalidSock INVALID_SOCKET
    #define trfLastSockError WSAGetLastError()
#else
    #include <unistd.h>
    #define TRFSock int
    #define trfSockValid(x) (x >= 0)
    #define TRFInvalidSock -1
    #define trfLastSockError errno
#endif

#define PTRFDisplay     struct TRFDisplay *
#define PTRFXFabric     struct TRFXFabric *
#define PTRFAddrV       struct TRFAddrV *
#define PTRFInterface   struct TRFInterface *
#define PTRFSession     struct TRFSession *
#define PTRFContext     struct TRFContext *
#define PTRFContextOpts struct TRFContextOpts *

#define TRF_SA_LEN(x) (((struct sockaddr *) x)->sa_family == AF_INET ? \
    sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6))

#define trf_perror(retval) trf__log_error("%s", strerror(-retval));

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
      *
      * Transmit events are used to track the progress of send and RMA
      * operations, including RMA read and write operations.
    */
    struct fid_cq       * tx_cq;
    /**
      * @brief Receive Completion queue
      * 
      * Receive events are used to track the progress of message receive
      * operations only.
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
     * @brief Message virtual memory address.
     * 
     * This address must correspond with the memory registered under msg_mr.
     */
    void                * msg_ptr;
    /**
     * @brief Message buffer size.
     * 
     * The length of the buffer referenced by msg_ptr.
     */
    size_t              msg_size;
    /**
      * @brief Interrupt vector
      *
      * The interrupt vector determines the CPU thread on which events are
      * delivered. This is a "best effort" option - not all fabric types support
      * this option.
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
     * @brief InfiniBand UD GID
    */
    TRFX_ADDR_IB_UD,
    /**
      * @brief Intel Performance Scaled Messaging 1 (True Scale Fabric)
    */
    TRFX_ADDR_PSMX,
    /**
     * @brief Intel Performance Scaled Messaging 2 (Omni-Path)
    */
    TRFX_ADDR_PSMX2,
    /**
     * @brief Intel Performance Scaled Messaging 3 (RoCE v2)
    */
    TRFX_ADDR_PSMX3,
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
     */
    TRF_TEX_DXT5,
    /**
     * @brief ETC1 compressed texture format
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
     * @brief BGRA, 16 bits per channel HDR float
     * 
     */
    TRF_TEX_BGRA_16161616F,
    /**
     * @brief BGRA, 16 bits per channel
     */
    TRF_TEX_BGRA_16161616,
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
     * @brief Frames since the start of the capture session.
     * 
     */
    uint32_t frame_cntr;
    /**
     * @brief Next display in the list.
     * 
     */
    struct TRFDisplay   * next;
};

/**
 * @brief Context options.
 *
 * Default context options may be set in this struct, which modifies the
 * behaviour of Telescope functions.
 *
 */
struct TRFContextOpts {
    /**
     * @brief   Negotiation channel send timeout in milliseconds
     */
    int32_t     nc_snd_timeo;
    /**
     * @brief   Negotiation channel receive timeout in milliseconds
    */
    int32_t     nc_rcv_timeo;
    /**
     * @brief   Negotiation channel send buffer size in bytes
    */
    size_t      nc_snd_bufsize;
    /**
     * @brief   Negotiation channel receive buffer size in bytes
    */
    size_t      nc_rcv_bufsize;
    /**
     * @brief   Negotiation channel send timeout in milliseconds
     */
    int32_t     fab_snd_timeo;
    /**
     * @brief   Negotiation channel receive timeout in milliseconds
     */
    int32_t     fab_rcv_timeo;
    /**
     * @brief   Fabric send buffer max size in bytes
     *
     * Note: If set to a positive value, this must be less than or equal to the
     * length of the fabric message buffer region.
    */
    size_t     fab_snd_bufsize;
    /**
     * @brief Fabric receive buffer max size in bytes
     *
     * Note: If set to a positive value, this must be less than or equal to the
     * length of the fabric message buffer region.
    */
    size_t     fab_rcv_bufsize;
    /**
     * @brief Fabric polling rate limit (sleep time in milliseconds)
     * 
     * Note: For latency sensitive applications, this should be set to 0,
     * to use busy waiting.
     */
    int32_t     fab_poll_rate;
    /**
     * @brief Synchronous CQ polling mode.
     */
    uint8_t     fab_cq_sync;
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
            TRFSock             listen_fd;
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
            TRFSock             client_fd;
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
     * @brief Context options
     * 
    */
    struct TRFContextOpts * opts;
    /**
     * @brief Indicates that the peer has sent a disconnect message. Prevents a
     * disconnect from being called twice.
     */
    uint8_t disconnected;
    /**
     * @brief Related context pointer, next entry
     * 
    */
    struct TRFContext * next;

};

/**
  * @brief      Get the system page size
  * 
  * @return     System page size
*/
static inline size_t trf__GetPageSize() {
    #if defined(_WIN32)
        SYSTEM_INFO si;
        GetSystemInfo(&si);
        return si.dwPageSize;
    #else
        return sysconf(_SC_PAGESIZE);
    #endif
}

static inline void trfSetDefaultOpts(PTRFContextOpts opts)
{
    opts->fab_cq_sync       = 0;
    opts->fab_poll_rate     = 0;
    opts->fab_rcv_bufsize   = trf__GetPageSize();
    opts->fab_snd_bufsize   = trf__GetPageSize();
    opts->fab_rcv_timeo     = 2000;
    opts->fab_snd_timeo     = 2000;
    opts->nc_rcv_bufsize    = trf__GetPageSize();
    opts->nc_snd_bufsize    = trf__GetPageSize();
    opts->nc_rcv_timeo      = 2000;
    opts->nc_snd_timeo      = 2000;
}

static inline void trfDuplicateOpts(PTRFContextOpts in, PTRFContextOpts out)
{
    if (!in || !out)
        return;
    
    memcpy(out, in, sizeof(struct TRFContextOpts));
}

#endif // _TRF_DEF_H_