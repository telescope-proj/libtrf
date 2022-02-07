/*
    SPDX-License-Identifier: LGPL-2.1-only

    Telescope Project
    Remote Framebuffer Library
    Reliable Datagram Test

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

#include "trf.h"

static const char * __trf_fi_proto[] = {
    "UNSPEC",
    "RDMA_CM_IB_RC",
    "IWARP",
    "IB_UD",
    "PSMX",
    "UDP",
    "SOCK_TCP",
#if TRF_FABRIC_VERSION >= FI_VERSION(1, 2)
    "MXM",
    "IWARP_RDM",
    "IB_RDM",
    "GNI",
#endif
#if TRF_FABRIC_VERSION >= FI_VERSION(1, 4)
    "RXM",
    "RXD",
#endif
#if TRF_FABRIC_VERSION >= FI_VERSION(1, 5)
    "MLX",
    "NETWORKDIRECT",
    "PSMX2",
#endif
#if TRF_FABRIC_VERSION >= FI_VERSION(1, 6)
    "SHM",
#endif
#if TRF_FABRIC_VERSION >= FI_VERSION(1, 7)
    "MRAIL",
    "RSTREAM",
    "RDMA_CM_IB_XRC",
#endif
#if TRF_FABRIC_VERSION >= FI_VERSION(1, 8)
    "EFA",
#endif
#if TRF_FABRIC_VERSION >= FI_VERSION(1, 12)
    "PSMX3",
#endif
    "__MAX"
};

static const uint32_t __trf_fi_enum[] = {
    FI_PROTO_UNSPEC,
    FI_PROTO_RDMA_CM_IB_RC,
    FI_PROTO_IWARP,
    FI_PROTO_IB_UD,
    FI_PROTO_PSMX,
    FI_PROTO_UDP,
    FI_PROTO_SOCK_TCP,
#if TRF_FABRIC_VERSION >= FI_VERSION(1, 2)
    FI_PROTO_MXM,
    FI_PROTO_IWARP_RDM,
    FI_PROTO_IB_RDM,
    FI_PROTO_GNI,
#endif
#if TRF_FABRIC_VERSION >= FI_VERSION(1, 4)
    FI_PROTO_RXM,
    FI_PROTO_RXD,
#endif
#if TRF_FABRIC_VERSION >= FI_VERSION(1, 5)
    FI_PROTO_MLX,
    FI_PROTO_NETWORKDIRECT,
    FI_PROTO_PSMX2,
#endif
#if TRF_FABRIC_VERSION >= FI_VERSION(1, 6)
    FI_PROTO_SHM,
#endif
#if TRF_FABRIC_VERSION >= FI_VERSION(1, 7)
    FI_PROTO_MRAIL,
    FI_PROTO_RSTREAM,
    FI_PROTO_RDMA_CM_IB_XRC,
#endif
#if TRF_FABRIC_VERSION >= FI_VERSION(1, 8)
    FI_PROTO_EFA,
#endif
#if TRF_FABRIC_VERSION >= FI_VERSION(1, 12)
    FI_PROTO_PSMX3,
#endif
    0
};

PTRFContext trfAllocContext() {
    PTRFContext ctx = calloc(1, sizeof(struct TRFContext));
    return ctx;
}

int trfAllocActiveEP(PTRFXFabric ctx, struct fi_info * fi, void * data, 
    size_t size)
{
    ctx->addr_fmt = fi->addr_format;
    int ret;
    ret = fi_fabric(fi->fabric_attr, &ctx->fabric, NULL);
    if (ret)
    {
        trf_fi_error("fi_fabric", ret);
        return ret;
    }
    ret = fi_domain(ctx->fabric, fi, &ctx->domain, NULL);
    if (ret)
    {
        trf_fi_error("fi_domain", ret);
        goto free_fabric;
    }
    struct fi_cq_attr cq_attr;
    memset(&cq_attr, 0, sizeof(cq_attr));
    cq_attr.size                = fi->tx_attr->size;
    cq_attr.flags               = 0;
    cq_attr.wait_obj            = FI_WAIT_UNSPEC;
    cq_attr.format              = FI_CQ_FORMAT_MSG;
    cq_attr.signaling_vector    = 0;
    cq_attr.wait_cond           = FI_CQ_COND_NONE;
    cq_attr.wait_set            = NULL;
    ret = fi_cq_open(ctx->domain, &cq_attr, &ctx->tx_cq, NULL);
    if (ret)
    {
        trf_fi_error("Open TX completion queue", ret);
        goto free_domain;
    }
    cq_attr.size = fi->rx_attr->size;
    ret = fi_cq_open(ctx->domain, &cq_attr, &ctx->rx_cq, NULL);
    if (ret)
    {
        trf_fi_error("Open RX completion queue", ret);
        goto free_tx_cq;
    }
    struct fi_av_attr av_attr;
    memset(&av_attr, 0, sizeof(av_attr));
    av_attr.type = FI_AV_UNSPEC;
    ret = fi_av_open(ctx->domain, &av_attr, &ctx->av, NULL);
    if (ret)
    {
        trf_fi_error("Open address vector", ret);
        goto free_rx_cq;
    }
    ret = fi_endpoint(ctx->domain, fi, &ctx->ep, NULL);
    if (ret)
    {
        trf_fi_error("Create endpoint on domain", ret);
        goto free_av;
    }
    ret = fi_ep_bind(ctx->ep, (fid_t)ctx->av, 0);
    if (ret)
    {
        trf_fi_error("EP bind to AV", ret);
        goto free_endpoint;
    }
    ret = fi_ep_bind(ctx->ep, &ctx->tx_cq->fid, FI_TRANSMIT);
    if (ret)
    {
        trf_fi_error("EP bind to TXCQ", ret);
        goto free_endpoint;
    }
    ret = fi_ep_bind(ctx->ep, &ctx->rx_cq->fid, FI_RECV);
    if (ret)
    {
        trf_fi_error("EP bind to RXCQ", ret);
        goto free_endpoint;
    }
    if (data)
    {
        ret = fi_setname(&ctx->ep->fid, data, size);
        if (ret)
        {
            trf_fi_error("Bind EP address", ret);
            goto free_endpoint;
        }
    }
    ret = fi_enable(ctx->ep);
    if (ret)
    {
        trf_fi_error("Enable endpoint", ret);
        goto free_endpoint;
    }
    return ret;

free_endpoint:
    fi_close(&ctx->ep->fid);
    ctx->ep = NULL;
free_av:
    fi_close(&ctx->av->fid);
    ctx->av = NULL;
free_rx_cq:
    fi_close(&ctx->rx_cq->fid);
    ctx->rx_cq = NULL;
free_tx_cq:
    fi_close(&ctx->tx_cq->fid);
    ctx->tx_cq = NULL;
free_domain:
    fi_close(&ctx->domain->fid);
    ctx->domain = NULL;
free_fabric:
    fi_close(&ctx->fabric->fid);
    ctx->fabric = NULL;
    ctx->addr_fmt = 0;
    return ret;
}

void trfDestroyFabricContext(PTRFXFabric ctx)
{
    if (ctx->fb_mr) {
        fi_close(&ctx->fb_mr->fid);
        ctx->fb_mr = NULL;
    }
    if (ctx->msg_mr) {
        fi_close(&ctx->msg_mr->fid);
        ctx->msg_mr = NULL;
    }
    if (ctx->ep)
    {
        fi_close(&ctx->ep->fid);
        ctx->ep = NULL;
    }
    if (ctx->tx_cq)
    {
        fi_close(&ctx->tx_cq->fid);
        ctx->tx_cq = NULL;
    }
    if (ctx->rx_cq)
    {
        fi_close(&ctx->rx_cq->fid);
        ctx->rx_cq = NULL;
    }
    if (ctx->av)
    {
        fi_close(&ctx->av->fid);
        ctx->av = NULL;
    }
    if (ctx->domain)
    {
        fi_close(&ctx->domain->fid);
        ctx->domain = NULL;
    }
    if (ctx->fabric)
    {
        fi_close(&ctx->fabric->fid);
        ctx->fabric = NULL;
    }
    free(ctx);
}

void trfSendDisconnectMsg(int fd, uint64_t session_id)
{
    //!todo actually send disconnect message
    close(fd);
}

void trfDestroyContext(PTRFContext ctx)
{
    int ret;
    if (!ctx)
        return;

    PTRFContext cur_ctx = ctx;
    PTRFContext prev_ctx = NULL;

    while (cur_ctx)
    {
        switch (cur_ctx->type)
        {
            case TRF_EP_SOURCE:
                close(cur_ctx->svr.listen_fd);
                trfDestroyContext(cur_ctx->svr.clients);
                break;
            case TRF_EP_SINK:
            case TRF_EP_CONN_ID:
                trfSendDisconnectMsg(cur_ctx->cli.client_fd, 
                    cur_ctx->cli.session_id);
                close(cur_ctx->cli.client_fd);
                break;
                trfSendDisconnectMsg(cur_ctx->cli.client_fd,
                    cur_ctx->cli.session_id);
                close(cur_ctx->cli.client_fd);
                break;
            default:
                break;
        }
        switch (ctx->xfer_type)
        {
            case TRFX_TYPE_LIBFABRIC:
                trfDestroyFabricContext(ctx->xfer.fabric);
                break;
            default:
                break;
        }
        prev_ctx = ctx;
        cur_ctx = cur_ctx->next;
        free(prev_ctx);
    }
}

int trfCreateChannel(PTRFContext ctx, struct fi_info * fi, void * data, 
    size_t size)
{
    if (!ctx || !fi)
        return -EINVAL;
    
    int ret;

    if (!ctx->xfer.fabric)
    {
        ctx->xfer.fabric = calloc(1, sizeof(*ctx->xfer.fabric));
        if (!ctx->xfer.fabric)
        {
            trf__log_error("Failed to allocate fabric resources\n");
            ret = -ENOMEM;
            goto free_info;
        }
    }

    ctx->xfer_type = TRFX_TYPE_LIBFABRIC;

    ret = trfAllocActiveEP(ctx->xfer.fabric, fi, data, size);
    if (ret)
    {
        goto free_fabric;
    }

    return 0;

free_fabric:
    free(ctx->xfer.fabric);
free_info:
    fi_freeinfo(fi);
    return ret;
}

int trfDeserializeWireProto(const char * proto, uint32_t * out)
{
    if (!proto || !out)
        return -EINVAL;

    assert( (sizeof(__trf_fi_proto) / sizeof(__trf_fi_proto[0]))
            == (sizeof(__trf_fi_enum) / sizeof(__trf_fi_enum[0])));

    // Libfabric protocol strings

    if (strncmp(proto, "FI_PROTO_", 9) == 0)
    {
        const char * tgt = proto + 9;
        for (int i = 0; i < sizeof(__trf_fi_proto) / sizeof(__trf_fi_proto[0]); 
            i++)
        {
            if (strcmp(tgt, __trf_fi_proto[i]) == 0)
            {
                *out = __trf_fi_enum[i];
                return 0;
            }
        }
    }
    return -EINVAL;
}

int trfSerializeWireProto(uint32_t proto, char ** out)
{
    if (!out)
        return -EINVAL;

    assert( (sizeof(__trf_fi_proto) / sizeof(__trf_fi_proto[0]))
            == (sizeof(__trf_fi_enum) / sizeof(__trf_fi_enum[0])));

    // Libfabric protocol strings

    for (int i = 0; i < sizeof(__trf_fi_proto) / sizeof(__trf_fi_proto[0]); 
        i++)
    {
        if (proto == __trf_fi_enum[i])
        {
            *out = calloc(1, strlen(__trf_fi_proto[i]) + sizeof("FI_PROTO_"));
            strcpy(*out, "FI_PROTO_");
            strcpy(*out + 9, __trf_fi_proto[i]);
            return 0;
        }
    }
    return -EINVAL;
}

int trfGetRoute(const char * dst, const char * prov, const char * proto,
    struct fi_info ** fi)
{
    int ret;
    struct fi_info *hints, *info = NULL;

    if (!dst || !prov)
        return -EINVAL;

    void * dst_copy;
    int trf_fmt;
    ret = trfDeserializeAddress(dst, strlen(dst), &dst_copy, &trf_fmt);
    if (ret)
        return ret;

    hints = fi_allocinfo();
    int lf_fmt = trfConvertInternalAF(trf_fmt);
    switch (lf_fmt)
    {
        case FI_SOCKADDR:
        case FI_SOCKADDR_IN:
        case FI_SOCKADDR_IN6:
            switch (((struct sockaddr *) dst_copy)->sa_family)
            {
                case AF_INET:
                    hints->dest_addrlen = sizeof(struct sockaddr_in);
                    break;
                case AF_INET6:
                    hints->dest_addrlen = sizeof(struct sockaddr_in6);
                    break;
                default:
                    trf__log_warn("Unknown address family\n");
                    break;
            }
            break;
        case FI_ADDR_STR:
            hints->dest_addrlen = strlen((char *) dst_copy);
            break;
        default:
            trf__log_error("Unknown address format\n");
            ret = -EINVAL;
            goto free_hints;
    }

    uint32_t proto_id = 0;
    ret = trfDeserializeWireProto(proto, &proto_id);
    if (ret)
        goto free_hints;

    trf__log_debug("Libfabric Format: %d", lf_fmt);
    
    hints->ep_attr->type    = FI_EP_RDM;
    hints->caps             = FI_MSG | FI_RMA;
    hints->mode             = FI_LOCAL_MR;
    hints->addr_format      = lf_fmt;
    hints->dest_addr        = dst_copy;
    hints->ep_attr->protocol = proto_id;
    hints->fabric_attr->prov_name = strdup(prov);

    ret = fi_getinfo(TRF_FABRIC_VERSION, NULL, NULL, 0, hints, &info);
    if (ret) {
        trf_fi_error("fi_getinfo", ret);
        goto free_hints;
    }

    trf__log_debug("info %s", fi_tostr(info, FI_TYPE_INFO));

    ret = 0;
    *fi = info;

free_hints:
    fi_freeinfo(hints);
    return ret;

}

int trfConvertFabricAF(uint32_t fi_addr_format)
{
    switch (fi_addr_format)
    {
        case FI_SOCKADDR:
            return TRFX_ADDR_SOCKADDR;
        case FI_SOCKADDR_IN:
            return TRFX_ADDR_SOCKADDR_IN;
        case FI_SOCKADDR_IN6:
            return TRFX_ADDR_SOCKADDR_IN6;
        case FI_ADDR_STR:
            return TRFX_ADDR_FI_STR;
        default:
            return -1;
    }
}

int trfConvertInternalAF(uint32_t trf_addr_format)
{
    switch (trf_addr_format)
    {
        case TRFX_ADDR_SOCKADDR:
            return FI_SOCKADDR;
        case TRFX_ADDR_SOCKADDR_IN:
            return FI_SOCKADDR_IN;
        case TRFX_ADDR_SOCKADDR_IN6:
            return FI_SOCKADDR_IN6;
        case TRFX_ADDR_FI_STR:
            return FI_ADDR_STR;
        default:
            return -1;
    }
}

int trfSerializeAddress(void * data, enum TRFXAddr format, char ** out)
{
    int ret;
    char * addr = NULL;
    switch (format)
    {
        case TRFX_ADDR_SOCKADDR:
            addr = calloc(1, TRFX_MAX_STR);
            strcpy(addr, "trfx_sockaddr://");
            ret = trfGetNodeService((struct sockaddr *)data,
                addr + sizeof("trfx_sockaddr://") - 1);
            if (ret)
            {
                free(addr);
                return ret;
            }
            break;
        case TRFX_ADDR_SOCKADDR_IN:
            addr = calloc(1, TRFX_MAX_STR);
            strcpy(addr, "trfx_sockaddr_in://");
            ret = trfGetNodeService((struct sockaddr *)data,
                addr + sizeof("trfx_sockaddr_in://") - 1);
            if (ret)
            {
                free(addr);
                return ret;
            }
            break;
        case TRFX_ADDR_SOCKADDR_IN6:
            addr = calloc(1, TRFX_MAX_STR);
            strcpy(addr, "trfx_sockaddr_in6://");
            ret = trfGetNodeService((struct sockaddr *)data,
                addr + sizeof("trfx_sockaddr_in6://") - 1);
            if (ret)
            {
                free(addr);
                return ret;
            }
            break;
        case TRFX_ADDR_FI_STR:
            addr = strdup((char *)data);
            break;
        default:
            return -EINVAL;
    }
    *out = addr;
    return 0;
}

int trfDeserializeAddress(const char * ser_addr, int data_len, void ** data,
    int * format)
{
    int fmt;
    void * out = NULL;
    if (strncmp(ser_addr, "fi_", sizeof("fi_") - 1) == 0)
    {
        fmt = TRFX_ADDR_FI_STR;
        *data = strdup(ser_addr);
    }
    else if (strncmp(ser_addr, "trfx_sockaddr", sizeof("trfx_sockaddr") - 1) == 0)
    {
        const char * tgt = ser_addr + sizeof("trfx_sockaddr") - 1;
        if (strncmp(tgt, "://", sizeof("://") - 1) == 0)
        {
            fmt = TRFX_ADDR_SOCKADDR;
            tgt += sizeof("://") - 1;
        } 
        else if (strncmp(tgt, "_in6://", sizeof("_in6://") - 1) == 0)
        {
            fmt = TRFX_ADDR_SOCKADDR_IN6;
            tgt += sizeof("_in6://") - 1;
        }
        else if (strncmp(tgt, "_in://", sizeof("_in://") - 1) == 0)
        {
            fmt = TRFX_ADDR_SOCKADDR_IN;
            tgt += sizeof("_in://") - 1;
        }
        else
        {
            return -EINVAL;
        }

        struct sockaddr *sock = calloc(1, sizeof(*sock));
        if (trfNodeServiceToAddr(tgt, sock) < 0)
        {
            trf__log_error("Unable to create sockaddr from node service");
        }
        out = (void *) sock;
    }
    else
    {
        return -EINVAL;
    }

    *data = (void *) out;
    *format = fmt;
    return 0;
}

int trfPrintFabricProviders(struct fi_info * fi)
{
    struct fi_info * fi_node;
    for (fi_node = fi; fi_node; fi_node = fi_node->next)
    {
        char srcstr[INET6_ADDRSTRLEN];
        char dststr[INET6_ADDRSTRLEN];
        char * src;
        char * dst;
        switch (fi_node->addr_format)
        {
            case FI_SOCKADDR:
            case FI_SOCKADDR_IN:
            case FI_SOCKADDR_IN6:
                if (fi_node->dest_addr)
                {
                    trfGetIPaddr(fi_node->dest_addr, dststr);
                    dst = dststr;
                }
                else
                {
                    dst = "null";
                }
                if (fi_node->src_addr)
                {
                    trfGetIPaddr(fi_node->src_addr, srcstr);
                    src = srcstr;
                }
                else
                {
                    dst = "null";
                }
            case FI_ADDR_STR:
                src = (char *) fi_node->src_addr;
                dst = (char *) fi_node->dest_addr;
                break;
        }
        trf__log_debug("(fabric) provider: %s, src: %s, dst: %s", 
            fi_node->fabric_attr->prov_name, src, dst
        );
    }
    return 0;
}

int trfGetFabricProviders(const char * host, const char * port, 
    enum TRFEPType req_type, struct fi_info ** fi_out)
{
    
    int ret;
    struct fi_info *hints, *fi = NULL;
    
    if (!host || !port)
        return -EINVAL;
    
    /*  Specify the minimum feaure set required by the fabric. Note that just
        because you specify FI_RMA here doesn't mean the fabric natively
        supports RDMA; rather support for FI_RMA just means the fabric can
        emulate RDMA operations in software as well.
    */

    hints                   = fi_allocinfo();
    hints->ep_attr->type    = FI_EP_RDM;
    hints->caps             = FI_MSG | FI_RMA;
    hints->mode             = FI_CONTEXT | FI_LOCAL_MR;
    hints->addr_format      = FI_FORMAT_UNSPEC;
    
    /*  Search for an available fabric provider. This should return a list of
        available providers sorted by libfabric preference i.e. RDMA interfaces
        should show up as the first item in this list with a fallback to TCP
        BTL.
    */

    trf__log_debug("Attempting to find fabric provider for %s:%s", host, port);
    
    uint64_t fiflags    = (req_type == TRF_EP_SOURCE) ? FI_SOURCE : 0;
    //const char * g_host = (req_type == TRF_EP_SOURCE) ? NULL : host;

    ret = fi_getinfo(TRF_FABRIC_VERSION, host, port, fiflags, hints, &fi);
    if (ret)
    {
        trf_fi_error("fi_getinfo", ret);
        return ret;
    }

    /*  Iterate through the list of interfaces and print out the name and
        provider name (debug)
    */
    
    trfPrintFabricProviders(fi);

    *fi_out = fi;
    return 0;
}

int trfInsertAVSerialized(PTRFXFabric ctx, char * addr, fi_addr_t * addr_out)
{
    void ** data = calloc(1, sizeof(void *));

    trf__log_trace("data: %p, data[0]: %p", data, data[0]);

    int fmt, ret;
    ret = trfDeserializeAddress(addr, strlen(addr), &data[0], &fmt);
    if (ret)
    {
        trf__log_error("Unable to deserialize address");
        return ret;
    }

    trf__log_trace("data: %p, data[0]: %p", data, data[0]);

    char dbgav[128];
    ret = trfGetIPaddr(data[0], dbgav);
    if (ret)
    {
        trf__log_error("Unable to get IP address");
        free(data);
        return ret;
    }

    trf__log_debug("Inserting AV for %s", dbgav);
    trf__log_debug("Family: %d", ((struct sockaddr *) data[0])->sa_family);

    int res;

    size_t addrlen = sizeof(struct sockaddr_storage);
    const char * saddr = fi_av_straddr(ctx->av, data[0], dbgav, &addrlen);
    if (!saddr)
    {
        trf__log_error("Unable to get address string");
        ret = -EINVAL;
        free(data);
        return ret;
    }

    trf__log_debug("Fi AV %s", saddr);
    trf__log_debug("Fi AV index %lu", *addr_out);

    ret = fi_av_insert(ctx->av, data[0], 1, addr_out, FI_SYNC_ERR, &res);
    if (ret != 1 || res != 0)
    {
        trf__log_error("Unable to insert address");
        trf_fi_error("fi_av_insert", -res);
        ret = (ret == 0) ? -EINVAL : ret;
        free(data);
        return ret;
    }

    trf__log_debug("Fi AV index2 %lu", *addr_out);

    struct sockaddr_storage out;
    ret = fi_av_lookup(ctx->av, *addr_out, &out, &addrlen);
    if (ret < 0)
    {
        trf__log_error("Unable to lookup address");
        ret = (ret == 0) ? -EINVAL : ret;
        free(data);
        return ret;
    }

    trf__log_debug("Family: %d", out.ss_family);
    trf__log_debug("Address: %s", &out);

    memset(dbgav, 0, INET6_ADDRSTRLEN);
    ret = trfGetIPaddr((struct sockaddr *) &out, dbgav);
    if (ret)
    {
        trf__log_error("Unable to get IP address");
        free(data);
        return ret;
    }

    trf__log_debug("Decoded address: %s", dbgav);

    free(data[0]);
    free(data);
    return 0;
}

int trfRegBuf(PTRFXFabric ctx, void * addr, size_t len, uint64_t flags,
    struct fid_mr ** mr_out)
{
    trf__log_debug("Registering buffer %p with size %lu", addr, len);
    int ret;
    struct fid_mr * mr;
    struct fid_domain * domain = ctx->domain;

    ret = fi_mr_reg(domain, addr, len, flags, 0, 0, flags, &mr, NULL);
    if (ret)
    {
        trf_fi_error("fi_mr_reg", ret);
        return ret;
    }

    *mr_out = mr;
    return 0;
}

int trfRegInternalMsgBuf(PTRFContext ctx, void * addr, size_t len)
{
    if (!ctx || !ctx->xfer_type || !ctx->xfer.fabric || !addr || !len)
    {
        trf__log_debug("ctx: %p, xfer_type: %d, fabric: %p, addr: %p, len: %lu",
            ctx, ctx->xfer_type, ctx->xfer.fabric, addr, len);
        return -EINVAL;
    }

    PTRFXFabric f = ctx->xfer.fabric;
    return trfRegBuf(f, addr, len, FI_READ | FI_WRITE, &f->msg_mr);
}

int trfRegInternalFrameRecvBuf(PTRFContext ctx, void * addr, size_t len)
{
    if (!ctx || !ctx->xfer_type || !ctx->xfer.fabric || !addr || !len)
        return -EINVAL;

    PTRFXFabric f = ctx->xfer.fabric;
    return trfRegBuf(f, addr, len, FI_REMOTE_WRITE, &f->fb_mr);
}

int trfRegInternalFrameSendBuf(PTRFContext ctx, void * addr, size_t len)
{
    if (!ctx || !ctx->xfer_type || !ctx->xfer.fabric || !addr || !len)
        return -EINVAL;

    PTRFXFabric f = ctx->xfer.fabric;
    return trfRegBuf(f, addr, len, FI_READ, &f->fb_mr);
}

int trf__CheckSessionID(PTRFContext ctx, uint64_t session, uint8_t first)
{
    if (!ctx)
    {
        return -EINVAL;
    }

    int found = 0;

    switch (first)
    {
        case 0:
            for (PTRFContext ctx_itm = ctx; ctx_itm; ctx_itm = ctx_itm->next)
            {
                if (ctx->cli.session_id == session)
                {
                    found++;
                }
            }
        case 1:
            for (PTRFContext ctx_itm = ctx; ctx_itm; ctx_itm = ctx_itm->next)
            {
                if (ctx->cli.session_id == session)
                {
                    return 1;
                }
            }
    }
    return found;
}

int trfGetEndpointName(PTRFContext ctx, char ** sas_buf)
{
    void * sas_tmp;
    size_t sas_len = 0;
    int ret;

    ret = fi_getname(&ctx->xfer.fabric->ep->fid, NULL, &sas_len);
    if (ret != 0 && ret != -FI_ETOOSMALL)
    {
        trf_fi_error("Get endpoint name length", ret);
        return -1;    
    }
    sas_tmp = calloc(1, sas_len);
    if (!sas_tmp)
    {
        trf__log_error("Unable to allocate source address buffer");
    }
    ret = fi_getname(&ctx->xfer.fabric->ep->fid, sas_tmp, &sas_len);
    if (ret)
    {
        trf_fi_error("Get name", ret);
        return -1;
    }

    ret = trfSerializeAddress(sas_tmp, 
        trfConvertFabricAF(ctx->xfer.fabric->addr_fmt), sas_buf);
    if (ret < 0)
    {
        trf__log_error("Unable to serialize address");
        free(sas_tmp);
        return ret;
    }
    return 0;
}