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

static const char * trf__fi_proto[] = {
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

static const uint32_t trf__fi_enum[] = {
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

PTRFContext trfAllocContext() 
{
    PTRFContext ctx = calloc(1, sizeof(struct TRFContext));
    return ctx;
}

int trfAllocActiveEP(PTRFXFabric ctx, struct fi_info * fi, void * data, 
    size_t size)
{
    void * abuf = NULL;
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
    cq_attr.wait_obj            = FI_WAIT_UNSPEC;
    cq_attr.format              = FI_CQ_FORMAT_DATA;
    cq_attr.wait_cond           = FI_CQ_COND_NONE;
    cq_attr.signaling_vector    = ctx->intrv;
    ret = trf__CreateCQ(ctx, &ctx->tx_cq, &cq_attr, NULL);
    if (ret)
    {
        trf_fi_error("Open TX completion queue", ret);
        goto free_domain;
    }
    cq_attr.size = fi->rx_attr->size;
    ret = trf__CreateCQ(ctx, &ctx->rx_cq, &cq_attr, NULL);
    if (ret)
    {
        trf_fi_error("Open RX completion queue", ret);
        goto free_tx_cq;
    }
    struct fi_av_attr av_attr;
    memset(&av_attr, 0, sizeof(av_attr));
    av_attr.type    = FI_AV_UNSPEC;
    av_attr.count   = 4;
    av_attr.flags   = FI_EVENT;
    ret = fi_av_open(ctx->domain, &av_attr, &ctx->av, NULL);
    if (ret)
    {
        trf_fi_error("Open address vector", ret);
        goto free_rx_cq;
    }
    struct fi_eq_attr eq_attr;
    memset(&eq_attr, 0, sizeof(eq_attr));
    eq_attr.size = 4;
    eq_attr.wait_obj = FI_WAIT_UNSPEC;
    ret = fi_eq_open(ctx->fabric, &eq_attr, &ctx->eq, NULL);
    if (ret)
    {
        trf_fi_error("Open event queue", ret);
        goto free_av;
    }
    ret = fi_av_bind(ctx->av, &ctx->eq->fid, 0);
    if (ret)
    {
        trf_fi_error("Bind event queue to address vector", ret);
        goto free_av;
    }
    if (data && !(fi->src_addr))
    {
        // Special handling for Verbs devices
        if (strncmp(fi->fabric_attr->prov_name, 
                    "verbs;ofi_rxm", sizeof("verbs;ofi_rxm") - 1) == 0)
        {
            abuf = malloc(size);
            if (!abuf)
            {
                ret = -FI_ENOMEM;
                goto free_av;
            }
            memcpy(abuf, data, size);
            fi->src_addr    = abuf;
            fi->src_addrlen = size;
        }
        else
        {
            ret = fi_setname(&ctx->ep->fid, data, size);
            if (ret < 0)
            {
                trf__log_error("Failed to set source address: %s",
                               fi_strerror(-ret));
                goto free_av;
            }
        }
    }
    ret = fi_endpoint(ctx->domain, fi, &ctx->ep, NULL);
    if (ret)
    {
        trf_fi_error("Create endpoint on domain", ret);
        goto free_addr_data;
    }

    ret = fi_ep_bind(ctx->ep, &ctx->av->fid, 0);
    if (ret)
    {
        trf_fi_error("EP bind to AV", ret);
        goto free_endpoint;
    }
    ret = fi_ep_bind(ctx->ep, &ctx->tx_cq->cq->fid, FI_TRANSMIT);
    if (ret)
    {
        trf_fi_error("EP bind to TXCQ", ret);
        goto free_endpoint;
    }
    ret = fi_ep_bind(ctx->ep, &ctx->rx_cq->cq->fid, FI_RECV);
    if (ret)
    {
        trf_fi_error("EP bind to RXCQ", ret);
        goto free_endpoint;
    }
    ret = fi_enable(ctx->ep);
    if (ret)
    {
        trf_fi_error("Enable endpoint", ret);
        goto free_endpoint;
    }
    if (fi->src_addr && data)
    {
        fi->src_addr = NULL;
        fi->src_addrlen = 0;
    }
    ctx->fi = fi_dupinfo(fi);
    return ret;

free_endpoint:
    fi_close(&ctx->ep->fid);
    ctx->ep = NULL;
free_addr_data:
    free(abuf);
free_av:
    fi_close(&ctx->av->fid);
    ctx->av = NULL;
free_rx_cq:
    trf__DestroyCQ(ctx->rx_cq);
    ctx->rx_cq = NULL;
free_tx_cq:
    trf__DestroyCQ(ctx->tx_cq);
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

void trfDestroyFabricContext(PTRFContext ctx)
{
    if (!ctx || !ctx->xfer.fabric)
        return;

    PTRFXFabric f = ctx->xfer.fabric;
    
    if (!ctx->disconnected && f->domain && f->ep && f->msg_mr && f->msg_ptr)
    {
        trf__log_trace("Sending disconnect message");
        TrfMsg__MessageWrapper mw = TRF_MSG__MESSAGE_WRAPPER__INIT;
        TrfMsg__Disconnect dc = TRF_MSG__DISCONNECT__INIT;
        mw.disconnect = &dc;
        mw.wdata_case = TRF_MSG__MESSAGE_WRAPPER__WDATA_DISCONNECT;
        mw.disconnect->info = 0;
        int ret = trfFabricSend(ctx, &mw);
        if (ret)
        {
            trf__log_error( "Failed to send disconnect message (fabric): %s;"
                            "peer may be in an invalid state", strerror(-ret));
        }
    }
    if (f->msg_mr)
    {
        fi_close(&f->msg_mr->fid);
        f->msg_mr = NULL;
    }
    if (f->msg_ptr)
    {
        free(f->msg_ptr);
        f->msg_ptr = NULL;
    }
    if (f->ep)
    {
        fi_close(&f->ep->fid);
        f->ep = NULL;
    }
    if (f->tx_cq)
    {
        trf__DestroyCQ(f->tx_cq);
        f->tx_cq = NULL;
    }
    if (f->rx_cq)
    {
        trf__DestroyCQ(f->rx_cq);
        f->rx_cq = NULL;
    }
    if (f->av)
    {
        fi_close(&f->av->fid);
        f->av = NULL;
    }
    if (f->domain)
    {
        fi_close(&f->domain->fid);
        f->domain = NULL;
    }
    if (f->fabric)
    {
        fi_close(&f->fabric->fid);
        f->fabric = NULL;
    }
    if (f->fi)
    {
        fi_freeinfo(f->fi);
    }
    free(ctx->xfer.fabric);
    ctx->xfer.fabric = NULL;
}

void trfSendDisconnectMsg(int fd, uint64_t session_id)
{
    if (fd <= 0)
    {
        return;
    }
    TrfMsg__MessageWrapper mw = TRF_MSG__MESSAGE_WRAPPER__INIT;
    TrfMsg__Disconnect dc = TRF_MSG__DISCONNECT__INIT;
    mw.disconnect = &dc;
    mw.wdata_case = TRF_MSG__MESSAGE_WRAPPER__WDATA_DISCONNECT;
    mw.disconnect->info = 0;
    size_t packed_size = trf_msg__message_wrapper__get_packed_size(&mw);
    void * tmp_buf = malloc(packed_size + sizeof(uint32_t));
    int ret;
    if (tmp_buf)
    {
        ret = trfNCSendDelimited(fd, tmp_buf, packed_size + sizeof(uint32_t), 
            1000, &mw);
        if (ret < 0)
        {
            trf__log_error( "Failed to send disconnect message (socket): %s;"
                            "peer may be in an invalid state", strerror(-ret));
        }
    }
    else
    {
        trf__log_error( "Failed to send disconnect message (socket): %s;"
                        "peer may be in an invalid state", strerror(ENOMEM));
    }
    close(fd);
}

void trfDestroyContext(PTRFContext ctx)
{
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
            default:
                break;
        }
        switch (cur_ctx->xfer_type)
        {
            case TRFX_TYPE_LIBFABRIC:
                trfDestroyFabricContext(cur_ctx);
                break;
            default:
                break;
        }
        free(cur_ctx->opts);
        prev_ctx = cur_ctx;
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
            return -ENOMEM;
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
    return ret;
}

int trfDeserializeWireProto(const char * proto, uint32_t * out)
{
    if (!proto || !out)
        return -EINVAL;

    assert( (sizeof(trf__fi_proto) / sizeof(trf__fi_proto[0]))
            == (sizeof(trf__fi_enum) / sizeof(trf__fi_enum[0])));

    // Libfabric protocol strings

    if (strncmp(proto, "FI_PROTO_", 9) == 0)
    {
        const char * tgt = proto + 9;
        for (int i = 0; i < sizeof(trf__fi_proto) / sizeof(trf__fi_proto[0]); 
            i++)
        {
            if (strcmp(tgt, trf__fi_proto[i]) == 0)
            {
                trf__log_trace("Wire protocol: %s", trf__fi_proto[i]);
                *out = trf__fi_enum[i];
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

    assert( (sizeof(trf__fi_proto) / sizeof(trf__fi_proto[0]))
            == (sizeof(trf__fi_enum) / sizeof(trf__fi_enum[0])));

    // Libfabric protocol strings

    for (int i = 0; i < sizeof(trf__fi_proto) / sizeof(trf__fi_proto[0]); 
        i++)
    {
        if (proto == trf__fi_enum[i])
        {
            *out = calloc(1, strlen(trf__fi_proto[i]) + sizeof("FI_PROTO_"));
            strcpy(*out, "FI_PROTO_");
            strcpy(*out + 9, trf__fi_proto[i]);
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

    hints = trf__GetFabricHints();
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
        case FI_ADDR_PSMX:
            hints->dest_addrlen = sizeof(uint64_t);
            break;
        case FI_ADDR_PSMX2:
#if TRF_FABRIC_VERSION >= FI_VERSION(1, 12)
        case FI_ADDR_PSMX3:
            hints->dest_addrlen = sizeof(uint64_t) * 2;
            break;
#endif
        case FI_ADDR_IB_UD:
            hints->dest_addrlen = sizeof(uint64_t) * 4;
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

    trf__log_trace("Libfabric Format: %d", lf_fmt);
    
    hints->addr_format              = lf_fmt;
    hints->dest_addr                = dst_copy;
    hints->ep_attr->protocol        = proto_id;
    hints->fabric_attr->prov_name   = strdup(prov);

    ret = fi_getinfo(TRF_FABRIC_VERSION, NULL, NULL, 0, hints, &info);
    if (ret) {
        trf_fi_warn("fi_getinfo", ret);
        goto free_hints;
    }

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
        case FI_ADDR_IB_UD:
            return TRFX_ADDR_IB_UD;
        case FI_ADDR_PSMX:
            return TRFX_ADDR_PSMX;
        case FI_ADDR_PSMX2:
            return TRFX_ADDR_PSMX2;
#if TRF_FABRIC_VERSION >= FI_VERSION(1, 12)
        case FI_ADDR_PSMX3:
            return TRFX_ADDR_PSMX3;
#endif
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
        case TRFX_ADDR_IB_UD:
            return FI_ADDR_IB_UD;
        case TRFX_ADDR_PSMX:
            return FI_ADDR_PSMX;
        case TRFX_ADDR_PSMX2:
            return FI_ADDR_PSMX2;
#if TRF_FABRIC_VERSION >= FI_VERSION(1, 12)
        case TRFX_ADDR_PSMX3:
            return FI_ADDR_PSMX3;
#endif
        default:
            return -1;
    }
}

int trfSerializeAddress(void * data, enum TRFXAddr format, char ** out)
{
    if (!data || !out)
    {
        return -EINVAL;
    }
    int ret;
    char * addr = NULL;
    switch (format)
    {
        case TRFX_ADDR_SOCKADDR:
            addr = calloc(1, TRFX_MAX_STR);
            if (!addr)
            {
                return -ENOMEM;
            }
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
            if (!addr)
            {
                return -ENOMEM;
            }
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
            if (!addr)
            {
                return -ENOMEM;
            }
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
            if (!addr)
            {
                return -ENOMEM;
            }
            break;
        case TRFX_ADDR_IB_UD:
            addr = calloc(1, TRFX_MAX_STR);
            if (!addr)
            {
                return -ENOMEM;
            }
            ret = snprintf(addr, TRFX_MAX_STR,
                "trfx_ib_ud://%016" PRIx64 "%016" PRIx64 "%016" PRIx64 "%016" PRIx64, 
                ((uint64_t *) data)[0], ((uint64_t *) data)[1], 
                ((uint64_t *) data)[2], ((uint64_t *) data)[3]);
            break;
        case TRFX_ADDR_PSMX:
            addr = calloc(1, TRFX_MAX_STR);
            if (!addr)
            {
                return -ENOMEM;
            }
            strcpy(addr, "trfx_psm://");
            ret = snprintf(addr, TRFX_MAX_STR, 
                "trfx_psm://%016" PRIx64, 
                ((uint64_t *) data)[0]);
            break;
        case TRFX_ADDR_PSMX2:
            addr = calloc(1, TRFX_MAX_STR);
            if (!addr)
            {
                return -ENOMEM;
            }
            strcpy(addr, "trfx_psm2://");
            ret = snprintf(addr, TRFX_MAX_STR, 
                "trfx_psm2://%016" PRIx64 "%016" PRIx64,
                ((uint64_t *) data)[0], ((uint64_t *) data)[1]);
            break;
#if TRF_FABRIC_VERSION >= FI_VERSION(1, 12)
        case TRFX_ADDR_PSMX3:
            addr = calloc(1, TRFX_MAX_STR);
            if (!addr)
            {
                return -ENOMEM;
            }
            strcpy(addr, "trfx_psm3://");
            ret = snprintf(addr, TRFX_MAX_STR, 
                "trfx_psm3://%016" PRIx64 "%016" PRIx64, 
                ((uint64_t *) data)[0], ((uint64_t *) data)[1]);
            break;
#endif
        default:
            trf__log_debug("invalid");
            return -EINVAL;
    }
    *out = addr;
    return 0;
}

int trfDeserializeAddress(const char * ser_addr, int data_len, void ** data,
    int * format)
{
    // Compare statically defined strings
    #define trf__len(x) (sizeof(x) - 1)
    #define trf__cmp(tgt, val) (strncmp(tgt, val, trf__len(val)) == 0)
    char * target = (char *) ser_addr;
    int fmt, sal;
    void * out = NULL;
    // Native libfabric-specific addressing formats which require no conversion
    if (trf__cmp(target, "fi_"))
    {
        trf__log_trace("Libfabric native string");
        fmt = TRFX_ADDR_FI_STR;
        out = strdup(target);
    }
    // Several of these addresses can be converted using fi_tostr, but they are
    // not understood by the transports in string format. TRFX addresses
    // explicitly indicate conversion is required.
    else if (trf__cmp(target, "trfx_"))
    {
        target += trf__len("trfx_");
        trf__log_trace("TRF serialized string -> %s", target);
        if (trf__cmp(target, "sockaddr://"))
        {
            fmt = TRFX_ADDR_SOCKADDR;
            target += trf__len("sockaddr://");
            sal = sizeof(struct sockaddr_storage);
            goto sockaddr_dispatch;
        }
        else if (trf__cmp(target, "sockaddr_in://"))
        {
            fmt = TRFX_ADDR_SOCKADDR_IN;
            target += trf__len("sockaddr_in://");
            sal = sizeof(struct sockaddr_in);
            goto sockaddr_dispatch;
        }
        else if (trf__cmp(target, "sockaddr_in6://"))
        {
            fmt = TRFX_ADDR_SOCKADDR_IN6;
            target += trf__len("sockaddr_in6://");
            sal = sizeof(struct sockaddr_in6);
            goto sockaddr_dispatch;
        }
        else if (trf__cmp(target, "ib_ud://"))
        {
            fmt = TRFX_ADDR_IB_UD;
            target += trf__len("ib_ud://");
            goto tsaf_dispatch;
        }
        else if (trf__cmp(target, "psm://"))
        {
            fmt = TRFX_ADDR_PSMX;
            target += trf__len("psm://");
            goto tsaf_dispatch;
        }
        else if (trf__cmp(target, "psm2://"))
        {
            fmt = TRFX_ADDR_PSMX2;
            target += trf__len("psm2://");
            goto tsaf_dispatch;
        }
#if TRF_FABRIC_VERSION >= FI_VERSION(1, 12)
        else if (trf__cmp(target, "psm3://"))
        {
            fmt = TRFX_ADDR_PSMX3;
            target += trf__len("psm3://");
            goto tsaf_dispatch;
        }
#endif
        trf__log_debug("invalid value \"%s\"", target);
        return -EINVAL;
sockaddr_dispatch: ;
        // Deserialization of sockaddr struct family
        struct sockaddr * sock = calloc(1, sal);
        if (trfNodeServiceToAddr(target, sock) < 0)
        {
            trf__log_error("Unable to create sockaddr from node service");
        }
        out = (void *) sock;
        goto data_out;
tsaf_dispatch: ;
        // Deserialization for transport-specific address formats, in the format
        // uint64_t[x]
        uint64_t * ts_addr;
        char * eptr;
        char ts_tmp[17];
        memset(ts_tmp, 0, sizeof(ts_tmp));
        switch (fmt)
        {
            case TRFX_ADDR_PSMX:
                ts_addr = calloc(1, sizeof(*ts_addr));
                if (!ts_addr)
                {
                    return -ENOMEM;
                }
                memcpy(ts_tmp, target, 16);
                ts_addr[0] = strtoull(ts_tmp, &eptr, 16);
                out = (void *) ts_addr;
                break;
            case TRFX_ADDR_PSMX2:
#if TRF_FABRIC_VERSION >= FI_VERSION(1, 12)
            case TRFX_ADDR_PSMX3:
#endif
                ts_addr = calloc(1, sizeof(*ts_addr) * 2);
                if (!ts_addr)
                {
                    return -ENOMEM;
                }
                memset(ts_tmp, 0, sizeof(ts_tmp));
                memcpy(ts_tmp, target, 16);
                ts_addr[0] = strtoull(ts_tmp, &eptr, 16);
                memcpy(ts_tmp, target + 8, 16);
                ts_addr[1] = strtoull(ts_tmp, &eptr, 16);
                out = (void *) ts_addr;
                break;
            case TRFX_ADDR_IB_UD:
                ts_addr = calloc(1, sizeof(*ts_addr) * 4);
                if (!ts_addr)
                {
                    return -ENOMEM;
                }
                memset(ts_tmp, 0, sizeof(ts_tmp));
                memcpy(ts_tmp, target, 16);
                ts_addr[0] = strtoull(ts_tmp, &eptr, 16);
                memcpy(ts_tmp, target + 16, 16);
                ts_addr[1] = strtoull(ts_tmp, &eptr, 16);
                memcpy(ts_tmp, target + 32, 16);
                ts_addr[2] = strtoull(ts_tmp, &eptr, 16);
                memcpy(ts_tmp, target + 48, 16);
                ts_addr[3] = strtoull(ts_tmp, &eptr, 16);
                out = (void *) ts_addr;
            default:
                return -EINVAL;
        }
        goto data_out;
    }
    else
    {
        trf__log_trace("Serialized address format invalid");
        return -EINVAL;
    }

data_out:

    *data = (void *) out;
    *format = fmt;
    return 0;

    #undef trf__len
    #undef trf__cmp
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
                    dst = "-";
                }
                if (fi_node->src_addr)
                {
                    trfGetIPaddr(fi_node->src_addr, srcstr);
                    src = srcstr;
                }
                else
                {
                    src = "-";
                }
            case FI_ADDR_STR:
                src = (char *) fi_node->src_addr;
                dst = (char *) fi_node->dest_addr;
                break;
            default:
                src = "unprintable";
                dst = "unprintable";
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
    {
        return -EINVAL;
    }

    hints = trf__GetFabricHints();
    trf__log_debug("Attempting to find fabric provider for %s:%s", host, port);
    ret = fi_getinfo(TRF_FABRIC_VERSION, host, port, 0, hints, &fi);
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
    if (!ctx || !addr || !addr_out)
    {
        return -EINVAL;
    }

    void ** data = calloc(1, sizeof(void *));

    int fmt, ret;
    ret = trfDeserializeAddress(addr, strlen(addr), &data[0], &fmt);
    if (ret)
    {
        trf__log_error("Unable to deserialize address");
        return ret;
    }

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

    int res = 0;

    size_t addrlen = sizeof(struct sockaddr_storage);
    const char * saddr = fi_av_straddr(ctx->av, data[0], dbgav, &addrlen);
    if (!saddr)
    {
        trf__log_error("Unable to get address string");
        ret = -EINVAL;
        free(data);
        return ret;
    }

    trf__log_trace("fi_av_straddr -> %s", saddr);

    ret = fi_av_insert(ctx->av, data[0], 1, addr_out, 0, &res);
    if (ret < 0 || res != 0)
    {
        trf__log_error("Unable to insert address: %s / %s", 
                       fi_strerror(-ret), fi_strerror(res));
        ret = (ret == 0) ? -EINVAL : ret;
        free(data);
        return ret;
    }

    uint32_t evt = 0;
    struct fi_eq_entry eqe;
    ret = fi_eq_sread(ctx->eq, &evt, &eqe, sizeof(eqe), -1, 0);
    if (ret <= 0)
    {
        if (ret == -FI_EAVAIL)
        {
            struct fi_eq_err_entry eqee;
            ret = fi_eq_readerr(ctx->eq, &eqee, 0);
            if (ret <= 0)
            {
                trf__log_error("Unable to read error event: %s", 
                               fi_strerror(ret));
                ret = (ret == 0) ? -EINVAL : ret;
                free(data);
                return ret;
            }
            trf__log_error("Error: %s", fi_strerror(eqee.err));
        }
        trf_fi_error("fi_eq_sread", ret);
        free(data);
        return ret;
    }

    trf__log_trace("AV Index: %lu", *addr_out);

    free(data[0]);
    free(data);
    return 0;
}

/* -------------------------------------------------------------------------- */
/* Memory Management & Registration Routines                                  */
/* -------------------------------------------------------------------------- */

int trf__FabricRegBuf(PTRFXFabric ctx, void * addr, size_t len, uint64_t flags,
    struct fid_mr ** mr_out)
{
    trf__log_debug("Registering buffer %p with size %lu", addr, len);
    int ret;
    struct fid_mr * mr;
    struct fid_domain * domain = ctx->domain;

    ret = fi_mr_reg(domain, addr, len, flags, 0, 0, 0, &mr, NULL);
    if (ret)
    {
        trf_fi_error("fi_mr_reg", ret);
        return ret;
    }

    *mr_out = mr;
    return 0;
}

int trfRegDisplaySource(PTRFContext ctx, PTRFDisplay disp)
{
    int ret;
    ret = trf__FabricRegBuf(ctx->xfer.fabric, disp->fb_addr, 
                            trfGetDisplayBytes(disp), FI_READ,
                            &disp->fb_mr);
    if (ret < 0)
        return ret;

    disp->fb_len    = trfGetDisplayBytes(disp);
    disp->fb_offset = 0;
    return ret;
}

int trfRegDisplaySink(PTRFContext ctx, PTRFDisplay disp)
{
    int ret;
    ret = trf__FabricRegBuf(ctx->xfer.fabric, disp->fb_addr, 
                            trfGetDisplayBytes(disp), 
                            FI_WRITE | FI_REMOTE_WRITE, &disp->fb_mr);
    if (ret < 0)
        return ret;

    disp->fb_len    = trfGetDisplayBytes(disp);
    disp->fb_offset = 0;
    return ret;
}

int trfRegDisplayCustom(PTRFContext ctx, PTRFDisplay disp, size_t size, 
                        size_t offset, uint64_t flags)
{
    if (!ctx || !disp || !size)
    {
        trf__log_debug("EINVAL trfRegDisplayCustom(ctx: %p, disp: %p, "
                       "size: %lu, offset: %lu, flags: %lu)");
        return -EINVAL;
    }
    if (disp->fb_addr + (offset + trfGetDisplayBytes(disp)) > 
        (disp->fb_addr + size))
    {
        trf__log_debug("Frame data would overflow buffer!");
        trf__log_debug("Data ends at: %p, Maximum: %p", 
                       (disp->fb_addr + (offset + trfGetDisplayBytes(disp))),
                       (disp->fb_addr + size));
        return -ENOSPC;
    }
    int ret;
    ret = trf__FabricRegBuf(ctx->xfer.fabric, disp->fb_addr, size, flags,
                            &disp->fb_mr);
    if (ret < 0)
        return ret;

    disp->fb_len    = size;
    disp->fb_offset = offset;
    return ret;
}

int trfDeregDisplay(PTRFContext ctx, PTRFDisplay disp)
{
    int ret = fi_close(&disp->fb_mr->fid);
    if (ret == 0)
    {
        disp->fb_mr = NULL;
    }
    else
    {
        trf_fi_error("fi_close", ret);
    }
    return ret;
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
    int ret;
    ret = trf__FabricRegBuf(f, addr, len, FI_READ | FI_WRITE, &f->msg_mr);
    if (ret == 0)
    {
        f->msg_ptr = addr;
        f->msg_size = len;
    }
    return ret;
}

void * trfAllocAligned(size_t size, size_t alignment)
{
    void * ptr;
    int ret;

    ret = posix_memalign(&ptr, alignment, size);
    if (ret)
    {
        trf__log_error("Unable to allocate aligned memory");
        return NULL;
    }
    return ptr;
}

/* -------------------------------------------------------------------------- */
/* Display List Management Functions                                          */
/* -------------------------------------------------------------------------- */

void trfFreeDisplayList(PTRFDisplay disp, int dealloc)
{
    if (!disp)
    {
        return;
    }

    PTRFDisplay disp_itm = disp;
    while (disp_itm)
    {
        PTRFDisplay disp_tmp = disp_itm->next;
        free(disp_itm);
        free(disp_itm->name);
        if (dealloc)
        {
            free(disp_itm->fb_addr);
            if (disp_itm->fb_mr)
            {
                fi_close(&disp_itm->fb_mr->fid);
            }
        }
        disp_itm = disp_tmp;
    }
}

int trfBindDisplayList(PTRFContext ctx, PTRFDisplay list)
{
    if (!ctx || !list)
        return -EINVAL;

    ctx->displays = list;
    return 0;
}

int trfUpdateDisplayAddr(PTRFContext ctx, PTRFDisplay disp, void * addr)
{
    if (!disp || !addr)
        return -EINVAL;

    int ret;
    
    if (ctx->type != TRF_EP_SINK && ctx->type != TRF_EP_CONN_ID)
    {
        trf__log_error("This context does not support display sources");
        return -EINVAL;
    }

    struct fid_mr * tmp_mr;

    disp->fb_addr = addr;
    ssize_t fb_len = trfGetDisplayBytes(disp);
    if (fb_len < 0)
    {
        trf__log_error("Unable to get display buffer length: %s", 
            strerror(-fb_len));
        return fb_len;
    }

    uint64_t flags = ctx->type == TRF_EP_SINK ? FI_REMOTE_WRITE : 0;
    ret = fi_mr_reg(ctx->xfer.fabric->domain, addr, fb_len, flags, 0, 0,
        0, &tmp_mr, NULL);
    if (ret)
    {
        trf_fi_error("fi_mr_reg", ret);
        return ret;
    }

    if (disp->fb_mr)
    {
        ret = fi_close(&disp->fb_mr->fid);
        if (ret)
        {
            trf_fi_error("fi_close", ret);
            fi_close(&tmp_mr->fid);
            return ret;
        }
    }

    disp->fb_mr = tmp_mr;
    return 0;
}

/* -------------------------------------------------------------------------- */
/* Session Management Routines                                                */
/* -------------------------------------------------------------------------- */

int trf__CheckSessionID(PTRFContext ctx, uint64_t session, uint8_t first)
{
    if (!ctx)
    {
        return -EINVAL;
    }

    int found = 0;

    if (first == 0)
    {
        for (PTRFContext ctx_itm = ctx; ctx_itm; ctx_itm = ctx_itm->next)
        {
            if (ctx->cli.session_id == session)
            {
                found++;
            }
        }
    }
    else
    {
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
        free(sas_tmp);
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
    free(sas_tmp);
    return 0;
}

int trfSendKeepAlive(PTRFContext ctx)
{
    if (!ctx || ((ctx->type != TRF_EP_CONN_ID) && (ctx->type != TRF_EP_SINK)))
    {
        return -EINVAL;
    }
    trf__log_trace("Keeping connection alive...");
    TrfMsg__MessageWrapper mw = TRF_MSG__MESSAGE_WRAPPER__INIT;
    TrfMsg__KeepAlive ka = TRF_MSG__KEEP_ALIVE__INIT;
    mw.wdata_case = TRF_MSG__MESSAGE_WRAPPER__WDATA_KA;
    mw.ka = &ka;
    ka.info = 0;
    return trfFabricSend(ctx, &mw);
}

int trfGetMessageAuto(PTRFContext ctx, uint64_t flags, uint64_t * processed,
    void ** data_out)
{
    if (!ctx || !data_out || !processed)
    {
        return -EINVAL;
    }

    int ret = 0;

    struct timespec tcur, tend;
    TrfMsg__MessageWrapper * msg = NULL;

    ret = clock_gettime(CLOCK_MONOTONIC, &tcur);
    if (ret < 0)
    {
        trf__log_error("System clock error: %s", strerror(errno));
        ret = -errno;
        goto free_msg;
    }

    trf__GetDelay(&tcur, &tend, ctx->opts->fab_rcv_timeo);

    ret = trf__FabricPostRecv(ctx, FI_ADDR_UNSPEC, &tend);
    if (ret < 0)
    {
        trf__log_error("Unable to post receive: %s", strerror(-ret));
        goto free_msg;
    }

    struct fi_cq_data_entry cqe;
    struct fi_cq_err_entry err;
    ret = trfGetRecvProgress(ctx, &cqe, &err, 1);
    if (ret != 1)
    {
        trf__log_error("CQ error: %s", strerror(-ret));
        goto free_msg;
    }

    ret = trfMsgUnpack(&msg, trfMsgGetPackedLength(ctx->xfer.fabric->msg_ptr), 
                        trfMsgGetPayload(ctx->xfer.fabric->msg_ptr));
    if (ret < 0)
    {
        trf__log_error("Unable to unpack message: %s", strerror(-ret));
        goto free_msg;
    }

    trf__log_trace("Message Type: %d",msg->wdata_case);
    // Determine whether message should be processed internally
    uint64_t ifmt = trfPBToInternal(msg->wdata_case);
    if (ifmt & ~flags)
    {
        // Caller must process message
        trf__log_trace("Message %d returned to user", ifmt);
        *processed = ifmt;
        *data_out = msg;
        return 1;
    }
    else
    {
        if (ifmt == TRFM_KEEP_ALIVE)
        {
            trf__log_trace("Got keep alive message...");
            trf_msg__message_wrapper__free_unpacked(msg, NULL);
            *data_out = NULL;
            *processed = ifmt;
            return -EAGAIN;
        }
        else if (ifmt == TRFM_CLIENT_DISP_REQ)
        {
            trf__log_trace("Sending display list");
            if (ctx->type == TRF_EP_CONN_ID)
            {
                if((ret = trfSendDisplayList(ctx)) < 0)
                {
                    trf__log_error("Unable to send display list");
                    goto free_msg;
                }
            }
            else
            {
                trf__log_debug("Invalid message");
                return -EBADMSG;
            }
        }
    }

    *processed = ifmt;
    *data_out = msg;
    return 0;

free_msg:
    trf_msg__message_wrapper__free_unpacked(msg, NULL);
    return ret;
}

PTRFDisplay trfGetDisplayByID(PTRFDisplay disp_list, int id)
{
    if (!disp_list || id < 0)
    {
        errno = EINVAL;
        return NULL;
    }
    for (PTRFDisplay disp = disp_list; disp; disp = disp->next)
    {
        if (disp->id == id)
        {
            errno = 0;
            return disp;
        }
    }
    errno = ESRCH;
    return NULL;
}

int trfSendClientReq(PTRFContext ctx, PTRFDisplay disp)
{
    if (!ctx || !disp)
    {
        return -EINVAL;
    }
    int ret;
    TrfMsg__MessageWrapper * mw = malloc(sizeof(TrfMsg__MessageWrapper));
    if (!mw)
    {
        ret = -ENOMEM;
        goto free_message;
    }
    trf_msg__message_wrapper__init(mw);
    
    TrfMsg__ClientReq * cr = malloc(sizeof(TrfMsg__ClientReq));
    if (!cr)
    {
        ret = -ENOMEM;
        goto free_message;
    }
    trf_msg__client_req__init(cr);

    mw->wdata_case = trfInternalToPB(TRFM_CLIENT_REQ);
    mw->client_req = cr;
    
    int size = 0;
    for (PTRFDisplay tmp_disp = disp; tmp_disp; tmp_disp = tmp_disp->next)
    {
        size++;
    }
    cr->n_display = size;
    cr->display = calloc(1, sizeof(void *) * size);
    if (!cr->display)
    {
        trf__log_error("Unable to allocate memory");
        ret = -ENOMEM;
        goto free_message;
    }
    int idx = 0;
    for (PTRFDisplay tmp_disp = disp; tmp_disp ; tmp_disp = tmp_disp->next)
    {   
        cr->display[idx] = malloc(sizeof(TrfMsg__DisplayReq));
        if(!cr->display[idx])
        {
            trf__log_error(
                "Unable to allocate memory for display Request message");
            ret = -ENOMEM;
            goto free_message;
        }
        trf_msg__display_req__init(cr->display[idx]);
        cr->display[idx]->id        = tmp_disp->id;
        cr->display[idx]->width     = tmp_disp->width;
        cr->display[idx]->height    = tmp_disp->height;
        cr->display[idx]->tex_fmt   = tmp_disp->format;
        idx++;
    }
    ret = trfFabricSend(ctx, mw);
free_message:
    trf_msg__message_wrapper__free_unpacked(mw, NULL);
    return ret;
}

int trfAckClientReq(PTRFContext ctx, uint32_t * disp_ids, int n_disp_ids)
{
    if (!ctx || n_disp_ids <= 0)
    {
        return -EINVAL;
    }
    TrfMsg__MessageWrapper mw = TRF_MSG__MESSAGE_WRAPPER__INIT;
    TrfMsg__ServerAckReq sar = TRF_MSG__SERVER_ACK_REQ__INIT;
    mw.session_id = ctx->cli.session_id;
    mw.wdata_case = trfInternalToPB(TRFM_SERVER_ACK);
    mw.server_ack = &sar;
    sar.display_ids = disp_ids;
    sar.n_display_ids = n_disp_ids;
    return trfFabricSend(ctx, &mw);
}

int trfSendDisplayList(PTRFContext ctx)
{
    int ret = 0;
    TrfMsg__MessageWrapper *msg = malloc(sizeof(TrfMsg__MessageWrapper));
    if (!msg)
    {
        trf__log_error("Unable to allocate memory");
        return -ENOMEM;
    }
    trf_msg__message_wrapper__init(msg);
    TrfMsg__ServerDisp *disp_list = malloc(sizeof(TrfMsg__ServerDisp));
    if (!disp_list)
    {
        trf__log_error("Unable to allocate memory");
        ret = -ENOMEM;
        goto free_message;

    }
    trf_msg__server_disp__init(disp_list);
    msg->wdata_case = trfInternalToPB(TRFM_SERVER_DISP);
    msg->server_disp = disp_list;
    msg->server_disp->n_displays = 0;
    for (PTRFDisplay tmp_disp = ctx->displays; tmp_disp; 
        tmp_disp = tmp_disp->next)
    {
        msg->server_disp->n_displays++;
    }
    msg->server_disp->displays = \
        malloc(sizeof(TrfMsg__Display) * msg->server_disp->n_displays);
    if (!msg->server_disp->displays)
    {
        trf__log_error("Unable to allocate memory");
        ret = -ENOMEM;
        goto free_message;
    }
    int index = 0;
    for (PTRFDisplay tmp_disp = ctx->displays; tmp_disp; 
        tmp_disp = tmp_disp->next)
    {
        msg->server_disp->displays[index] = malloc(sizeof(TrfMsg__Display));
        if (!msg->server_disp->displays[index])
        {
            trf__log_error("Unable to allocate memory");
            ret = -ENOMEM;
            goto free_message;
        }
        trf_msg__display__init(msg->server_disp->displays[index]);
        msg->server_disp->displays[index]->id = tmp_disp->id;
        msg->server_disp->displays[index]->name = strdup(tmp_disp->name);
        msg->server_disp->displays[index]->width = tmp_disp->width;
        msg->server_disp->displays[index]->height = tmp_disp->height;
        msg->server_disp->displays[index]->rate = tmp_disp->rate;
        msg->server_disp->displays[index]->dgid = tmp_disp->dgid;
        msg->server_disp->displays[index]->x_offset = tmp_disp->x_offset;
        msg->server_disp->displays[index]->y_offset = tmp_disp->y_offset;
        // Todo change to support more than one @matthewjmc
        msg->server_disp->displays[index]->tex_fmt = malloc(sizeof(uint32_t));
        if (!msg->server_disp->displays[index]->tex_fmt)
        { 
            trf__log_error("Unable to allocate memory");
            goto free_message;
        }
        msg->server_disp->displays[index]->tex_fmt[0] = tmp_disp->format;
        msg->server_disp->displays[index]->n_tex_fmt = 1;
        
        index++;
    }

    // Send Server Display Request
    ret = trfFabricSend(ctx, msg);
    if (ret < 0)
    {
        trf__log_error("Unable to send Data");
        goto free_message;
    }

    ret = 0;
free_message:
    trf_msg__message_wrapper__free_unpacked(msg, NULL);
    msg = NULL;
    return ret;
}

int trfGetServerDisplays(PTRFContext ctx, PTRFDisplay * out)
{
    int ret = 0;
    if (!ctx || ctx->type != TRF_EP_SINK || !out)
    {
        trf__log_trace("EINVAL trfGetServerDisplays(ctx: %p, out: %p)", 
                       ctx, out);
        return -EINVAL;
    }

    TrfMsg__MessageWrapper * msg = calloc(1, sizeof(TrfMsg__MessageWrapper));
    if (!msg)
    {
        trf__log_error("Unable to allocate memory");
        return -ENOMEM;
    }

    TrfMsg__ClientDispReq * dr = calloc(1, sizeof(TrfMsg__ClientDispReq));
    if (!dr)
    {
        trf__log_error("Unable to allocate memory");
        ret = -ENOMEM;
        goto free_msg;
    }

    trf_msg__message_wrapper__init(msg);
    trf_msg__client_disp_req__init(dr);
    msg->wdata_case = TRF_MSG__MESSAGE_WRAPPER__WDATA_CLIENT_DISP_REQ;
    msg->client_disp_req = dr;
    msg->session_id = ctx->cli.session_id;
    msg->client_disp_req->info = 0;
    
    // Send Server Display Request
    ret = trfFabricSend(ctx, msg);
    if (ret < 0)
    {
        trf__log_error("Unable to send data");
        goto free_msg;
    }

    trf__log_trace("Display request cookie sent");
    trf_msg__message_wrapper__free_unpacked(msg, NULL);

    ret = trfFabricRecv(ctx, &msg);
    if (ret < 0)
    {
        trf__log_error("Message receive failed: %s", strerror(-ret));
        return ret;
    }
    
    if (msg->wdata_case != TRF_MSG__MESSAGE_WRAPPER__WDATA_SERVER_DISP)
    {
        trf__log_error("Unexpected message type");
        trf_msg__message_wrapper__free_unpacked(msg, NULL);
        ret = -EBADMSG;
        goto free_msg;
    }

    if (msg->server_disp->n_displays == 0)
    {
        trf__log_error("No displays available");
        trf_msg__message_wrapper__free_unpacked(msg, NULL);
        ret = -ENOENT;
        goto free_msg;
    }

    PTRFDisplay tmp_out     = calloc(1, sizeof(struct TRFDisplay));
    if (!tmp_out)
    {
        ret = -ENOMEM;
        goto free_msg;
    }
    PTRFDisplay tmp_start   = tmp_out;
    PTRFDisplay prev_disp   = NULL;
    for (int i = 0; i < msg->server_disp->n_displays; i++)
    {
        tmp_out->id         = msg->server_disp->displays[i]->id;
        tmp_out->name       = strdup(msg->server_disp->displays[i]->name);
        tmp_out->width      = msg->server_disp->displays[i]->width;
        tmp_out->height     = msg->server_disp->displays[i]->height;
        tmp_out->rate       = msg->server_disp->displays[i]->rate;
        tmp_out->dgid       = msg->server_disp->displays[i]->dgid;
        tmp_out->x_offset   = msg->server_disp->displays[i]->x_offset;
        tmp_out->y_offset   = msg->server_disp->displays[i]->y_offset;
        tmp_out->format     = msg->server_disp->displays[i]->tex_fmt[0];
        tmp_out->next       = calloc(1, sizeof(struct TRFDisplay));
        if (!tmp_out->next)
        {
            trf__log_error("Unable to allocate memory");
            trfFreeDisplayList(tmp_start, 0);
            trf_msg__message_wrapper__free_unpacked(msg, NULL);
            return -ENOMEM;
        }
        prev_disp = tmp_out;
        tmp_out = tmp_out->next;
    }

    ret  = 0;
    *out = tmp_start;
    free(tmp_out);
    if (prev_disp)
    {
        prev_disp->next = NULL;
    }
free_msg:
    trf_msg__message_wrapper__free_unpacked(msg, NULL);
    return ret;
}

int trfFabricSend(PTRFContext ctx, TrfMsg__MessageWrapper * msg)
{
    if (!ctx)
    {
        return -EINVAL;
    }

    PTRFContextOpts opts = ctx->opts;
    size_t buff_size = opts->fab_snd_bufsize > 0 ? 
        opts->fab_snd_bufsize : ctx->xfer.fabric->msg_size;

    int ret = 0;
    uint32_t size;
    ret = trfMsgPack(msg, buff_size, ctx->xfer.fabric->msg_ptr, &size);
    if (ret < 0)
    {
        trf__log_error("Unable to pack message");
        return ret;
    }

    struct timespec tstart, tend;
    clock_gettime(CLOCK_MONOTONIC, &tstart);
    trf__GetDelay(&tstart, &tend, opts->fab_snd_timeo);
    trf__log_trace("Attempting fabric send");
    ret = trf__FabricPostSend(ctx, size, ctx->xfer.fabric->peer_addr, &tend);
    if (ret < 0)
    {
        trf_fi_error("FabricPostSend", ret);
        return ret;
    }
    
    struct fi_cq_data_entry cqe;
    struct fi_cq_err_entry err;
    ret = trf__PollCQ(ctx->xfer.fabric->tx_cq, &cqe, &err, opts, &tend, 1, 
                      TRF_SEND_CQ);
    if (ret != 1)
    {
        memset(&err, 0, sizeof(err));
        trf__log_error("CQ read error: %s\n", 
            trf__GetCQErrString(ctx->xfer.fabric->tx_cq->cq, &err));
        return ret == 0 ? -EIO : ret;
    }
    trf__log_trace("Message payload sent over fabric");
    return 0;
}

int trfFabricRecv(PTRFContext ctx, TrfMsg__MessageWrapper ** msg)
{
    if (!ctx)
    {
        return -EINVAL;
    }

    ssize_t ret;
    PTRFContextOpts opts = ctx->opts;
    size_t buff_size = opts->fab_rcv_bufsize > 0 ? 
        opts->fab_rcv_bufsize : ctx->xfer.fabric->msg_size;

    trf__log_trace("Buffer size: %ld", buff_size);

    struct timespec tstart, tend;
    clock_gettime(CLOCK_MONOTONIC, &tstart);
    trf__GetDelay(&tstart, &tend, opts->fab_rcv_timeo);
    trf__log_trace("Attempting fabric recv");
    ret = trf__FabricPostRecv(ctx, ctx->xfer.fabric->peer_addr, &tend);
    if (ret < 0)
    {
        trf__log_error("Unable to post recv");
        return ret;
    }
    
    struct fi_cq_data_entry cqe;
    struct fi_cq_err_entry err;
    ret = trf__PollCQ(ctx->xfer.fabric->rx_cq, &cqe, &err, opts, &tend, 1, 
                      TRF_SEND_CQ);
    if (ret != 1)
    {
        trf__log_error("CQ read failed: %s\n", 
            trf__GetCQErrString(ctx->xfer.fabric->rx_cq->cq, &err));
        return ret == 0 ? -EIO : ret;
    }

    return trfMsgUnpack(msg, trfMsgGetPackedLength(ctx->xfer.fabric->msg_ptr), 
        trfMsgGetPayload(ctx->xfer.fabric->msg_ptr));
}

int trfAckFrameReq(PTRFContext ctx, PTRFDisplay display)
{
    int ret;
    TrfMsg__MessageWrapper msg = TRF_MSG__MESSAGE_WRAPPER__INIT;
    TrfMsg__ServerAckFReq ack = TRF_MSG__SERVER_ACK_FREQ__INIT;
    msg.wdata_case  = trfInternalToPB(TRFM_SERVER_ACK_F_REQ);
    msg.server_ack_f_req = &ack;
    ack.id = display->id;
    ack.frame_cntr = display->frame_cntr;
    if ((ret = trfFabricSend(ctx, &msg)) < 0)
    {
        trf__log_error("Unable to send data");
    }
    return ret;
}

ssize_t trfSendFramePart(PTRFContext ctx, PTRFDisplay disp, uint64_t rbuf,
    uint64_t rkey, struct TRFRect * rects, size_t num_rects)
{
    if (!ctx || !disp || !rects || num_rects == 0)
    {
        return -EINVAL;
    }
    
    // Shorten access
    PTRFXFabric f = ctx->xfer.fabric;

    // Compressed texture formats are not directly pixel addressable and require
    // special handling - for now, we'll just ignore them
    if (trfTextureIsCompressed(disp->format))
    {
        return -ENOTSUP;
    }

    // Allocate iovec for posting frame updates
    ssize_t ret;
    size_t max_iov = f->fi->tx_attr->rma_iov_limit;
    struct iovec * iov = malloc(sizeof(struct iovec) * max_iov);
    if (!iov)
    {
        return -ENOMEM;
    }

    // Since all the memory indirectly referenced by the rectangles should be in
    // the same MR, we just need to set the MR descriptor to be the same across
    // all items in the description array
    void ** desc = malloc(sizeof(void *) * max_iov);
    for (int i = 0; i < max_iov; i++)
    {
        desc[i] = fi_mr_desc(disp->fb_mr);
    }

    trf__log_debug("Display: %d x %d", disp->width, disp->height);

    // Framebuffer line pitch
    int32_t lpitch = trfGetTextureBytes(disp->width, 1, disp->format);
    // Pixel pitch in bytes
    int32_t ppitch = trfGetTextureBytes(1, 1, disp->format);

    if (lpitch < 0)
    {
        free(iov);
        free(desc);
        return lpitch;
    }
    if (ppitch < 0)
    {
        free(iov);
        free(desc);
        return ppitch;
    }
    
    // Determine how many CQEs we will need to use to track this operation
    size_t num_cqe = 0;
    for (int i = 0; i < num_rects; i++)
    {
        // Some rudimentary error checking
        if (rects[i].x + rects[i].width > disp->width
            || rects[i].y + rects[i].height > disp->height)
        {
            trf__log_error("Invalid rectangle! Pos: %d, %d Size: %d, %d", 
                rects[i].x, rects[i].y, rects[i].width, rects[i].height);
            return -EINVAL;
        }
        if (rects[i].x == 0 && rects[i].width == disp->width)
        {
            // Rectangles that span the entire width of the frame can be sent
            // as a single RMA operation
            num_cqe++;
        }
        else
        {
            // Otherwise we can send a vectored RMA for up to max_iov lines
            num_cqe += rects[i].height / max_iov;
        }
    }

    // The operation will never succeed if our max CQE count is exceeded -
    // caller must optimize accesses before retrying
    if (num_cqe > f->fi->tx_attr->size)
    {
        trf__log_error("Write operation exceeds max CQE count");
        return -E2BIG;
    }

    // There may also be other operations in progress that have consumed CQEs
    size_t rem_cqe = trf__DecrementCQ(f->tx_cq, num_cqe);
    if (rem_cqe < num_cqe)
        return -EAGAIN;

    size_t iter = 0;
    for (int i = 0; i < num_rects; i++)
    {
        // Get offset in framebuffer to rectangle
        size_t offset = lpitch * rects[i].y + ppitch * rects[i].x;
        // Rectangle line pitch
        uint32_t rpitch = ppitch * rects[i].width;

        trf__log_debug("Damage update rect: %d,%d %dx%d", 
                       rects[i].x, rects[i].y, rects[i].width, rects[i].height);
        trf__log_debug("lpitch: %d, ppitch: %d, offset: %lu, rpitch: %d",
                       lpitch, ppitch, offset, rpitch);

        // Full-width update mode
        if (rects[i].x == 0 && rects[i].width == disp->width)
        {
            // Calculate contiguous region length
            ssize_t rlen = trfGetTextureBytes(rects[i].width, rects[i].height, 
                                             disp->format);
            // The region length was invalid
            if (rlen < 0)
            {
                goto try_recover;
            }

            // Post RMA write
            ret = fi_write(ctx->xfer.fabric->ep, 
                           disp->fb_addr + offset, (size_t) rlen, 
                           disp->fb_mr, ctx->xfer.fabric->peer_addr, 
                           rbuf + offset, rkey, (void *) iter);
            if (ret < 0)
            {
                goto try_recover;
            }
            iter++;
            continue;
        }

        // Vector update mode
        size_t total = rects[i].height;
        while (total)
        {
            // Split rectangle into max_iov lines
            size_t iov_l = total > max_iov ? max_iov : total;
            for (int j = 0; j < iov_l; j++)
            {
                iov[j].iov_base = disp->fb_addr + offset;
                iov[j].iov_len  = rpitch;
            }
            
            // Perform RMA write
            ret = fi_writev(ctx->xfer.fabric->ep, iov, desc, max_iov,
                            ctx->xfer.fabric->peer_addr, rbuf, rkey, 
                            (void *) iter);
            if (ret < 0)
            {
                goto try_recover;
            }

            // Update total and request count
            total -= iov_l;
            iter++;
        }
    }

    // Return the number of submitted events
    free(iov);
    free(desc);
    return iter;

try_recover:
    trf__log_error("Unable to perform RMA write # %d. fi_writev "
        "returned: %s. Attempting to recover", iter, fi_strerror(-ret));
    // Release the unused CQEs immediately then try to reclaim the rest by
    // monitoring progress.
    trf__IncrementCQ(f->tx_cq, num_cqe - iter);
    while (iter)
    {
        struct fi_cq_data_entry de;
        struct fi_cq_err_entry err;
        ssize_t ret2 = trfGetSendProgress(ctx, &de, &err, 1);
        if (ret2 < 0)
        {
            trf__log_error("Unable to recover: %s", 
                trf__GetCQErrString(ctx->xfer.fabric->tx_cq->cq, &err));
            trf__log_error("Context should be considered invalid");
            free(iov);
            free(desc);
            return ret2;
        }
        trf__IncrementCQ(ctx->xfer.fabric->tx_cq, 1);
        iter--;
    }
    return ret;
}

ssize_t trfSendFrameChunk(PTRFContext ctx, PTRFDisplay disp, size_t start, 
                          size_t end, uint64_t rbuf, uint64_t rkey)
{
    if (!ctx || !disp || !rbuf || !rkey)
    {
        trf__log_debug("Invalid argument - trfSendFrameChunk(ctx: %p, "
                       "disp: %p, start: %lu, end: %lu, rbuf: %lu, rkey: %lu)",
                       ctx, disp, start, end, rbuf, rkey);
        return -EINVAL;
    }

    if (end > start || (end - start) > trfGetDisplayBytes(disp))
    {
        trf__log_debug("Invalid display range - trfSendFrameChunk(ctx: %p, "
                       "disp: %p, start: %lu, end: %lu, rbuf: %lu, rkey: %lu)",
                       ctx, disp, start, end, rbuf, rkey);
        return -EINVAL;
    }
    
    // Shorten access
    PTRFXFabric f = ctx->xfer.fabric;

    // Compressed texture formats are not directly pixel addressable and require
    // special handling - for now, we'll just ignore them
    if (trfTextureIsCompressed(disp->format))
    {
        return -ENOTSUP;
    }

    trf__DecrementCQ(f->tx_cq, 1);
    ssize_t ret;
    ret = fi_write(f->ep, 
                   trfGetFBPtr(disp), end - start,
                   fi_mr_desc(disp->fb_mr), f->peer_addr, 
                   rbuf, rkey, NULL);
    if (ret < 0)
    {
        trf__IncrementCQ(f->tx_cq, 1);
    }
    return ret;
}