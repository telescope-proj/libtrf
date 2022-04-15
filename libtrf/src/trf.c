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
        goto free_eq;
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
                goto free_eq;
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
                goto free_eq;
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
        trf_fi_error("EP bind to TX CQ", ret);
        goto free_endpoint;
    }
    ret = fi_ep_bind(ctx->ep, &ctx->rx_cq->cq->fid, FI_RECV);
    if (ret)
    {
        trf_fi_error("EP bind to RX CQ", ret);
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
    if (!ctx->fi)
    {
        trf_fi_error("Duplicate fi_info struct", -errno);
        goto free_endpoint;
    }
    trf__log_trace("ctx->fi: %p", ctx->fi);
    return ret;

free_endpoint:
    fi_close(&ctx->ep->fid);
    ctx->ep = NULL;
free_addr_data:
    free(abuf);
free_eq:
    fi_close(&ctx->eq->fid);
    ctx->eq = NULL;
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
    if (!ctx || ctx->xfer_type != TRFX_TYPE_LIBFABRIC || !ctx->xfer.fabric)
        return;

    PTRFXFabric f = ctx->xfer.fabric;
    
    if (!ctx->disconnected && f->domain && f->ep && f->msg_mem.ptr 
        && f->msg_mem.fabric_mr)
    {
        trf__log_trace("Sending disconnect message");
        TrfMsg__MessageWrapper mw = TRF_MSG__MESSAGE_WRAPPER__INIT;
        TrfMsg__Disconnect dc = TRF_MSG__DISCONNECT__INIT;
        mw.disconnect = &dc;
        mw.wdata_case = TRF_MSG__MESSAGE_WRAPPER__WDATA_DISCONNECT;
        mw.disconnect->info = 0;
        int ret = trfFabricSendMsg(ctx, &f->msg_mem, trfMemPtr(&f->msg_mem),
                                   trfMemSize(&f->msg_mem), f->peer_addr, 
                                   ctx->opts, &mw);
        if (ret != 1)
        {
            trf__log_error( "Failed to send disconnect message (fabric): %s;"
                            "peer may be in an invalid state", strerror(-ret));
        }
        ctx->disconnected = 1;
    }
    if (trfMemFabricMR(&f->msg_mem))
    {
        fi_close((fid_t) trfMemFabricMR(&f->msg_mem));
        f->msg_mem.fabric_mr = NULL;
    }
    if (trfMemPtr(&f->msg_mem))
    {
        free(trfMemPtr(&f->msg_mem));
        f->msg_mem.ptr  = NULL;
        f->msg_mem.size = 0;
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
    if (f->eq)
    {
        fi_close(&f->eq->fid);
        f->eq = NULL;
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
        trf__log_trace("freeing ctx->fi: %p %p", f->fi, ctx->xfer.fabric->fi);
        fi_freeinfo(f->fi);
        f->fi = NULL;
    }
    
    free(ctx->xfer.fabric);
    ctx->xfer.fabric = NULL;
    ctx->xfer_type = TRFX_TYPE_INVALID;
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
        free(tmp_buf);
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

    switch (ctx->type)
    {
        case TRF_EP_SOURCE:
            if (trfSockValid(ctx->svr.listen_fd))
            {
                close(ctx->svr.listen_fd);
            }
            for (int i = 0; i < ctx->svr.max_clients; i++)
            {
                if (ctx->svr.clients[i])
                {
                    trfDestroyContext(ctx->svr.clients[i]);
                }
            }
            break;
        case TRF_EP_SINK:
        case TRF_EP_CONN_ID:
            if (trfSockValid(ctx->cli.client_fd))
            {
                trfSendDisconnectMsg(ctx->cli.client_fd, 
                    ctx->cli.session_id);
                close(ctx->cli.client_fd);
            }
            break;
        default:
            break;
    }
    switch (ctx->xfer_type)
    {
        case TRFX_TYPE_LIBFABRIC:
            trfDestroyFabricContext(ctx);
            break;
        default:
            break;
    }

    free(ctx->opts);
    free(ctx);
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

int trfBindSubchannel(PTRFContext main, PTRFContext sub)
{
    if (!main || !sub)
        return -EINVAL;

    if ((main->type != TRF_EP_SINK && main->type != TRF_EP_CONN_ID)
        || (sub->type != TRF_EP_SINK && sub->type != TRF_EP_CONN_ID))
    {
        trf__log_error("Invalid channel type");
        return -EINVAL;
    }

    for (int i = 0; i < main->cli.max_channels; i++)
    {
        if (!main->cli.channels[i])
        {
            main->cli.channels[i] = sub;
            return i;
        }
    }

    return -ESRCH;
}

int trfUnbindSubchannel(PTRFContext main, uint32_t id)
{
    if (!main || !id)
        return -EINVAL;

    if (main->type != TRF_EP_SINK && main->type != TRF_EP_CONN_ID)
    {
        trf__log_error("Invalid channel type");
        return -EINVAL;
    }

    for (int i = 0; i < main->cli.max_channels; i++)
    {
        if (main->cli.channels[i] && main->cli.channels[i]->channel_id == id)
        {
            main->cli.channels[i] = NULL;
            return 0;
        }
    }

    return -ESRCH;
}

int trfCreateSubchannel(PTRFContext ctx, PTRFContext * ctx_out, uint32_t id)
{
    if (!ctx || !ctx_out || !id)
        return -EINVAL;

    PTRFContext new_ctx = trfAllocContext();
    if (!new_ctx)
        return -ENOMEM;

    new_ctx->disconnected = 1;

    struct fi_info * fi_copy = fi_dupinfo(ctx->xfer.fabric->fi);
    if (!fi_copy)
    {
        free(new_ctx);
        return -ENOMEM;
    }

    free(fi_copy->src_addr);
    fi_copy->src_addr = NULL;

    int ret = trfCreateChannel(new_ctx, fi_copy, NULL, 0);
    if (ret < 0)
    {
        trf__log_error("Failed to allocate subchannel endpoint: %s",
                       fi_strerror(-ret));
        return ret;
    }

    new_ctx->opts = calloc(1, sizeof(*new_ctx->opts));
    trfDuplicateOpts(ctx->opts, new_ctx->opts);
    if (!new_ctx->opts)
    {
        new_ctx->disconnected = 1;
        trfDestroyContext(new_ctx);
        return -ENOMEM;
    }

    char * prov_str = strdup(fi_copy->fabric_attr->prov_name);
    fi_freeinfo(fi_copy);
    assert(prov_str);

    char * addr_str = NULL;
    ret = trfGetEndpointName(new_ctx, &addr_str);
    if (ret < 0)
    {
        trf__log_error("Failed to get endpoint name: %s", fi_strerror(-ret));
        goto free_new_ctx;
    }

    assert(addr_str);

    char * proto_str = NULL;
    ret = trfSerializeWireProto(new_ctx->xfer.fabric->fi->ep_attr->protocol,
                                &proto_str);
    if (ret < 0)
    {
        trf__log_error("Failed to get wire protocol %d", 
                       new_ctx->xfer.fabric->fi->ep_attr->protocol);
        goto free_addr;
    }

    assert(proto_str);

    trf__log_debug("[subch] Serialized endpoint created");
    trf__log_debug("[subch] Address : %s", addr_str);
    trf__log_debug("[subch] Protocol: %s", proto_str);
    trf__log_debug("[subch] Provider: %s", prov_str);

    // Register a temporary buffer to store the hello message. This buffer will
    // be deregistered afterwards; the subchannel user is expected to manage
    // and size their own message buffers to their requirements.

    void * mem = NULL;
    size_t s = trf__GetPageSize();
    assert(s > 0);
    mem = trfAllocAligned(s, s);
    if (!mem)
        goto free_proto;

    {
        TrfMsg__MessageWrapper mw   = TRF_MSG__MESSAGE_WRAPPER__INIT;
        TrfMsg__ChannelOpen co      = TRF_MSG__CHANNEL_OPEN__INIT;
        TrfMsg__Transport tr        = TRF_MSG__TRANSPORT__INIT;
        mw.session_id               = ctx->cli.session_id;
        mw.wdata_case               = TRF_MSG__MESSAGE_WRAPPER__WDATA_CH_OPEN;
        mw.ch_open                  = &co;
        co.id                       = id;
        co.reply                    = 0;
        co.transport                = &tr;
        tr.src                      = addr_str;
        tr.name                     = prov_str;
        tr.dest                     = NULL;
        tr.proto                    = proto_str;

        // Send the channel open message over the socket

        ret = trfNCSendMsg(ctx->cli.client_fd, mem, s, ctx->opts->nc_snd_timeo,
                           &mw);
        if (ret < 0)
        {
            trf__log_error("Failed to send channel open message: %s",
                           strerror(-ret));
            goto free_mem;
        }
    }
    
    trf__log_trace("[subch] Sent channel open message");

    TrfMsg__MessageWrapper * rcv = NULL;
    ret = trfNCRecvMsg(ctx->cli.client_fd, mem, s, 
                       ctx->opts->nc_rcv_timeo, &rcv);
    if (ret < 0)
    {
        trf__log_error("Failed to receive channel open response: %s",
                       strerror(-ret));
        goto free_mem;
    }

    trf__log_trace("[subch] Received open message");

    assert(rcv);

    if (rcv->wdata_case != TRF_MSG__MESSAGE_WRAPPER__WDATA_CH_OPEN)
    {
        trf__log_warn("Peer sent invalid message type %d (expected %d)", 
                      rcv->wdata_case, TRF_MSG__MESSAGE_WRAPPER__WDATA_CH_OPEN);
        ret = -EBADMSG;
        goto free_rcv;
    }

    TrfMsg__ChannelOpen * rco = rcv->ch_open;

    if (!rco->transport
        || !trf__ProtoStringValid(rco->transport->src)
        || !trf__ProtoStringValid(rco->transport->name)
        || !trf__ProtoStringValid(rco->transport->proto))
    {
        trf__log_warn("Peer sent garbage transport data");
        goto free_rcv;
    }

    if (rco->id != id || !rco->reply)
    {
        trf__log_warn("Peer sent invalid data - values: "
                      "id = %d (expected %d), reply: %d (expected %d)",
                      rco->id, id, rco->reply, 1);
        ret = -EBADMSG;
        goto free_rcv;
    }

    ret = trfRegInternalMsgBuf(new_ctx, mem, s);
    if (ret < 0)
        goto free_rcv;
    
    assert(trfMemPtr(&ctx->xfer.fabric->msg_mem));

    // Try to send a message over the transport

    new_ctx->xfer.fabric->peer_addr = FI_ADDR_UNSPEC;
    ret = trfInsertAVSerialized(new_ctx->xfer.fabric, rco->transport->src, 
                                &new_ctx->xfer.fabric->peer_addr);
    if (ret < 0)
        goto dereg_mem;

    assert(new_ctx->xfer.fabric->peer_addr != FI_ADDR_UNSPEC);
    struct TRFMem * msg_mem = &new_ctx->xfer.fabric->msg_mem;

    {
        TrfMsg__MessageWrapper mw   = TRF_MSG__MESSAGE_WRAPPER__INIT;
        TrfMsg__ChannelHello hl     = TRF_MSG__CHANNEL_HELLO__INIT;
        mw.wdata_case               = TRF_MSG__MESSAGE_WRAPPER__WDATA_CH_HELLO;
        mw.ch_hello                 = &hl;
        mw.session_id               = ctx->cli.session_id;
        hl.channel_id               = id;
        hl.reply                    = 0;

        ret = trfFabricSendMsg(new_ctx, msg_mem, trfMemPtr(msg_mem), s,
                               FI_ADDR_UNSPEC, ctx->opts, &mw);
        if (ret < 0)
            goto dereg_mem;
    }

    TrfMsg__MessageWrapper * rcv_sub = NULL;
    ret = trfFabricRecvMsg(new_ctx, msg_mem, trfMemPtr(msg_mem),
                           trfMemSize(msg_mem), new_ctx->xfer.fabric->peer_addr,
                           ctx->opts, &rcv_sub);
    if (ret < 0)
        goto dereg_mem;

    assert(rcv_sub);

    if (rcv_sub->wdata_case != TRF_MSG__MESSAGE_WRAPPER__WDATA_CH_HELLO)
    {
        trf__log_warn("Peer sent invalid message type %d (expected %d)", 
                      rcv->wdata_case, TRF_MSG__MESSAGE_WRAPPER__WDATA_CH_OPEN);
        ret = -EBADMSG;
        goto free_rcv_sub;
    }

    if (!rcv_sub->ch_hello->reply
        || rcv_sub->ch_hello->channel_id != id
        || rcv_sub->session_id != ctx->cli.session_id)
    {
        trf__log_warn("Peer sent invalid data - values (actual/expect): "
                      "reply: (%d/%d), channel: (%d/%d) session: (%d/%d)",
                      rcv_sub->ch_hello->reply, 1, 
                      rcv_sub->ch_hello->channel_id, id,
                      rcv_sub->session_id, new_ctx->cli.session_id);
        ret = -EBADMSG;
        goto free_rcv_sub;
    }

    // Connected - now clean everything up

    fi_close(&msg_mem->fabric_mr->fid);
    free(msg_mem->ptr);
    msg_mem->fabric_mr = NULL;
    msg_mem->ptr = NULL;

    trf_msg__message_wrapper__free_unpacked(rcv_sub, NULL);
    trf_msg__message_wrapper__free_unpacked(rcv, NULL);

    free(proto_str);
    free(addr_str);
    free(prov_str);

    new_ctx->disconnected = 0;
    new_ctx->channel_id = id;
    *ctx_out = new_ctx;

    return 0;

free_rcv_sub:
    trf_msg__message_wrapper__free_unpacked(rcv_sub, NULL);
dereg_mem:
    fi_close((fid_t) trfMemFabricMR(&new_ctx->xfer.fabric->msg_mem));
    new_ctx->xfer.fabric->msg_mem.ptr = NULL;
    new_ctx->xfer.fabric->msg_mem.fabric_mr = NULL;
free_rcv:
    trf_msg__message_wrapper__free_unpacked(rcv, NULL);
    proto_str = NULL;
    addr_str = NULL;
free_mem:
    free(mem);
free_proto:
    free(proto_str);
free_addr:
    free(addr_str);
free_new_ctx:
    free(prov_str);
    trfDestroyContext(new_ctx);
    return ret;
}

int trfProcessSubchannelReq(PTRFContext ctx, PTRFContext * ctx_out,
                            TrfMsg__MessageWrapper * req)
{
    if (!ctx || !ctx_out || !req)
        return -EINVAL;

    TrfMsg__ChannelOpen * rco = req->ch_open;

    if (trfPBToInternal(req->wdata_case) != TRFM_CH_OPEN
        || !rco->transport)
        return -EBADMSG;

    if (!rco->transport
        || !trf__ProtoStringValid(rco->transport->src)
        || !trf__ProtoStringValid(rco->transport->name)
        || !trf__ProtoStringValid(rco->transport->proto))
    {
        trf__log_warn("Peer sent garbage transport data");
        return -EBADMSG;
    }

    trf__log_trace("Processing subchannel request");
    PTRFContext new_ctx = trfAllocContext();
    if (!new_ctx)
        return -ENOMEM;

    new_ctx->opts = calloc(1, sizeof(*new_ctx->opts));
    trfDuplicateOpts(ctx->opts, new_ctx->opts);
    if (!new_ctx->opts)
    {
        free(new_ctx);
        return -ENOMEM;
    }
    new_ctx->disconnected = 1;

    uint32_t id = rco->id;
    new_ctx->channel_id     = id;
    new_ctx->cli.session_id = ctx->cli.session_id;

    struct fi_info * fi = NULL;
    int ret = trfGetRoute(rco->transport->src,
                          rco->transport->name,
                          rco->transport->proto, &fi);
    if (ret < 0)
    {
        goto free_new_ctx;
    }

    ret = trfCreateChannel(new_ctx, fi, NULL, 0);
    if (ret < 0)
    {
        trf__log_error("Failed to allocate subchannel endpoint: %s",
                       fi_strerror(-ret));
        goto free_fi;
    }

    fi_freeinfo(fi);
    fi = NULL;

    char * addr_str = NULL;
    ret = trfGetEndpointName(new_ctx, &addr_str);
    if (ret < 0)
    {
        trf__log_error("Failed to get endpoint name: %s", fi_strerror(-ret));
        goto free_new_ctx;
    }

    assert(addr_str);

    char * proto_str = NULL;
    ret = trfSerializeWireProto(new_ctx->xfer.fabric->fi->ep_attr->protocol,
                                &proto_str);
    if (ret < 0)
    {
        trf__log_error("Failed to get wire protocol %d", 
                       new_ctx->xfer.fabric->fi->ep_attr->protocol);
        goto free_addr;
    }

    assert(proto_str);

    trf__log_debug("[subch] Serialized endpoint name: %s, protocol: %s",
                   addr_str, proto_str);

    // Register temporary message buffer

    void * mem = NULL;
    size_t s = trf__GetPageSize();
    assert(s > 0);
    mem = trfAllocAligned(s, s);
    if (!mem)
    {
        ret = -ENOMEM;
        goto free_proto;
    }

    {
        PTRFXFabric f = new_ctx->xfer.fabric;
        TrfMsg__MessageWrapper mw   = TRF_MSG__MESSAGE_WRAPPER__INIT;
        TrfMsg__ChannelOpen co      = TRF_MSG__CHANNEL_OPEN__INIT;
        TrfMsg__Transport tr        = TRF_MSG__TRANSPORT__INIT;
        mw.session_id               = new_ctx->cli.session_id;
        mw.wdata_case               = TRF_MSG__MESSAGE_WRAPPER__WDATA_CH_OPEN;
        mw.ch_open                  = &co;
        co.id                       = id;
        co.reply                    = 1;
        co.transport                = &tr;
        tr.name                     = f->fi->fabric_attr->prov_name;
        tr.src                      = addr_str;
        tr.dest                     = NULL;
        tr.proto                    = proto_str;

        // Send the channel open reply over the main socket

        ret = trfNCSendMsg(ctx->cli.client_fd, mem, s, ctx->opts->nc_snd_timeo,
                           &mw);
        if (ret < 0)
        {
            trf__log_error("Failed to send channel open message: %s",
                           strerror(-ret));
            goto free_mem;
        }
    }

    // Register the client in the address vector

    TrfMsg__MessageWrapper * rcv = NULL;
    new_ctx->xfer.fabric->peer_addr = FI_ADDR_UNSPEC;
    ret = trfInsertAVSerialized(new_ctx->xfer.fabric, rco->transport->src, 
                                &new_ctx->xfer.fabric->peer_addr);
    if (ret < 0)
        goto free_mem;

    assert(new_ctx->xfer.fabric->peer_addr != FI_ADDR_UNSPEC);
    
    // Post fabric receive

    ret = trfRegInternalMsgBuf(new_ctx, mem, s);
    if (ret < 0)
        goto free_mem;

    struct TRFMem * msg_mem = &new_ctx->xfer.fabric->msg_mem;
    assert(trfMemPtr(msg_mem));

    ret = trfFabricRecvMsg(new_ctx, msg_mem, trfMemPtr(msg_mem),
                           trfMemSize(msg_mem), new_ctx->xfer.fabric->peer_addr,
                           new_ctx->opts, &rcv);
    if (ret < 0)
        goto dereg_mem;

    assert(rcv);

    if (rcv->ch_hello->reply
        || rcv->ch_hello->channel_id != id
        || rcv->session_id != new_ctx->cli.session_id)
    {
        trf__log_warn("Peer sent invalid data - values (actual/expect): "
                      "reply: (%d/%d), channel: (%d/%d) session: (%d/%d)",
                      rcv->ch_hello->reply, 0,
                      rcv->ch_hello->channel_id, id,
                      rcv->session_id, new_ctx->cli.session_id);
        ret = -EBADMSG;
        goto free_rcv;
    }

    // Send back a reply echoing back the data

    rcv->ch_hello->reply = 1;
    ret = trfFabricSendMsg(new_ctx, msg_mem, trfMemPtr(msg_mem), 
                           trfMemSize(msg_mem), new_ctx->xfer.fabric->peer_addr,
                           new_ctx->opts, rcv);
    if (ret < 0)
    {
        trf__log_error("Fabric send failed: %s", fi_strerror(-ret));
        goto free_rcv;
    }

    // Connected - now clean everything up

    fi_close(&msg_mem->fabric_mr->fid);
    free(msg_mem->ptr);
    msg_mem->fabric_mr = NULL;
    msg_mem->ptr = NULL;

    trf_msg__message_wrapper__free_unpacked(rcv, NULL);

    free(proto_str);
    free(addr_str);

    new_ctx->disconnected = 0;
    new_ctx->channel_id = id;

    *ctx_out = new_ctx;

    return 0;

free_rcv:
    trf_msg__message_wrapper__free_unpacked(rcv, NULL);
dereg_mem:
    fi_close((fid_t) trfMemFabricMR(&new_ctx->xfer.fabric->msg_mem));
    new_ctx->xfer.fabric->msg_mem.fabric_mr = NULL;
    new_ctx->xfer.fabric->msg_mem.ptr = NULL;
free_mem:
    free(mem);
    mem = NULL;
free_proto:
    free(proto_str);
free_addr:
    free(addr_str);
free_fi:
    fi_freeinfo(fi);
free_new_ctx:
    trfDestroyContext(new_ctx);
    return ret;
}

int trfDeserializeWireProto(const char * proto, uint32_t * out)
{
    assert( (sizeof(trf__fi_proto) / sizeof(trf__fi_proto[0]))
            == (sizeof(trf__fi_enum) / sizeof(trf__fi_enum[0])));

    if (!proto || !out)
        return -EINVAL;

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
    assert( (sizeof(trf__fi_proto) / sizeof(trf__fi_proto[0]))
            == (sizeof(trf__fi_enum) / sizeof(trf__fi_enum[0])));

    if (!out)
        return -EINVAL;

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

    hints = trf__FabricGetHints();
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
    hints->fabric_attr->prov_name   = (char *) prov;

    ret = fi_getinfo(TRF_FABRIC_VERSION, NULL, NULL, 0, hints, &info);
    if (ret) {
        trf_fi_warn("fi_getinfo", ret);
        goto free_hints;
    }

    ret = 0;
    *fi = info;

free_hints:
    hints->fabric_attr->prov_name = NULL;
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

/**
 * @brief Deduplicate entries in an fi_info list, based on the fabric provider
 * name. This function is currently for internal use only.
 *
 * @param fi    The fi_info list to deduplicate.
 */
static inline void trfDedupFabricList(struct fi_info * fi)
{
    char prov_names[32][32];
    for (int i = 0; i < 32; i++)
    {
        memset(prov_names[i], 0, 32);
    }
    int names_used          = 0;
    struct fi_info * prev   = NULL;
    struct fi_info * tmp    = fi;
    while (tmp)
    {
        int flag = 0;
        for (int i = 0; i < names_used; i++)
        {
            if (strncmp(tmp->fabric_attr->prov_name, &prov_names[i][0], 32)
                == 0)
            {
                flag = 1;
                break;
            }
        }
        if (flag)
        {
            struct fi_info * tmp2 = NULL;
            if (tmp->next)
            {
                tmp2 = tmp->next;
                tmp->next = NULL;
                fi_freeinfo(tmp);
                if (prev)
                {
                    prev->next = tmp2;
                }
                tmp = tmp2;
                continue;
            }
        }
        else
        {
            strncpy(&prov_names[names_used][0], tmp->fabric_attr->prov_name, 
                    32);
            names_used++;
        }
        prev = tmp;
        tmp = tmp->next;
    }
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

    hints = trf__FabricGetHints();
    trf__log_debug("Attempting to find fabric provider for %s:%s", host, port);
    ret = fi_getinfo(TRF_FABRIC_VERSION, host, port, 0, hints, &fi);
    if (ret)
    {
        trf_fi_error("fi_getinfo", ret);
        return ret;
    }

    /*  Deduplicate the list of fabric providers, the other side does not need
        the extra information (such as FI_INJECT size)
    */
    trfDedupFabricList(fi);

    /*  Iterate through the list of interfaces and print out the name and
        provider name (debug)
    */
    trfPrintFabricProviders(fi);

    fi_freeinfo(hints);
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

int trfRegDisplaySource(PTRFContext ctx, PTRFDisplay disp)
{
    int ret;
    ret = trf__FabricRegBuf(ctx->xfer.fabric, trfMemPtr(&disp->mem), 
                            trfGetDisplayBytes(disp), FI_READ,
                            &disp->mem.fabric_mr);
    if (ret < 0)
        return ret;

    disp->mem.type      = TRF_MEM_TYPE_LF_MR;
    disp->mem.size      = trfGetDisplayBytes(disp);
    disp->fb_offset     = 0;
    return ret;
}

int trfRegDisplaySink(PTRFContext ctx, PTRFDisplay disp)
{
    int ret;
    ret = trf__FabricRegBuf(ctx->xfer.fabric, trfMemPtr(&disp->mem), 
                            trfGetDisplayBytes(disp), 
                            FI_WRITE | FI_REMOTE_WRITE, &disp->mem.fabric_mr);
    if (ret < 0)
        return ret;

    disp->mem.type      = TRF_MEM_TYPE_LF_MR;
    disp->mem.size      = trfGetDisplayBytes(disp);
    disp->fb_offset     = 0;
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
    if (trfMemPtr(&disp->mem) + (offset + trfGetDisplayBytes(disp)) > 
        (trfMemPtr(&disp->mem) + size))
    {
        trf__log_debug("Frame data would overflow buffer!");
        trf__log_debug("Data ends at: %p, Maximum: %p", 
                       (trfMemPtr(&disp->mem) + 
                            (offset + trfGetDisplayBytes(disp))),
                       (trfMemPtr(&disp->mem) + size));
        return -ENOSPC;
    }
    ssize_t ret;
    ret = trf__FabricRegBuf(ctx->xfer.fabric, trfMemPtr(&disp->mem), size, 
                            flags, &disp->mem.fabric_mr);
    if (ret < 0)
        return ret;

    disp->mem.type      = TRF_MEM_TYPE_LF_MR;
    disp->mem.size      = size;
    disp->fb_offset     = offset;
    return ret;
}

int trfDeregDisplay(PTRFContext ctx, PTRFDisplay disp)
{
    int ret = fi_close(&disp->mem.fabric_mr->fid);
    if (ret == 0)
    {
        disp->mem.fabric_mr = NULL;
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
    struct TRFMem * meta = &f->msg_mem;
    size_t ret;
    ret = trf__FabricRegBuf(f, addr, len, FI_READ | FI_WRITE, &meta->fabric_mr);
    if (ret == 0)
    {
        f->msg_mem.ptr  = addr;
        f->msg_mem.size = len;
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
        if (dealloc)
        {
            if (disp_itm->mem.fabric_mr)
            {
                fi_close(&disp_itm->mem.fabric_mr->fid);
            }
            free(disp_itm->mem.ptr);
        }
        free(disp_itm->name);
        free(disp_itm);
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
    if (!disp)
        return -EINVAL;

    int ret;
    
    if (ctx->type != TRF_EP_SINK && ctx->type != TRF_EP_CONN_ID)
    {
        trf__log_error("This context does not support display sources");
        return -EINVAL;
    }

    struct fid_mr * tmp_mr = NULL;

    disp->mem.ptr = addr;
    ssize_t fb_len = trfGetDisplayBytes(disp);
    if (fb_len < 0)
    {
        trf__log_error("Unable to get display buffer length: %s", 
            strerror(-fb_len));
        return fb_len;
    }

    if (addr)
    {
        uint64_t flags = ctx->type == TRF_EP_SINK ? FI_REMOTE_WRITE : 0;
        ret = fi_mr_reg(ctx->xfer.fabric->domain, addr, fb_len, flags, 0, 0,
            0, &tmp_mr, NULL);
        if (ret)
        {
            trf_fi_error("fi_mr_reg", ret);
            return ret;
        }
    }

    if (disp->mem.fabric_mr)
    {
        ret = fi_close(&disp->mem.fabric_mr->fid);
        if (ret)
        {
            trf_fi_error("fi_close", ret);
            fi_close(&tmp_mr->fid);
            return ret;
        }
    }

    disp->mem.fabric_mr = tmp_mr;
    return 0;
}

/* -------------------------------------------------------------------------- */
/* Session Management Routines                                                */
/* -------------------------------------------------------------------------- */

int trf__CheckSessionID(PTRFContext ctx, uint64_t session)
{
    if (!ctx)
    {
        return -EINVAL;
    }

    PTRFContext * itms = ctx->svr.clients;
    for (int i = 0; i < ctx->svr.max_clients; i++)
    {
        if (itms[i] && itms[i]->cli.session_id == session)
        {
            return i;
        }
    }

    return -1;
}

int trfGetFabricEndpointName(PTRFXFabric ctx, char ** sas_buf)
{
    if (!ctx || !sas_buf)
        return -EINVAL;

    void * sas_tmp;
    size_t sas_len = 0;
    int ret;

    ret = fi_getname(&ctx->ep->fid, NULL, &sas_len);
    if (ret != 0 && ret != -FI_ETOOSMALL)
    {
        trf_fi_error("Get endpoint name length", ret);
        return ret;
    }
    sas_tmp = calloc(1, sas_len);
    if (!sas_tmp)
    {
        trf__log_error("Unable to allocate source address buffer");
        return -ENOMEM;
    }
    ret = fi_getname(&ctx->ep->fid, sas_tmp, &sas_len);
    if (ret)
    {
        trf_fi_error("Get name", ret);
        free(sas_tmp);
        return ret;
    }
    ret = trfSerializeAddress(sas_tmp, trfConvertFabricAF(ctx->addr_fmt),
                              sas_buf);
    if (ret < 0)
    {
        trf__log_error("Unable to serialize address");
        free(sas_tmp);
        return ret;
    }
    free(sas_tmp);
    return 0;
}

int trfGetEndpointName(PTRFContext ctx, char ** sas_buf)
{
    switch (ctx->xfer_type)
    {
        case TRFX_TYPE_LIBFABRIC:
            return trfGetFabricEndpointName(ctx->xfer.fabric, sas_buf);
        case TRFX_TYPE_INVALID:
        case TRFX_TYPE_MAX:
            return -EINVAL;
        default:
            return -ENOSYS;
    }
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
    PTRFXFabric f = ctx->xfer.fabric;
    return trfFabricSendMsg(ctx, &f->msg_mem, trfMemPtr(&f->msg_mem), 
                            trfMemSize(&f->msg_mem), f->peer_addr, ctx->opts,
                            &mw);
}

int trfGetMessageAuto(PTRFContext ctx, uint64_t flags, uint64_t * processed,
    void ** data_out, int * opaque)
{
    if (!ctx || !data_out || !processed)
    {
        return -EINVAL;
    }

    int ret = 0;

    struct timespec tend;
    TrfMsg__MessageWrapper * msg = NULL;

    trfGetDeadline(&tend, ctx->opts->fab_rcv_timeo);
    struct TRFMem * mem = &ctx->xfer.fabric->msg_mem;
    int flag = 0;

    if (!*opaque)
    {
        ret = trfFabricRecvUnchecked(ctx, mem, trfMemPtr(mem),
                                        trfMemSize(mem), 
                                        ctx->xfer.fabric->peer_addr);
        if (ret < 0)
        {
            trf__log_error("Unable to receive message: %s", strerror(-ret));
            return ret;
        }

        *opaque = 1;
    }
    
    struct fi_cq_data_entry de;
    struct fi_cq_err_entry err;

    while (1)
    {
        ret = trfNCPollMsg(ctx->cli.client_fd);
        if (ret > 0)
        {
            flag = 1;
            break;
        }
        else if (ret < 0 && ret != -EAGAIN)
        {
            trf__log_error("Receive error (control): %s", strerror(-ret));
            break;
        }

        ret = trfFabricPollRecv(ctx, &de, &err, ctx->opts->fab_cq_sync,
                                ctx->opts->fab_poll_rate, NULL, 1);
        if (ret < 0 && ret != -FI_EAGAIN)
        {
            trf__log_error("Receive error (fabric): %s", fi_strerror(-ret));
            break;
        }
        if (ret == 1)
        {
            *opaque = 0;
            flag = 2;
            break;
        }
        trfSleep(ctx->opts->fab_poll_rate);
    }

    switch (flag)
    {
        case 0:
            return -ETIMEDOUT;
        case 1:
            ret = trfNCRecvMsg(ctx->cli.client_fd, trfMemPtr(mem),
                               trfMemSize(mem), ctx->opts->nc_rcv_timeo, &msg);
            if (ret < 0)
            {
                trf__log_error("Unable to unpack message (NC): %s",
                               strerror(-ret));
                return ret;
            }
            break;
        case 2:
            ret = trfMsgUnpack(&msg, trfMsgGetPackedLength(trfMemPtr(mem)), 
                       trfMsgGetPayload(trfMemPtr(mem)));
            if (ret < 0)
            {
                trf__log_error("Unable to unpack message (fabric): %s",
                               strerror(-ret));
                return ret;
            }
            break;
        default:
            return ret < 0 ? ret : -EIO;
    }

    trf__log_trace("Message Type: %d", msg->wdata_case);

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

    struct TRFMem * mem = &ctx->xfer.fabric->msg_mem;
    ret = trfFabricSendMsg(ctx, mem, trfMemPtr(mem), trfMemSize(mem),
                           ctx->xfer.fabric->peer_addr, ctx->opts, mw);
    trf__log_trace("Sent client request over fabric");

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
    struct TRFMem * mem = &ctx->xfer.fabric->msg_mem;
    return trfFabricSendMsg(ctx, mem, trfMemPtr(mem), trfMemSize(mem),
                            ctx->xfer.fabric->peer_addr, ctx->opts, &mw);
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
    struct TRFMem * mem = &ctx->xfer.fabric->msg_mem;
    ret = trfFabricSendMsg(ctx, mem, trfMemPtr(mem), trfMemSize(mem),
                           ctx->xfer.fabric->peer_addr, ctx->opts, msg);
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
    struct TRFMem * mem = &ctx->xfer.fabric->msg_mem;
    ret = trfFabricSendMsg(ctx, mem, trfMemPtr(mem), trfMemSize(mem),
                           ctx->xfer.fabric->peer_addr, ctx->opts, msg);
    if (ret < 0)
    {
        trf__log_error("Unable to send data");
        goto free_msg;
    }

    trf__log_trace("Display request cookie sent");
    trf_msg__message_wrapper__free_unpacked(msg, NULL);
    msg = NULL;

    ret = trfFabricRecvMsg(ctx, mem, trfMemPtr(mem), trfMemSize(mem),
                           ctx->xfer.fabric->peer_addr, ctx->opts, &msg);
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

int trfAckFrameReq(PTRFContext ctx, PTRFDisplay display)
{
    int ret;
    TrfMsg__MessageWrapper msg = TRF_MSG__MESSAGE_WRAPPER__INIT;
    TrfMsg__ServerAckFReq ack = TRF_MSG__SERVER_ACK_FREQ__INIT;
    msg.wdata_case  = trfInternalToPB(TRFM_SERVER_ACK_F_REQ);
    msg.server_ack_f_req = &ack;
    ack.id = display->id;
    ack.frame_cntr = display->frame_cntr;
    struct TRFMem * mem = &ctx->xfer.fabric->msg_mem;
    trf__log_trace("Sending message: mem ptr: %p, size: %lu", trfMemPtr(mem), trfMemSize(mem));
    ret = trfFabricSendMsg(ctx, mem, trfMemPtr(mem), trfMemSize(mem),
                           ctx->xfer.fabric->peer_addr, ctx->opts, &msg);
    if (ret < 0)
    {
        trf__log_error("Unable to send data");
    }
    return ret;
}

ssize_t trfRecvFrame(PTRFContext ctx, PTRFDisplay disp)
{
    PTRFXFabric f       = ctx->xfer.fabric;
    PTRFMem msg_mem     = &ctx->xfer.fabric->msg_mem;

    TrfMsg__MessageWrapper mw   = TRF_MSG__MESSAGE_WRAPPER__INIT;
    TrfMsg__ClientFReq fr       = TRF_MSG__CLIENT_FREQ__INIT;
    mw.wdata_case               = trfInternalToPB(TRFM_CLIENT_F_REQ);
    mw.client_f_req             = &fr;
    fr.id                       = disp->id;
    fr.addr                     = (uint64_t) trfGetFBPtr(disp);
    fr.rkey                     = trfMemFabricKey(&disp->mem);
    fr.frame_cntr               = disp->frame_cntr;

    ssize_t ret = trfFabricSendMsg(ctx, msg_mem, trfMemPtr(msg_mem), 
                                   trfMemSize(msg_mem), f->peer_addr, ctx->opts,
                                   &mw);
    if (ret < 0)
    {
        trf__log_error("Unable to send frame request");
        return ret;
    }
    
    ret = trfFabricRecvUnchecked(ctx, msg_mem, trfMemPtr(msg_mem),
                                 trfMemSize(msg_mem), f->peer_addr);
    if (ret < 0)
    {
        trf__log_error("Unable to post receive request");
        return ret;
    }

    return 0;
}

// ssize_t trfSendFramePart(PTRFContext ctx, PTRFDisplay disp, uint64_t rbuf,
//     uint64_t rkey, struct TRFRect * rects, size_t num_rects)
// {
//     if (!ctx || !disp || !rects || num_rects == 0)
//     {
//         return -EINVAL;
//     }
    
//     // Shorten access
//     PTRFXFabric f = ctx->xfer.fabric;

//     // Compressed texture formats are not directly pixel addressable and require
//     // special handling - for now, we'll just ignore them
//     if (trfTextureIsCompressed(disp->format))
//     {
//         return -ENOTSUP;
//     }

//     // Allocate iovec for posting frame updates
//     ssize_t ret;
//     size_t max_iov = f->fi->tx_attr->rma_iov_limit;
//     struct iovec * iov = malloc(sizeof(struct iovec) * max_iov);
//     if (!iov)
//     {
//         return -ENOMEM;
//     }

//     // Since all the memory indirectly referenced by the rectangles should be in
//     // the same MR, we just need to set the MR descriptor to be the same across
//     // all items in the description array
//     void ** desc = malloc(sizeof(void *) * max_iov);
//     for (int i = 0; i < max_iov; i++)
//     {
//         desc[i] = fi_mr_desc(&disp->mem.fabric_mr);
//     }

//     trf__log_debug("Display: %d x %d", disp->width, disp->height);

//     // Framebuffer line pitch
//     int32_t lpitch = trfGetTextureBytes(disp->width, 1, disp->format);
//     // Pixel pitch in bytes
//     int32_t ppitch = trfGetTextureBytes(1, 1, disp->format);

//     if (lpitch < 0)
//     {
//         free(iov);
//         free(desc);
//         return lpitch;
//     }
//     if (ppitch < 0)
//     {
//         free(iov);
//         free(desc);
//         return ppitch;
//     }
    
//     // Determine how many CQEs we will need to use to track this operation
//     size_t num_cqe = 0;
//     for (int i = 0; i < num_rects; i++)
//     {
//         // Some rudimentary error checking
//         if (rects[i].x + rects[i].width > disp->width
//             || rects[i].y + rects[i].height > disp->height)
//         {
//             trf__log_error("Invalid rectangle! Pos: %d, %d Size: %d, %d", 
//                 rects[i].x, rects[i].y, rects[i].width, rects[i].height);
//             return -EINVAL;
//         }
//         if (rects[i].x == 0 && rects[i].width == disp->width)
//         {
//             // Rectangles that span the entire width of the frame can be sent
//             // as a single RMA operation
//             num_cqe++;
//         }
//         else
//         {
//             // Otherwise we can send a vectored RMA for up to max_iov lines
//             num_cqe += rects[i].height / max_iov;
//         }
//     }

//     // The operation will never succeed if our max CQE count is exceeded -
//     // caller must optimize accesses before retrying
//     if (num_cqe > f->fi->tx_attr->size)
//     {
//         trf__log_error("Write operation exceeds max CQE count");
//         return -E2BIG;
//     }

//     // There may also be other operations in progress that have consumed CQEs
//     size_t rem_cqe = trf__DecrementCQ(f->tx_cq, num_cqe);
//     if (rem_cqe < num_cqe)
//         return -EAGAIN;

//     size_t iter = 0;
//     for (int i = 0; i < num_rects; i++)
//     {
//         // Get offset in framebuffer to rectangle
//         size_t offset = lpitch * rects[i].y + ppitch * rects[i].x;
//         // Rectangle line pitch
//         uint32_t rpitch = ppitch * rects[i].width;

//         trf__log_debug("Damage update rect: %d,%d %dx%d", 
//                        rects[i].x, rects[i].y, rects[i].width, rects[i].height);
//         trf__log_debug("lpitch: %d, ppitch: %d, offset: %lu, rpitch: %d",
//                        lpitch, ppitch, offset, rpitch);

//         // Full-width update mode
//         if (rects[i].x == 0 && rects[i].width == disp->width)
//         {
//             // Calculate contiguous region length
//             ssize_t rlen = trfGetTextureBytes(rects[i].width, rects[i].height, 
//                                              disp->format);
//             // The region length was invalid
//             if (rlen < 0)
//             {
//                 goto try_recover;
//             }

//             // Post RMA write
//             ret = fi_write(ctx->xfer.fabric->ep, 
//                            trfMemPtr(&disp->mem) + offset, (size_t) rlen, 
//                            disp->mem.fabric_mr, ctx->xfer.fabric->peer_addr, 
//                            rbuf + offset, rkey, (void *) iter);
//             if (ret < 0)
//             {
//                 goto try_recover;
//             }
//             iter++;
//             continue;
//         }

//         // Vector update mode
//         size_t total = rects[i].height;
//         while (total)
//         {
//             // Split rectangle into max_iov lines
//             size_t iov_l = total > max_iov ? max_iov : total;
//             for (int j = 0; j < iov_l; j++)
//             {
//                 iov[j].iov_base = trfMemPtr(&disp->mem) + offset;
//                 iov[j].iov_len  = rpitch;
//             }
            
//             // Perform RMA write
//             ret = fi_writev(ctx->xfer.fabric->ep, iov, desc, max_iov,
//                             ctx->xfer.fabric->peer_addr, rbuf, rkey, 
//                             (void *) iter);
//             if (ret < 0)
//             {
//                 goto try_recover;
//             }

//             // Update total and request count
//             total -= iov_l;
//             iter++;
//         }
//     }

//     // Return the number of submitted events
//     free(iov);
//     free(desc);
//     return iter;

// try_recover:
//     trf__log_error("Unable to perform RMA write # %d. fi_writev "
//         "returned: %s. Attempting to recover", iter, fi_strerror(-ret));
//     // Release the unused CQEs immediately then try to reclaim the rest by
//     // monitoring progress.
//     trf__IncrementCQ(f->tx_cq, num_cqe - iter);
//     while (iter)
//     {
//         struct fi_cq_data_entry de;
//         struct fi_cq_err_entry err;
//         ssize_t ret2 = trfGetSendProgress(ctx, &de, &err, 1);
//         if (ret2 < 0)
//         {
//             trf__log_error("Unable to recover: %s", 
//                 trf__FabricGetCQErrString(ctx->xfer.fabric->tx_cq->cq, &err));
//             trf__log_error("Context should be considered invalid");
//             free(iov);
//             free(desc);
//             return ret2;
//         }
//         trf__IncrementCQ(ctx->xfer.fabric->tx_cq, 1);
//         iter--;
//     }
//     return ret;
// }

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
    void * sptr = (void *) ((uintptr_t) trfGetFBPtr(disp) + (uintptr_t) start);

    trf__DecrementCQ(f->tx_cq, 1);
    ssize_t ret;
    ret = fi_write(f->ep, sptr, end - start, trfMemFabricDesc(&disp->mem), 
                   f->peer_addr, rbuf, rkey, NULL);
    if (ret < 0)
    {
        trf__IncrementCQ(f->tx_cq, 1);
    }
    return ret;
}

ssize_t trfGetSendProgress(PTRFContext ctx, struct fi_cq_data_entry * de,
                           struct fi_cq_err_entry * err, size_t count,
                           PTRFContextOpts opts)
{
    PTRFContextOpts o = opts ? opts : ctx->opts;
    ssize_t ret;
    struct timespec deadline;
    ret = trfGetDeadline(&deadline, o->fab_snd_timeo);
    if (ret < 0)
        return ret;

    return trfFabricPollSend(ctx, de, err, o->fab_cq_sync, o->fab_poll_rate,
                             &deadline, count);
}

ssize_t trfGetRecvProgress(PTRFContext ctx, struct fi_cq_data_entry * de,
                           struct fi_cq_err_entry * err, size_t count,
                           PTRFContextOpts opts)
{
    PTRFContextOpts o = opts ? opts : ctx->opts;
    ssize_t ret;
    struct timespec deadline;
    ret = trfGetDeadline(&deadline, o->fab_rcv_timeo);
    if (ret < 0)
        return ret;

    return trfFabricPollRecv(ctx, de, err, o->fab_cq_sync, o->fab_poll_rate,
                             &deadline, count);
}