/*
    SPDX-License-Identifier: LGPL-2.1-only

    Telescope Project
    Remote Framebuffer Library
    Negotiation Channel Protocol

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

#include "internal/trfi_ncp_client.h"

int trf__NCCreateClientSocket(const char * host, const char * port,
                              TRFSock * fd)
{
    struct addrinfo hints;
    struct addrinfo * res = NULL;
    TRFSock sfd = TRFInvalidSock;
    int ret;

    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_family     = AF_UNSPEC;
    hints.ai_socktype   = SOCK_STREAM;
    hints.ai_flags      = 0;

    ret = getaddrinfo(host, port, &hints, &res);
    if (ret != 0)
    {
        trf__log_error("Client init: getaddrinfo() failed: %s",
            gai_strerror(ret));
        return -ret;
    }

    struct addrinfo * res_p;

    for (res_p = res; res_p; res_p = res_p->ai_next)
    {
        trf__log_debug("Trying connection...");
        sfd = socket(res_p->ai_family, res_p->ai_socktype, res_p->ai_protocol);
        if (!trfSockValid(sfd))
        {
            continue;
        }

        ret = connect(sfd, res_p->ai_addr, res_p->ai_addrlen);
        if (ret == 0)
        {
            break;
        }
    }

    if (!trfSockValid(sfd))
    {
        trf__log_error("Failed to connect to %s:%s", host, port);
        return -1;
    }

    * fd = sfd;

    return 0;
}


int trf__NCSendClientHello(PTRFContext ctx, uint8_t * buffer, size_t size)
{
    TrfMsg__MessageWrapper mw   = TRF_MSG__MESSAGE_WRAPPER__INIT;
    TrfMsg__ClientHello ch      = TRF_MSG__CLIENT_HELLO__INIT;
    TrfMsg__APIVersion av       = TRF_MSG__APIVERSION__INIT;
    
    mw.wdata_case   = TRF_MSG__MESSAGE_WRAPPER__WDATA_CLIENT_HELLO;
    mw.client_hello = &ch;
    ch.version      = &av;
    av.api_major    = TRF_API_MAJOR;
    av.api_minor    = TRF_API_MINOR;
    av.api_patch    = TRF_API_PATCH;

    size_t m_size = trf_msg__message_wrapper__get_packed_size(&mw);
    if (m_size > trf__Min(size, trfPBMaxSize))
        return -E2BIG;

    uint8_t * buf = buffer ? buffer : malloc(m_size);
    if (!buf)
        return -ENOMEM;

    int ret = trfNCSendDelimited(ctx->cli.client_fd, buf, 
                                 ctx->opts->nc_snd_bufsize, 
                                 ctx->opts->nc_snd_timeo, &mw);

    if (!buffer)
        free(buf);

    return ret;
}


int trf__NCRecvServerHello(PTRFContext ctx, uint8_t * buffer, size_t size,
                           TrfMsg__MessageWrapper ** out)
{
    int ret;
    size_t bufsize = trf__Min(size, ctx->opts->nc_rcv_bufsize);
    ret = trfNCRecvDelimited(trf__ClientFD(ctx), buffer, bufsize, 
                             ctx->opts->nc_rcv_timeo, out);
    if (ret < 0)
    {
        trf__log_trace("Receive failed: %s", strerror(-ret));
        return ret;
    }
    
    if ((*out)->wdata_case != TRF_MSG__MESSAGE_WRAPPER__WDATA_SERVER_HELLO
        && (*out)->wdata_case != TRF_MSG__MESSAGE_WRAPPER__WDATA_SERVER_REJECT)
    {
        trf__log_trace("Invalid message type %d in buffer", (*out)->wdata_case);
        trf_msg__message_wrapper__free_unpacked(*out, NULL);
        return -EBADMSG;
    }

    return 0;
}


int trf__NCSendInterfaceList(PTRFContext ctx, uint8_t * buffer, size_t size,
                             uint64_t flags)
{
    int ret;
    uint32_t num_ifs;
    PTRFInterface client_ifs = NULL;
    ret = trfGetInterfaceList(&client_ifs, &num_ifs, ctx->opts->iface_flags);
    if (ret < 0)
        return ret;
    
    trf__log_debug("Interfaces found: %d", num_ifs);

    char temp[TRFX_MAX_STR];
    for (PTRFInterface tmp = client_ifs; tmp; tmp = tmp->next)
    {
        trfGetIPaddr(tmp->addr, temp);
        trf__log_trace("Found Interface: %s", temp);
    }


    TrfMsg__MessageWrapper mw   = TRF_MSG__MESSAGE_WRAPPER__INIT;
    TrfMsg__AddrPF apf          = TRF_MSG__ADDR_PF__INIT;
    mw.wdata_case               = TRF_MSG__MESSAGE_WRAPPER__WDATA_ADDR_PF;
    mw.addr_pf                  = &apf;
    apf.n_addrs                 = num_ifs;
    apf.addrs                   = malloc(sizeof(TrfMsg__AddrCand) * num_ifs);
    if (!apf.addrs)
    {
        ret = -ENOMEM;
        goto free_ci_list;
    }

    int i = 0;
    char addr[INET6_ADDRSTRLEN];
    for (PTRFInterface tmp_if = client_ifs; tmp_if; tmp_if = tmp_if->next)
    {
        memset(addr, 0, INET6_ADDRSTRLEN);
        apf.addrs[i] = calloc(1, sizeof(TrfMsg__AddrCand));
        if (!apf.addrs[i])
        {
            trf__log_error("Memory allocation failed");
            goto free_cands;
        }
        trf_msg__addr_cand__init(apf.addrs[i]);
        if (trfGetIPaddr(tmp_if->addr, addr) < 0)
        {
            trf__log_error("IP address serialization failed");
            continue;
        }
        apf.addrs[i]->addr    = strdup(addr);
        apf.addrs[i]->speed   = tmp_if->speed;
        apf.addrs[i]->netmask = tmp_if->netmask;
        i++;
    }

    mw.wdata_case = TRF_MSG__MESSAGE_WRAPPER__WDATA_ADDR_PF;
    mw.session_id = ctx->cli.session_id;

    size_t m_size = trf_msg__message_wrapper__get_packed_size(&mw);
    if (m_size > trf__Min(size, trfPBMaxSize))
    {
        ret = -E2BIG;
        goto free_cands;
    }

    uint8_t * buf = buffer ? buffer : malloc(m_size);
    if (!buf)
    {
        ret = -ENOMEM;
        goto free_cands;
    }

    ret = trfNCSendDelimited(ctx->cli.client_fd, buf, 
                                 ctx->opts->nc_snd_bufsize, 
                                 ctx->opts->nc_snd_timeo, &mw);

    if (!buffer)
        free(buf);

    i--;

free_cands:
    for (int j = i; j >= 0; j--) {
        if (apf.addrs[j])
        {
            free(apf.addrs[j]->addr);
            free(apf.addrs[j]);
        }
    }
    free(apf.addrs);
free_ci_list:
    trfFreeInterfaceList(client_ifs);
    return ret;
}


int trf__NCRecvServerAddrs(PTRFContext ctx, uint8_t * buffer, size_t size,
                           PTRFInterface * out)
{
    int ret;
    size_t bufsize = trf__Min(size, ctx->opts->nc_rcv_bufsize);
    TrfMsg__MessageWrapper * mw = NULL;
    ret = trfNCRecvDelimited(trf__ClientFD(ctx), buffer, bufsize, 
                             ctx->opts->nc_rcv_timeo, &mw);
    if (ret < 0)
        return ret;

    if (mw->wdata_case != TRF_MSG__MESSAGE_WRAPPER__WDATA_ADDR_PF)
    {
        ret = -EBADMSG;
        goto free_msg;
    }

    if (mw->addr_pf->n_addrs == 0)
    {
        ret = -ENOENT;
        goto free_msg;
    }

    PTRFInterface ifs = NULL;
    ret = trf__AddrMsgToInterface(mw, &ifs);
    if (ret < 0)
        goto free_msg;

    *out = ifs;
    ret = 0;
    goto free_msg;

free_msg:
    trf_msg__message_wrapper__free_unpacked(mw, NULL);
    return ret;
}


int trf__NCSendClientTransports(PTRFContext ctx, PTRFInterface dests, 
                                uint8_t * buffer, size_t size)
{
    int ret;
    int dests_len = trfGetInterfaceListLength(dests);
    if (dests_len < 0)
    {
        trf__log_error("Failed to get interface list length");
        return -EINVAL;
    }

    struct fi_info ** fi_list = calloc(dests_len, sizeof(struct fi_info *));
    if (!fi_list)
    {
        trf__log_error("Failed to allocate fi_info list");
        return -ENOMEM;
    }

    // Get the list of all fabric providers

    int valid       = 0;
    int num_fabrics = 0;
    for (PTRFInterface dests_tmp = dests; dests_tmp;
         dests_tmp = dests_tmp->next)
    {
        char addr[INET6_ADDRSTRLEN];
        memset(addr, 0, INET6_ADDRSTRLEN);
        ret = trfGetIPaddr(dests_tmp->addr, addr);
        if (ret < 0)
        {
            trf__log_error("Address decode failed");
            continue;
        }
        ret = trfGetFabricProviders(addr, "0", TRF_EP_SINK, &fi_list[valid]);
        if (ret < 0)
        {
            continue;
        }
        for (struct fi_info * fi_node = fi_list[valid]; fi_node; 
             fi_node = fi_node->next)
        {
            num_fabrics++;
        }
        valid++;
    }

    if (!valid)
    {
        trf__log_error("No valid fabric providers found");
        ret = -ENODATA;
        goto free_fi_list;
    }

    TrfMsg__MessageWrapper mw   = TRF_MSG__MESSAGE_WRAPPER__INIT;
    TrfMsg__ClientCap cc        = TRF_MSG__CLIENT_CAP__INIT;
    mw.wdata_case               = TRF_MSG__MESSAGE_WRAPPER__WDATA_CLIENT_CAP;
    mw.session_id               = ctx->cli.session_id;
    mw.client_cap               = &cc;
    cc.n_transports             = num_fabrics;
    cc.transports               = calloc(num_fabrics, sizeof(TrfMsg__Transport));
    
    int i = 0;
    int j = 0;
    valid = 0;

    // Serialize address list for transmission

    for (PTRFInterface dests_tmp = dests; dests_tmp;
         dests_tmp = dests_tmp->next)
    {
        for (struct fi_info * fi_node = fi_list[i]; fi_node;
             fi_node = fi_node->next)
        {
            if (!cc.transports[j])
            {
                cc.transports[j] = calloc(1, sizeof(TrfMsg__Transport));
                if (!cc.transports[j])
                {
                    trf__log_error("Failed to allocate transport");
                    ret = -ENOMEM;
                    goto free_transports;
                }
                trf_msg__transport__init(cc.transports[j]);
            }
            cc.transports[j]->name = trfStrdup(fi_node->fabric_attr->prov_name);
            if (!cc.transports[j]->name)
            {
                trf__log_error("Failed to allocate transport name");
                ret = -ENOMEM;
                goto free_transports;
            }
            ret = trfSerializeWireProto(fi_node->ep_attr->protocol, 
                                        &cc.transports[j]->proto);
            if (ret)
            {
                trf__log_error("Unable to serialize wire protocol");
                continue;
            }
            int fmt = trfConvertFabricAF(fi_node->addr_format);
            if (fmt < 0)
            {
                trf__log_error("Unable to convert fabric address format");
                free(cc.transports[j]->proto);
                continue;
            }
            if (fi_node->src_addr)
            {
                ret = trfSerializeAddress(fi_node->src_addr, fmt,
                                          &cc.transports[j]->src);
                if (ret < 0)
                {
                    trf__log_error("Unable to serialize destination address");
                    free(cc.transports[j]->proto);
                    continue;
                }
            }
            if (fi_node->dest_addr)
            {
                ret = trfSerializeAddress(fi_node->dest_addr, fmt,
                                          &cc.transports[j]->dest);
                if (ret < 0)
                {
                    trf__log_error("Unable to serialize destination address");
                    free(cc.transports[j]->src);
                    free(cc.transports[j]->proto);
                    continue;
                }
            }
            else
            {
                int dfmt = TRFX_ADDR_INVALID;
                switch (dests_tmp->addr->sa_family)
                {
                    case AF_INET:
                        dfmt = TRFX_ADDR_SOCKADDR_IN;
                        break;
                    case AF_INET6:
                        dfmt = TRFX_ADDR_SOCKADDR_IN6;
                        break;
                    default:
                        trf__log_error("Unsupported address family");
                        free(cc.transports[j]->dest);
                        free(cc.transports[j]->src);
                        free(cc.transports[j]->proto);
                        continue;
                }
                ret = trfSerializeAddress(dests_tmp->addr, dfmt,
                                          &cc.transports[j]->dest);
                if (ret < 0)
                {
                    trf__log_error("Unable to serialize destination address");
                    free(cc.transports[j]->dest);
                    free(cc.transports[j]->src);
                    free(cc.transports[j]->proto);
                    continue;
                }
            }
            j++;
        }
        if (++i >= num_fabrics)
        {
            break;
        }
    }

    // Free fi_info list
    for (i = 0; i < dests_len; i++)
    {
        if (fi_list[i])
        {
            fi_freeinfo(fi_list[i]);
        }
    }
    free(fi_list);

    // We may have skipped some transports due to serialization errors
    cc.n_transports = j;

    // Send the data
    size_t m_size = trf_msg__message_wrapper__get_packed_size(&mw);
    if (m_size > trf__Min(size, trfPBMaxSize))
        return -E2BIG;

    uint8_t * buf = buffer ? buffer : malloc(m_size);
    if (!buf)
        return -ENOMEM;

    ret = trfNCSendDelimited(ctx->cli.client_fd, buf, 
                             ctx->opts->nc_snd_bufsize, 
                             ctx->opts->nc_snd_timeo, &mw);

    if (!buffer)
        free(buf);

    return 0;

free_transports:
    while (j)
    {
        if (cc.transports[j])
        {
            free(cc.transports[j]->proto);
            free(cc.transports[j]->src);
            free(cc.transports[j]->dest);
            free(cc.transports[j]);
        }
        j--;
    }
free_fi_list:
    for (i = 0; i < dests_len; i++)
    {
        if (fi_list[i])
        {
            fi_freeinfo(fi_list[i]);
        }
    }
    free(fi_list);
    return ret;
}


int trf__NCRecvAndTestCandidate(PTRFContext ctx, uint8_t * buffer, size_t size)
{
    if (!ctx)
        return -EINVAL;

    TrfMsg__MessageWrapper * mw = NULL;
    struct fi_info * fii        = NULL;

    size_t bufsize = trf__Min(size, ctx->opts->nc_rcv_bufsize);
    int ret = trfNCRecvDelimited(trf__ClientFD(ctx), buffer, bufsize,
                                 ctx->opts->nc_rcv_timeo, &mw);
    if (ret < 0)
    {
        trf__log_error("Failed to receive message");
        return ret;
    }

    if (mw->wdata_case != TRF_MSG__MESSAGE_WRAPPER__WDATA_SERVER_CAP)
    {
        trf__log_error("Invalid message type");
        trf_msg__message_wrapper__free_unpacked(mw, NULL);
        return -EINVAL;
    }

    if (!mw->server_cap->transport)
    {
        trf__log_error("Server ran out of transport candidates");
        trf_msg__message_wrapper__free_unpacked(mw, NULL);
        return -ENOENT;
    }

    trf__log_debug("Bind address: %s", mw->server_cap->bind_addr);
    trf__log_info("Candidate transport %s @ %s", 
        mw->server_cap->transport->name, mw->server_cap->transport->src);

    ret = trfGetRoute(mw->server_cap->transport->src,
                      mw->server_cap->transport->name, 
                      mw->server_cap->transport->proto, &fii);
    if (ret < 0)
    {
        trf__log_error("Failed to get route");
        goto free_msg;
    }

    // If the server provided a bind address, we will try to use it

    struct sockaddr_in6 bind_addr;
    bind_addr.sin6_family = AF_UNSPEC;
    if (trf__ProtoStringValid(mw->server_cap->bind_addr) &&
        strnlen(mw->server_cap->bind_addr, INET6_ADDRSTRLEN + 1) 
        < INET6_ADDRSTRLEN + 1)
    {
        ret = trfConvertCharToAddr(mw->server_cap->bind_addr, 
                                   (struct sockaddr *) &bind_addr);
        if (ret < 0)
        {
            trf__log_error("Failed to convert bind address");
        }
    }

    // We only want the first transport in the list so free all the other ones
    // that Libfabric may have provided us with

    if (fii->next)
    {
        struct fi_info * tmp = fii->next;
        fii->next = NULL;
        fi_freeinfo(tmp);
    }

    // Next try to create the endpoint

    if (bind_addr.sin6_family != AF_UNSPEC)
    {
        ret = trfCreateChannel(ctx, fii, &bind_addr, size);
    }
    else
    {
        ret = trfCreateChannel(ctx, fii, NULL, 0);
    }
    if (ret < 0)
    {
        trf__log_error("Failed to create channel");
        goto free_fi;
    }

    // Once we did that we need to register a message buffer

    size_t s = trf__Max(ctx->opts->fab_rcv_bufsize, ctx->opts->fab_snd_bufsize);
    void * fabric_buf = trfAllocAligned(s, trf__GetPageSize());
    if (!fabric_buf)
    {
        trf__log_error("Failed to allocate fabric buffer");
        ret = -ENOMEM;
        goto close_conn;
    }

    ret = trfRegInternalMsgBuf(ctx, fabric_buf, s);
    if (ret < 0)
    {
        trf__log_error("Failed to register internal message buffer");
        goto close_conn;
    }
    ctx->xfer.fabric->msg_ptr = fabric_buf;

    // Once we have created the endpoint, we'll need to:
    // - Send the endpoint details via the regular NCP channel
    // - Send our session ID via the fabric channel

    fi_addr_t lf_addr;
    ret = trfInsertAVSerialized(ctx->xfer.fabric, 
                                mw->server_cap->transport->src, &lf_addr);
    if (ret < 0)
    {
        trf__log_error("Could not insert peer address into AV");
        goto close_conn;
    }
    ctx->xfer.fabric->peer_addr = lf_addr;

    // Construct and send the newly created endpoint details

    char * ep_name = NULL;
    char * tpt_name = NULL;
    char * proto_name = NULL;
    ret = trfGetEndpointName(ctx, &ep_name);
    if (ret < 0 || !ep_name)
    {
        trf__log_error("Failed to get endpoint name");
        goto free_ep_strs;
    }

    tpt_name = strdup(fii->fabric_attr->prov_name);
    if (!tpt_name)
    {
        trf__log_error("Failed to allocate transport provider name");
        ret = -ENOMEM;
        goto free_ep_strs;
    }

    proto_name = strdup(mw->server_cap->transport->proto);
    if (!proto_name)
    {
        trf__log_error("Failed to allocate protocol name");
        ret = -ENOMEM;
        goto free_ep_strs;
    }

    trf_msg__message_wrapper__free_unpacked(mw, NULL);
    mw = malloc(sizeof(TrfMsg__MessageWrapper));
    if (!mw)
    {
        trf__log_error("Could not allocate response message data");
        ret = -ENOMEM;
        goto free_ep_strs;
    }
    trf_msg__message_wrapper__init(mw);
    mw->wdata_case = TRF_MSG__MESSAGE_WRAPPER__WDATA_ENDPOINT;
    mw->endpoint = malloc(sizeof(TrfMsg__Endpoint));
    if (!mw->endpoint)
    {
        trf__log_error("Could not allocate response message data");
        ret = -ENOMEM;
        goto free_ep_strs;
    }
    trf_msg__endpoint__init(mw->endpoint);
    mw->endpoint->transport = malloc(sizeof(TrfMsg__Transport));
    if (!mw->endpoint->transport)
    {
        trf__log_error("Could not allocate response message data");
        ret = -ENOMEM;
        goto free_ep_strs;
    }
    trf_msg__transport__init(mw->endpoint->transport);
    mw->endpoint->transport->name  = tpt_name;
    mw->endpoint->transport->src   = ep_name;
    mw->endpoint->transport->proto = proto_name;

    ret = trfNCSendDelimited(trf__ClientFD(ctx), fabric_buf, s, 
                             ctx->opts->fab_snd_timeo, mw);
    if (ret < 0)
    {
        trf__log_error("Unable to send endpoint info via negotiation channel");
        goto free_ep_strs;
    }

    // This should also free tpt_name, ep_name, proto_name
    trf_msg__message_wrapper__free_unpacked(mw, NULL);
    mw = NULL;

    // Send the session ID over the fabric interface

    uint64_t session_id_be64 = htobe64(ctx->cli.session_id);
    memcpy(ctx->xfer.fabric->msg_ptr, &session_id_be64,
           sizeof(session_id_be64));

    struct timespec ts = {0};
    struct timespec dl = {0};
    ret = clock_gettime(CLOCK_MONOTONIC, &ts);
    if (ret < 0)
    {
        trf__log_error("System clock error! "
                       "Other TRF API calls are likely to fail!");
        goto free_ep_strs;
    }
    trf__GetDelay(&ts, &dl, ctx->opts->fab_snd_timeo);

    ret = trf__FabricPostSend(ctx, sizeof(uint64_t), lf_addr, &dl);
    if (ret < 0)
    {
        trf_fi_error("trf__FabricPostSend", ret);
        goto close_conn;
    }

    // Check whether the message was sent, or a timeout occurred

    struct fi_cq_data_entry cqe;
    struct fi_cq_err_entry err;
    do {
        ret = fi_cq_read(ctx->xfer.fabric->tx_cq->cq, &cqe, 1);
        if (ret == -FI_EAVAIL)
        {
            ret = fi_cq_readerr(ctx->xfer.fabric->tx_cq->cq, &err, 0);
            if (ret < 0)
            {
                trf_fi_error("fi_cq_readerr", ret);
            }
            trf_fi_error("fi_cq_read", ret);
        }
    } while (ret == -FI_EAGAIN);
    
    trf__log_debug("Sent session cookie to server, waiting for response...");

    // The server should echo back our session ID before the timeout

    ret = clock_gettime(CLOCK_MONOTONIC, &ts);
    if (ret < 0)
    {
        trf__log_error("System clock error! "
                       "Other TRF API calls are likely to fail!");
        goto free_ep_strs;
    }
    trf__GetDelay(&ts, &dl, ctx->opts->fab_rcv_timeo);
    memset(ctx->xfer.fabric->msg_ptr, 0, sizeof(session_id_be64));


    ret = trf__FabricPostRecv(ctx, FI_ADDR_UNSPEC, &dl);
    if (ret < 0)
    {
        trf_fi_error("trf__FabricPostRecv", ret);
        goto close_conn;
    }

    do {
        ret = fi_cq_read(ctx->xfer.fabric->rx_cq->cq, &cqe, 1);
        if (ret == -FI_EAVAIL)
        {
            ret = fi_cq_readerr(ctx->xfer.fabric->rx_cq->cq, &err, 0);
            if (ret < 0)
            {
                trf_fi_error("fi_cq_readerr", ret);
            }
            trf_fi_error("fi_cq_read", ret);
        }
    } while (ret == -FI_EAGAIN);

    if (* (uint64_t *) fabric_buf != session_id_be64)
    {
        trf__log_error("Server echoed back incorrect session ID %lu "
                       "instead of %lu", be64toh(* (uint64_t *) fabric_buf),
                        be64toh(session_id_be64));
        ret = -EBADMSG;
        goto close_conn;
    }

    ctx->xfer.fabric->fi = fii;

    return 0;

free_ep_strs:
    free(ep_name);
    free(tpt_name);
    free(proto_name);
close_conn:
    trfDestroyFabricContext(ctx);
    fabric_buf = NULL;
free_fi:
    fi_freeinfo(fii);
    fii = NULL;
free_msg:
    trf_msg__message_wrapper__free_unpacked(mw, NULL);
    return ret;
}

