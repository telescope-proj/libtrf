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

#include "internal/trfi_ncp_server.h"

int trf__NCServerCreateSocket(const char * host, const char * port,
                              TRFSock * sock)
{
    struct addrinfo hints;
    struct addrinfo * res = NULL;
    int ret;

    TRFSock sfd = TRFInvalidSock;

    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_family     = AF_UNSPEC;
    hints.ai_socktype   = SOCK_STREAM;
    hints.ai_flags      = AI_PASSIVE;

    ret = getaddrinfo(host, port, &hints, &res);
    if (ret != 0)
    {
        trf__log_error("getaddrinfo() failed: %s", gai_strerror(ret));
        return -ret;
    }

    trf__log_trace("getaddrinfo() completed");

    struct addrinfo * res_p;

    for (res_p = res; res_p != NULL; res_p = res_p->ai_next)
    {
        sfd = socket(res_p->ai_family, res_p->ai_socktype, res_p->ai_protocol);
        if (!trfSockValid(sfd))
        {
            continue;
        }
        ret = bind(sfd, res_p->ai_addr, res_p->ai_addrlen);
        if (ret == 0)
        {
            break;
        }
    }

    freeaddrinfo(res);
    res = NULL;

    if (!trfSockValid(sfd))
    {
        trf__log_error("Failed to bind to %s:%s", host, port);
        return -1;
    }
    
    ret = listen(sfd, 1);
    if (ret == -1)
    {   
        trf__log_error("Listen failed: %s", strerror(trfLastSockError));
        goto cleanup_sock;
    }
    int enable = 1;
    if (setsockopt(sfd, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(int)) < 0)
    {
        trf__log_error("Unable to set SO_REUSEADDR: %s", 
            strerror(trfLastSockError));
    }
    
    *sock = sfd;
    trf__log_trace("Assign Server FD");
    return 0;

cleanup_sock:
    if (sfd) {
        close(sfd);
    }
    if (res) {
        freeaddrinfo(res);
    }
    return ret;
}

int trf__NCServerExchangeVersions(PTRFContext ctx, TRFSock client_sock,
                                  uint8_t * buffer, size_t size,
                                  uint64_t * session_id)
{
    int ret;
    int sto = ctx->opts->nc_snd_timeo;
    int rto = ctx->opts->nc_rcv_timeo;
    TrfMsg__MessageWrapper * msg = NULL;
    ret = trfNCRecvDelimited(client_sock, buffer, size, rto, &msg);
    if (ret < 0)
    {
        trf__log_error("Delimited recv failed %s", strerror(-ret));
        return ret;
    }

    if (msg->wdata_case != TRF_MSG__MESSAGE_WRAPPER__WDATA_CLIENT_HELLO)
    {
        trf__log_error("Invalid payload type %d", msg->wdata_case);
        trf_msg__message_wrapper__free_unpacked(msg, NULL);
        return -EBADMSG;
    }

    if (!msg->client_hello)
    {
        trf__log_error("Invalid payload");
        trf_msg__message_wrapper__free_unpacked(msg, NULL);
        return -EBADMSG;
    }

    TrfMsg__APIVersion * ver = msg->client_hello->version;
    if (!ver)
    {
        trf__log_error("No version in client hello");
        trf_msg__message_wrapper__free_unpacked(msg, NULL);
        return -EBADMSG;
    }
    
    trf__log_info(
        "Client API version: %d.%d.%d; "
        "Server API version: %d.%d.%d",
        ver->api_major, ver->api_minor, ver->api_patch,
        TRF_API_MAJOR, TRF_API_MINOR, TRF_API_PATCH
    );

    if ( ver->api_major != TRF_API_MAJOR
         || ver->api_minor != TRF_API_MINOR
         || ver->api_patch != TRF_API_PATCH )
    {
        trf__log_error("Incompatible API versions!");
        trf_msg__message_wrapper__free_unpacked(msg, NULL);
        TrfMsg__MessageWrapper mw   = TRF_MSG__MESSAGE_WRAPPER__INIT;
        TrfMsg__ServerReject sr     = TRF_MSG__SERVER_REJECT__INIT;
        TrfMsg__APIVersion av       = TRF_MSG__APIVERSION__INIT;
        mw.server_reject            = &sr;
        sr.version                  = &av;
        av.api_major                = TRF_API_MAJOR;
        av.api_minor                = TRF_API_MINOR;
        av.api_patch                = TRF_API_PATCH;
        ret = trfNCSendDelimited(client_sock, buffer, size, sto, &mw);
        if (ret < 0)
        {
            trf__log_error("Delimited send failed %s", strerror(-ret));
            return ret;
        }
        close(client_sock);
        return -ENOTSUP;
    }

    trf_msg__message_wrapper__free_unpacked(msg, NULL);
    msg = NULL;

    TrfMsg__MessageWrapper mw   = TRF_MSG__MESSAGE_WRAPPER__INIT;
    TrfMsg__ServerHello sh      = TRF_MSG__SERVER_HELLO__INIT;
    mw.wdata_case               = TRF_MSG__MESSAGE_WRAPPER__WDATA_SERVER_HELLO;
    mw.server_hello             = &sh;
    sh.new_session_id           = trf__Rand64();
    ret = trfNCSendDelimited(client_sock, buffer, size, sto, &mw);
    if (ret < 0)
    {
        trf__log_error("Delimited send failed %s", strerror(-ret));
        return ret;
    }

    *session_id = sh.new_session_id;
    return 0;
}

int trf__NCServerExchangeViableLinks(PTRFContext ctx, TRFSock client_sock,
                                     uint8_t * buffer, size_t size,
                                     PTRFAddrV * av)
{
    int sto = ctx->opts->nc_snd_timeo;
    int ret;
    TrfMsg__MessageWrapper * msg    = NULL;
    PTRFInterface client_ifs        = NULL;
    PTRFInterface server_ifs        = NULL;
    uint32_t svr_num_ifs            = 0;

    ret = trfNCRecvDelimited(client_sock, buffer, size, sto, &msg);
    if (ret < 0)
    {
        trf__log_error("Delimited recv failed %s", strerror(-ret));
        return ret;
    }

    if (msg->wdata_case != TRF_MSG__MESSAGE_WRAPPER__WDATA_ADDR_PF)
    {
        trf__log_error("Invalid payload type %d", msg->wdata_case);
        ret = -EBADMSG;
        goto free_msg;
    }

    trf__log_debug("Address count: %lu",msg->addr_pf->n_addrs);
    for (int i = 0; i < msg->addr_pf->n_addrs; i++)
    {
        trf__log_debug("[Candidate] Addr: %s, Mask: %d, Speed: %d", 
            msg->addr_pf->addrs[i]->addr, msg->addr_pf->addrs[i]->netmask,
            msg->addr_pf->addrs[i]->speed);
    }
    
    ret = trf__AddrMsgToInterface(msg, &client_ifs);
    if (ret < 0)
    {
        trf__log_error("Message conversion failed");
        ret = -EBADMSG;
        goto free_msg;
    }

    ret = trfGetInterfaceList(&server_ifs, &svr_num_ifs, ctx->opts->iface_flags);
    if (ret < 0)
    {
        trf__log_error("Unable to get interface list");
        goto free_cli_ifs;
    }

    PTRFInterface server_ifs2 = trfSortInterfaceList(server_ifs);
    if (!server_ifs2)
    {
        trf__log_error("Unable to sort interface list");
        ret = errno;
        goto free_svr_ifs;
    }

    PTRFAddrV av_cand = NULL;
    if ((ret = trfCreateAddrV(server_ifs, client_ifs, &av_cand)) < 0)
    {
        trf__log_error("Unable to create address vector");
        goto free_svr_ifs;
    }

    PTRFAddrV av_cand2 = trfSortAddrV(av_cand);
    if (!av_cand2)
    {
        ret = errno;
        goto free_av;
    }

    av_cand = av_cand2;

    // Free the old message addresses

    for (int i = 0; i < msg->addr_pf->n_addrs; i++)
    {
        free(msg->addr_pf->addrs[i]->addr);
        free(msg->addr_pf->addrs[i]);
    }
    free(msg->addr_pf->addrs);

    // First pass just to find out how long the list is

    int len = 0;
    for (PTRFAddrV av_tmp = av_cand; av_tmp; av_tmp = av_tmp->next)
    {
        len++;
    }
    
    // Next construct the actual message. If the message construction fails, the
    // protobuf message free function will reclaim memory that we have allocated
    // here

    msg->addr_pf->addrs     = calloc(1, sizeof(TrfMsg__AddrCand *) * len);
    if (!msg->addr_pf->addrs)
    {
        goto free_av;
    }
    
    msg->addr_pf->n_addrs = 0;
    for (PTRFAddrV av_tmp = av_cand; av_tmp; av_tmp = av_tmp->next)
    {
        int idx = msg->addr_pf->n_addrs;
        if (!msg->addr_pf->addrs[idx])
        {
            msg->addr_pf->addrs[idx] = calloc(1, sizeof(TrfMsg__AddrCand));
            if (!msg->addr_pf->addrs[idx])
            {
                goto free_av;
            }
            trf_msg__addr_cand__init(msg->addr_pf->addrs[idx]);
        }
        if (!msg->addr_pf->addrs[idx]->addr
            || msg->addr_pf->addrs[idx]->addr == protobuf_c_empty_string)
        {
            msg->addr_pf->addrs[idx]->addr = calloc(1, INET6_ADDRSTRLEN);
            if (!msg->addr_pf->addrs[idx]->addr)
            {
                goto free_av;
            }
        }
        ret = trfGetIPaddr(av_cand->src_addr, msg->addr_pf->addrs[idx]->addr);
        if (ret < 0)
        {
            trf__log_debug("Address encoding failed");
            continue;
        }
        msg->addr_pf->n_addrs++;
    }

    if (!msg->addr_pf->n_addrs)
    {
        trf__log_error("Address encoding failed: %s", strerror(-ret));
        goto free_av;
    }

    if (msg->addr_pf->n_addrs != len)
    {
        trf__log_warn("Only %d of %d addresses were successfully encoded",
                      msg->addr_pf->n_addrs, len);
    }

    ret = trfNCSendDelimited(client_sock, buffer, size, sto, msg);
    if (ret < 0)
    {
        trf__log_error("Delimited send failed %s", strerror(-ret));
        goto free_av;
    }

    trf_msg__message_wrapper__free_unpacked(msg, NULL);
    msg = NULL;
    *av = trfDuplicateAddrV(av_cand);
    if (!*av)
    {
        trf__log_error("Unable to duplicate address vector");
        ret = -ENOMEM;
    }

free_av:
    trfFreeAddrV(av_cand);
free_svr_ifs:
    trfFreeInterfaceList(server_ifs);
free_cli_ifs:
    trfFreeInterfaceList(client_ifs);
free_msg:
    trf_msg__message_wrapper__free_unpacked(msg, NULL);
    return ret;
}


int trf__NCServerTestTransport(PTRFContext ctx, TRFSock client_sock, 
                               uint64_t session_id,
                               uint8_t * buffer, size_t size, 
                               void * src_addr, size_t src_addr_size,
                               struct fi_info * fi, PTRFContext * new_ctx)
{
    PTRFContext nctx = trfAllocContext();
    if (!nctx)
    {
        trf__log_error("Unable to allocate context");
        return -ENOMEM;
    }

    // Allocate communication channel

    nctx->opts           = malloc(sizeof(*nctx->opts));
    nctx->type           = TRF_EP_CONN_ID;
    nctx->cli.client_fd  = TRFInvalidSock;
    nctx->cli.session_id = session_id;
    nctx->xfer_type      = TRFX_TYPE_LIBFABRIC;
    nctx->disconnected   = 1;
    trfDuplicateOpts(ctx->opts, nctx->opts);
    if (!nctx->opts)
    {
        trf__log_error("Unable to duplicate options");
        free(nctx);
        return -ENOMEM;
    }

    int ret;
    ret = trfCreateChannel(nctx, fi, src_addr, src_addr_size);
    if (ret < 0)
    {
        trf__log_error("Unable to create channel");
        return ret;
    }

    char * sas_buf = NULL;
    ret = trfGetEndpointName(nctx, &sas_buf);
    if (ret < 0)
    {
        trf__log_error("Unable to get created endpoint name: %s",
                       fi_strerror(-ret));
        trfDestroyContext(nctx);
        return -EINVAL;
    }

    size_t regd_buf_size = \
        ctx->opts->fab_rcv_bufsize > ctx->opts->fab_snd_bufsize ?
        ctx->opts->fab_rcv_bufsize : ctx->opts->fab_snd_bufsize;
    void * regd_buf = trfAllocAligned(regd_buf_size, trf__GetPageSize());
    if (!regd_buf)
    {
        trf__log_error("Unable to allocate pinned message buffer");
        free(regd_buf);
        free(sas_buf);
        trfDestroyContext(nctx);
        return -ENOMEM;
    }

    ret = trfRegInternalMsgBuf(nctx, regd_buf, regd_buf_size);
    if (ret < 0)
    {
        trf_fi_error("Unable to register internal message buffer", ret);
        free(sas_buf);
        trfDestroyContext(nctx);
        return ret;
    }

    // Send created transport to the client for testing

    char * proto_str = NULL;
    ret = trfSerializeWireProto(fi->ep_attr->protocol, &proto_str);
    if (ret < 0)
    {
        trf__log_error("Unable to serialize wire protocol");
        free(sas_buf);
        trfDestroyContext(nctx);
        return ret;
    }

    TrfMsg__MessageWrapper msg  = TRF_MSG__MESSAGE_WRAPPER__INIT;
    TrfMsg__ServerCap sc        = TRF_MSG__SERVER_CAP__INIT;
    TrfMsg__Transport tpt       = TRF_MSG__TRANSPORT__INIT;
    msg.wdata_case              = TRF_MSG__MESSAGE_WRAPPER__WDATA_SERVER_CAP;
    msg.server_cap              = &sc;
    sc.transport                = &tpt;
    tpt.name                    = fi->fabric_attr->prov_name;
    tpt.proto                   = proto_str;
    tpt.src                     = sas_buf;
    tpt.dest                    = NULL;

    ret = trfNCSendDelimited(client_sock, buffer, 
                             size, ctx->opts->nc_snd_timeo, &msg);
    if (ret < 0)
    {
        trf__log_error("Delimited send failed %s", strerror(-ret));
        free(proto_str);
        free(sas_buf);
        trfDestroyContext(nctx);
        return ret;
    }

    free(proto_str);
    free(sas_buf);
    sas_buf = NULL;

    // Wait for the client to send back its transport endpoint

    TrfMsg__MessageWrapper * peer_msg = NULL;
    ret = trfNCRecvDelimited(client_sock, buffer, size, 
                             ctx->opts->nc_rcv_timeo, &peer_msg);
    if (ret < 0)
    {
        trf__log_error("Delimited receive failed %s", strerror(-ret));
        trfDestroyContext(nctx);
        return ret;
    }

    if (peer_msg->wdata_case != TRF_MSG__MESSAGE_WRAPPER__WDATA_ENDPOINT)
    {
        trf__log_error("Invalid message type received");
        trf_msg__message_wrapper__free_unpacked(peer_msg, NULL);
        trfDestroyContext(nctx);
        return -EINVAL;
    }

    // Insert peer address into AV

    fi_addr_t peer;
    ret = trfInsertAVSerialized(nctx->xfer.fabric, 
                                peer_msg->endpoint->transport->src, &peer);
    if (ret < 0)
    {
        trf__log_error("Unable to insert source address: %s", fi_strerror(-ret));
        trfDestroyContext(nctx);
        return -EINVAL;
    }

    trf__ProtoFree(peer_msg);

    // Temporarily set the NC socket to non-blocking mode so we can wait on
    // multiple events.

    ret = trf__SetSockNonBlocking(client_sock);
    if (ret < 0)
    {
        trf__log_error("Unable to set socket to non-blocking mode");
        trfDestroyContext(nctx);
        return ret;
    }

    // Post receive to get session identifier
    
    nctx->xfer.fabric->peer_addr = peer;

    ret = trfFabricRecvUnchecked(nctx, &nctx->xfer.fabric->msg_mem, 
                                 trfMemPtr(&nctx->xfer.fabric->msg_mem),
                                 nctx->xfer.fabric->msg_mem.size, peer);
    if (ret < 0)
    {
        trf_fi_error("trfFabricRecv", ret);
        trfDestroyContext(nctx);
        return ret;
    }

    // Wait for either a reply, timeout, or NACK

    struct timespec tend;
    ret = trfGetDeadline(&tend, trf__Max(nctx->opts->fab_rcv_timeo, 
                                         nctx->opts->nc_rcv_timeo));
    if (ret != 0)
    {
        trf__log_fatal("System clock error: %s", strerror(errno));
        return 0;
    }

    while (1)
    {
        // Poll socket for data

        ret = recv(client_sock, buffer, size, MSG_PEEK);
        if (ret <= 0 && errno != EAGAIN && errno != EWOULDBLOCK)
        {
            trf__log_error("Socket error: %s", strerror(errno));
            trfDestroyContext(nctx);
            return ret == 0 ? -ECONNRESET : -errno;
        }
        else if (ret > 0)
        {
            // Receive NACK message from client
            trf__log_debug("Client socket has data");
            ret = trfNCRecvDelimited(client_sock, buffer, size, 
                                     nctx->opts->nc_rcv_timeo, &peer_msg);
            if (ret < 0)
            {
                trf__log_error("Delimited receive failed %s", strerror(-ret));
                trfDestroyContext(nctx);
                return ret;
            }
            
            if ((peer_msg->wdata_case 
                != TRF_MSG__MESSAGE_WRAPPER__WDATA_TRANSPORT_NACK)
                || (!peer_msg->transport_nack))
            {
                trf__log_error("Unexpected message type %d in buffer "
                               "(or buffer is corrupted)", 
                               peer_msg->wdata_case);
                trfDestroyContext(nctx);
                return -EBADMSG;
            }

            errno = peer_msg->transport_nack->reason;
            trf_msg__message_wrapper__free_unpacked(peer_msg, NULL);
            trfDestroyContext(nctx);
            return -ECONNABORTED;
        }

        // Poll for session identifier on fabric

        struct fi_cq_data_entry cqe;
        struct fi_cq_err_entry err;
        ret = trfFabricPollRecv(nctx, &cqe, &err, 0, 0, NULL, 1);
        if (ret < 0 && ret != -FI_EAGAIN)
        {
            trf_fi_error("trfFabricPollRecv", ret);
            trfDestroyContext(nctx);
            return ret;
        }
        if (ret == 1)
        {
            // Session identifier received, send back the ID to the client
            if (be64toh(* (uint64_t *) regd_buf) == session_id)
            {
                ret = trfFabricSend(nctx, &nctx->xfer.fabric->msg_mem, 
                                    trfMemPtr(&nctx->xfer.fabric->msg_mem),
                                    nctx->xfer.fabric->msg_mem.size, peer, 
                                    nctx->opts);
                switch (ret)
                {
                    // Success
                    case 1:
                        *new_ctx = nctx;
                        return 0;
                    // Timeout
                    case -FI_EAGAIN:
                    case -FI_ETIMEDOUT:
                        ;
                        TrfMsg__TransportNack nack = \
                            TRF_MSG__TRANSPORT_NACK__INIT;
                        msg.wdata_case = \
                            TRF_MSG__MESSAGE_WRAPPER__WDATA_TRANSPORT_NACK;
                        msg.transport_nack = &nack;
                        nack.reason = ETIMEDOUT;
                        ret = trfNCSendDelimited(client_sock, buffer, 
                                                size, ctx->opts->nc_snd_timeo, 
                                                &msg);
                        if (ret < 0)
                        {
                            trf__log_error("Delimited send failed %s", 
                                           strerror(-ret));
                            trfDestroyContext(nctx);
                            return ret;
                        }
                        trfDestroyContext(nctx);
                        return -ETIMEDOUT;
                    default:
                        trf__log_error("Unexpected return value received: %d",
                                       ret);
                }
            }
            else
            {
                trf__log_error("Invalid session identifier received");
                trfDestroyContext(nctx);
                return -EINVAL;
            }
        }

        // Check deadline
        if (trf__HasPassed(CLOCK_MONOTONIC, &tend))
        {
            TrfMsg__TransportNack nack = \
                TRF_MSG__TRANSPORT_NACK__INIT;
            msg.wdata_case = \
                TRF_MSG__MESSAGE_WRAPPER__WDATA_TRANSPORT_NACK;
            msg.transport_nack = &nack;
            nack.reason = ETIMEDOUT;
            ret = trfNCSendDelimited(client_sock, buffer, 
                                    size, ctx->opts->nc_snd_timeo, 
                                    &msg);
            if (ret < 0)
            {
                trf__log_error("Delimited send failed %s", 
                                strerror(-ret));
                trfDestroyContext(nctx);
                return ret;
            }
            trfDestroyContext(nctx);
            return -ETIMEDOUT;
        }

        trfSleep(ctx->opts->fab_poll_rate);
    }
}

int trf__NCServerGetClientFabrics(PTRFContext ctx, TRFSock client_sock,
                                  uint64_t session_id, 
                                  uint8_t * buffer, size_t size,
                                  PTRFContext * new_ctx)
{
    int ret;
    int rto = ctx->opts->nc_rcv_timeo;
    TrfMsg__MessageWrapper * msg = NULL;
    ret = trfNCRecvDelimited(client_sock, buffer, size, rto, &msg);
    if (ret < 0)
    {
        trf__log_error("Delimited receive failed %s", strerror(-ret));
        return ret;
    }

    if (msg->wdata_case != TRF_MSG__MESSAGE_WRAPPER__WDATA_CLIENT_CAP)
    {
        trf__log_error("Invalid payload type %d", msg->wdata_case);
        trf_msg__message_wrapper__free_unpacked(msg, NULL);
        return -EBADMSG;
    }

    // Look through the routes the client has sent and see if we can use any of
    // them

    int i = 0;
    uint8_t flag = 0;
    PTRFContext nctx = NULL;
    for (; i < msg->client_cap->n_transports; i++)
    {
        if (!trf__ProtoStringValid(msg->client_cap->transports[i]->name)
            || !trf__ProtoStringValid(msg->client_cap->transports[i]->proto)
            || !trf__ProtoStringValid(msg->client_cap->transports[i]->src))
        {
            trf__log_warn("Route %d has invalid transport data", i);
            continue;
        }
        
        struct fi_info * fi = NULL;
        trf__log_debug("(fabric) trying prov %d/%d (name: %s proto: %s) r: %s",
                       i + 1, msg->client_cap->n_transports,
                       msg->client_cap->transports[i]->name,
                       msg->client_cap->transports[i]->proto,
                       msg->client_cap->transports[i]->src);
        
        ret = trfGetRoute(msg->client_cap->transports[i]->src, 
                          msg->client_cap->transports[i]->name, 
                          msg->client_cap->transports[i]->proto, &fi);
        if (ret < 0)
        {
            trf__log_warn("Unable to get route for %s",
                          msg->client_cap->transports[i]->src);
            continue;
        }

        // We found a transport, try this one
        ret = trf__NCServerTestTransport(ctx, client_sock, session_id,
                                         buffer, size, NULL, 0,
                                         fi, &nctx);
        if (ret < 0)
        {
            trf__log_info("Route %d invalid: %s", i, fi_strerror(-ret));
        }
        else
        {
            fi_freeinfo(fi);
            trf__log_info("Route %d valid", i);
            flag = 1;
            break;
        }
    }

    if (!flag)
    {
        trf__log_error("Client transports not supported");
        trf_msg__message_wrapper__free_unpacked(msg, NULL);
        return -ENOPROTOOPT;
    }

    *new_ctx = nctx;
    trf_msg__message_wrapper__free_unpacked(msg, NULL);
    return 0;
}