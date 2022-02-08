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

#include "trf_ncp.h"

// Client-server OOB connection setup

int trfNCServerInit(PTRFContext ctx, char * host, char * port)
{
    srand(time(NULL));
    if (!ctx)
    {
        trf__log_error("Server init: Invalid connection context");
        return -EINVAL;
    }

    if (ctx->svr.listen_fd > 0)
    {
        trf__log_error("Server init: Socket exists");
        return -EALREADY;
    }

    trf__log_info("libtrf server %d.%d.%d initializing", 
        TRF_API_MAJOR, TRF_API_MINOR, TRF_API_PATCH
    );

    struct addrinfo hints;
    struct addrinfo * res = NULL;
    int sfd = -1;
    int ret;

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
        if (sfd == -1)
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
    trf__log_trace("Free AddrINFO");
    res = NULL;

    if (sfd == -1)
    {
        trf__log_error("Failed to bind to %s:%s", host, port);
        return -1;
    }
    trf__log_trace("Check Server FD");
    ret = listen(sfd, 1);
    trf__log_trace("Listening");
    if (ret == -1)
    {   
        trf__log_error("Listen failed");
        goto cleanup_sock;
    }
    int enable = 1;
    if (setsockopt(sfd, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(int)) < 0)
    {
        trf__log_error("Unable to set preflight socket reuse");
    }
    ctx->svr.listen_fd = sfd;
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

int trfNCClientInit(PTRFContext ctx, char * host, char * port)
{
    if (!ctx)
    {
        trf__log_error("Client init: Invalid connection context");
        return -EINVAL;
    }

    if (ctx->cli.client_fd > 0)
    {
        trf__log_error("Client already initialized");
        return -EALREADY;
    }

    trf__log_info("libtrf client %d.%d.%d initializing", 
        TRF_API_MAJOR, TRF_API_MINOR, TRF_API_PATCH
    );

    struct addrinfo hints;
    struct addrinfo * res = NULL;
    int sfd = -1;
    int ret;

    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_family     = AF_UNSPEC;
    hints.ai_socktype   = SOCK_STREAM;
    hints.ai_flags      = 0;

    ret = getaddrinfo(host, port, &hints, &res);
    if (ret != 0)
    {
        trf__log_error("Client init: getaddrinfo() failed: %s", gai_strerror(ret));
        return -ret;
    }

    struct addrinfo * res_p;

    for (res_p = res; res_p; res_p = res_p->ai_next)
    {
        trf__log_debug("Trying connection...");
        sfd = socket(res_p->ai_family, res_p->ai_socktype, res_p->ai_protocol);
        if (sfd == -1)
        {
            continue;
        }

        ret = connect(sfd, res_p->ai_addr, res_p->ai_addrlen);
        if (ret == 0)
        {
            break;
        }
    }

    if (sfd == -1)
    {
        trf__log_error("Failed to connect to %s:%s", host, port);
        return -1;
    }

    trf__log_debug("Connected");

    // Send client hello message to server indicating API version

    uint8_t * buff = trfAllocAligned(4096, trf__GetPageSize());
    if (!buff)
    {
        trf__log_error("Unable to allocate buffer!");
        goto close_sock;
    }
    
    free(res);
    res = NULL;

    TrfMsg__MessageWrapper * msg = malloc(sizeof(TrfMsg__MessageWrapper));
    if (!msg)
    {
        trf__log_error("Unable to allocate message wrapper!");
        goto free_buff;
    }
    trf_msg__message_wrapper__init(msg);
    TrfMsg__ClientHello * ch = malloc(sizeof(TrfMsg__ClientHello));
    if (!ch)
    {
        trf__log_error("Unable to allocate client hello!");
        trf_msg__message_wrapper__free_unpacked(msg, NULL);
        goto free_buff;
    }
    trf_msg__client_hello__init(ch);
    TrfMsg__APIVersion * ver = malloc(sizeof(TrfMsg__APIVersion));
    if (!ver)
    {
        trf__log_error("Unable to allocate API version!");
        trf_msg__message_wrapper__free_unpacked(msg, NULL);
        goto free_buff;
    }
    trf_msg__apiversion__init(ver);
    
    msg->wdata_case     = TRF_MSG__MESSAGE_WRAPPER__WDATA_CLIENT_HELLO;
    msg->client_hello   = ch;
    ch->version         = ver;
    ver->api_major      = TRF_API_MAJOR;
    ver->api_minor      = TRF_API_MINOR;
    ver->api_patch      = TRF_API_PATCH;

    ret = trfNCSendDelimited(sfd, buff, 4096, 0, msg);
    trf_msg__message_wrapper__free_unpacked(msg, NULL);
    if (ret < 0)
    {
        trf__log_error("Unable to send client hello!");
        goto free_buff;
    }

    // Get session ID from server

    msg = NULL;
    ret = trfNCRecvDelimited(sfd, buff, 4096, 0, &msg);
    if (ret < 0)
    {
        trf__log_error("Unable to receive session ID!");
        goto free_buff;
    }

    if (!msg)
    {
        trf__log_error("Receive message handle not set");
        goto free_buff;
    }

    switch (msg->wdata_case)
    {
        case TRF_MSG__MESSAGE_WRAPPER__WDATA_SERVER_HELLO:
            ctx->cli.session_id = msg->server_hello->new_session_id;
            break;
        case TRF_MSG__MESSAGE_WRAPPER__WDATA_SERVER_REJECT:
            TrfMsg__APIVersion * ver = msg->server_reject->version;
            trf__log_error(
                "API ver. mismatch! "
                "Client Version: %d.%d.%d; Server: %d.%d.%d",
                TRF_API_MAJOR, TRF_API_MINOR, TRF_API_PATCH,
                ver->api_major, ver->api_minor, ver->api_patch
            );
            goto free_buff;
        default:
            trf__log_error("Unexpected message type in buffer!");
            goto free_buff;
    }

    trf_msg__message_wrapper__free_unpacked(msg, NULL);
    msg = NULL;
    trf__log_info("API version valid");

    // Send list of client interfaces

    uint32_t num_ifs;
    PTRFInterface clientIf;
    if ((ret = trfGetInterfaceList(&clientIf, &num_ifs)) < 0)
    {
        trf__log_error("Unable to get Interface Lists");
        goto free_buff;
    }

    trf__log_debug("Number of interfaces: %d, clientIf: %p", num_ifs, clientIf);

    msg = malloc(sizeof(TrfMsg__MessageWrapper));
    if (!msg)
    {
        trf__log_error("Unable to allocate message wrapper!");
        goto free_ci_list;
    }
    trf_msg__message_wrapper__init(msg);
    msg->session_id = ctx->cli.session_id;
    msg->wdata_case = TRF_MSG__MESSAGE_WRAPPER__WDATA_ADDR_PF;
    TrfMsg__AddrPF * addr_pf = malloc(sizeof(TrfMsg__AddrPF));
    if (!addr_pf)
    {
        trf__log_error("Unable to allocate preflight address list");
        goto free_ci_list;
    }
    trf_msg__addr_pf__init(addr_pf);
    msg->addr_pf = addr_pf;
    msg->addr_pf->addrs = calloc(1, sizeof(TrfMsg__AddrCand *) * num_ifs);
    if (!msg->addr_pf->addrs)
    {
        trf__log_error("Unable to allocate address list");
        goto free_ci_list;
    }
    msg->addr_pf->n_addrs = num_ifs;
    
    int i = 0;
    for (PTRFInterface tmp_if = clientIf; tmp_if; tmp_if = tmp_if->next)
    {
        msg->addr_pf->addrs[i] = malloc(sizeof(TrfMsg__AddrCand));
        if (!msg->addr_pf->addrs[i])
        {
            trf__log_error("Memory allocation failed");
            goto free_ci_list;
        }
        trf_msg__addr_cand__init(msg->addr_pf->addrs[i]);
        char addr[INET6_ADDRSTRLEN];
        if (trfGetIPaddr(tmp_if->addr, addr) < 0)
        {
            trf__log_error("Unable to decode ip addr");
            continue;
        }
        msg->addr_pf->addrs[i]->addr    = strdup(addr);
        msg->addr_pf->addrs[i]->speed   = tmp_if->speed;
        msg->addr_pf->addrs[i]->netmask = tmp_if->netmask;
        i++;
    }
    
    if ((ret = trfNCSendDelimited(sfd, buff, 4096, 0, msg)) < 0) 
    {
        trf__log_error("Unable to send Client Interfaces");
        goto free_ci_list;
    }

    free(clientIf);
    clientIf = NULL;
    trf_msg__message_wrapper__free_unpacked(msg, NULL);
    msg = NULL;

    // Receive possibly viable address from server
    
    ret = trfNCRecvDelimited(sfd, buff, 4096, 0, &msg);
    if (ret < 0)
    {
        trf__log_error("Unable to receive address");
        goto free_ci_list;
    }

    if (msg->wdata_case != TRF_MSG__MESSAGE_WRAPPER__WDATA_ADDR_PF)
    {
        trf__log_error("Unexpected message type in buffer");
        goto free_ci_list;
    }

    if (msg->addr_pf->n_addrs == 0)
    {
        trf__log_error("No addresses received!");
        goto free_ci_list;
    }

    //!todo multiple candidate selection
    
    trf__log_debug("Interface Addr: %s/%d, Speed: %d Mbps", 
        msg->addr_pf->addrs[0]->addr, msg->addr_pf->addrs[0]->netmask, 
        msg->addr_pf->addrs[0]->speed
    );

    // Get the list of all providers regardless of addressing format

    struct fi_info * fi_out;
    ret = trfGetFabricProviders(msg->addr_pf->addrs[0]->addr, "0",
        TRF_EP_SOURCE, &fi_out);
    if (ret)
    {
        trf__log_error("Unable to get fabric providers");
        goto free_ci_list;
    }
    
    trf_msg__addr_pf__free_unpacked(msg->addr_pf, NULL);
    msg->addr_pf = NULL;

    // Convert raw Libfabric info and serialize data for network transmission
    
    struct fi_info *fi_node;
    int num_fabrics = 0;
    for (fi_node = fi_out; fi_node; fi_node = fi_node->next)
    {
        num_fabrics++;
    }
    
    TrfMsg__ClientCap * ccap = malloc(sizeof(TrfMsg__ClientCap));
    if (!ccap)
    {
        trf__log_error("Memory allocation failed");
        goto free_fpl;
    }
    trf_msg__client_cap__init(ccap);
    msg->wdata_case = TRF_MSG__MESSAGE_WRAPPER__WDATA_CLIENT_CAP;
    msg->client_cap = ccap;
    msg->client_cap->transports = calloc(1, 
        sizeof(TrfMsg__Transport *) * num_fabrics);
    if (!msg->client_cap->transports)
    {
        trf__log_error("Memory allocation failed");
        goto free_fpl;
    }
    msg->client_cap->n_transports = num_fabrics;

    int cf = 0;
    for (fi_node = fi_out; fi_node; fi_node = fi_node->next)
    {
        msg->client_cap->transports[cf] = calloc(1, sizeof(TrfMsg__Transport));
        trf_msg__transport__init(msg->client_cap->transports[cf]);
        msg->client_cap->transports[cf]->name = \
            strdup(fi_node->fabric_attr->prov_name);
        ret = trfSerializeWireProto(fi_node->ep_attr->protocol, 
            &msg->client_cap->transports[cf]->proto);
        if (ret)
        {
            trf__log_error("Unable to serialize wire protocol");
            goto free_fpl;
        }
        int fmt = trfConvertFabricAF(fi_node->addr_format);
        if (fmt < 0)
        {
            trf__log_error("Unable to convert fabric address format %d", 
                fi_node->addr_format);
            continue;
        }
        ret = trfSerializeAddress((void *) fi_node->src_addr, fmt, 
            &msg->client_cap->transports[cf]->route);
        if (ret < 0)
        {
            trf__log_error("Unable to serialize address");
            continue;
        }
        else
        {
            trf__log_debug("Serialized: %s", 
                msg->client_cap->transports[cf]->route);
        }
        cf++;
    }

    if (!cf)
    {
        trf__log_error("No fabrics found");
        goto free_fpl;
    }

    if ((ret = trfNCSendDelimited(sfd, buff, 4096, 0, msg)) < 0)
    {
        trf__log_error("Unable to send client fabric info");
        goto free_fpl;
    }

    trf_msg__message_wrapper__free_unpacked(msg, NULL);
    msg = NULL;

    // Wait for the server to send transport information

    ret = trfNCRecvDelimited(sfd, buff, 4096, 0, &msg);
    if (ret < 0)
    {
        trf__log_error("Unable to receive transport info");
        goto free_fpl;
    }

    if (msg->wdata_case != TRF_MSG__MESSAGE_WRAPPER__WDATA_SERVER_CAP)
    {
        trf__log_error("Unexpected message type in buffer");
        goto free_fpl;
    }

    trf__log_debug("Bind address %s", msg->server_cap->bind_addr);
    trf__log_info("Candidate transport %s @ %s", 
        msg->server_cap->transport->name, msg->server_cap->transport->route);

    // Narrow down the list of providers based on the server's capabilities
    
    fi_freeinfo(fi_out);
    ret = trfGetRoute(msg->server_cap->transport->route,
        msg->server_cap->transport->name, 
        msg->server_cap->transport->proto, &fi_out);
    if (ret)
    {
        trf__log_error("Unable to get fabric providers");
        goto free_fpl;
    }

    //!todo check valid before using

    struct sockaddr_in6 bind_addr;
    ret = trfConvertCharToAddr(msg->server_cap->bind_addr, (struct sockaddr *) 
        &bind_addr);
    if (ret)
    {
        trf__log_error("Unable to convert bind address");
        goto free_fpl;
    }

    ret = trfCreateChannel(ctx, fi_out, (void *) &bind_addr, 
        TRF_SA_LEN(&bind_addr));
    if (ret)
    {
        trf__log_error("Unable to create channel");
        goto free_fpl;
    }

    void * regd_buf = trfAllocAligned(4096, 2097152);
    if (!regd_buf)
    {
        trf__log_error("Unable to allocate pinned message buffer");
        goto free_fpl;
    }

    ret = trfRegInternalMsgBuf(ctx, regd_buf, 4096);
    if (ret)
    {
        trf_fi_error("Register internal message buffer", ret);
        goto free_reg_buf;
    }

    * (uint64_t *) regd_buf = ctx->cli.session_id;
    fi_addr_t addr_out;

    ret = trfInsertAVSerialized(ctx->xfer.fabric, 
        msg->server_cap->transport->route, &addr_out);
    if (ret)
    {
        trf__log_error("Unable to insert AV entry");
        goto close_mr;
    }

    trf__log_debug("Fabric Addr: %lu", addr_out);

    // Send back the address of our endpoint to the server
    
    char * ep_name;
    if (trfGetEndpointName(ctx, &ep_name) < 0)
    {
        trf__log_error("Unable to get libfabric endpoint Name");
        goto close_mr;
    }

    char * tpt_name = strdup(msg->server_cap->transport->name);
    if (!tpt_name)
    {
        trf__log_error("Unable to allocate transport name");
        free(ep_name);
        goto close_mr;
    }
    char * proto_name = strdup(msg->server_cap->transport->proto);
    if (!proto_name)
    {
        trf__log_error("Unable to allocate protocol name");
        free(tpt_name);
        free(ep_name);
        goto close_mr;
    }

    trf_msg__server_cap__free_unpacked(msg->server_cap, NULL);
    msg->server_cap = NULL;
    msg->wdata_case = TRF_MSG__MESSAGE_WRAPPER__WDATA_ENDPOINT;
    msg->endpoint = malloc(sizeof(TrfMsg__Endpoint));
    if (!msg->endpoint)
    {
        trf__log_error("Unable to allocate endpoint");
        free(proto_name);
        free(tpt_name);
        free(ep_name);
        goto close_mr;
    }
    trf_msg__endpoint__init(msg->endpoint);
    msg->endpoint->transport = malloc(sizeof(TrfMsg__Transport));
    if (!msg->endpoint->transport)
    {
        trf__log_error("Unable to allocate transport");
        free(proto_name);
        free(tpt_name);
        free(ep_name);
        goto close_mr;
    }

    trf_msg__transport__init(msg->endpoint->transport);
    msg->endpoint->transport->name = tpt_name;
    msg->endpoint->transport->route = ep_name;
    msg->endpoint->transport->proto = proto_name;

    ret = trfNCSendDelimited(sfd, buff, 4096, 0, msg);
    if (ret < 0)
    {
        trf__log_error("Unable to send endpoint info");
        goto close_mr;
    }

    trf_msg__message_wrapper__free_unpacked(msg, NULL);
    msg = NULL;

    // After sending the endpoint info on the negotiation channel, send a
    // message on the main channel to notify the server that we are ready

    do {
        ret = fi_send(ctx->xfer.fabric->ep, regd_buf, 8, 
            fi_mr_desc(ctx->xfer.fabric->msg_mr), addr_out, NULL);
        usleep(1000);
    } while (ret == -FI_EAGAIN);
    
    if (ret)
    {
        fprintf(stderr, "fi_cq_sread %d", ret);
        return ret;
    }

    struct fi_cq_data_entry cqe;
    
    do {
        ret = fi_cq_sread(ctx->xfer.fabric->tx_cq, &cqe, 1, 0, 0);
        usleep(1000);
    } while (ret == -FI_EAGAIN);
    
    if (ret != 1)
    {
        fprintf(stderr, "fi_cq_sread %d", ret);
        return ret;
    }

    trf__log_info("Sent cookie %lu", *(uint64_t *) regd_buf);

    fi_freeinfo(fi_out);
    free(buff);
    ctx->cli.client_fd = sfd;
    trf__log_trace("Done");

    return 0;

close_mr:
    if (ctx->xfer.fabric->msg_mr) {
        fi_close((fid_t) ctx->xfer.fabric->msg_mr);
    }
free_reg_buf:
    free(regd_buf);
free_fpl:
    fi_freeinfo(fi_out);
free_ci_list:
    trfFreeInterfaceList(clientIf);
    trf_msg__message_wrapper__free_unpacked(msg, NULL);
free_buff:
    free(buff);
close_sock:
    if (sfd) {
        close(sfd);
    }
    if (res) {
        freeaddrinfo(res);
    }
    return ret;
}

int trfNCAccept(PTRFContext ctx, PTRFContext ctx_out)
{
    // Check fd created
    if (!ctx->svr.listen_fd)
    {
        return -EINVAL;
    }

    struct sockaddr_in client_addr;
    int client_sock = 0;
    socklen_t client_size;
    uint8_t * mbuf = calloc(1,4096);
    int ret = 0;
    if (!mbuf)
    {
        return -ENOMEM;
    }

    // Accept client connection on side channel
    
    client_size = sizeof(client_addr);
    client_sock = accept(
        ctx->svr.listen_fd, (struct sockaddr *) &client_addr, &client_size
    );
    if (!client_sock)
    {
        trf__log_error("Unable to accept client connection");
        ret = -errno;
        goto free_buf;
    }

    // Receive client hello message and verify API version
    
    TrfMsg__MessageWrapper * msg = NULL;
    ret = trfNCRecvDelimited(client_sock, mbuf, 4096, 0, &msg);
    if (ret < 0)
    {
        trf__log_error("Delimited recv failed %s", strerror(-ret));
        goto close_sock;
    }

    if (msg->wdata_case != TRF_MSG__MESSAGE_WRAPPER__WDATA_CLIENT_HELLO)
    {
        trf__log_error("Invalid payload type %d", msg->wdata_case);
        goto free_msg;
    }

    TrfMsg__APIVersion * ver = msg->client_hello->version;
    
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
        goto free_msg;
    }
    
    trf_msg__message_wrapper__free_unpacked(msg, NULL); // Free previous Message
    msg = NULL;
    
    // Generate and send a new session ID to the client

    uint64_t sessID = trf__Rand64();
    
    msg = malloc(sizeof(TrfMsg__MessageWrapper));
    if(!msg)
    {
        trf__log_error("Unable to initialize message wrapper");
        goto free_msg;
    }
    trf_msg__message_wrapper__init(msg);
    
    TrfMsg__ServerHello * svr_hello = malloc(sizeof(TrfMsg__ServerHello));
    if (!svr_hello)
    {
        trf__log_error("Unable to initialize server hello message");
        goto free_msg;
    }
    trf_msg__server_hello__init(svr_hello);
    msg->wdata_case = TRF_MSG__MESSAGE_WRAPPER__WDATA_SERVER_HELLO;
    svr_hello->new_session_id = sessID;
    msg->server_hello = svr_hello;
 
    ret = trfNCSendDelimited(client_sock, mbuf, 4096, 0, msg);
    if (ret)
    {
        trf__log_error("Delimited send failed");
        goto free_msg;
    }

    trf_msg__message_wrapper__free_unpacked(msg, NULL); // Free Previous Message
    msg = NULL;

    // Receive the preflight list of client addresses

    ret = trfNCRecvDelimited(client_sock, mbuf, 4096, 0, &msg);
    if (ret < 0)
    {
        trf__log_error("Delimited recv failed %s", strerror(-ret));
        goto free_msg;
    }

    if (msg->wdata_case != TRF_MSG__MESSAGE_WRAPPER__WDATA_ADDR_PF)
    {
        trf__log_error("Invalid payload type %d", msg->wdata_case);
        goto free_msg;
    }
    trf__log_debug("Number of Addrs: %lu",msg->addr_pf->n_addrs);
    for (int i = 0; i < msg->addr_pf->n_addrs; i++)
    {
        trf__log_debug("Addr: %s, Mask: %d, Speed: %d", 
            msg->addr_pf->addrs[i]->addr, msg->addr_pf->addrs[i]->netmask,
            msg->addr_pf->addrs[i]->speed);
    }

    // Determine viable links
    
    PTRFInterface client_ifs;
    if ((ret = trf__AddrMsgToInterface(msg, &client_ifs)) < 0)
    {
        trf__log_error("Message conversion failed");
        goto close_sock;
    }
    
    PTRFInterface svr_ifs;
    uint32_t svr_num_ifs;
    if ((ret = trfGetInterfaceList(&svr_ifs, &svr_num_ifs)))
    {
        trf__log_error("Unable to get interface list");
        goto free_ci_list;
    }
    
    PTRFAddrV av;
    if ((ret = trfCreateAddrV(svr_ifs, client_ifs, &av)) < 0)
    {
        trf__log_error("Unable to create address vector");
        goto free_sv_list;
    }

    PTRFAddrV av_cand;
    if ((ret = trfGetFastestLink(av, &av_cand)))
    {
        trf__log_error("Unable to get fastest link");
        goto free_av_list;
    }

    // Free the old message

    for (int i = 0; i < msg->addr_pf->n_addrs; i++)
    {
        free(msg->addr_pf->addrs[i]->addr);
        free(msg->addr_pf->addrs[i]);
    }

    free(msg->addr_pf->addrs);

    // Create a new message with the viable links

    msg->addr_pf->addrs     = calloc(1, sizeof(TrfMsg__AddrCand *) * 1);
    if (!msg->addr_pf->addrs)
    {
        goto free_av_cand;
    }
    msg->addr_pf->addrs[0]  = calloc(1, sizeof(TrfMsg__AddrCand));
    if (!msg->addr_pf->addrs[0])
    {
        goto free_av_cand;
    }
    msg->addr_pf->n_addrs = 1;
    trf_msg__addr_cand__init(msg->addr_pf->addrs[0]);
    msg->addr_pf->addrs[0]->addr = calloc(1, INET6_ADDRSTRLEN);
    if (!msg->addr_pf->addrs[0]->addr)
    {
        goto free_av_cand;
    }
    ret = trfGetIPaddr(av_cand->src_addr, msg->addr_pf->addrs[0]->addr);
    if (ret < 0)
    {
        trf__log_error("Unable to get IP address");
        goto free_av_cand;
    }
    
    trf__log_trace("Address to Connect: %s", msg->addr_pf->addrs[0]->addr);

    if ((ret = trfNCSendDelimited(client_sock, mbuf, 4096, 0, msg)) < 0)
    {
        trf__log_error("Delimited send failed %s", strerror(-ret));
        goto free_av_cand;
    }

    trf_msg__message_wrapper__free_unpacked(msg, NULL);
    msg = NULL;

    // Get the transport list from the client, and determine available routes

    ret = trfNCRecvDelimited(client_sock, mbuf, 4096, 0, &msg);
    if (ret < 0)
    {
        trf__log_error("Delimited recv failed %s", strerror(-ret));
        goto free_av_cand;
    }

    if (msg->wdata_case != TRF_MSG__MESSAGE_WRAPPER__WDATA_CLIENT_CAP)
    {
        trf__log_error("Invalid payload type %d", msg->wdata_case);
        goto free_av_cand;
    }
    int i = 0;
    int flag = 0;
    struct fi_info * fi;
    for (; i < msg->client_cap->n_transports; i++)
    {
        trf__log_debug("(fabric) trying prov %d/%d (name: %s proto: %s) r: %s",
            i + 1, msg->client_cap->n_transports,
            msg->client_cap->transports[i]->name,
            msg->client_cap->transports[i]->proto,
            msg->client_cap->transports[i]->route);
        ret = trfGetRoute(msg->client_cap->transports[i]->route, 
            msg->client_cap->transports[i]->name, 
            msg->client_cap->transports[i]->proto, &fi );
        if (ret)
        {
            trf__log_error("Unable to get route");
            goto free_av_cand;
        }
        else 
        {
            flag = 1;
            break;
        }
    }

    if (!flag)
    {
        trf__log_error("No usable transport found");
        goto free_av_cand;
    }

    // Allocate resources and create a communication channel

    PTRFContext cli_ctx = trfAllocContext();
    if (!cli_ctx)
    {
        trf__log_error("Unable to allocate context");
        goto free_av_cand;
    }
    cli_ctx->type           = TRF_EP_CONN_ID;
    cli_ctx->cli.client_fd  = client_sock;
    cli_ctx->cli.session_id = sessID;
    cli_ctx->xfer_type      = TRFX_TYPE_LIBFABRIC;
    ret = trfCreateChannel(cli_ctx, fi, av_cand->src_addr, 
        TRF_SA_LEN(av_cand->src_addr));
    if (ret < 0)
    {
        trf__log_error("Unable to create main channel");
        goto destroy_ctx;
    }

    char * sas_buf;
    if (trfGetEndpointName(cli_ctx, &sas_buf) < 0)
    {
        trf__log_error("Unable to get libfabric endpoint name");
        goto destroy_ctx;
    }
    
    // Allocate pinned message buffer

    void * regd_buf = trfAllocAligned(4096, 4096);
    if (!regd_buf)
    {
        trf__log_error("Unable to allocate pinned message buffer");
        free(sas_buf);
        goto destroy_ctx;
    }

    ret = trfRegInternalMsgBuf(cli_ctx, regd_buf, 4096);
    if (ret < 0)
    {
        trf_fi_error("Unable to register internal message buffer", ret);
        goto free_regd_buf;
    }

    // Send created transport to the client

    trf_msg__client_cap__free_unpacked(msg->client_cap, NULL);
    msg->client_cap = NULL;

    char cli_bind[INET6_ADDRSTRLEN];
    memset(cli_bind, 0, INET6_ADDRSTRLEN);
    ret = trfGetIPaddr(av_cand->dst_addr, cli_bind);
    if (ret < 0)
    {
        trf__log_error("Unable to get client bind address");
        goto free_regd_buf;
    }

    TrfMsg__ServerCap * sc = malloc(sizeof(TrfMsg__ServerCap));
    if (!sc)
    {
        trf__log_error("Unable to allocate server cap message");
        goto free_regd_buf;
    }
    trf_msg__server_cap__init(sc);
    TrfMsg__Transport * st = malloc(sizeof(TrfMsg__Transport));
    if (!st)
    {
        trf__log_error("Unable to allocate server transports message");
        goto free_regd_buf;
    }
    trf_msg__transport__init(st);
    msg->wdata_case = TRF_MSG__MESSAGE_WRAPPER__WDATA_SERVER_CAP;
    msg->server_cap = sc;
    msg->server_cap->transport = st;
    msg->server_cap->transport->name = strdup(fi->fabric_attr->prov_name);
    msg->server_cap->transport->route = sas_buf;
    ret = trfSerializeWireProto(fi->ep_attr->protocol,
        &msg->server_cap->transport->proto);
    if (ret < 0)
    {
        trf__log_error("Unable to serialize wire protocol");
        goto free_regd_buf;
    }
    msg->server_cap->bind_addr = strdup(cli_bind);

    ret = trfNCSendDelimited(cli_ctx->cli.client_fd, mbuf, 4096, 0, msg);
    if (ret < 0)
    {
        trf__log_error("Delimited send failed %s", strerror(-ret));
        goto free_regd_buf;
    }

    // Receive the client's address
    trf_msg__message_wrapper__free_unpacked(msg, NULL);
    msg = NULL;

    ret = trfNCRecvDelimited(cli_ctx->cli.client_fd, mbuf, 4096, 0, &msg);
    if (ret < 0)
    {
        trf__log_error("Unable to receive Client Address: %s", strerror(ret));
        goto free_regd_buf;
    }

    if (msg->wdata_case != TRF_MSG__MESSAGE_WRAPPER__WDATA_ENDPOINT)
    {
        trf__log_error("Invalid payload type %d", msg->wdata_case);
        goto free_regd_buf;
    }

    fi_addr_t src_addr;
    if (trfInsertAVSerialized(cli_ctx->xfer.fabric, 
        msg->endpoint->transport->route, &src_addr) < 0)
    {
        trf__log_error("Unable to serialize source address");
        goto free_regd_buf;
    }
    trf__log_trace("Received Client Address: %s", msg->endpoint->transport->route);
    
    // Wait on the main channel for an incoming message

    *(uint64_t *) regd_buf = 0;

    do {
        ret = fi_recv(cli_ctx->xfer.fabric->ep, regd_buf, 8, 
            fi_mr_desc(cli_ctx->xfer.fabric->msg_mr), 0, NULL);
        usleep(1000);
    } while (ret == -FI_EAGAIN);
    
    if (ret)
    {
        fprintf(stderr, "fi_cq_sread %d", ret);
        goto free_regd_buf;
        return ret;
    }

    struct fi_cq_data_entry cqe;

    do {
        ret = fi_cq_sread(cli_ctx->xfer.fabric->rx_cq, &cqe, 1, 0, 0);
        usleep(1000);
    } while (ret == -FI_EAGAIN);
    
    if (ret != 1)
    {
        fprintf(stderr, "fi_cq_sread %d", ret);
        goto free_regd_buf;
        return ret;
    }

    trf__log_info("Recv Cookie %lu", *(uint64_t *) regd_buf);

    free(mbuf);
    return ret;

free_regd_buf:
    free(regd_buf);
destroy_ctx:
    trfDestroyContext(cli_ctx);
free_av_cand:
    trfFreeAddrV(av_cand);
free_av_list:
    trfFreeAddrV(av);
free_sv_list:
    trfFreeInterfaceList(svr_ifs);
free_ci_list:
    trfFreeInterfaceList(client_ifs);
close_sock:
    if (client_sock) {
        close(client_sock);
    }
free_msg:
    if (msg) {
        trf_msg__message_wrapper__free_unpacked(msg, NULL);
    }
free_buf:
    if (mbuf) {
        free(mbuf);
    }
    return -1;
}

int trfNCNewSession(PTRFContext ctx, PTRFContext * out)
{
    int ret;    
    if (ctx->type != TRF_EP_SOURCE)
        return -EINVAL;
    
    uint64_t session_id = trf__Rand64();
    if (session_id == 0)
    {
        trf__log_error("trf__Rand64() returned invalid session ID");
        return -EAGAIN;
    }
    if ( !ctx->svr.clients 
        || trf__CheckSessionID(ctx->svr.clients, session_id, 1) == 0 )
    {
        ret = trf__AllocSessionForClient(ctx, session_id, out);
        if (ret)
        {
            trf__log_error("Could not allocate session");
            return ret;
        }
    }
    return 0;
}

int trfNCServerClose(PTRFContext ctx)
{
    if (!ctx)
    {
        trf__log_error("Server close: Invalid connection context");
        return -EINVAL;
    }

    if (!ctx->svr.clients)
    {
        trf__log_error("No clients");
        return -ENOTCONN;
    }

    if (ctx->svr.listen_fd <= 0)
    {
        trf__log_error("Server close: No connection");
        return -ENOTCONN;
    }

    TrfMsg__MessageWrapper msg = TRF_MSG__MESSAGE_WRAPPER__INIT;
    TrfMsg__Disconnect disc = TRF_MSG__DISCONNECT__INIT;
    msg.wdata_case = TRF_MSG__MESSAGE_WRAPPER__WDATA_DISCONNECT;
    msg.disconnect = &disc;
    disc.info = 0;

    size_t bufsz = trf_msg__message_wrapper__get_packed_size(&msg);
    uint8_t * buff = calloc(1, bufsz);
    
    for (PTRFContext c = ctx->svr.clients; c; c = c->next)
    {
        if(trfNCSendDelimited(c->cli.client_fd, buff, bufsz, 0, &msg) < 0 )
        {
            trf__log_error("unable to disconnect client");
        }
    }

    close(ctx->svr.listen_fd);
    ctx->svr.listen_fd = -1;
    return 0;
}

int trfNCServerDisconnectClient(PTRFContext client_ctx)
{
    if (!client_ctx)
    {
        trf__log_debug("Client context invalid!");
        return -EINVAL;
    }

    if (client_ctx->type != TRF_EP_CONN_ID)
    {
        trf__log_debug("Endpoint type invalid!");
        return -EINVAL;
    }
    
    TrfMsg__MessageWrapper msg = TRF_MSG__MESSAGE_WRAPPER__INIT;
    TrfMsg__Disconnect disc = TRF_MSG__DISCONNECT__INIT;
    msg.wdata_case = TRF_MSG__MESSAGE_WRAPPER__WDATA_DISCONNECT;
    msg.disconnect = &disc;
    disc.info = 0;

    size_t bufsz = trf_msg__message_wrapper__get_packed_size(&msg);
    uint8_t * buff = calloc(1, bufsz);

    trfNCSendDelimited(client_ctx->cli.client_fd, buff, bufsz, 0, &msg);
    close(client_ctx->cli.client_fd);
    return 0;
}

int trfNCClientClose(PTRFContext ctx)
{
    if (!ctx)
    {
        trf__log_error("Client close: Invalid connection context");
        return -EINVAL;
    }

    if (ctx->cli.client_fd <= 0)
    {
        trf__log_error("Client close: No connection");
        return -ENOTCONN;
    }

    TrfMsg__MessageWrapper msg = TRF_MSG__MESSAGE_WRAPPER__INIT;
    TrfMsg__Disconnect disc = TRF_MSG__DISCONNECT__INIT;
    msg.wdata_case = TRF_MSG__MESSAGE_WRAPPER__WDATA_DISCONNECT;
    msg.disconnect = &disc;
    disc.info = 0;

    size_t bufsz = trf_msg__message_wrapper__get_packed_size(&msg);
    uint8_t * buff = calloc(1, bufsz);

    trfNCSendDelimited(ctx->cli.client_fd, buff, bufsz, 0, &msg);

    close(ctx->cli.client_fd);
    ctx->cli.client_fd = -1;
    return 0;
}

int trf__AddrMsgToInterface(TrfMsg__MessageWrapper * msg, PTRFInterface * out)
{
    if (!out || !msg 
        || msg->wdata_case != TRF_MSG__MESSAGE_WRAPPER__WDATA_ADDR_PF
        || !msg->addr_pf
        || msg->addr_pf->n_addrs == 0)
    {
        trf__log_warn("Invalid argument");
        return -EINVAL;
    }

    int ret;
    PTRFInterface out_tmp = malloc(sizeof(*out_tmp));
    if (!out_tmp)
    {
        trf__log_error("Unable to allocate memory");
        return -ENOMEM;
    }

    PTRFInterface out_start = out_tmp;
    PTRFInterface out_prev;
    for (int i = 0; i < msg->addr_pf->n_addrs; i++)
    {
        out_tmp->addr = calloc(1, sizeof(struct sockaddr_in6));
        if (!out_tmp->addr)
        {
            trf__log_error("Unable to allocate memory");
            ret = -ENOMEM;
            goto free_out;
        }
        ret = trfConvertCharToAddr(msg->addr_pf->addrs[i]->addr, out_tmp->addr);
        if (ret < 0)
        {
            trf__log_error("Unable to convert address");
            goto free_out;
        }
        out_tmp->netmask = msg->addr_pf->addrs[i]->netmask;
        out_tmp->port    = msg->addr_pf->addrs[i]->port;
        out_tmp->speed   = msg->addr_pf->addrs[i]->speed;
        out_tmp->flags   = 0;
        out_tmp->next    = malloc(sizeof(*out_tmp));
        if (!out_tmp->next)
        {
            trf__log_error("Unable to allocate memory");
            ret = -ENOMEM;
            goto free_out;
        }
        out_prev = out_tmp;
        out_tmp = out_tmp->next;
    }

    free(out_tmp);
    out_prev->next = NULL;
    *out = out_start;
    return 0;

free_out:
    trfFreeInterfaceList(out_tmp);
    return ret;
}
