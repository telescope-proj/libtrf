#include "internal/trfi_ncp.h"

int trf__NCSendTransportNack(PTRFContext ctx, TRFSock sock, uint32_t reason,
                    uint8_t * buffer, size_t size)
{
    TrfMsg__MessageWrapper mw   = TRF_MSG__MESSAGE_WRAPPER__INIT;
    TrfMsg__TransportNack tn    = TRF_MSG__TRANSPORT_NACK__INIT;
    mw.transport_nack           = &tn;
    tn.reason                   = reason;

    return trfNCSendDelimited(sock, buffer, size,
                              ctx->opts->nc_snd_timeo, &mw);
}

int trf__SetSockNonBlocking(TRFSock sock)
{
    int flags = fcntl(sock, F_GETFL);
    if (flags == -1)
    {
        trf__log_error("Unable to get flags: %s", strerror(errno));
        return -errno;
    }
    flags |= O_NONBLOCK;
    if (fcntl(sock, F_SETFL, flags) == -1)
    {
        trf__log_error("Unable to set flags: %s", strerror(errno));
        return -errno;
    }
    return 0;
}

int trf__SetSockBlocking(TRFSock sock)
{
    int flags = fcntl(sock, F_GETFL);
    if (flags == -1)
    {
        trf__log_error("Unable to get flags: %s", strerror(errno));
        return -errno;
    }
    flags &= ~O_NONBLOCK;
    if (fcntl(sock, F_SETFL, flags) == -1)
    {
        trf__log_error("Unable to set flags: %s", strerror(errno));
        return -errno;
    }
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