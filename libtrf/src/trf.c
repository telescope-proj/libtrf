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

#include "trf.h"                         


/*  Get the system page size. */
size_t trfGetPageSize() {
    #if defined(_WIN32)
        SYSTEM_INFO si;
        GetSystemInfo(&si);
        return si.dwPageSize;
    #else
        return sysconf(_SC_PAGESIZE);
    #endif
}


PTRFContext trfAllocContext() {
    PTRFContext ctx = calloc(1, sizeof(struct TRFContext));
    return ctx;
}


int trfAllocActiveEP(PTRFContext ctx, struct fi_info * fi)
{
    int ret;
    ret = fi_domain(ctx->fabric, fi, &ctx->domain, NULL);
    if (ret)
    {
        fprintf(stderr, "fi_domain failed with error: %s\n", fi_strerror(ret));
        goto free_domain;
    }
    ret = fi_domain_bind(ctx->domain, &ctx->eq->fid, 0);
    if (ret)
    {
        fprintf(stderr, "fi_domain_bind failed with error: %s\n", fi_strerror(ret));
        goto free_domain;
    }
    struct fi_cq_attr cq_attr;
    memset(&cq_attr, 0, sizeof(cq_attr));
    cq_attr.size                = 0;
    cq_attr.flags               = 0;
    cq_attr.wait_obj            = FI_WAIT_UNSPEC;
    cq_attr.format              = FI_CQ_FORMAT_MSG;
    cq_attr.signaling_vector    = 0;
    cq_attr.wait_cond           = FI_CQ_COND_NONE;
    cq_attr.wait_set            = NULL;

    ret = fi_cq_open(ctx->domain, &cq_attr, &ctx->cq, NULL);
    if (ret) {
        trf_fi_error("Open completion queue", ret);
        goto free_domain;
    }

    ret = fi_endpoint(ctx->domain, fi, &ctx->ep, NULL);
    if (ret) {
        trf_fi_error("Create endpoint on domain", ret);
        goto free_domain;
    }

    ret = fi_ep_bind(ctx->ep, &ctx->eq->fid, 0);
    if (ret) {
        trf_fi_error("EP bind to EQ", ret);
        goto free_domain;
    }

    ret = fi_ep_bind(ctx->ep, &ctx->cq->fid, FI_TRANSMIT | FI_RECV);
    if (ret) {
        trf_fi_error("EP bind to CQ", ret);
        goto free_domain;
    }

    return ret;

free_domain:
    if (ctx->ep)
    {
        fi_shutdown(ctx->ep, 0);
        fi_close(&ctx->ep->fid);
    }
    if (ctx->cq)
    {
        fi_close(&ctx->cq->fid);
    }
    if (ctx->domain)
    {
        fi_close(&ctx->domain->fid);
        ctx->domain = NULL;
    }
    return ret;
}


int trfDestroyContext(PTRFContext ctx) {
    int ret;
    if (!ctx) {
        return -EINVAL;
    }
    if (ctx->ep) {
        ret = fi_shutdown(ctx->ep, 0);
        if (ret)
            return ret;
        ret = fi_close(&ctx->ep->fid);
        if (ret)
            return ret;
    }
    else if (ctx->pep) {
        ret = fi_close(&ctx->pep->fid);
        if (ret)
            return ret;
    }
    if (ctx->cq) {
        ret = fi_close(&ctx->cq->fid);
        if (ret)
            return ret;
    }
    if (ctx->eq) {
        ret = fi_close(&ctx->eq->fid);
        if (ret)
            return ret;
    }
    if (ctx->domain) {
        ret = fi_close(&ctx->domain->fid);
        if (ret)
            return ret;
    }
    if (ctx->fabric) {
        ret = fi_close(&ctx->fabric->fid);
        if (ret)
            return ret;
    }
    free(ctx);
    return 0;
}


int trfAllocLocalBuffer(PTRFContext ctx, size_t size, struct fid_mr ** mr) {
    int ret;
    void * buf = aligned_alloc(trfGetPageSize(), size);
    ret = fi_mr_reg(ctx->domain, buf, size, FI_SEND | FI_RECV, 0, 0, 0, mr, buf);
    if (ret) {
        trf_fi_error("Register memory region", ret);
        return ret;
    }
    return 0;
}


int trfGetCQEvent(PTRFContext ctx) {
    int ret;
    struct fi_cq_msg_entry cq_entry;
    
    if (!ctx->cq) {
        return -EINVAL;
    }
    
    ret = fi_cq_sread(ctx->cq, &cq_entry, 1, NULL, -1);
    if (ret < 0) {
        trf_fi_error("Read completion queue", ret);
        return ret;
    }
    return 0;
}


int trfCreateEP(const char * host, const char * port, enum TRFEPType req_type, PTRFContext ctx)
{

    int ret;
    struct fi_info *hints, *fi, *fi_node = NULL;
    
    if (!ctx)
        return EINVAL;
    
    /*  Specify the minimum feaure set required by the fabric. Note that just
        because you specify FI_RMA here doesn't mean the fabric natively
        supports RDMA; rather support for FI_RMA just means the fabric can
        emulate RDMA operations in software as well.
    */

    hints                   = fi_allocinfo();
    hints->ep_attr->type    = FI_EP_MSG;
    hints->caps             = FI_MSG | FI_RMA;
    hints->mode             = FI_CONTEXT | FI_LOCAL_MR;
    hints->addr_format      = FI_FORMAT_UNSPEC;
    hints->fabric_attr->prov_name = strdup("tcp");
    
    /*  Search for an available fabric provider. This should return a list of
        available providers sorted by libfabric preference i.e. RDMA interfaces
        should show up as the first item in this list with a fallback to TCP
        BTL.
    */

    trf_debug("Attempting to find fabric provider for %s:%s\n", host, port);
    
    uint64_t fiflags    = (req_type == TRF_EP_SERVER) ? FI_SOURCE : 0;
    const char * g_host = (req_type == TRF_EP_SERVER) ? NULL : host;

    ret = fi_getinfo(FI_VERSION(1, 0), g_host, port, fiflags, hints, &fi);
    if (ret) {
        trf_fi_error("fi_getinfo", ret);
        goto free_context;
    }

    /*  Iterate through the list of interfaces and print out the name and
        provider name (debug)
    */
    
    trf_debug("Available fabric providers:\n");
    trf_debug("%15s %15s %30s %20s\n", "NIC", "Link Type", "Network", "Provider");
    for (fi_node = fi; fi_node; fi_node = fi_node->next)
    {
        trf_debug(
            "%15s %15s %30s %20s\n",
            fi_node->nic ? fi_node->nic->device_attr->name : "-",
            fi_node->nic ? fi_node->nic->link_attr->network_type : "-",
            fi_node->fabric_attr ? fi_node->fabric_attr->name : "-",
            fi_node->fabric_attr ? fi_node->fabric_attr->prov_name : "-"
        );
    }


    fi_freeinfo(hints);
    hints = NULL;

    /*  Create a fabric and event queue */

    ret = fi_fabric(fi->fabric_attr, &ctx->fabric, NULL);
    if (ret) {
        trf_fi_error("Open fabric", ret);
        goto free_context;
    }

    struct fi_eq_attr eq_attr;
    memset(&eq_attr, 0, sizeof(eq_attr));
    eq_attr.size = 0;
    eq_attr.wait_obj = FI_WAIT_UNSPEC;
    eq_attr.signaling_vector = 0;
    eq_attr.flags = 0;
    eq_attr.wait_set = NULL;
    
    ret = fi_eq_open(ctx->fabric, &eq_attr, &ctx->eq, NULL);
    if (ret) {
        trf_fi_error("Open event queue", ret);
        goto free_context;
    }

    /*  Bind a domain to the fabric */

    ret = fi_domain(ctx->fabric, fi, &ctx->domain, NULL);
    if (ret) {
        trf_fi_error("Open domain", ret);
        goto free_context;
    }

    /*  Create a completion queue */

    struct fi_cq_attr cq_attr;
    memset(&cq_attr, 0, sizeof(cq_attr));
    cq_attr.size                = 0;
    cq_attr.flags               = 0;
    cq_attr.wait_obj            = FI_WAIT_UNSPEC;
    cq_attr.format              = FI_CQ_FORMAT_MSG;
    cq_attr.signaling_vector    = 0;
    cq_attr.wait_cond           = FI_CQ_COND_NONE;
    cq_attr.wait_set            = NULL;
    
    ret = fi_cq_open(ctx->domain, &cq_attr, &ctx->cq, NULL);
    if (ret) {
        trf_fi_error("Open completion queue", ret);
        goto free_context;
    }

    
    /*  If we are the server, we only need to create a domain when clients
        connect.
    */

    if (req_type == TRF_EP_CLIENT)
    {
        ret = trfAllocActiveEP(ctx, fi);
        if (ret) {
            trf_fi_error("Create active endpoint", ret);
            goto free_context;
        }
        ret = fi_enable(ctx->ep);
        if (ret) {
            trf_fi_error("Enable endpoint", ret);
            goto free_context;
        }
        ret = fi_connect(ctx->ep, (void *) fi->dest_addr, NULL, 0);
        if (ret) {
            trf_fi_error("Connect to remote endpoint", ret);
            goto free_context;
        }
        
        uint32_t expected = sizeof(struct fi_eq_cm_entry);
        uint32_t evt;
        struct fi_eq_cm_entry entry;
        
        ret = fi_eq_sread(ctx->eq, &evt, &entry, expected, -1, 0);
        if (ret < 0) {
            if (-ret == FI_EAVAIL) {
                char * out;
                ret = trfEQLastErrorDesc(ctx->eq, &out);
                if (ret) {
                    trf_fi_error("Get last EQ error", ret);
                    goto free_context;
                }
                trf_error("Fabric error: %s\n", out);
            }
            trf_fi_error("Connection event wait", ret);
            goto free_context;
        }
        if (ret != expected)
        {
            struct fi_eq_err_entry *err = (struct fi_eq_err_entry *) &entry;
            fprintf(stderr, "fi_eq_sread returned %d bytes, expected %d\n", ret, expected);
            fprintf(stderr, "Error data: Fabric: %s, Provider: %s\n", 
                fi_strerror(err->err), strerror(err->prov_errno));
            goto free_context;
        }
        if (evt != FI_CONNECTED)
        {
            fprintf(stderr, "fi_eq_sread returned unexpected event (%d)\n", evt);
            goto free_context;
        }
    }
    else if (req_type == TRF_EP_SERVER)
    {
        ret = fi_passive_ep(ctx->fabric, fi, &ctx->pep, NULL);
        if (ret) {
            trf_fi_error("Create passive endpoint", ret);
            goto free_context;
        }
        ret = fi_pep_bind(ctx->pep, &ctx->eq->fid, 0);
        if (ret) {
            trf_fi_error("Bind passive endpoint to event queue", ret);
            goto free_context;
        }
        ret = fi_listen(ctx->pep);
        if (ret) {
            trf_fi_error("Listen on passive endpoint", ret);
            goto free_context;
        }
    }
    else
    {
        fprintf(stderr, "Invalid request type\n");
        goto free_context;
    }
    
    /*  Clean up the interface list */

    fi_freeinfo(fi);
    return 0;

free_context:
    
    if (fi) {
        fi_freeinfo(fi);
    }
    if (hints) {
        fi_freeinfo(hints);
    }
    if (ctx->ep) {
        fi_shutdown(ctx->ep, 0);
        fi_close(&ctx->ep->fid);
    }
    else if (ctx->pep) {
        fi_close(&ctx->pep->fid);
    }
    if (ctx->cq) {
        fi_close(&ctx->cq->fid);
    }
    if (ctx->eq) {
        fi_close(&ctx->eq->fid);
    }
    if (ctx->domain) {
        fi_close(&ctx->domain->fid);
    }
    if (ctx->fabric) {
        fi_close(&ctx->fabric->fid);
    }
    return ret;

}


int trfAccept(PTRFContext ctx, PTRFContext client) {

    if (!client || !ctx)
        return -EINVAL;

    ssize_t ret;
    uint32_t evt;
    struct fi_eq_cm_entry entry;

    ret = fi_eq_sread(ctx->eq, &evt, &entry, sizeof(entry), -1, 0);
    if (ret == 0) {
        return ret;
    } if (ret < 0) {
        char * out = NULL;
        ret = trfEQLastErrorDesc(ctx->eq, &out);
        if (ret < 0) {
            trf_error("Couldn't read error data: %s\n", out);
        } else {
            trf_error("EQ read failed: %s\n", out);
        }
        return ret;
    } if (ret != sizeof(entry)) {
        trf_error("EQ read failed: byte count invalid");
        return ret;
    } if (evt != FI_CONNREQ) {
        trf_error("EQ read failed: unexpected event %d\n", evt);
        return ret;
    }

    trf_log("Handling connection request\n");

    trf_debug("domain: %p, entry: %p, client: %p, ctx: %p\n",
        ctx->domain, entry.info, client, ctx);

    ret = fi_endpoint(ctx->domain, entry.info, &client->ep, NULL);
    if (ret) {
        trf_fi_error("Create endpoint", ret);
        return ret;
    }

    trf_debug("Binding EP/EQ ep: %p, eq: %p\n", client->ep, ctx->eq);

    ret = fi_ep_bind(client->ep, &ctx->eq->fid, 0);
    if (ret) {
        trf_fi_error("Bind endpoint to event queue", ret);
        return ret;
    }

    trf_debug("Binding EP/CQ ep: %p, eq: %p\n", client->ep, ctx->eq);

    ret = fi_ep_bind(client->ep, &ctx->cq->fid, FI_TRANSMIT | FI_RECV);
    if (ret) {
        trf_fi_error("Bind endpoint to completion queue", ret);
        return ret;
    }

    trf_debug("Registering memory\n");

    ret = trfAllocLocalBuffer(ctx, 4096, &ctx->msg_mr);
    if (ret) {
        trf_error("Couldn't allocate memory region\n");
        return ret;
    }

    trf_debug("Queueing receive into %p\n", ctx->msg_mr->fid.context);
    ret = fi_recv(client->ep, ctx->msg_mr->fid.context, 4096, ctx->msg_mr->mem_desc, 0, NULL);
    if (ret) {
        trf_fi_error("Queue receive", ret);
        return ret;
    }

    trf_debug("Accepting\n");

    ret = fi_accept(client->ep, NULL, 0);
    if (ret) {
        trf_fi_error("Could not accept connection", ret);
        return ret;
    }

    ret = fi_eq_sread(ctx->eq, &evt, &entry, sizeof(entry), -1, 0);
    if (evt != FI_CONNECTED) {
        trf_error("Could not read event\n");
        return ret;
    }

    return 0;

}


int trfPopEQ(struct fid_eq * eq, void * buf, size_t len, int nb, int consume) {
    
    ssize_t ret;
    uint32_t evt;
    struct fi_eq_cm_entry entry;
    size_t expected = sizeof(entry);

    uint64_t flags = consume ? 0 : FI_PEEK;

    if (nb) {
        ret = fi_eq_read(eq, &evt, &entry, expected, flags);
    } else {
        ret = fi_eq_sread(eq, &evt, &entry, expected, -1, flags);
    }

    if (ret == 0) {
        return 0;
    } if (ret < 0) {
        char * out = NULL;
        ret = trfEQLastErrorDesc(eq, &out);
        if (ret < 0) {
            trf_error("Couldn't read error data: %s\n", out);
        } else {
            trf_error("EQ read failed: %s\n", out);
        }
    } if (ret != expected) {
        trf_error("EQ read failed: byte count invalid (%ld/%ld)\n", ret, expected);
        return ret;
    } if (evt != FI_CONNREQ) {
        trf_error("EQ read failed: unexpected event %d\n", evt);
        return -1;
    } else {
        printf("hello client\n");
        return 1;
    }
}


int trfEQLastErrorDesc(struct fid_eq * eq, char ** out)
{
    int ret;
    struct fi_eq_err_entry err;
    ret = fi_eq_readerr(eq, &err, 0);
    if (ret < 0)
    {
        *out = (char *) fi_strerror(ret);
        return ret;
    }
    *out = (char *) fi_eq_strerror(eq, err.prov_errno, err.err_data, NULL, 0);
    return 0;
}


int trfSinkInit(char * node, char * service, PTRFContext ctx)
{
    if (!ctx)
        return -EINVAL;
    
    return trfCreateEP(node, service, TRF_EP_CLIENT, ctx);
}


int trfSourceInit(char * node, char * service, PTRFContext ctx)
{
    if (!ctx)
        return -EINVAL;
    
    return trfCreateEP(node, service, TRF_EP_SERVER, ctx);
}


int trfSourceCheckReq(PTRFContext ctx, int nb)
{
    ssize_t ret;
    uint32_t evt;
    struct fi_eq_cm_entry entry;
    ssize_t expected = sizeof(entry);

    if (nb) {
        ret = fi_eq_read(ctx->eq, &evt, &entry, expected, FI_PEEK);
    } else {
        ret = fi_eq_sread(ctx->eq, &evt, &entry, expected, -1, FI_PEEK);
    }

    if (ret == 0) {
        return 0;
    } if (ret < 0) {
        char * ret;
        trfEQLastErrorDesc(ctx->eq, &ret);
        trf_error("ConnReq EQ read failed: %s\n", ret);
    } if (ret != expected) {
        trf_error("ConnReq check failed, byte count invalid (%ld/%ld)\n", ret, expected);
        return ret;
    } if (evt != FI_CONNREQ) {
        trf_error("ConnReq check failed: unexpected event %d\n", evt);
        return -1;
    } else {
        printf("hello client\n");
        return 1;
    }
}