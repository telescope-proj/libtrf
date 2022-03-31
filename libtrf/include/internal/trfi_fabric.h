/*
    SPDX-License-Identifier: LGPL-2.1-only

    Telescope Project
    Remote Framebuffer Library
    Internal Libfabric channel operations

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

#include "trf_def.h"
#include "trfi.h"
#include <rdma/fi_endpoint.h>

#define trf_fi_error(call, err) \
    trf__log_error("(fabric) %s failed (%d): %s", call, abs((int) err), \
    fi_strerror(abs((int) err)))

#define trf_fi_warn(call, err) \
    trf__log_warn("(fabric) %s failed (%d): %s", call, abs((int) err), \
    fi_strerror(abs((int) err)))

static inline int trf__FabricRegBuf(PTRFXFabric ctx, void * addr, size_t len, 
                                    uint64_t flags, struct fid_mr ** mr_out)
{
    trf__log_debug("Registering buffer %p with size %lu", addr, len);
    int ret;

    struct fid_domain * domain = ctx->domain;
    ret = fi_mr_reg(domain, addr, len, flags, 0, 0, 0, mr_out, NULL);
    if (ret < 0)
    {
        trf_fi_error("fi_mr_reg", ret);
        return ret;
    }

    trf__log_debug("Registered memory - desc: %p, key: %lu", 
                   fi_mr_desc(*mr_out), fi_mr_key(*mr_out));

    return 0;
}

/**
 * @brief           Default fabric requirements used by libtrf.
 * 
 */
static inline struct fi_info * trf__FabricGetHints(void)
{
    struct fi_info * hints;
    
    /*  Specify the feature set required/supported by libtrf. */

    hints                       = fi_allocinfo();
    if (!hints)
    {
        return NULL;
    }
    hints->ep_attr->type        = FI_EP_RDM;
    hints->caps                 = FI_MSG | FI_RMA;
    hints->addr_format          = FI_FORMAT_UNSPEC;
    hints->mode                 = FI_LOCAL_MR | FI_RX_CQ_DATA;
    hints->domain_attr->mr_mode = FI_MR_BASIC;
    return hints;
}

static inline const char * trf__FabricGetCQErrString(struct fid_cq * cq, 
    struct fi_cq_err_entry * err)
{
    return fi_cq_strerror(cq, err->prov_errno, err->err_data, NULL, 0);
}

/**
 * @brief           Internal tracked send operation.
 * 
 * @param cq        Completion queue associated with this operation.
 * 
 * @param ep        Endpoint associated with this operation.
 * 
 * @param peer      Peer address.
 * 
 * @param mem       Memory region details.
 * 
 * @param addr      Buffer start address. Must be within the memory region.
 * 
 * @param len       Length of the buffer.
 * 
 * @return          0 on success, negative error code on failure.
 */
static inline ssize_t trf__FabricTrackedSend(PTRFTCQFabric cq, 
                                             struct fid_ep * ep,
                                             fi_addr_t peer, PTRFMem mem, 
                                             void * addr, size_t len)
{
    if (trf__DecrementCQ(cq, 1) != 1)
        return -FI_EAGAIN;

    ssize_t ret = fi_send(ep, addr, len, trfMemFabricDesc(mem), peer, NULL);
    if (ret < 0)
        trf__IncrementCQ(cq, 1);
    
    return ret;
}

/**
 * @brief           Internal tracked receive operation.
 * 
 * @param cq        Completion queue associated with this operation.
 * 
 * @param ep        Endpoint associated with this operation.
 * 
 * @param peer      Peer address.
 * 
 * @param mem       Memory region details.
 * 
 * @param addr      Buffer start address. Must be within the memory region.
 * 
 * @param len       Length of the buffer.
 * 
 * @return          0 on success, negative error code on failure.
 */
static inline ssize_t trf__FabricTrackedRecv(PTRFTCQFabric cq,
                                             struct fid_ep * ep,
                                             fi_addr_t peer, PTRFMem mem, 
                                             void * addr, size_t len)
{
    if (trf__DecrementCQ(cq, 1) != 1)
        return -FI_EAGAIN;

    ssize_t ret = fi_recv(ep, addr, len, trfMemFabricDesc(mem), peer, NULL);
    if (ret < 0)
        trf__IncrementCQ(cq, 1);

    return ret;
}