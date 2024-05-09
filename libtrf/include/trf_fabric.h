/*
    SPDX-License-Identifier: LGPL-2.1-only

    Telescope Project
    Remote Framebuffer Library
    Libfabric-based data fabric interface

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

#ifndef _TRF_FABRIC_H_
#define _TRF_FABRIC_H_

#include "trf.h"
#include "trf_def.h"
#include "trf_msg.h"
#include "internal/trfi_fabric.h"

/**
 * @brief           Flush errors from the fabric CQ.
 *
 * @param tcq       CQ to flush.
 *
 * @param err       List containing error details.
 *
 * @param err       Maximum number of errors to return.
 *
 * @return          Number of errors returned, negative error code on failure.
 */
static inline ssize_t trfFabricFlushCQErrors(struct TRFTCQFabric * tcq,
                                         struct fi_cq_err_entry * err,
                                         size_t max_err)
{
    size_t total = 0;
    ssize_t ret;
    do {
        struct fi_cq_data_entry de;

        trf__log_trace("Flushing CQ...");

        ret = fi_cq_read(tcq->cq, &de, 1);
        if (ret != -FI_EAVAIL)
        {
            trf__log_trace("Read CQ: %d", ret);
            break;
        }

        trf__log_trace("Reading error...");

        ssize_t ret2 = fi_cq_readerr(tcq->cq, err, 0);
        if (ret2 < 0)
            return ret2;

        trf__log_trace("Flushed error %d -> Err: %d (%s), ProvErr: %d", total, 
                       err->err, fi_strerror(err->err), err->prov_errno);

        total++;
    } while (--max_err);
    return total;
}

/**
 * @brief               Poll a completion queue for completed operations. 
 *
 *                      Note that this function does not necessarily return the 
 *                      exact number of completions requested. If there are 
 *                      fewer completions than are requested in the queue, the
 *                      queue is emptied, and the number of items that were 
 *                      pulled out of the queue is returned.
 *
 * @param cq            Completion queue to poll.
 *
 * @param de            Pointer to a data entry to be filled in with completion
 *                      details. Note that if multiple completions are requested
 *                      the size of the data entry must be multiplied by the
 *                      number of completions requested.
 *
 * @param err           Pointer to a data entry to be filled in with applicable
 *                      error details. Note that if multiple completions are
 *                      requested the size of the data entry must be multiplied
 *                      by the number of completions requested.
 *
 * @param sync          Synchonous operation mode. Setting this to true causes
 *                      the function to block until either a timeout occurs or a
 *                      completion is received. This option reduces CPU usage at
 *                      the expense of latency - not all fabrics support this
 *                      option.
 * 
 * @param rate          The interval between polling operations. If the sync
 *                      parameter is set, this parameter is ignored.
 *
 * @param deadline      Deadline for the operation. Corresponds to the time when
 *                      the operation should be considered timed out. Uses
 *                      CLOCK_MONOTONIC.
 *
 *                      The behaviour of setting deadline to NULL depends on
 *                      whether sync is set. If sync is set to true, the 
 *                      function blocks until a completion is received. 
 *                      Otherwise, the function polls once and returns.
 *
 * @param count         Number of completions to wait for.
 *
 * @return              Number of completions received, negative error code on
 *                      failure.
 */
static inline ssize_t trfFabricPoll(struct TRFTCQFabric * tcq,
                                    struct fi_cq_data_entry * de,
                                    struct fi_cq_err_entry * err, 
                                    bool sync, int64_t rate, 
                                    struct timespec * deadline, size_t count)
{
    ssize_t ret;
    if (sync)
    {
        int timeout = -1;
        if (deadline)
        {
            int timeout = trf__RemainingMS(deadline);
            if (timeout <= 0)
                return -ETIMEDOUT;
        }
        ret = fi_cq_sread(tcq->cq, de, count, NULL, timeout);
        if (ret > 0)
        {
            trf__IncrementCQ(tcq, ret);
        }
        else if (ret == -FI_EAVAIL)
        {
            ssize_t ret2 = trfFabricFlushCQErrors(tcq, err, count);
            if (ret2 < 0)
                return ret2;
        }
        return ret;
    }
    else
    {
        while (1)
        {
            if (deadline && trf__HasPassed(CLOCK_MONOTONIC, deadline))
            {
                return -ETIMEDOUT;
            }
            ret = fi_cq_read(tcq->cq, de, count);
            if (ret > 0)
            {
                trf__IncrementCQ(tcq, ret);
                return ret;
            }
            else
            {
                switch (ret)
                {
                    case -FI_EAGAIN:
                        if (deadline)
                        {
                            trfNanoSleep(rate);
                            continue;
                        }
                        else
                        {
                            return ret;
                        }
                    case -FI_EAVAIL:
                        ;
                        trf__log_trace("Flushing CQ error...");
                        ssize_t ret2 = trfFabricFlushCQErrors(tcq, err, count);
                        if (ret2 < 0)
                            return ret2;
                    default:
                        return ret;
                }
            }
        }
    }
}

/**
 * @brief               Performs trfFabricPoll() on the send queue.
 * 
 *                      See the documentation for trfFabricPoll() for more
 *                      information.
 */
static inline ssize_t trfFabricPollSend(PTRFContext ctx,
                                        struct fi_cq_data_entry * de,
                                        struct fi_cq_err_entry * err,
                                        bool sync, int rate,
                                        struct timespec * deadline,
                                        size_t count)
{
    return trfFabricPoll(ctx->xfer.fabric->tx_cq, de, err, sync, rate, deadline,
                         count);
}

/**
 * @brief               Performs trfFabricPoll() on the receive queue.
 * 
 *                      See the documentation for trfFabricPoll() for more
 *                      information.
 */
static inline ssize_t trfFabricPollRecv(PTRFContext ctx,
                                        struct fi_cq_data_entry * de,
                                        struct fi_cq_err_entry * err,
                                        bool sync, int rate,
                                        struct timespec * deadline,
                                        size_t count)
{
    return trfFabricPoll(ctx->xfer.fabric->rx_cq, de, err, sync, rate, deadline,
                         count);
}

/**
 * @brief           Send a message without checking for a send completion. This
 *                  function is useful if you are sending multiple messages, or
 *                  want to defer the completion check until later.
 *
 * @param ctx       Context to use for the send.
 *
 * @param mem       Memory region details.
 * 
 * @param addr      Buffer start address. Must be within the memory region.
 * 
 * @param len       Length of the buffer.
 * 
 * @param peer      Peer address.
 * 
 * @return          0 on success, negative error code on failure.
 */
static inline ssize_t trfFabricSendUnchecked(PTRFContext ctx, PTRFMem mem, 
                                             void * addr, size_t len, 
                                             fi_addr_t peer)
{
    if (!ctx || !ctx->xfer.fabric || !mem || !addr)
        return -EINVAL;

    PTRFXFabric f       = ctx->xfer.fabric;
    return trf__FabricTrackedSend(f->tx_cq, f->ep, peer, mem, addr, len);
}

/**
 * @brief           Receive a message without checking for a receive completion.
 *                  This function is useful if you are receiving multiple
 *                  messages, or want to defer the completion check until later.
 *
 * @param ctx       Context to use for the receive.
 *
 * @param mem       Memory region details.
 *
 * @param addr      Buffer start address. Must be within the memory region.
 *
 * @param len       Length of the buffer.
 *
 * @param peer      Peer address.
 *
 * @return          0 on success, negative error code on failure.
 */
static inline ssize_t trfFabricRecvUnchecked(PTRFContext ctx, PTRFMem mem, 
                                             void * addr, size_t len, 
                                             fi_addr_t peer)
{
    if (!ctx || !mem || !addr)
        return -EINVAL;

    PTRFXFabric f       = ctx->xfer.fabric;
    return trf__FabricTrackedRecv(f->rx_cq, f->ep, peer, mem, addr, len);
}

/**
 * @brief           Send a raw message on the fabric connection. The memory
 *                  region passed to this operation must remain valid until the
 *                  completion is received. Additionally, the peer must be
 *                  registered in the address vector and called trfFabricRecv()
 *                  with an adequately sized memory buffer.
 *
 * @param ctx       Context to use for the send.
 * 
 * @param mem       Memory region details.
 * 
 * @param addr      Buffer start address. Must be within the memory region.
 * 
 * @param len       Length of the buffer.
 * 
 * @param peer      Peer address.
 * 
 * @param opts      Options to use for the send. If not specified, the default
 *                  context options are used instead.
 * 
 * @return          0 on success, negative error code on failure.
 */
ssize_t trfFabricSend(PTRFContext ctx, PTRFMem mem, void * addr, size_t len,
                      fi_addr_t peer, PTRFContextOpts opts);

/**
 * @brief           Receive a raw message on the fabric connection. The memory
 *                  region passed to this operation must remain valid until the
 *                  completion is received. The peer must be registered in the
 *                  address vector.
 *
 * @param ctx       Context to use for the send.
 *
 * @param mem       Memory region details.
 *
 * @param addr      Buffer start address. Must be within the memory region.
 *
 * @param len       Length of the buffer.
 *
 * @param peer      Peer address.
 *
 * @param opts      Options to use for the receive. If not specified, the
 *                  default context options are used instead.
 *
 * @return          0 on success, negative error code on failure.
 */
ssize_t trfFabricRecv(PTRFContext ctx, PTRFMem mem, void * addr, size_t len,
                      fi_addr_t peer, PTRFContextOpts opts);

/**
 * @brief           Send a TRF formatted message over the fabric connection.
 * 
 *                  This should only be used for messages on the main channel.
 *                  Subchannels should use a user-defined data format.
 *
 * @param ctx       Context to use for the send.
 * 
 * @param mem       Memory region details.
 * 
 * @param addr      Buffer start address. Must be within the memory region.
 * 
 * @param len       Length of the buffer.
 * 
 * @param peer      Peer address.
 * 
 * @param opts      Options to use for the send. If not specified, the default
 *                  context options are used instead.
 * 
 * @param msg       Message to send.
 * 
 * @return          0 on success, negative error code on failure.
 */
ssize_t trfFabricSendMsg(PTRFContext ctx, PTRFMem mem, void * addr, size_t len,
                         fi_addr_t peer, PTRFContextOpts opts, 
                         TrfMsg__MessageWrapper * msg);

/**
 * @brief           Receive a TRF formatted message over the fabric connection.
 *                  
 *                  This should only be used for messages on the main channel.
 *                  Subchannels should use a user-defined data format.
 * 
 * @param ctx       Context to use for the send.
 * 
 * @param mem       Memory region details.
 * 
 * @param addr      Buffer start address. Must be within the memory region.
 * 
 * @param len       Length of the buffer.
 * 
 * @param peer      Peer address.
 * 
 * @param opts      Options to use for the receive. If not specified, the
 *                  default context options are used instead.
 * 
 * @param msg       Pointer to be set to the received message.
 * 
 * @return          0 on success, negative error code on failure.
 */
ssize_t trfFabricRecvMsg(PTRFContext ctx, PTRFMem mem, void * addr, size_t len,
                         fi_addr_t peer, PTRFContextOpts opts, 
                         TrfMsg__MessageWrapper ** msg);

#endif