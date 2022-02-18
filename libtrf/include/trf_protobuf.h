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

/**
 * @file    trf_protobuf.h
 * @brief   Protocol Buffers Message Conversion Functions
*/

#ifndef _TRF_PROTOBUF_H_
#define _TRF_PROTOBUF_H_

#include "trf_msg.pb-c.h"

enum TRFM_Type {
    TRFM_INVALID          = 0,
    TRFM_CLIENT_HELLO     = (1 << 0),
    TRFM_SERVER_HELLO     = (1 << 1),
    TRFM_SERVER_REJECT    = (1 << 2),
    TRFM_DISCONNECT       = (1 << 3),
    TRFM_CLIENT_CAP       = (1 << 4),
    TRFM_SERVER_CAP       = (1 << 5),
    TRFM_ENDPOINT         = (1 << 6),
    TRFM_CLIENT_DISP_REQ  = (1 << 7),
    TRFM_SERVER_DISP      = (1 << 8),
    TRFM_CLIENT_REQ       = (1 << 9),
    TRFM_SERVER_ACK       = (1 << 10),
    TRFM_CLIENT_F_REQ     = (1 << 11),
    TRFM_SERVER_ACK_F_REQ = (1 << 12),
    TRFM_ADDR_PF          = (1 << 13),
    TRFM_CH_OPEN          = (1 << 14),
    TRFM_MAX              = (1 << 15)
};

/**
 * @brief Hello message types
*/
#define TRFM_SET_HELLO     (TRFM_CLIENT_HELLO | TRFM_SERVER_HELLO | TRFM_SERVER_REJECT | TRFM_DISCONNECT)
/**
 * @brief Capability exchange messages
 */
#define TRFM_SET_CAP       (TRFM_CLIENT_CAP | TRFM_SERVER_CAP)
/**
 * @brief Display metadata messages
 */
#define TRFM_SET_DISP      (TRFM_CLIENT_DISP_REQ | TRFM_SERVER_DISP)
/**
 * @brief Display source setup messages
 */
#define TRFM_SET_REQ       (TRFM_CLIENT_REQ | TRFM_SERVER_ACK)
/**
 * @brief Frame request messages
 */
#define TRFM_SET_F_REQ     (TRFM_CLIENT_F_REQ | TRFM_SERVER_ACK_F_REQ)
/**
 * @brief Channel fast open messages
 */
#define TRFM_SET_OPEN      (TRFM_CH_OPEN)
/**
 * @brief Connection setup and control messages
 */
#define TRFM_SET_CONTROL   (TRFM_HELLO | TRFM_CAP | TRFM_DISP | TRFM_REQ | TRFM_OPEN)
/**
 * @brief Framebuffer data control messages
 */
#define TRFM_SET_DATA      (TRFM_F_REQ)
/**
 * @brief All messages
*/
#define TRFM_SET_ALL       (TRFM_MAX - 1)

static inline uint64_t trfPBToInternal(int pb_type)
{
    switch (pb_type)
    {
        case TRF_MSG__MESSAGE_WRAPPER__WDATA_CLIENT_HELLO:
            return TRFM_CLIENT_HELLO;
        case TRF_MSG__MESSAGE_WRAPPER__WDATA_SERVER_HELLO:
            return TRFM_SERVER_HELLO;
        case TRF_MSG__MESSAGE_WRAPPER__WDATA_DISCONNECT:
            return TRFM_DISCONNECT;
        case TRF_MSG__MESSAGE_WRAPPER__WDATA_CLIENT_CAP:
            return TRFM_CLIENT_CAP;
        case TRF_MSG__MESSAGE_WRAPPER__WDATA_SERVER_CAP:
            return TRFM_SERVER_CAP;
        case TRF_MSG__MESSAGE_WRAPPER__WDATA_ENDPOINT:
            return TRFM_ENDPOINT;
        case TRF_MSG__MESSAGE_WRAPPER__WDATA_CLIENT_DISP_REQ:
            return TRFM_CLIENT_DISP_REQ;
        case TRF_MSG__MESSAGE_WRAPPER__WDATA_SERVER_DISP:
            return TRFM_SERVER_DISP;
        case TRF_MSG__MESSAGE_WRAPPER__WDATA_CLIENT_REQ:
            return TRFM_CLIENT_REQ;
        case TRF_MSG__MESSAGE_WRAPPER__WDATA_SERVER_ACK:
            return TRFM_SERVER_ACK;
        case TRF_MSG__MESSAGE_WRAPPER__WDATA_CLIENT_F_REQ:
            return TRFM_CLIENT_F_REQ;
        case TRF_MSG__MESSAGE_WRAPPER__WDATA_SERVER_ACK_F_REQ:
            return TRFM_SERVER_ACK_F_REQ;
        case TRF_MSG__MESSAGE_WRAPPER__WDATA_ADDR_PF:
            return TRFM_ADDR_PF;
        case TRF_MSG__MESSAGE_WRAPPER__WDATA_CH_OPEN:
            return TRFM_CH_OPEN;
        default:
            return TRFM_INVALID;
    }
}

static inline uint64_t trfInternalToPB(enum TRFM_Type type)
{
    switch (type)
    {
        case TRFM_CLIENT_HELLO:
            return TRF_MSG__MESSAGE_WRAPPER__WDATA_CLIENT_HELLO;
        case TRFM_SERVER_HELLO:
            return TRF_MSG__MESSAGE_WRAPPER__WDATA_SERVER_HELLO;
        case TRFM_DISCONNECT:
            return TRF_MSG__MESSAGE_WRAPPER__WDATA_DISCONNECT;
        case TRFM_CLIENT_CAP:
            return TRF_MSG__MESSAGE_WRAPPER__WDATA_CLIENT_CAP;
        case TRFM_SERVER_CAP:
            return TRF_MSG__MESSAGE_WRAPPER__WDATA_SERVER_CAP;
        case TRFM_ENDPOINT:
            return TRF_MSG__MESSAGE_WRAPPER__WDATA_ENDPOINT;
        case TRFM_CLIENT_DISP_REQ:
            return TRF_MSG__MESSAGE_WRAPPER__WDATA_CLIENT_DISP_REQ;
        case TRFM_SERVER_DISP:
            return TRF_MSG__MESSAGE_WRAPPER__WDATA_SERVER_DISP;
        case TRFM_CLIENT_REQ:
            return TRF_MSG__MESSAGE_WRAPPER__WDATA_CLIENT_REQ;
        case TRFM_SERVER_ACK:
            return TRF_MSG__MESSAGE_WRAPPER__WDATA_SERVER_ACK;
        case TRFM_CLIENT_F_REQ:
            return TRF_MSG__MESSAGE_WRAPPER__WDATA_CLIENT_F_REQ;
        case TRFM_SERVER_ACK_F_REQ:
            return TRF_MSG__MESSAGE_WRAPPER__WDATA_SERVER_ACK_F_REQ;
        case TRFM_ADDR_PF:
            return TRF_MSG__MESSAGE_WRAPPER__WDATA_ADDR_PF;
        case TRFM_CH_OPEN:
            return TRF_MSG__MESSAGE_WRAPPER__WDATA_CH_OPEN;
        default:
            return TRF_MSG__MESSAGE_WRAPPER__WDATA__NOT_SET;
    }
}

#endif