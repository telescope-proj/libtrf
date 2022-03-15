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
 * @file    trf_ncp.h
 * @brief   Negotiation Channel Protocol Messaging Functions
 */

#ifndef _TRF_NCP_H_
#define _TRF_NCP_H_

#include "trf.h"
#include "trf_def.h"
#include "trf_msg.h"
#include "trf_inet.h"
#include "trf_interface.h"
#include "trf_protobuf.h"
#include "trf_platform.h"

#include <string.h>
#include <stdlib.h>

#if defined(__linux__)
#include <linux/sockios.h>
#include <linux/if.h>
#include <linux/ethtool.h>
#endif

#if defined(_TRF_UNIX_)
    #include <ifaddrs.h>
    #include <sys/ioctl.h>
    #include <netinet/in.h>
    #if defined(_TRF_OSX_)
        #include "osx/endian.h"
    #else
        #include <endian.h>
    #endif
    #include <fcntl.h>
#endif

#define TRF_API_MAJOR    0
#define TRF_API_MINOR    2
#define TRF_API_PATCH    2

/**
  * @brief Add Protobuf message to PTRFInterface
  * @param msg      Protobuf message wrapper
  * @param out      PTRFInterface to message to be decoded into
  * @return 0 on success, negative error code on failure
*/
int trf__AddrMsgToInterface(TrfMsg__MessageWrapper * msg, PTRFInterface * out);

#endif