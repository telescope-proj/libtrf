/*
    SPDX-License-Identifier: LGPL-2.1-only

    Telescope Project
    Remote Framebuffer Library
    Preflight Requests

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
 * @file trf_preflight.h
 * @brief Preflight Requests
*/

#ifndef _TRF_PREFLIGHT_H_
#define _TRF_PREFLIGHT_H_

#include "trf.h"
#include "trf_inet.h"

/**
  * @brief Get Client reachables to server 
  * @param serverIf     Server reachable interfaces
  * @param sessionID    SessionID provided by the server during handshake
  * @return 0 on success, negative error code on failure
*/
int trfNCClientGetReachable(PTRFInterface serverIf, int64_t sessionID);

/**
  * @brief Start server socket for client to test connections
  * @param fd_out       socket the server is listening to connections on
  * @param port         port listening for connections
  * @return 0 on success, negative error code on failure
*/
int trfNCServerPreFlight(int * fd_out, uint16_t * port);

/**
  * @brief Check Incoming connections src addresses
  * @param sfd          socket server is listening on
  * @param timeout      timeout for preflight checking
  * @param session_id   session_id
  * @param addrs        list fo addresses client will be coming from 
*/
int trfNCServerPreFlightCheck(int sfd, int timeout, uint64_t session_id, 
    PTRFInterface addrs);

#endif // _TRF_PREFLIGHT_H_