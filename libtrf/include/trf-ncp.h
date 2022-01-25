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

#pragma once

#include "trf.h"

#define TRF_API_MAJOR    0
#define TRF_API_MINOR    1
#define TRF_API_PATCH    0

/*  Initialize the out-of-band negotiation channel server.
    Sets the listening FD inside the context.
    ctx: Context to use.
    host: Hostname to bind to.
    port: Port to bind to.
    Returns 0 on success, negative error code on failure.
*/
int trfNCServerInit(PTRFContext ctx, char * host, char * port);

/*  Initialize the out-of-band negotiation channel client.
    Sets the client FD inside of the context to an established connection.
    ctx: Context to use.
    host: Hostname to connect to.
    port: Port to connect to.
    Returns 0 on success, negative error code on failure.
*/
int trfNCServerInit(PTRFContext ctx, char * host, char * port);

/*  Accept an incoming connection.
    Sets the client FD inside of the context to the accepted connection.
    ctx: Context to use.
    Returns 0 on success, negative error code on failure.
*/
int trfNCAccept(PTRFContext ctx);

/*  Close the negotiation channel server, disconnecting the client.
    ctx: Context to use.
    Returns 0 on success, negative error code on failure.
*/
int trfNCServerClose(PTRFContext ctx);

/*  Close the negotiation channel client.
    ctx: Context to use.
    Returns 0 on success, negative error code on failure.
*/
int trfNCClientClose(PTRFContext ctx);

