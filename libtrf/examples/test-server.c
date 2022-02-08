/*
    SPDX-License-Identifier: LGPL-2.1-only

    Telescope Project
    Example Server

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
#include "trf_ncp.h"
#include <signal.h>

int main(int argc, char ** argv)
{
    char* host = "127.0.0.1";
    char* port = "35085";

    PTRFContext ctx = trfAllocContext();
    if (trfNCServerInit(ctx,host,port) < 0)
    {
        fflush(stdout);
        return -1;
    }
    PTRFContext client_ctx = trfAllocContext();
    if (trfNCAccept(ctx , client_ctx ) < 0)
    {
        fflush(stdout);
        return -1;
    }

    printf("Hello!\n");

    trfDestroyContext(client_ctx);
    trfDestroyContext(ctx);

}