/*
    SPDX-License-Identifier: LGPL-2.1-only

    Telescope Project
    Remote Framebuffer Library
    Interface & Address Vector Management

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

#ifndef _TRF_INTERFACE_H_
#define _TRF_INTERFACE_H_

#include "trf.h"
#include "trf_def.h"
#include "internal/trfi.h"
#include "trf_platform.h"

/**
 * @file trf_interface.h
 * @brief Interface & Address Vector Management
*/

/**
  * @brief Mark an address in an interface list as valid and reachable.
  * @param addr         Address to mark
  * @param clientIf     Interface List
  * @return True on success, False on failure
*/
bool trfValidRouteUpdate(PTRFInterface clientIf, char *address);

/**
  * @brief Remove invalid or unreachable addresses from an interface list.
  * @param ifs:     PTRFInterface for client
  * @param out_ifs  new interface to return to client
  * @param n_ifs    Number of interfaces in the new list
  * @return 0 on success, negative error code on failure
*/
int trfRemoveInvalid(PTRFInterface ifs, PTRFInterface * out_ifs, int * n_ifs);

/**
  * @brief Free an address vector
  * @param av   Address vector to free
  * @return no return value
*/
void trfFreeAddrV(PTRFAddrV av);

/**
 * @brief Sort an address vector.
 * 
 * @param av  Address vector to sort
 * @return    int 
 */
int trfSortAddrV(PTRFAddrV av);

/**
  * @brief Create an address vector list containing viable links between two
  * interface lists.
  * @param src      Souce addresses
  * @param dest     Destination addresses
  * @param av_out   Output address vector list
  * @return 0 on success, -errno on failure
*/
int trfCreateAddrV(PTRFInterface src, PTRFInterface dest,
    PTRFAddrV * av_out);

/**
  * @brief Free an interface list.
  * @param ifaces   Interfaces list to free
  * @return no return value
*/
void trfFreeInterfaceList(PTRFInterface ifaces);

/**
  * @brief Create an interface list containing all interfaces on the system.
  * @param list_out     Output interface list
  * @param length       Output interface list length
  * @param flags        Flags used to limit interfaces returned
  * @return 0 on success, negative error code on failure
*/
int trfGetInterfaceList(PTRFInterface * list_out, uint32_t * length, uint64_t flags);

/**
  * @brief Determine the fastest interface in the address vector.
  * @param av       Addess vector to search
  * @param av_out: Pointer to the node inside av containing the fastest interface
  * @return 0 on success, negative error code on failure
*/
int trfGetFastestLink(PTRFAddrV av, PTRFAddrV * av_out);

/**
  * @brief Get the link speed of an interface.
  * @param iface        Interface name
  * @param speed_out    Speed
  * @return 0 on success, negative error code on failure
*/
int trfGetLinkSpeed(char * ifname, int32_t * speed_out);

/**
 * @brief Get the length of an interface list.
 * 
 * @param list 
 * @return int 
 */
static inline int trfGetInterfaceListLength(PTRFInterface list)
{
    if (!list)
        return -EINVAL;
    
    int i = 0;
    PTRFInterface tmp = list;
    while (tmp)
    {
        i++;
        tmp = tmp->next;
    }
    return i;
}

#endif // _TRF_INTERFACE_H_