/*
    SPDX-License-Identifier: LGPL-2.1-only

    Telescope Project
    Remote Framebuffer Library
    Address Parsing Functions

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
  * @file trf_inet.h
  * @brief Address Parsing Function
*/
#ifndef _TRF_INET_H_
#define _TRF_INET_H_

#include "trf.h"

/**
  * @brief Check ip address if it is IPV4 or IPV6
  * @param addr    the ip address string 
  * @return 4 if it is ipv4, 6 if it is ipv6, and -1 if it is neither
*/
int trfCheckIPVersion(char* addr);

/**
  * @brief Converts and IPV6-mapped IPV4 address to an IPV4 address
  * @param addr     The sockaddr_in6 struct container the ipv6 mapped address
  * @param address  Char pointer the store the decoded ipv4 address
  * @return returns 0 on success, negative error code on failure
*/
int trfGetMappedIPv4addr(struct sockaddr_in6 * addr,char * address);

/**
  * @brief Converts a sockaddr structure to string
  * @param sdr      Address sockaddr container the ip address to be decoded
  * @param addr     Char pointer to store the decoded ip address
  * @return 0 on success, negative error code on failure 
*/
int trfGetIPaddr(struct sockaddr * sdr, char * addr);

/**
  * @brief Converts a string to an address structure
  * @param addr     Char pointer of the IP Address
  * @param sdr      Sockaddr struct to be decoded into
  * @return 0 on success, negative error code on failure
*/
int trfConvertCharToAddr(char * addr, struct sockaddr * sdr);

/**
 * @brief Converts a sockaddr structure into a string containing a node and
 * service name in the format node:service for IPv4 and [node]:service for IPv6.
 *
 * @param sdr       Address sockaddr containing the ip address to be decoded
 * 
 * @param addr      Pointer to store the decoded ip address
 * 
 * @return          0 on success, negative error code on failure
 */
int trfGetNodeService(struct sockaddr * sdr, char * addr);

/**
  * @brief Convert Node service to sockaddr struct
  * @param addr     addr
  * @param sdr      sockadd output
  * @return 0 on success, negative error code on failure
*/
int trfNodeServiceToAddr(const char * addr, struct sockaddr * sdr);

/**
  * @brief Remove Character
  * @param addr   string
  * @param ch     Character to remove
*/
int removeCharacter(char *addr, char ch);
#endif // _TRF_INET_H_