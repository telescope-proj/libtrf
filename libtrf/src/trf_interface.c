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

#include "trf_interface.h"

int trfRemoveInvalid(PTRFInterface ifs, PTRFInterface * out_ifs, int * n_ifs)
{
    int n = 0;
    PTRFInterface out_tmp = calloc(1, sizeof(out_tmp));
    if (!out_tmp)
    {
        trf__log_error("Memory allocation failed");
        return -ENOMEM;
    }
    PTRFInterface out_start = out_tmp;
    for (PTRFInterface tmp_ifs = ifs; tmp_ifs; tmp_ifs = tmp_ifs->next)
    {
        if (tmp_ifs->flags & TRFI_VALID)
        {
            n++;
            out_tmp->addr       = tmp_ifs->addr;
            out_tmp->flags      = tmp_ifs->flags;
            out_tmp->port       = tmp_ifs->port;
            out_tmp->speed      = tmp_ifs->speed;
            out_tmp->next       = calloc(1, sizeof(*out_ifs));
            if (!out_tmp->next)
            {
                trf__log_error("Memory allocation failed");
                trfFreeInterfaceList(out_tmp);
                return -ENOMEM;
            }
            out_tmp = out_tmp->next;
        }
    }
    
    *out_ifs    = out_start;
    *n_ifs      = n;
    return 0;
}

void trfFreeAddrV(PTRFAddrV av)
{
    PTRFAddrV v = av;
    PTRFAddrV vn;
    while (v)
    {
        vn = v->next;
        free(v->src_addr);
        free(v->dst_addr);
        free(v);
        v = vn;
    }
}

static int trf__InterfaceLength(PTRFInterface iface)
{
    int count = 0;
    for (; iface; iface = iface->next)
    {
        count++;
    }
    return count;
}

int trfCreateAddrV(PTRFInterface src, PTRFInterface dest,
    PTRFAddrV * av_out)
{
    if (!src || !dest)
    {
        trf__log_warn("Invalid data passed to interface pair creator");
        return -EINVAL;
    }

    PTRFAddrV av_tmp = malloc(sizeof(*av_tmp));
    PTRFAddrV av_start = av_tmp;

    trf__log_trace("Lengths: src: %d, dest: %d",
        trf__InterfaceLength(src), trf__InterfaceLength(dest));

    int i = 0;
    int j = 0;

    for (PTRFInterface tmp_src = src; tmp_src; tmp_src = tmp_src->next)
    {
        for (PTRFInterface tmp_dest = dest; tmp_dest; tmp_dest = tmp_dest->next)
        {
            trf__log_trace("(link) src: %d, dest: %d", tmp_src->speed, 
                tmp_dest->speed);
            if (tmp_src->addr->sa_family != tmp_dest->addr->sa_family)
            {
                trf__log_trace("Addr family mismatch %d - %d", 
                    tmp_src->addr->sa_family, tmp_dest->addr->sa_family);
                continue;
            }
            if (tmp_src->addr->sa_family == AF_INET)
            {
                if (
                    (((struct sockaddr_in *) &tmp_src->addr)->sin_addr.s_addr 
                    & htonl((uint32_t) -1 >> tmp_src->netmask)) ==
                    (((struct sockaddr_in *) &tmp_dest->addr)->sin_addr.s_addr 
                    & htonl((uint32_t) -1 >> tmp_dest->netmask))
                )
                {
                    av_tmp->src_addr = malloc(sizeof(struct sockaddr_in));
                    av_tmp->dst_addr = malloc(sizeof(struct sockaddr_in));
                    * (struct sockaddr_in *) av_tmp->src_addr = \
                        * (struct sockaddr_in *) tmp_src->addr;
                    * (struct sockaddr_in *) av_tmp->dst_addr = \
                        * (struct sockaddr_in *) tmp_dest->addr;
                    av_tmp->pair_speed = tmp_src->speed >= tmp_dest->speed ?
                        tmp_dest->speed : tmp_src->speed;
                    av_tmp->next = calloc(1, sizeof(*av_tmp));
                    if (!av_tmp->next)
                    {
                        trf__log_error("Memory allocation failed");
                        trfFreeAddrV(av_start);
                        return -ENOMEM;
                    }
                }
            }
            else if (tmp_src->addr->sa_family == AF_INET6)
            {
                uint64_t * ca1 = (uint64_t *) \
                    ((struct sockaddr_in6 *) &tmp_src->addr)->sin6_addr.s6_addr;
                uint64_t * ca2 = ca1++;

                uint64_t * da1 = (uint64_t *) \
                    ((struct sockaddr_in6 *) &tmp_dest->addr)->sin6_addr.s6_addr;
                uint64_t * da2 = da1++;

                uint64_t cnm1 = tmp_src->netmask > 64 ? \
                    htobe64((uint64_t) -1 >> 63) : \
                    htobe64((uint64_t) -1 >> (tmp_dest->netmask - 1));
                uint64_t cnm2 = tmp_src->netmask > 64 ? \
                    htobe64((uint64_t) -1 >> (tmp_src->netmask - 65)) : \
                    0;

                uint64_t dnm1 = tmp_dest->netmask > 64 ? \
                    htobe64((uint64_t) -1 >> 63) : \
                    htobe64((uint64_t) -1 >> (tmp_dest->netmask - 1));
                uint64_t dnm2 = tmp_dest->netmask > 64 ? \
                    htobe64((uint64_t) -1 >> (tmp_dest->netmask - 65)) : \
                    0;
                    
                uint64_t cr1 = *ca1 & cnm1;
                uint64_t cr2 = *ca2 & cnm2;
                uint64_t sr1 = *da1 & dnm1;
                uint64_t sr2 = *da2 & dnm2;

                if (cr1 == sr1 && cr2 == sr2)
                {
                    av_tmp->src_addr = malloc(sizeof(struct sockaddr_in6));
                    av_tmp->dst_addr = malloc(sizeof(struct sockaddr_in6));
                    * (struct sockaddr_in6 *) av_tmp->src_addr = \
                        * (struct sockaddr_in6 *) tmp_src->addr;
                    * (struct sockaddr_in6 *) av_tmp->dst_addr = \
                        * (struct sockaddr_in6 *) tmp_dest->addr;
                    av_tmp->pair_speed = tmp_src->speed >= tmp_dest->speed ?
                        tmp_dest->speed : tmp_src->speed;
                    av_tmp->next = calloc(1, sizeof(*av_tmp));
                    if (!av_tmp->next)
                    {
                        trf__log_error("Memory allocation failed");
                        trfFreeAddrV(av_start);
                        return -ENOMEM;
                    }
                }
            }
            else
            {
                trf__log_warn("Unknown address family");
                continue;
            }
            trf__log_trace("Pair speed: %d", av_tmp->pair_speed);
            av_tmp = av_tmp->next;
            j++;
        }
        i++;
    }

    free(av_tmp->next);
    *av_out = av_start;
    return 0;
}

void trfFreeInterfaceList(PTRFInterface ifaces)
{
    PTRFInterface iface_tmp = ifaces;
    while (iface_tmp)
    {
        PTRFInterface next = iface_tmp->next;
        free(iface_tmp->addr);
        free(iface_tmp);
        iface_tmp = next;
    }
}

int trfGetInterfaceList(PTRFInterface * list_out, uint32_t * length)
{
    #if defined(__linux__)
    
    if (!list_out || !length)
    {
        trf__log_error("Invalid arguments for trfGetInterfaceList()");
        return -EINVAL;
    }
    
    int len = 0;
    int out;
    struct ifaddrs * ifa, * ifa_tmp;
    struct TRFInterface * trfi = calloc(1, sizeof(struct TRFInterface));
    if (!trfi)
    {
        trf__log_error("Could not allocate interface list storage");
        return -ENOMEM;
    }

    struct TRFInterface * trf_tmp = trfi;
    if (getifaddrs(&ifa) < 0)
    {
        trf__log_error("getifaddrs() error: %s", strerror(errno));
        goto freenomem;
    }

    for (ifa_tmp = ifa; ifa_tmp; ifa_tmp = ifa_tmp->ifa_next)
    {
        if (ifa_tmp->ifa_addr)
        {
            out = trfGetLinkSpeed(ifa_tmp->ifa_name, &trf_tmp->speed);
            if (out < 0 || trf_tmp->speed < 0)
            {
                trf__log_warn("Unable to get interface speed for %s", 
                    ifa_tmp->ifa_name);
            }
            switch (ifa_tmp->ifa_addr->sa_family)
            {
                char dbg[INET6_ADDRSTRLEN];
                case AF_INET:
                    trf__log_trace("Actual Mask %s", inet_ntop(AF_INET, 
                        &((struct sockaddr_in *) ifa_tmp->ifa_netmask)->sin_addr.s_addr,
                        dbg, INET_ADDRSTRLEN
                    ));
                    trf_tmp->netmask = trf__HammingWeight64(
                        ((struct sockaddr_in *) \
                            ifa_tmp->ifa_netmask)->sin_addr.s_addr
                    );
                    trf_tmp->addr = malloc(sizeof(struct sockaddr_in));
                    if (!trf_tmp->addr)
                    {
                        trf__log_error("Memory allocation failed");
                        goto freenomem;
                    }
                    memcpy(trf_tmp->addr, ifa_tmp->ifa_addr, 
                        sizeof(struct sockaddr_in));
                    break;
                case AF_INET6:
                    trf__log_trace("Actual Mask %s", inet_ntop(AF_INET6, 
                        &((struct sockaddr_in6 *) ifa_tmp->ifa_netmask)->sin6_addr.s6_addr,
                        dbg, INET6_ADDRSTRLEN
                    ));
                    uint8_t tmp = 0;
                    uint64_t * addr_ptr = (uint64_t *) &((struct sockaddr_in6 *) \
                        ifa_tmp->ifa_netmask)->sin6_addr.s6_addr;
                    tmp += trf__HammingWeight64((uint64_t) *addr_ptr);
                    tmp += trf__HammingWeight64((uint64_t) *++addr_ptr);
                    trf_tmp->netmask = tmp;
                    trf_tmp->addr = malloc(sizeof(struct sockaddr_in6));
                    if (!trf_tmp->addr)
                    {
                        trf__log_error("Memory allocation failed");
                        goto freenomem;
                    }
                    memcpy(trf_tmp->addr, ifa_tmp->ifa_addr, 
                        sizeof(struct sockaddr_in6));
                    break;
                default:
                    trf__log_warn("Unknown address family %d", 
                        ifa_tmp->ifa_addr->sa_family);
            }

            

            if (trf_tmp->netmask)
            {
                trf__log_trace("Netmask: %d", trf_tmp->netmask);   
                if (ifa_tmp->ifa_next)
                {
                    trf_tmp->next = calloc(1, sizeof(struct TRFInterface));
                    if (!trf_tmp->next)
                    {
                        trf__log_error("%s", strerror(ENOMEM));
                        goto freenomem;
                    }
                    trf_tmp = trf_tmp->next;
                }
                len++;
            } else {

            }

        }
    }

    freeifaddrs(ifa);

    *length = len;  // shut up compiler waeeee
    *list_out = trfi;
    return 0;
    
    #else
    return -ENOSYS;
    #endif

freenomem:
    out = -ENOMEM;
    trfFreeInterfaceList(trfi);
    freeifaddrs(ifa);
    return out;
}

int trfGetFastestLink(PTRFAddrV av, PTRFAddrV * av_out)
{
    if (!av || !av_out)
    {
        trf__log_error("Invalid arguments for trfGetFastestLink()");
        return -EINVAL;
    }

    int32_t max_spd = -2;
    PTRFAddrV av_tmp = av;
    PTRFAddrV av_max = av;
    while (av_tmp)
    {
        if (av_tmp->pair_speed > max_spd)
        {
            trf__log_debug("Fastest pair speed: %d", av_tmp->pair_speed);
            av_max = av_tmp;
            max_spd = av_tmp->pair_speed;
        }
        av_tmp = av_tmp->next;
    }

    *av_out = av_max;
    return 0;
}

int trfGetLinkSpeed(char * ifname, int32_t * speed_out)
{
    #if defined(__linux__)

    if (!ifname || !speed_out)
    {
        return -EINVAL;
    }
    
    int sock;
    struct ifreq ifr;
    struct ethtool_cmd edata;
    int rc;
    
    if (strnlen(ifname, sizeof(ifr.ifr_name) + 1) > sizeof(ifr.ifr_name))
    {
        trf__log_warn("Interface name too long");
        return -EOVERFLOW;
    }

    sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
    if (sock < 0) {
        trf__log_warn("Link speed check failed");
        return -1;
    }
    
    strncpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name));
    ifr.ifr_data = &edata;

    edata.cmd = ETHTOOL_GSET;

    rc = ioctl(sock, SIOCETHTOOL, &ifr);
    if (rc < 0) {
        trf__log_warn("Unknown link speed on interface %s", ifname);
        return -1;
    }

    uint32_t rate = ethtool_cmd_speed(&edata);
    trf__log_debug("Interface: %s, Rate: %d Mbps", ifname, rate);
    *speed_out = rate;
    return 0;

    #else
    return -ENOSYS;
    #endif
}