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
#include "trf_platform.h"

int trfRemoveInvalid(PTRFInterface ifs, PTRFInterface * out_ifs, int * n_ifs)
{
    int n = 0;
    PTRFInterface out_tmp = calloc(1, sizeof(*out_tmp));
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
            out_tmp->next       = calloc(1, sizeof(*out_tmp));
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
    while (v)
    {
        PTRFAddrV v2 = v->next;
        free(v->src_addr);
        free(v->dst_addr);
        free(v);
        v = v2;
    }
}

PTRFAddrV trfDuplicateAddrV(PTRFAddrV av)
{
    PTRFAddrV out = calloc(1, sizeof(*out));
    if (!out)
    {
        trf__log_error("Memory allocation failed");
        return NULL;
    }
    PTRFAddrV out_start = out;
    PTRFAddrV out_prev = NULL;
    PTRFAddrV v = av;
    while (v)
    {
        out->src_addr = calloc(1, sizeof(*out->src_addr));
        if (!out->src_addr)
        {
            trf__log_error("Memory allocation failed");
            trfFreeAddrV(out_start);
            return NULL;
        }
        memcpy(out->src_addr, v->src_addr, sizeof(*out->src_addr));
        out->dst_addr = calloc(1, sizeof(*out->dst_addr));
        if (!out->dst_addr)
        {
            trf__log_error("Memory allocation failed");
            trfFreeAddrV(out_start);
            return NULL;
        }
        memcpy(out->dst_addr, v->dst_addr, sizeof(*out->dst_addr));
        out->next = calloc(1, sizeof(*out->next));
        if (!out->next)
        {
            trf__log_error("Memory allocation failed");
            trfFreeAddrV(out_start);
            return NULL;
        }
        out->pair_speed = v->pair_speed;
        out_prev = out;
        out = out->next;
        v = v->next;
    }

    if (out_prev)
    {
        trfFreeAddrV(out_prev->next);
        out_prev->next = NULL;
    }

    return out_start;
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

#define trf__Netmask4(n) ((n) == 0 ? 0 : htonl((n) == 32 ? 0xFFFFFFFF : (0xFFFFFFFF << (32 - (n)))))
#define TRF__PSAI struct sockaddr_in *
#define TRF__PSAI6 struct sockaddr_in6 *
#define trf__RawAddr4(a) (((TRF__PSAI)a)->sin_addr.s_addr)
#define trf__RawAddr6(a) (((TRF__PSAI6)a)->sin6_addr.s6_addr)

int trfCreateAddrV(PTRFInterface src, PTRFInterface dest,
    PTRFAddrV * av_out)
{
    if (!src || !dest)
    {
        trf__log_warn("Invalid data passed to interface pair creator");
        return -EINVAL;
    }

    PTRFAddrV av_tmp = calloc(1, sizeof(*av_tmp));
    if (!av_tmp)
    {
        return - ENOMEM;
    }
    PTRFAddrV av_start = av_tmp;
    PTRFAddrV av_prev = NULL;

    trf__log_trace("Lengths: src: %d, dest: %d",
        trf__InterfaceLength(src), trf__InterfaceLength(dest));
 
    int i = 0;
    int j = 0;

    for (PTRFInterface tmp_src = src; tmp_src; tmp_src = tmp_src->next)
    {
        for (PTRFInterface tmp_dest = dest; tmp_dest; tmp_dest = tmp_dest->next)
        {
            uint8_t flag = 0;
            if (tmp_src->addr->sa_family != tmp_dest->addr->sa_family)
            {
                trf__log_trace("Address family mismatch");
                continue;
            }
            trf__log_trace("[link %d] src: %d, dest: %d", j, tmp_src->speed, 
                tmp_dest->speed);
            if (tmp_src->addr->sa_family == AF_INET)
            {
                if (
                    (trf__RawAddr4(tmp_src->addr) 
                    & trf__Netmask4(tmp_src->netmask)) ==
                    (trf__RawAddr4(tmp_dest->addr)
                    & trf__Netmask4(tmp_dest->netmask))
                )
                {
                    trf__log_debug("Netmask matched");
                    av_tmp->src_addr = calloc(1, sizeof(struct sockaddr_in));
                    av_tmp->dst_addr = calloc(1, sizeof(struct sockaddr_in));
                    if (!av_tmp->src_addr || !av_tmp->dst_addr)
                    {
                        trf__log_error("Memory allocation failed");
                        trfFreeAddrV(av_start);
                        return -ENOMEM;
                    }
                    * (TRF__PSAI) av_tmp->src_addr = \
                        * (TRF__PSAI) tmp_src->addr;
                    * (TRF__PSAI) av_tmp->dst_addr = \
                        * (TRF__PSAI) tmp_dest->addr;
                    av_tmp->pair_speed = tmp_src->speed >= tmp_dest->speed ?
                        tmp_dest->speed : tmp_src->speed;
                    av_tmp->next = calloc(1, sizeof(*av_tmp));
                    if (!av_tmp->next)
                    {
                        trf__log_error("Memory allocation failed");
                        trfFreeAddrV(av_start);
                        return -ENOMEM;
                    }
                    flag = 1;
                }
                else
                {
                    trf__log_trace("Netmask not matched");
                    continue;
                }
            }
            else if (tmp_src->addr->sa_family == AF_INET6)
            {
                trf__log_debug("Skipping IPv6 interface");
                continue;
            }
            else
            {
                trf__log_warn("Unknown address family");
                continue;
            }
            trf__log_trace("Pair speed: %d", av_tmp->pair_speed);
            if (flag)
            {
                av_prev = av_tmp;
                av_tmp = av_tmp->next;
                j++;
            }
        }
        i++;
    }

    free(av_tmp);
    if (av_prev)
    {
        av_prev->next = NULL;
    }
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

int trfGetInterfaceList(PTRFInterface * list_out, uint32_t * length, uint64_t flags)
{
    #ifdef _TRF_UNIX_
    
    if (!list_out || !length)
    {
        trf__log_error("Invalid arguments for trfGetInterfaceList()");
        return -EINVAL;
    }
    
    int len = 0;
    int out, ret;
    struct ifaddrs * ifa, * ifa_tmp;
    struct TRFInterface * trfi = calloc(1, sizeof(struct TRFInterface));
    if (!trfi)
    {
        trf__log_error("Could not allocate interface list storage");
        return -ENOMEM;
    }

    struct TRFInterface * trf_tmp = trfi;
    struct TRFInterface * prev_trf = NULL;
    if (getifaddrs(&ifa) < 0)
    {
        trf__log_error("getifaddrs() error: %s", strerror(errno));
        goto freenomem;
    }

    for (ifa_tmp = ifa; ifa_tmp; ifa_tmp = ifa_tmp->ifa_next)
    {
        if (ifa_tmp->ifa_addr)
        {
            char dbg[INET6_ADDRSTRLEN];

            if (ifa_tmp->ifa_addr->sa_family == AF_INET
                && (flags & TRF_INTERFACE_IP4))
            {
                trf__log_trace("Actual Mask %s", inet_ntop(AF_INET, 
                        &((struct sockaddr_in *) \
                            ifa_tmp->ifa_netmask)->sin_addr.s_addr,
                        dbg, INET_ADDRSTRLEN
                    ));
                
                
                if (flags & TRF_INTERFACE_EXT)
                {
                    uint8_t nm =  trf__HammingWeight64(
                        ((struct sockaddr_in *) \
                            ifa_tmp->ifa_netmask)->sin_addr.s_addr
                        );
                    for (struct TRFNet *tmp = netDb; tmp; tmp = tmp->next)
                    {
                        if (tmp->type == TRF_NET_BLACKLIST 
                            && ifa_tmp->ifa_name == tmp->ifname){
                            break;
                        }
                        if (tmp->sa.ss_family == AF_INET 
                            && tmp->type == TRF_NET_LINK_LOCAL){
                            
                            char test[INET6_ADDRSTRLEN], test2[INET6_ADDRSTRLEN];
                            trfGetIPaddr(ifa_tmp->ifa_addr, test);
                            trfGetIPaddr((struct sockaddr *) &tmp->sa, test2);
                            trf__log_debug("Checking IP address pair %s <--> %s"
                                    ,test,test2);

                            ret = trfCheckNetwork(ifa_tmp->ifa_addr, nm, 
                                (struct sockaddr *) &tmp->sa, tmp->subnet);
                            trf__log_trace("Return Value from check network: %d", 
                                    ret);
                            if (ret == 0){
                                trf_tmp->netmask = nm;
                                trf_tmp->addr = \
                                    malloc(sizeof(struct sockaddr_in));
                                if (!trf_tmp->addr)
                                {
                                    trf__log_error("Memory allocation failed");
                                    goto freenomem;
                                }
                                out = trfGetLinkSpeed(ifa_tmp->ifa_name, 
                                    &trf_tmp->speed);
                                if ((out < 0 || trf_tmp->speed < 0) 
                                    && (flags & TRF_INTERFACE_SPD))
                                {
                                    trf__log_warn("Unable to get"
                                        "interface speed for %s", 
                                        ifa_tmp->ifa_name);
                                    break;
                                }
                                memset(test, 0, INET6_ADDRSTRLEN);
                                if (trfGetIPaddr(ifa_tmp->ifa_addr, test) == 0)
                                {
                                    trf__log_trace("External IP address found: %s", test);
                                }
                                memcpy(trf_tmp->addr, ifa_tmp->ifa_addr, 
                                    sizeof(struct sockaddr_in));
                                break;
                            }
                            else if(ret == 1)
                            {
                                break;
                            }
                            else
                            {
                                trf__log_error("Unable to check address");
                                return -1;
                            }
                        }
                    }
                }
                if (flags & TRF_INTERFACE_LOCAL)
                {
                    trf__log_trace("Getting hammer weight of Subnet");
                    uint8_t nm =  trf__HammingWeight64(
                        ((struct sockaddr_in *) \
                            ifa_tmp->ifa_netmask)->sin_addr.s_addr
                        );
                    trf__log_trace("Finished getting hammer weight");
                    for (struct TRFNet *tmp = netDb; tmp; tmp = tmp->next)
                    {
                        if (tmp->type == TRF_NET_BLACKLIST //Check blacklist addresses
                            && ifa_tmp->ifa_name == tmp->ifname){
                            break;
                        }

                        if (tmp->sa.ss_family == AF_INET 
                            && tmp->type == TRF_NET_LINK_LOCAL)
                        {

                            ret = trfCheckNetwork(ifa_tmp->ifa_addr, nm, 
                                (struct sockaddr *) &tmp->sa, tmp->subnet);
                            if (ret == 1)
                            {
                                trf_tmp->netmask = nm;
                                trf_tmp->addr = \
                                    malloc(sizeof(struct sockaddr_in));
                                if (!trf_tmp->addr)
                                {
                                    trf__log_error("Memory allocation failed");
                                    goto freenomem;
                                }
                                out = trfGetLinkSpeed(ifa_tmp->ifa_name, 
                                    &trf_tmp->speed);
                                if ((out < 0 || trf_tmp->speed < 0) 
                                    && (flags & TRF_INTERFACE_SPD))
                                {
                                    trf__log_warn("Unable to get"
                                        "interface speed for %s", 
                                        ifa_tmp->ifa_name);
                                    break;
                                }
                                trf__log_trace("linklocal ipv4 address added to interface list");
                                memcpy(trf_tmp->addr, ifa_tmp->ifa_addr, 
                                    sizeof(struct sockaddr_in));
                                break;
                            }
                            else if(ret == 0)
                            {
                                break;
                            }
                            else
                            {
                                trf__log_error("Unable to check address");
                                return -1;
                            }
                        }
                    }
                }
            }
            else if (ifa_tmp->ifa_addr->sa_family == AF_INET6
                && (flags & TRF_INTERFACE_IP6))
            {
                if (flags & TRF_INTERFACE_EXT)
                {
                    trf__log_trace("Actual Mask %s", inet_ntop(AF_INET6, 
                        &((struct sockaddr_in6 *) \
                            ifa_tmp->ifa_netmask)->sin6_addr.s6_addr,
                            dbg, INET6_ADDRSTRLEN
                    ));
                    uint8_t v6sn = 0;
                    uint64_t * addr_ptr = (uint64_t *) &((struct sockaddr_in6 *) \
                        ifa_tmp->ifa_netmask)->sin6_addr.s6_addr;
                    v6sn += trf__HammingWeight64((uint64_t) *addr_ptr);
                    v6sn += trf__HammingWeight64((uint64_t) *++addr_ptr);

                    for (struct TRFNet *tmp = netDb; tmp; tmp = tmp->next)
                    {
                        if (tmp->sa.ss_family == AF_INET6 
                                && tmp->type == TRF_NET_LINK_LOCAL)
                        {
                            ret = trfCheckNetwork(ifa_tmp->ifa_addr, v6sn, 
                                (struct sockaddr *) &tmp->sa, tmp->subnet);
                            if (ret == 0)
                            {
                                trf_tmp->netmask = v6sn;
                                trf_tmp->addr = malloc(sizeof(struct sockaddr_in6));
                                if (!trf_tmp->addr)
                                {
                                    trf__log_error("Memory allocation failed");
                                    goto freenomem;
                                }
                                out = trfGetLinkSpeed(ifa_tmp->ifa_name, 
                                    &trf_tmp->speed);
                                if ((out < 0 || trf_tmp->speed < 0) 
                                    && (flags & TRF_INTERFACE_SPD))
                                {
                                    trf__log_warn("Unable to get"
                                        "interface speed for %s", 
                                        ifa_tmp->ifa_name);
                                    break;
                                }
                                trf__log_trace("External ipv6 address added to interface list");
                                memcpy(trf_tmp->addr, ifa_tmp->ifa_addr, 
                                    sizeof(struct sockaddr_in6));
                                break;
                            }
                        }
                    }
                }
                if (flags & TRF_INTERFACE_LOCAL)
                {
                    trf__log_trace("Actual Mask %s", inet_ntop(AF_INET6, 
                        &((struct sockaddr_in6 *) \
                            ifa_tmp->ifa_netmask)->sin6_addr.s6_addr,
                            dbg, INET6_ADDRSTRLEN
                    ));
                    uint8_t v6sn = 0;
                    uint64_t * addr_ptr = (uint64_t *) &((struct sockaddr_in6 *) \
                        ifa_tmp->ifa_netmask)->sin6_addr.s6_addr;
                    v6sn += trf__HammingWeight64((uint64_t) *addr_ptr);
                    v6sn += trf__HammingWeight64((uint64_t) *++addr_ptr);

                    for (struct TRFNet *tmp = netDb; tmp; tmp = tmp->next)
                    {
                        if (tmp->sa.ss_family == AF_INET6 
                                && tmp->type == TRF_NET_LINK_LOCAL)
                        {
                            ret = trfCheckNetwork(ifa_tmp->ifa_addr, v6sn, 
                                (struct sockaddr *) &tmp->sa, tmp->subnet);
                            if (ret == 1)
                            {
                                trf_tmp->netmask = v6sn;
                                trf_tmp->addr = malloc(sizeof(struct sockaddr_in6));
                                if (!trf_tmp->addr)
                                {
                                    trf__log_error("Memory allocation failed");
                                    goto freenomem;
                                }
                                out = trfGetLinkSpeed(ifa_tmp->ifa_name, 
                                    &trf_tmp->speed);
                                if ((out < 0 || trf_tmp->speed < 0) 
                                    && (flags & TRF_INTERFACE_SPD))
                                {
                                    trf__log_warn("Unable to get"
                                        "interface speed for %s", 
                                        ifa_tmp->ifa_name);
                                    break;
                                }
                                trf__log_trace("linklocal ipv6 address added to interface list");
                                memcpy(trf_tmp->addr, ifa_tmp->ifa_addr, 
                                    sizeof(struct sockaddr_in6));
                                break;
                            }
                        }
                    }
                }
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
                    prev_trf = trf_tmp;
                    trf_tmp = trf_tmp->next;
                }
                len++;
            }
        }
    }
    free(trf_tmp);
    if (prev_trf)
    {
        prev_trf->next = NULL;
    }

    freeifaddrs(ifa);

    *length = len; 
    *list_out = trfi;
    return 0;
    
    #else
    return -ENOSYS;
    #endif

#ifdef _TRF_UNIX_
freenomem:
    out = -ENOMEM;
    trfFreeInterfaceList(trfi);
    freeifaddrs(ifa);
    return out;
#endif
}

PTRFInterface trfSortInterfaceList(PTRFInterface list)
{
    if (!list)
    {
        trf__log_error(
            "Invalid interface list passed to trfSortInterfaceList()");
        errno = -EINVAL;
        return NULL;
    }

    int len = 0;
    PTRFInterface if_tmp = list;
    while (if_tmp)
    {
        len++;
        if_tmp = if_tmp->next;
    }

    if (len > UINT16_MAX)
    {
        errno = -ENOBUFS;
        return NULL;
    }

    uint16_t * idx_list = calloc(len, sizeof(uint16_t));
    if (!idx_list)
    {
        errno = -ENOMEM;
        return NULL;
    }

    PTRFInterface * ptr_list = calloc(len + 1, sizeof(PTRFInterface));
    if (!ptr_list)
    {
        free(ptr_list);
        errno = -ENOMEM;
        return NULL;
    }

    int rem = len;
    while (rem)
    {
        PTRFInterface if_max = NULL;
        int max_spd = -100;
        int idx = 0;
        int if_max_idx = 0;
        for (if_tmp = list; if_tmp; if_tmp = if_tmp->next)
        {
            if (!idx_list[idx] && if_tmp->speed > max_spd)
            {
                trf__log_trace("Fastest link speed: %d", if_tmp->speed);
                if_max = if_tmp;
                max_spd = if_tmp->speed;
                if_max_idx = idx;
            }
            idx++;
        }
        idx_list[if_max_idx] = rem;
        ptr_list[len - rem] = if_max;
        rem--;
    }

    for (; rem < len; rem++)
    {
        assert(ptr_list[rem]);
        ptr_list[rem]->next = ptr_list[rem + 1];
    }

    PTRFInterface head = ptr_list[0];
    free(ptr_list);
    free(idx_list);
    return head;
}

PTRFAddrV trfSortAddrV(PTRFAddrV av)
{
    // This is very inefficient, but it should work for now

    if (!av)
    {
        trf__log_error("Invalid address vector passed to trfSortAddrV()");
        errno = -EINVAL;
        return NULL;
    }

    int len = 0;
    PTRFAddrV av_tmp = av;
    while (av_tmp)
    {
        len++;
        av_tmp = av_tmp->next;
    }

    if (len > UINT16_MAX)
    {
        errno = -ENOBUFS;
        return NULL;
    }

    uint16_t * idx_list = calloc(len, sizeof(uint16_t));
    if (!idx_list)
    {
        errno = -ENOMEM;
        return NULL;
    }

    PTRFAddrV * ptr_list = calloc(len + 1, sizeof(PTRFAddrV));
    if (!ptr_list)
    {
        free(idx_list);
        errno = -ENOMEM;
        return NULL;
    }

    int rem = len;
    while (rem)
    {
        PTRFAddrV av_max = NULL;
        int max_spd = -100;
        int idx = 0;
        int av_max_idx = 0;
        for (av_tmp = av; av_tmp; av_tmp = av_tmp->next)
        {
            if (!idx_list[idx] && av_tmp->pair_speed > max_spd)
            {
                trf__log_debug("Fastest pair speed: %d", av_tmp->pair_speed);
                av_max = av_tmp;
                max_spd = av_tmp->pair_speed;
                av_max_idx = idx;
            }
            idx++;
        }
        idx_list[av_max_idx] = rem;
        ptr_list[len - rem] = av_max;
        rem--;
    }

    for (; rem < len; rem++)
    {
        assert(ptr_list[rem]);
        ptr_list[rem]->next = ptr_list[rem + 1];
    }

    PTRFAddrV head = ptr_list[0];
    free(ptr_list);
    free(idx_list);
    return head;
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