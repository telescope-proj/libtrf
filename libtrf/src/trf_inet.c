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

#include "trf_inet.h"
#include "trf_platform.h"
int trfCheckIPVersion(char * addr)
{
    char buf[INET6_ADDRSTRLEN];
    if (inet_pton(AF_INET, addr, buf))
    {
        return 4;
    } 
    else if (inet_pton(AF_INET6, addr, buf))
    {
        return 6;
    }
    return -1;
}

int trfConvertCharToAddr(char * addr, struct sockaddr * data)
{
    switch (trfCheckIPVersion(addr))
    {
        case 4:
            data->sa_family = AF_INET;
            if (inet_pton(AF_INET, addr, &((struct sockaddr_in *) data)->sin_addr.s_addr) < 0)
            {
                trf__log_error("Unable to convert IPv4 address: %s", strerror(errno));
                return -errno;
            };
            break;
        case 6:
            data->sa_family = AF_INET6;
            if (inet_pton(AF_INET6, addr, 
                &((struct sockaddr_in6 *) data)->sin6_addr.s6_addr) < 0)
            {
                trf__log_error("Unable to convert IPv6 address: %s", strerror(errno));
                return -errno;
            }
            break;
        default:
            trf__log_error("Unknown address family");
            return -errno;
    }
    return 0;
}

int trfNodeServiceToAddr(const char * addr, struct sockaddr * sdr)
{
    char ip[INET6_ADDRSTRLEN];
    char port[7];
    memset(ip, 0, INET6_ADDRSTRLEN);
    memset(port, 0, 6);
    if (!addr)
    {
        return -EINVAL;
    }

    char * daddr = strdup(addr);
    char * token = strrchr(daddr, ':');
    if (strchr(daddr, '['))
    {
        strncpy(ip, daddr + 1, token - daddr - 1);
    }
    else 
    {
        strncpy(ip, daddr, token - daddr);
    }
    strncpy(port, token + 1, 6);

    int ret;
    if((ret = trfConvertCharToAddr(ip,sdr)) < 0)
    {
        trf__log_error("Unable to decode IP address");
        return ret;
    }
    ((struct sockaddr_in *) sdr)->sin_port = htons(atoi(port));
    free(daddr);
    return 0;
}

int trfGetNodeService(struct sockaddr * sdr, char * addr)
{
    if (!sdr || !addr)
    {
        return -EINVAL;
    }
    switch (sdr->sa_family)
    {
        case AF_INET:
            if (!inet_ntop(AF_INET, 
                &((struct sockaddr_in *) sdr)->sin_addr.s_addr, addr, 
                INET_ADDRSTRLEN))
            {
                trf__log_error("Unable to decode IPv4 address");
                return -errno;
            }
            if (!snprintf(addr + strlen(addr), 7, ":%d", 
                ntohs(((struct sockaddr_in *) sdr)->sin_port)))
            {
                trf__log_error("Unable to decode port");
                return -errno;
            }
            break;
        case AF_INET6:
            addr[0] = '[';
            if(!inet_ntop(AF_INET6, 
                &((struct sockaddr_in6 *) sdr)->sin6_addr.s6_addr, addr + 1, 
                INET6_ADDRSTRLEN))
            {
                trf__log_error("Unable to decode IPv6 address");
                return -errno;
            }
            if (!snprintf(addr + strlen(addr), 8, "]:%d", 
                ntohs(((struct sockaddr_in6 *) sdr)->sin6_port)))
            {
                trf__log_error("Unable to decode port");
                return -errno;
            }
            break;
    }
    return 0;
}

int trfGetIPaddr(struct sockaddr * sdr, char * addr)
{
    if (!addr || !sdr)
    {
        trf__log_error("Invalid argument to trfGetIPaddr: sdr: %p; addr: %p",
                       sdr, addr);
        return -EINVAL;
    }
    switch (sdr->sa_family)
    {
        case AF_INET:
            if (!inet_ntop(AF_INET, 
                &((struct sockaddr_in *) sdr)->sin_addr.s_addr, addr, 
                INET_ADDRSTRLEN))
            {
                trf__log_error("Unable to decode IPv4 address");
                return -errno;
            }
            break;
        case AF_INET6:
            if(!inet_ntop(AF_INET6, 
                &((struct sockaddr_in6 *) sdr)->sin6_addr.s6_addr, addr, 
                INET6_ADDRSTRLEN))
            {
                trf__log_error("Unable to decode IPv6 address");
                return -errno;
            }
            break;
        default:
            trf__log_error("Unknown address family");
            return -EINVAL;
    }
    return 0;
}

int trfGetMappedIPv4addr(struct sockaddr_in6 * addr, char * address)
{
    if (IN6_IS_ADDR_V4MAPPED(&addr->sin6_addr))
    {
        if (!inet_ntop(AF_INET6, &addr->sin6_addr, address, INET6_ADDRSTRLEN))
            {
                trf__log_error("Failed to decode mapped address: %s",
                    strerror(errno));
                return -errno;
            }
        return 0;
    }
    const uint8_t *bytes = ((const struct sockaddr_in6 *)addr)->sin6_addr.s6_addr;
    bytes += 12;
    struct in_addr taddr = { *(const in_addr_t *)bytes };
    if (!inet_ntop(AF_INET, &taddr, address, INET_ADDRSTRLEN))
    {
        trf__log_error("Failed to decode mapped address: %s",
            strerror(errno));
        return -errno;
    }
    return 0;
}

#define trf__Netmask4(n) ((n) == 0 ? 0 : ((n) == 32 ? 0xFFFFFFFF : (0xFFFFFFFF << (32 - (n)))))
#define trf__Netmask6(n) ((n) == 0 ? 0 : ((n) == 128 ? 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF : (0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF << (128 - (n)))))
#define TRF__PSAI struct sockaddr_in *
#define TRF__PSAI6 struct sockaddr_in6 *
#define trf__RawAddr4(a) (((TRF__PSAI)a)->sin_addr.s_addr)
#define trf__RawAddr6(a) (((TRF__PSAI6)a)->sin6_addr.s6_addr)

int trfCheckNetwork(struct sockaddr * net1, int8_t net1_sn , 
        struct sockaddr * net2, int8_t net2_sn){

    if (net1->sa_family != net2->sa_family){
        trf__log_error("Source and destination addresses must be the same type");
        return -1;
    }
    switch (net1->sa_family)
    {
    case AF_INET:
        if (
            (trf__RawAddr4(net1) 
            & trf__Netmask4(net1_sn)) ==
            (trf__RawAddr4(net2)
            & trf__Netmask4(net2_sn))
        )
        {
            return 1;
        }
        else 
        {
            return 0;
        }
        break;
    case AF_INET6: ;
        uint64_t * ca1 = (uint64_t *) \
            ((struct sockaddr_in6 *) &net1)->sin6_addr.s6_addr;
        uint64_t * ca2 = ca1 ++;

        uint64_t * da1 = (uint64_t *) \
            ((struct sockaddr_in6 *) &net2)->sin6_addr.s6_addr;
        uint64_t * da2 = da1 ++;

        uint64_t cnm1 = net1_sn > 64 ? \
            htobe64(INT64_MIN >> 63) : \
            htobe64(INT64_MIN >> (net1_sn - 1));
        uint64_t cnm2 = net1_sn > 64 ? \
            htobe64(INT64_MIN >> (net1_sn - 65)): \
            0;

        uint64_t dnm1 = net2_sn > 64 ? \
            htobe64(INT64_MIN >> 63): \
            htobe64(INT64_MIN >> (net2_sn - 1));
        uint64_t dnm2 = net2_sn > 64 ? \
            htobe64(INT64_MIN >> (net2_sn - 65)) : \
            0;

        uint64_t cr1 = *ca1 & cnm1;
        uint64_t cr2 = *ca2 & cnm2;
        uint64_t sr1 = *da1 & dnm1;
        uint64_t sr2 = *da2 & dnm2;

        if (cr1 == sr1 && cr2 == sr2)
        {
            return 1;
        }
        else 
        {
            return 0;
        }

        break;
    default:
        trf__log_error("Invalid ip address family");
        return -1;
    }
    return 0;
}