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

#include "trf_preflight.h"

int trfNCClientGetReachable(PTRFInterface serverIf, int64_t sessionID)
{
    int sockfd;
    struct sockaddr_in servaddr;
    struct sockaddr_in6 servaddr6;
    uint64_t be_session = htobe64(sessionID);
    PTRFAddrV v_pair = malloc(sizeof(*v_pair));
    for(PTRFInterface tmp_if = serverIf; tmp_if; tmp_if = tmp_if->next)
    {
        char *tmp_addr[INET6_ADDRSTRLEN];
        if (trfGetIPaddr(tmp_if->addr,tmp_addr) < 0)
        {
            trf__log_error("unable to convert ip addr to char");
        }
        int protocolVersion = trfCheckIPVersion(tmp_addr);
        switch (protocolVersion)
        {
            case 4:
                trf__log_trace("Opening IPV4 Socket");
                if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0))<0)
                {
                    trf__log_error("Unable to open ipv4 socket");
                    break;
                }
                v_pair->dst_addr = tmp_if->addr; 
                v_pair->pair_speed = tmp_if->speed;

                memset(&servaddr, 0, sizeof(servaddr));
                servaddr.sin_family = AF_INET;
                servaddr.sin_port = htons(tmp_if->port);
                servaddr.sin_addr.s_addr = inet_addr(tmp_if->addr.sa_data);
                if(sendto(sockfd, &be_session, sizeof(be_session),0,
                (const struct sockaddr *) &servaddr, 
                sizeof(servaddr)) < 0){
                    trf__log_error("Unable to send serverID to address: %s",tmp_if->addr);
                    close(sockfd);
                    break;
                }
                int ret =0;
                char buf[8];
                if((ret = recvfrom(sockfd,buf,8, 0, (struct sockaddr *) &servaddr, sizeof(servaddr)) < 0)){
                    trf__log_error("Unable to receive message from server: %s",strerror(ret));
                }
                close(sockfd);
                break;
            case 6:
                trf__log_trace("Opening IPV6 Socket");
                if((sockfd = socket(AF_INET6, SOCK_DGRAM, 0)) < 0){
                    trf__log_error("Unable to open ipv6 socket");
                    break;
                }
                trf__log_trace("tmp_if: %p", tmp_if);
                trf__log_trace("tmp: %d %p", tmp_if->port, tmp_if->addr);
                memset(&servaddr6, 0, sizeof(servaddr6));
                servaddr6.sin6_family   = AF_INET6;
                servaddr6.sin6_flowinfo = 0;
                servaddr6.sin6_port     = htons(tmp_if->port);
                if(inet_pton(AF_INET6, tmp_addr, (void *) &servaddr6.sin6_addr) != 1)
                {
                    trf__log_error("Unable to convert ipv6 address");
                    break;
                }

                if(sendto(sockfd, &be_session, sizeof(sessionID),0,
                (const struct sockaddr *) &servaddr6, 
                sizeof(servaddr6)) < 0)
                {
                    trf__log_error("Unable to send serverID to address: [%s]:%d -> %s",
                        tmp_if->addr, tmp_if->port, strerror(errno));
                    close(sockfd);
                    break;
                }
                int ret =0;
                char buf[8];
                if( (ret = recvfrom(sockfd,buf,8, 0, (struct sockaddr *) &servaddr6, sizeof(servaddr6)) < 0)){
                    trf__log_error("Unable to receive message from server: %s",strerror(ret));
                }
                close(sockfd);
                break;
            case -1:
                trf__log_error("Unable to decode IP address");
                break;
        }
    }
    return 0;
}

int trfNCServerPreFlight(int * fd_out, uint16_t * port)
{
    int ret;
    int sfd = socket(AF_INET6, SOCK_DGRAM, 0);
    if (sfd < 0)
    {
        trf__log_error("Preflight server creation failed: %s", strerror(errno));
        return -errno;
    }

    struct sockaddr_in6 in6;
    in6.sin6_family     = AF_INET6;
    in6.sin6_addr       = in6addr_any;
    in6.sin6_port       = 0;
    
    int val = 0;
    ret = setsockopt(sfd, IPPROTO_IPV6, IPV6_V6ONLY, (void *) &val, sizeof(val));
    if (ret < 0)
    {
        trf__log_error("Dual stack socket creation failed");
        close(sfd);
        return -errno;
    }

    socklen_t len = sizeof(in6);

    ret = bind(sfd, (struct sockaddr *) &in6, len);
    if (ret < 0)
    {
        trf__log_error("Preflight server creation failed: %s", strerror(errno));
        close(sfd);
        return -errno;
    }

    ret = getsockname(sfd, (struct sockaddr *) &in6, &len);
    if (ret < 0)
    {
        trf__log_error("Preflight server creation failed");
        close(sfd);
    }
    
    char tmp_addr[INET6_ADDRSTRLEN];
    trf__log_debug(
        "Preflight receiver created at [%s]:%d", 
        inet_ntop(AF_INET6, &in6.sin6_addr, tmp_addr, len),
        ntohs(in6.sin6_port)
    );

    *fd_out = sfd;
    *port   = ntohs(in6.sin6_port);
    return 0;
}

int trfNCServerPreFlightCheck(int sfd, int timeout, uint64_t session_id, 
    PTRFInterface addrs)
{   
    struct sockaddr_in6 src_addr;
    ssize_t ret;
    char buf[8];

    struct timespec tcur, tend;

    ret = clock_gettime(CLOCK_MONOTONIC, &tcur);
    if (ret < 0)
    {
        trf__log_error("System clock error: %s", strerror(errno));
        return -errno;
    }

    tend = tcur;
    tend.tv_sec += timeout;

    trf__log_trace("cur: %lu %lu", tcur.tv_sec, tcur.tv_nsec);
    trf__log_trace("end: %lu %lu", tend.tv_sec, tend.tv_nsec);

    // Set timeout
    struct timeval tv;
    tv.tv_sec = timeout;
    tv.tv_usec = 0;

    if (setsockopt(sfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0)
    {
        trf__log_error("Unable to set preflight server timeout");
        return -errno;
    }

    socklen_t len = sizeof(src_addr);
    char addr[INET6_ADDRSTRLEN];
    while (1)
    {   
        int client_valid = 0;
        ret = recvfrom(sfd, buf, 8, 0, (struct sockaddr *) &src_addr, &len);
        if (ret == 8)
        {
            //!todo determine client
            if(trfGetMappedIPv4addr(&src_addr, addr)<0)
            {
                trf__log_error("Unable to decode mapped address");
            }
            trf__log_debug("Preflight message from %s:%d, cookie: %lu",
               addr, ntohs(src_addr.sin6_port), * (uint64_t *) buf
            );
            if (be64toh(*(uint64_t*)buf) == session_id)
            {
                client_valid = 1;
                if (!trfValidRouteUpdate(addrs, addr))
                {
                    trf__log_error("Unable to update valid flag");
                }
                if (sendto(sfd, buf, 8, MSG_CONFIRM, &src_addr, len) < 0)
                {
                    trf__log_error("Unable to confirm connection from client");
                }
            }
        }
        else if (ret < 0 && (errno != EAGAIN && errno != EWOULDBLOCK))
        {
            trf__log_error("Preflight channel error: %s", strerror(errno));
            return -errno;
        }
        else if (ret > 0)
        {
            trf__log_warn(
                "Invalid preflight message - %ld bytes (expected 8)", ret
            );
        }

        // Recalculate remaining time

        ret = clock_gettime(CLOCK_MONOTONIC, &tcur);
        if (ret < 0)
        {
            trf__log_error("System clock error: %s", strerror(errno));
            return -errno;
        }

        trf__log_trace("cur: %lu %lu", tcur.tv_sec, tcur.tv_nsec);

        if ( (tcur.tv_sec > tend.tv_sec)
             || (tcur.tv_sec == tend.tv_sec && tcur.tv_nsec >= tend.tv_nsec))
        {
            break;
        }

        long tdiff = (tend.tv_nsec - tcur.tv_nsec) / 1000;
        trf__log_trace("tdiff: %ld", tdiff);
        tv.tv_sec = tdiff > 0 ? \
            (tend.tv_sec - tcur.tv_sec) : (tend.tv_sec - tcur.tv_sec - 1);
        tv.tv_usec = tdiff > 0 ? \
            tdiff : (1e6 + tdiff);
        trf__log_trace("Waiting %lu %lu longer for preflight message", 
            tv.tv_sec, tv.tv_usec);
        if (setsockopt(sfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0)
        {
            trf__log_error("Unable to set preflight server timeout");
            return -errno;
        }
    }

    return 0;
}
