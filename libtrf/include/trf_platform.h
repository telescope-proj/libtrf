#ifndef _TRF_PLATFORM_H_
#define _TRF_PLATFORM_H_

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include "internal/trfi.h"
#include "trf_inet.h"

#if defined (__unix__) || (defined (__APPLE__) && defined (__MACH__))
  #define _TRF_UNIX_ 1
  #include <sys/socket.h>
  #include <arpa/inet.h>
  #include <ifaddrs.h>
  #include <sys/ioctl.h>
  #include <netinet/in.h>
  #if (defined (__APPLE__) && defined (__MACH__))
    #define _TRF_OSX_ 1
    #include "osx/endian.h"
  #else
    #include <endian.h>
  #endif
#endif

#define TRF_NET_LINK_LOCAL  1               // Link-local networks, such as localhost
#define TRF_NET_LOCAL       2               // Local networks, such as RFC1918

#define TRF_NET_ADDR        5               // This TRFNet struct contains a populated struct sockaddr
#define TRF_NET_IFNAME      6               // ... interface name
#define TRF_NET_BLACKLIST   7               // ... unusable interface name

struct TRFNet {
    int8_t                      type;             // Link type (e.g. linklocal, local)
    int8_t                      name;             // Determines whether it is blacklisted address stored or interfacename
    int8_t                      subnet;           // Subnet
    union {
        struct sockaddr_storage sa;               // IP address
        char                    * ifname;         // Interface name
    };
    struct TRFNet *           next;               // Next item in linked list
};

extern struct TRFNet *netDb;

/**
 * @brief Parse OS specific linklocal and local addresses and interface names
 * 
 * @param configFile      Path to config file 
 * @param out             Output from from function containing the configurations
 * @return 0 on success, negative error code on failure
 */
int trfParseConfig(char *configFile);

#endif