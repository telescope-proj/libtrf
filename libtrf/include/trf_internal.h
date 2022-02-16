/*
    SPDX-License-Identifier: LGPL-2.1-only

    Telescope Project
    Remote Framebuffer Library
    Internal Functions

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
 * @file trf_internal.h
 * @brief Internal Functions
*/

#ifndef _TRF_INTERNAL_H_
#define _TRF_INTERNAL_H_

#include "trf.h"
#include "trf_log.h"

#if RAND_MAX/256 >= 0xFFFFFFFFFFFFFF
  #define TRF__LOOPS 1
#elif RAND_MAX/256 >= 0xFFFFFF
  #define TRF__LOOPS 2
#elif RAND_MAX/256 >= 0x3FFFF
  #define TRF__LOOPS 3
#elif RAND_MAX/256 >= 0x1FF
  #define TRF__LOOPS 4
#else
  #define TRF__LOOPS 5
#endif

/**
  * @brief          Check the number of times a session ID has been used.
  * 
  * @param ctx      Context
  * 
  * @param session  Session ID
  * 
  * @param first    Whether to the first item or the total count
  * 
  * @return         Number of times this session ID has been used, negative
  *                 error code on failure.
*/
int trf__CheckSessionID(PTRFContext ctx, uint64_t session, uint8_t first);

/**
  * @brief Allocate resouces for an incoming session on ther server side with a
  * specific cookie. 
  *
  * Allocates a resouces for an incoming session on the server side with a
  * specific cookie, The cookie must not be in use; use the function
  * trf__CheckSessionID() to verify
  * 
  * @param ctx      Context
  * 
  * @param session  Session ID
  * 
  * @param ctx_out  Pointer to the context item inserted into ctx
  * 
  * @return         0 on success, negative error code on failurey.
*/
int trf__AllocSessionForClient(PTRFContext ctx, uint64_t session_id,
    PTRFContext * ctx_out);

/**
  * @brief      Generate an 64-bit random integer
  * 
  * @return     A random integer.
*/
static inline uint64_t trf__Rand64()
{
    uint64_t r = 0;
    for (int i = TRF__LOOPS; i > 0; i--)
    {
        r = r * (RAND_MAX + (uint64_t) 1) + rand();
    }
    return r;
}

/**
  * @brief      Get the system page size
  * 
  * @return     System page size
*/
static inline size_t trf__GetPageSize() {
    #if defined(_WIN32)
        SYSTEM_INFO si;
        GetSystemInfo(&si);
        return si.dwPageSize;
    #else
        return sysconf(_SC_PAGESIZE);
    #endif
}

/**
  * @brief      Calculate the Hamming Weight (ones count) of a 64-bit integer
  * 
  * @param x    64-bit integer
  * 
  * @return     Hamming Weight
*/
static inline uint8_t trf__HammingWeight64(uint64_t x)
{
    uint8_t count = 0;
    while (x)
    {
        count++;
        x &= x - 1;
    }
    return count;
}

/**
 * @brief Return a timespec corresponding to a delay in milliseconds after the
 * input timespec.
 * 
 * @param ts            Timespec to start from
 * 
 * @param ts_out        Output timespec
 * 
 * @param delay_ms      Delay in milliseconds
 */
static inline void trf__GetDelay(struct timespec * ts, struct timespec * ts_out, 
    uint64_t delay_ms)
{
    ts_out->tv_sec = ts->tv_sec + (delay_ms / 1000);
    ts_out->tv_nsec = ts->tv_nsec + ((delay_ms % 1000) * 1000000);
    if (ts_out->tv_nsec > 1000000000)
    {
        ts_out->tv_sec++;
        ts_out->tv_nsec -= 1000000000;
    }
}

/**
 * @brief Determine whether a timespec is in the past
 * 
 * @param clock         Clock to use
 * 
 * @param ts            Timespec to check
 * 
 * @return              1 if ts in the past, 0 otherwise
 *                      Negative error code on failure
 */
static inline int trf__HasPassed(clockid_t clock, struct timespec * ts)
{
    struct timespec now;
    int ret = clock_gettime(clock, &now);
    if (ret != 0) {
        return -errno;
    }
    return (now.tv_sec > ts->tv_sec) ||
        ((now.tv_sec == ts->tv_sec) && (now.tv_nsec > ts->tv_nsec));
}

#endif // _TRF_INTERNAL_H_