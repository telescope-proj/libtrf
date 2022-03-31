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

struct TRFContext;

#include <stdlib.h>

#include "trf_def.h"
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

/* Maximum protocol buffers message size, including delimiter */
#define trfPBMaxSize ((1UL << 31) - sizeof(uint32_t))

/**
 * @brief Returns the error code if negative
 * 
 */
#define trf__RetIfNeg(x) if ((x) < 0) { return (x); }

static inline int trf__CreateCQ(PTRFXFabric ctx, PTRFTCQFabric * tcq, 
                                struct fi_cq_attr * attr, void * context)
{
    PTRFTCQFabric tcq2 = calloc(1, sizeof(*tcq2));
    if (!tcq2)
    {
        return -ENOMEM;
    }
    int ret = fi_cq_open(ctx->domain, attr, &tcq2->cq, context);
    if (ret < 0)
    {
        free(tcq2);
        return ret;
    }
    tcq2->entries = attr->size;
    *tcq = tcq2;
    return 0;
}

static inline int trf__DestroyCQ(PTRFTCQFabric tcq)
{
    atomic_init(&tcq->entries, 0);
    fi_close(&tcq->cq->fid);
    free(tcq);
    return 0;
}

/**
 * @brief       Decrement number of available CQ entries
 * 
 * @param tcq   Pointer to the CQ
 * @param n     Number of entries to decrement
 * @return      Number of remaining entries. 0 if insufficient.
 */
static inline int_fast64_t trf__DecrementCQ(PTRFTCQFabric tcq, uint64_t n)
{
    int_fast64_t f;
    f = atomic_fetch_sub_explicit(&tcq->entries, n, memory_order_acq_rel);
    if (f < 0)
    {
        atomic_fetch_add_explicit(&tcq->entries, n, memory_order_acq_rel);
        return 0;
    }
    return n;
}

/**
 * @brief       Increment number of available CQ entries
 * 
 * @param tcq   Pointer to the CQ
 * @param n     Number of entries to increment
 */
static inline int_fast64_t trf__IncrementCQ(PTRFTCQFabric tcq, uint64_t n)
{
    int_fast64_t f;
    f = atomic_fetch_add_explicit(&tcq->entries, n, memory_order_acq_rel);
    return f + n;
}

/**
  * @brief          Check the number of times a session ID has been used.
  * 
  * @param ctx      Server context
  * 
  * @param session  Session ID
  * 
  * @return         Index where the session ID is used. -1 if not used.
*/
int trf__CheckSessionID(PTRFContext ctx, uint64_t session);

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
 * @brief Simple string duplication function for standard C.
 * 
 * @param str   String to duplicate
 * @return      Pointer to the duplicated string stored in the heap.
 */
static inline char * trfStrdup(char * str)
{
    size_t len = strlen(str) + 1;
    char * out = malloc(len);
    memcpy(out, str, len);
    return out;
}

/**
 * @brief Sleep for a given number of milliseconds.
 * 
 * @param ms    Number of milliseconds to sleep.
 */
static inline void trfSleep(int ms) {
    if (ms <= 0) { return; }
#ifdef _WIN32
    Sleep(ms);
#else
    struct timespec t;
    t.tv_sec    = ms / 1000;
    t.tv_nsec   = (ms % 1000) * 1000000;
    nanosleep(&t, NULL);
#endif
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

static inline int trf__RemainingMS(struct timespec * ts)
{
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    int ms;
    if ((now.tv_sec > ts->tv_sec && now.tv_nsec > ts->tv_nsec)
            || (now.tv_sec == ts->tv_sec && now.tv_nsec > ts->tv_nsec))
    {
        ms = 0;
    }
    else
    {
        ms = (ts->tv_sec - now.tv_sec) * 1000;
        ms += (ts->tv_nsec - now.tv_nsec) / 1000000;
    }
    return ms;
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
    return ((now.tv_sec > ts->tv_sec && now.tv_nsec > ts->tv_nsec)
            || (now.tv_sec == ts->tv_sec && now.tv_nsec > ts->tv_nsec));
}

#define trf__ProtoStringValid(ptr) \
    (ptr != NULL && ptr != protobuf_c_empty_string)

#endif // _TRF_INTERNAL_H_