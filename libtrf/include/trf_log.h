/**
 * Copyright (c) 2020 rxi
 *
 * This library is free software; you can redistribute it and/or modify it
 * under the terms of the MIT license. See `log.c` for details.
 */

/*  
    ------------------ Internal LibTRF Logging Functions ------------------- 

    Do not use these functions outside of library code; please load your own
    log.c file from https://github.com/rxi/log.c

    ------------------------------------------------------------------------
*/

#ifndef _TRF_LOG_H_
#define _TRF_LOG_H_

#include <stdio.h>
#include <stdarg.h>
#include <stdbool.h>
#include <time.h>

#define TRF_LOG_VERSION "0.1.0"

#define _TRF_FNAME_ (strrchr("/" __FILE__, '/') + 1)

typedef struct {
  va_list ap;
  const char *fmt;
  const char *file;
  struct tm *time;
  void *udata;
  int line;
  int level;
} trf__log_Event;

typedef void (*trf__log_LogFn)(trf__log_Event *ev);
typedef void (*trf__log_LockFn)(bool lock, void *udata);

enum { TRF__LOG_TRACE, TRF__LOG_DEBUG, TRF__LOG_INFO, TRF__LOG_WARN, TRF__LOG_ERROR, TRF__LOG_FATAL };

#define trf__log_trace(...) trf__log_log(TRF__LOG_TRACE, _TRF_FNAME_, __LINE__, __VA_ARGS__)
#define trf__log_debug(...) trf__log_log(TRF__LOG_DEBUG, _TRF_FNAME_, __LINE__, __VA_ARGS__)
#define trf__log_info(...)  trf__log_log(TRF__LOG_INFO,  _TRF_FNAME_, __LINE__, __VA_ARGS__)
#define trf__log_warn(...)  trf__log_log(TRF__LOG_WARN,  _TRF_FNAME_, __LINE__, __VA_ARGS__)
#define trf__log_error(...) trf__log_log(TRF__LOG_ERROR, _TRF_FNAME_, __LINE__, __VA_ARGS__)
#define trf__log_fatal(...) trf__log_log(TRF__LOG_FATAL, _TRF_FNAME_, __LINE__, __VA_ARGS__)

const char* trf__log_level_string(int level);
void trf__log_set_lock(trf__log_LockFn fn, void *udata);
void trf__log_set_level(int level);
void trf__log_set_quiet(bool enable);
int trf__log_add_callback(trf__log_LogFn fn, void *udata, int level);
int trf__log_add_fp(FILE *fp, int level);

void trf__log_log(int level, const char *file, int line, const char *fmt, ...);

#endif
